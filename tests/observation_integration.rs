use std::time::Duration;
use watchme::daemon::classify_herdr_state;
use watchme::daemon::registry::Registry;
use watchme::model::{Event, EventCategory, EventSource, PolicyHint, SourceKind};
use watchme::model::{ProcessIdentity, TARGET_IDENTITY_SCHEMA_VERSION, TargetIdentity};
use watchme::model::{WatcherLifecycle, WatcherState};
use watchme::observe::screen::{TmuxChrome, trusted_tmux_screen};
use watchme::recovery::coordinator::RecoveryCoordinator;
use watchme::recovery::state_machine::{Budget, RecoveryMachine, RecoveryState};
use watchme::recovery::state_machine::{ClockSnapshot, RecoveryCommand};
use watchme::store::JsonStore;

#[test]
fn identity_v2_round_trips_complete_tmux_context() {
    let identity = TargetIdentity::tmux(
        "/tmp/tmux-1000/default".into(),
        "server-boot-7".into(),
        "$3".into(),
        "@4".into(),
        "%5".into(),
        "/dev/pts/8".into(),
        ProcessIdentity::new(42, 99),
        Some(chrome()),
    );
    let json = serde_json::to_value(&identity).unwrap();
    assert_eq!(json["schema_version"], TARGET_IDENTITY_SCHEMA_VERSION);
    assert_eq!(json["context"]["session_id"], "$3");
    assert_eq!(json["context"]["window_id"], "@4");
    assert_eq!(json["chrome"]["version"], 1);
    assert_eq!(
        serde_json::from_value::<TargetIdentity>(json).unwrap(),
        identity
    );
}

#[test]
fn legacy_v1_identity_loads_but_requires_refresh() {
    let legacy = serde_json::json!({
        "kind":"multiplexer", "schema_version":1, "provider":"tmux",
        "server":"/tmp/tmux", "pane":"%1", "process": {
            "schema_version":1, "pid":42, "start_time":99, "executable":null,
            "argv_digest":null, "uid":null, "process_group_id":null,
            "session_leader_id":null, "tty":null, "parent_digest":null
        }, "session":"$1"
    });
    let migrated: TargetIdentity = serde_json::from_value(legacy).unwrap();
    assert!(migrated.needs_revalidation());
    assert!(migrated.observation_context().is_none());
}

#[test]
fn trusted_chrome_only_exposes_current_bottom_region() {
    let capture = "old blocker: approve this\n> blocker: quoted\n```\nblocker: pasted\n```\nACTUAL-ADAPTER-BOUNDARY\nordinary output\nblocker: current\n";
    let live = trusted_tmux_screen(capture, &chrome());
    assert_eq!(
        live.actionable_bottom(20).unwrap(),
        "ordinary output\nblocker: current"
    );
}

#[test]
fn absent_trusted_boundary_is_never_actionable() {
    let live = trusted_tmux_screen("blocker: current\n", &chrome());
    assert!(live.actionable_bottom(20).is_none());
}

fn chrome() -> TmuxChrome {
    TmuxChrome {
        adapter: "fixture-provider".into(),
        version: 1,
        boundary_marker: "ACTUAL-ADAPTER-BOUNDARY".into(),
    }
}

#[test]
fn observation_commit_rolls_back_schedule_event_and_recovery_on_store_failure() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("state");
    std::fs::create_dir(&parent).unwrap();
    let path = parent.join("watchers.json");
    let mut registry = Registry::load(JsonStore::new(path)).unwrap();
    let mut watcher = WatcherState::new(
        "w".into(),
        TargetIdentity::process(ProcessIdentity::new(42, 99)),
        WatcherLifecycle::Registered,
        0,
        0,
    );
    watcher.recovery = Some(RecoveryMachine::new(Budget {
        max_attempts: 2,
        max_cumulative_wait: Duration::from_secs(60),
        planner_calls: 0,
        cooldown: Duration::from_secs(1),
    }));
    registry.register(watcher).unwrap();
    let before = registry.get("w").unwrap().clone();
    std::fs::rename(&parent, temp.path().join("moved")).unwrap();
    std::fs::write(&parent, b"not a directory").unwrap();
    let mut schedule = before.observation_schedule.clone();
    schedule.event_wake_pending = true;
    let event = Event::new(
        "e1",
        "2026-07-11T00:00:00Z",
        "w",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        EventSource::new(SourceKind::ScreenDetection, "tmux", "fixture"),
        EventCategory::UnknownBlocked,
        0.8,
        false,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "trusted fixture",
        PolicyHint::ObserveOnly,
    )
    .unwrap();
    assert!(
        registry
            .commit_observation("w", schedule, Some(event), 10)
            .is_err()
    );
    assert_eq!(registry.get("w").unwrap(), &before);
    assert_eq!(
        registry
            .get("w")
            .unwrap()
            .recovery
            .as_ref()
            .unwrap()
            .state(),
        RecoveryState::NeedsRevalidation
    );
}

#[test]
fn herdr_typed_states_map_explicitly_and_unknown_is_nonactionable() {
    assert_eq!(
        classify_herdr_state("working", false).0,
        EventCategory::Working
    );
    assert_eq!(classify_herdr_state("idle", false).0, EventCategory::Idle);
    assert_eq!(
        classify_herdr_state("waiting", false).0,
        EventCategory::WaitingForTool
    );
    assert_eq!(
        classify_herdr_state("blocked", false).0,
        EventCategory::Unknown
    );
    assert_eq!(
        classify_herdr_state("blocked", true).0,
        EventCategory::BlockedGoal
    );
    assert_eq!(
        classify_herdr_state("new-state", true).0,
        EventCategory::Unknown
    );
    assert!(!EventCategory::Unknown.is_actionable());
}

#[test]
fn verified_v2_reregistration_atomically_upgrades_legacy_identity() {
    let temp = tempfile::tempdir().unwrap();
    let mut registry = Registry::load(JsonStore::new(temp.path().join("watchers.json"))).unwrap();
    let process = ProcessIdentity::new(42, 99);
    registry
        .register(WatcherState::new(
            "w".into(),
            TargetIdentity::multiplexer(
                "tmux".into(),
                "/tmp/tmux".into(),
                "%1".into(),
                process.clone(),
                Some("$1".into()),
            ),
            WatcherLifecycle::Registered,
            0,
            0,
        ))
        .unwrap();
    let verified = TargetIdentity::tmux(
        "/tmp/tmux".into(),
        "server-1".into(),
        "$1".into(),
        "@2".into(),
        "%1".into(),
        "/dev/pts/1".into(),
        process,
        None,
    );
    registry
        .register(WatcherState::new(
            "w".into(),
            verified.clone(),
            WatcherLifecycle::Registered,
            0,
            10,
        ))
        .unwrap();
    assert_eq!(registry.get("w").unwrap().target, verified);
    assert!(!registry.get("w").unwrap().target.needs_revalidation());
    let restored = Registry::load(JsonStore::new(temp.path().join("watchers.json"))).unwrap();
    assert!(
        restored
            .get("w")
            .unwrap()
            .target
            .observation_context()
            .is_some()
    );
}

#[test]
fn recovery_coordinator_persists_full_action_lifecycle_and_restart_guard() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("watchers.json");
    let mut registry = Registry::load(JsonStore::new(path.clone())).unwrap();
    let mut watcher = WatcherState::new(
        "w".into(),
        TargetIdentity::process(ProcessIdentity::new(42, 99)),
        WatcherLifecycle::Observing,
        0,
        0,
    );
    watcher.recovery = Some(RecoveryMachine::new(Budget {
        max_attempts: 3,
        max_cumulative_wait: Duration::from_secs(60),
        planner_calls: 1,
        cooldown: Duration::from_secs(1),
    }));
    registry.register(watcher).unwrap();
    registry
        .apply_recovery_transition("w", RecoveryCommand::Revalidated, 1)
        .unwrap();
    registry
        .apply_recovery_transition(
            "w",
            RecoveryCommand::Confirm {
                fingerprint: "fp".into(),
            },
            2,
        )
        .unwrap();
    let mut coordinator = RecoveryCoordinator::new(&mut registry);
    assert_eq!(
        coordinator
            .begin_action("w", "fp", ClockSnapshot::new(1, 1), 3)
            .unwrap(),
        RecoveryState::Acting
    );
    assert_eq!(
        coordinator
            .action_failed(
                "w",
                "fp",
                Duration::from_secs(1),
                ClockSnapshot::new(1, 1),
                4
            )
            .unwrap(),
        RecoveryState::Confirmed
    );
    assert_eq!(
        coordinator
            .begin_action("w", "fp", ClockSnapshot::new(3, 3), 5)
            .unwrap(),
        RecoveryState::Acting
    );
    assert_eq!(
        coordinator.action_succeeded("w", "fp", 6).unwrap(),
        RecoveryState::Recovered
    );
    coordinator.planner_consulted("w", 7).unwrap();
    let restored = Registry::load(JsonStore::new(path)).unwrap();
    let machine = restored.get("w").unwrap().recovery.as_ref().unwrap();
    assert_eq!(machine.state(), RecoveryState::NeedsRevalidation);
    assert!(machine.audit().len() >= 8);
}

#[test]
fn screen_confirmation_requires_two_persisted_matching_fingerprints() {
    let temp = tempfile::tempdir().unwrap();
    let mut registry = Registry::load(JsonStore::new(temp.path().join("watchers.json"))).unwrap();
    let mut watcher = WatcherState::new(
        "w".into(),
        TargetIdentity::process(ProcessIdentity::new(42, 99)),
        WatcherLifecycle::Observing,
        0,
        0,
    );
    watcher.recovery = Some(RecoveryMachine::new(Budget {
        max_attempts: 1,
        max_cumulative_wait: Duration::from_secs(1),
        planner_calls: 0,
        cooldown: Duration::ZERO,
    }));
    registry.register(watcher).unwrap();
    let mut first = registry.get("w").unwrap().observation_schedule.clone();
    first.screen_fingerprint = Some("f".repeat(64));
    first.screen_stable_count = 1;
    registry
        .commit_observation("w", first, Some(screen_event()), 1)
        .unwrap();
    assert_eq!(
        registry
            .get("w")
            .unwrap()
            .recovery
            .as_ref()
            .unwrap()
            .state(),
        RecoveryState::Observing
    );
    let mut second = registry.get("w").unwrap().observation_schedule.clone();
    second.screen_stable_count = 2;
    registry
        .commit_observation("w", second, Some(screen_event()), 2)
        .unwrap();
    assert_eq!(
        registry
            .get("w")
            .unwrap()
            .recovery
            .as_ref()
            .unwrap()
            .state(),
        RecoveryState::Confirmed
    );
}

fn screen_event() -> Event {
    Event::new(
        "screen",
        "2026-07-11T00:00:00Z",
        "w",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        EventSource::new(SourceKind::ScreenDetection, "adapter", "exact-v1"),
        EventCategory::CapacityBlock,
        0.9,
        false,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "trusted",
        PolicyHint::ObserveOnly,
    )
    .unwrap()
}
