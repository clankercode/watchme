use std::time::Duration;
use watchme::daemon::registry::Registry;
use watchme::model::{Event, EventCategory, EventSource, PolicyHint, SourceKind};
use watchme::model::{ProcessIdentity, TARGET_IDENTITY_SCHEMA_VERSION, TargetIdentity};
use watchme::model::{WatcherLifecycle, WatcherState};
use watchme::observe::screen::{TmuxChrome, trusted_tmux_screen};
use watchme::recovery::state_machine::{Budget, RecoveryMachine, RecoveryState};
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
        TmuxChrome::conservative_v1(),
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
    let capture = "old blocker: approve this\n> blocker: quoted\n```\nblocker: pasted\n```\n── watchme-live-v1 ──\nordinary output\nblocker: current\n";
    let live = trusted_tmux_screen(capture, &TmuxChrome::conservative_v1());
    assert_eq!(
        live.actionable_bottom(20).unwrap(),
        "ordinary output\nblocker: current"
    );
}

#[test]
fn absent_trusted_boundary_is_never_actionable() {
    let live = trusted_tmux_screen("blocker: current\n", &TmuxChrome::conservative_v1());
    assert!(live.actionable_bottom(20).is_none());
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
