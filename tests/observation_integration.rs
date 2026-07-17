use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use watchme::daemon::classify_herdr_state;
use watchme::daemon::registry::Registry;
use watchme::daemon::{GenericObserver, Observer};
use watchme::model::{Event, EventCategory, EventSource, PolicyHint, SourceKind};
use watchme::model::{
    HerdrWireProtocol, MultiplexerContext, ProcessIdentity, TARGET_IDENTITY_SCHEMA_VERSION,
    TargetIdentity,
};
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
fn herdr_wire_protocol_round_trips_and_legacy_context_defaults_to_auto() {
    let identity = TargetIdentity::herdr(
        "/tmp/herdr.sock".into(),
        "native-0.7.4-protocol-16-1-2".into(),
        "ws".into(),
        "tab".into(),
        "pane".into(),
        "/dev/pts/8".into(),
        ProcessIdentity::new(42, 99),
        HerdrWireProtocol::Native16,
    );
    let json = serde_json::to_value(&identity).unwrap();
    assert_eq!(json["context"]["wire_protocol"], "native16");
    assert_eq!(
        serde_json::from_value::<TargetIdentity>(json).unwrap(),
        identity
    );

    let legacy_context = serde_json::json!({
        "provider":"herdr", "socket_path":"/tmp/herdr.sock",
        "server_instance":"legacy", "workspace_id":"ws", "tab_id":"tab",
        "pane_id":"pane", "tty":"/dev/pts/8"
    });
    let context: MultiplexerContext = serde_json::from_value(legacy_context).unwrap();
    assert!(matches!(
        context,
        MultiplexerContext::Herdr {
            wire_protocol: HerdrWireProtocol::Auto,
            ..
        }
    ));
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
    let capture = "old blocker: approve this\n> blocker: quoted\n```\nblocker: pasted\n```\nchrome\nordinary output\nblocker: current\n";
    let live = trusted_tmux_screen(capture, &chrome());
    assert_eq!(
        live.actionable_bottom(20).unwrap(),
        "ordinary output\nblocker: current"
    );
}

#[test]
fn hostile_content_cannot_forge_the_out_of_band_boundary() {
    let capture = "TRUSTED-BOUNDARY\nblocker: hostile transcript\nordinary live output\n";
    let boundary = TmuxChrome {
        adapter: "fixture-provider".into(),
        version: 1,
        first_live_line: 2,
    };
    let live = trusted_tmux_screen(capture, &boundary);
    assert_eq!(live.actionable_bottom(20).unwrap(), "ordinary live output");
}

#[test]
fn absent_trusted_boundary_is_never_actionable() {
    let live = trusted_tmux_screen("blocker: current\n", &chrome());
    assert!(live.actionable_bottom(20).is_none());
}

#[test]
fn trusted_live_region_retains_the_current_menu_cursor_but_not_old_quotes() {
    let capture = "old quote\n> 1. old option\nchrome\n> 1. current option\n  2. other\n";
    let boundary = TmuxChrome {
        adapter: "fixture-provider".into(),
        version: 1,
        first_live_line: 3,
    };
    assert_eq!(
        trusted_tmux_screen(capture, &boundary)
            .actionable_bottom(8)
            .unwrap(),
        "> 1. current option\n  2. other"
    );
}

fn chrome() -> TmuxChrome {
    TmuxChrome {
        adapter: "fixture-provider".into(),
        version: 1,
        first_live_line: 6,
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
fn herdr_typed_states_map_explicitly_and_unclassified_has_no_wire_event() {
    assert_eq!(
        classify_herdr_state("working", false).unwrap().0,
        EventCategory::Working
    );
    assert_eq!(
        classify_herdr_state("idle", false).unwrap().0,
        EventCategory::Idle
    );
    assert_eq!(
        classify_herdr_state("waiting", false).unwrap().0,
        EventCategory::WaitingForTool
    );
    assert!(classify_herdr_state("blocked", false).is_none());
    assert_eq!(
        classify_herdr_state("blocked", true).unwrap().0,
        EventCategory::BlockedGoal
    );
    assert!(classify_herdr_state("new-state", true).is_none());
}

#[test]
fn canonical_event_category_wire_enum_rejects_non_schema_unknown() {
    assert!(serde_json::from_value::<EventCategory>(json!("unknown")).is_err());
    assert_eq!(
        serde_json::to_value(EventCategory::UnknownBlocked).unwrap(),
        json!("unknown_blocked")
    );
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

#[test]
fn recovery_coordinator_begin_action_store_failure_rolls_back() {
    coordinator_store_failure("begin");
}

#[test]
fn recovery_coordinator_action_failed_store_failure_rolls_back() {
    coordinator_store_failure("failed");
}

#[test]
fn recovery_coordinator_action_succeeded_store_failure_rolls_back() {
    coordinator_store_failure("succeeded");
}

#[test]
fn recovery_coordinator_planner_consulted_store_failure_rolls_back() {
    coordinator_store_failure("planner");
}

fn coordinator_store_failure(operation: &str) {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("state");
    std::fs::create_dir(&parent).unwrap();
    let mut registry = Registry::load(JsonStore::new(parent.join("watchers.json"))).unwrap();
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
        planner_calls: 2,
        cooldown: Duration::ZERO,
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
    if matches!(operation, "failed" | "succeeded") {
        registry
            .apply_recovery_transition(
                "w",
                RecoveryCommand::BeginAction {
                    fingerprint: "fp".into(),
                    clock: ClockSnapshot::new(1, 1),
                },
                3,
            )
            .unwrap();
    }
    let before = registry.get("w").unwrap().clone();
    std::fs::rename(&parent, temp.path().join("moved")).unwrap();
    std::fs::write(&parent, b"not-directory").unwrap();
    let mut coordinator = RecoveryCoordinator::new(&mut registry);
    let result = match operation {
        "begin" => coordinator.begin_action("w", "fp", ClockSnapshot::new(1, 1), 4),
        "failed" => coordinator.action_failed(
            "w",
            "fp",
            Duration::from_secs(1),
            ClockSnapshot::new(2, 2),
            4,
        ),
        "succeeded" => coordinator.action_succeeded("w", "fp", 4),
        "planner" => coordinator.planner_consulted("w", 4),
        _ => unreachable!(),
    };
    assert!(result.is_err());
    assert_eq!(registry.get("w").unwrap(), &before);
}

#[tokio::test]
async fn generic_observer_herdr_socket_maps_typed_working_and_uses_persisted_cursor() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("herdr.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let requests = Arc::new(Mutex::new(Vec::<Value>::new()));
    let recorded = requests.clone();
    let server = thread::spawn(move || {
        for connection in listener.incoming().take(3) {
            let mut connection = connection.unwrap();
            let mut line = String::new();
            BufReader::new(connection.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            recorded.lock().unwrap().push(request.clone());
            let result = if request["method"] == "pane_info" {
                herdr_pane()
            } else {
                json!({"state":"working","events":[{"sequence":8,"kind":"turn"}]})
            };
            let response = json!({"schema_version":1,"protocol":"watchme.herdr",
                "request_id":request["request_id"],"method":request["method"],
                "ok":true,"result":result});
            connection
                .write_all(&serde_json::to_vec(&response).unwrap())
                .unwrap();
            connection.write_all(b"\n").unwrap();
        }
    });
    let schedule = watchme::model::ObservationSchedule {
        herdr_after_sequence: 7,
        ..Default::default()
    };
    let mut watcher = WatcherState::new(
        "h".into(),
        TargetIdentity::herdr(
            socket.to_string_lossy().into_owned(),
            "server-1".into(),
            "ws".into(),
            "tab".into(),
            "pane".into(),
            "/dev/pts/8".into(),
            herdr_process(),
            HerdrWireProtocol::BridgeV1,
        ),
        WatcherLifecycle::Observing,
        0,
        0,
    );
    watcher.observation_schedule = schedule;
    let event = GenericObserver
        .observe(watcher)
        .await
        .unwrap()
        .event
        .unwrap();
    assert_eq!(event.category, EventCategory::Working);
    assert_eq!(event.monotonic_sequence, Some(8));
    server.join().unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests[2]["params"]["after"], 7);
}

fn herdr_process() -> ProcessIdentity {
    let mut process = ProcessIdentity::new(4242, 99);
    process.tty = Some("/dev/pts/8".into());
    process
}

fn herdr_pane() -> Value {
    json!({"server_id":"server-1","workspace_id":"ws","workspace_name":"work",
        "tab_id":"tab","tab_title":"tab","tab_index":0,"pane_id":"pane",
        "pane_index":0,"pane_title":"agent","tty":"/dev/pts/8",
        "current_command":"codex","current_path":"/tmp","process":{
            "pid":4242,"start_time":99,"executable":null,"argv_digest":null,"uid":null,
            "process_group_id":null,"session_leader_id":null,"tty":"/dev/pts/8",
            "parent_digest":null}})
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn native_herdr_observation_validates_identity_without_using_bridge_state_calls() {
    use std::os::unix::fs::MetadataExt;
    use watchme::process::ProcessInspector;

    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("herdr-native.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pid = std::process::id();
    let requests = Arc::new(Mutex::new(Vec::<Value>::new()));
    let recorded = requests.clone();
    let server = thread::spawn(move || {
        for connection in listener.incoming().take(3) {
            let mut connection = connection.unwrap();
            let mut line = String::new();
            BufReader::new(connection.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            recorded.lock().unwrap().push(request.clone());
            let result = match request["method"].as_str().unwrap() {
                "ping" => json!({"type":"pong", "version":"0.16.0", "protocol":16}),
                "pane.current" => json!({"type":"pane_current", "pane":{
                    "pane_id":"pane", "workspace_id":"ws", "tab_id":"tab", "revision":9
                }}),
                "pane.process_info" => json!({"type":"pane_process_info", "process_info":{
                    "pane_id":"pane", "tty":"/dev/pts/8",
                    "foreground_processes":[{"pid":pid}]
                }}),
                method => panic!("unexpected native observer method {method}"),
            };
            let response = json!({"id":request["id"], "result":result});
            connection
                .write_all(&serde_json::to_vec(&response).unwrap())
                .unwrap();
            connection.write_all(b"\n").unwrap();
        }
    });
    let inspected = watchme::process::linux::LinuxProcessInspector::default()
        .inspect(pid)
        .unwrap();
    let mut process = ProcessIdentity::new(pid, inspected.start_time);
    process.tty = Some("/dev/pts/8".into());
    let metadata = std::fs::metadata(&socket).unwrap();
    let watcher = WatcherState::new(
        "native-observer".into(),
        TargetIdentity::herdr(
            socket.to_string_lossy().into_owned(),
            format!(
                "native-0.16.0-protocol-16-{}-{}",
                metadata.dev(),
                metadata.ino()
            ),
            "ws".into(),
            "tab".into(),
            "pane".into(),
            "/dev/pts/8".into(),
            process,
            HerdrWireProtocol::Native16,
        ),
        WatcherLifecycle::Observing,
        0,
        0,
    );

    let result = GenericObserver.observe(watcher).await.unwrap();
    assert!(result.event.is_none());
    server.join().unwrap();
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request["method"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["ping", "pane.current", "pane.process_info"]
    );
}

#[tokio::test]
async fn generic_observer_herdr_empty_events_uses_bounded_sanitized_unknown_fallback() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("herdr.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let methods = Arc::new(Mutex::new(Vec::new()));
    let recorded = methods.clone();
    let server = thread::spawn(move || {
        for connection in listener.incoming().take(6) {
            let mut connection = connection.unwrap();
            let mut line = String::new();
            BufReader::new(connection.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let method = request["method"].as_str().unwrap().to_owned();
            recorded
                .lock()
                .unwrap()
                .push((method.clone(), request["params"].clone()));
            let result = match method.as_str() {
                "pane_info" => herdr_pane(),
                "agent_state_events" => json!({"state":"blocked","events":[]}),
                "pane_read" => json!({"text":"\u{001b}]52;c;secret\u{0007}BLOCKED", "bytes":21,
                    "truncated":false}),
                _ => unreachable!(),
            };
            let response = json!({"schema_version":1,"protocol":"watchme.herdr",
                "request_id":request["request_id"],"method":request["method"],
                "ok":true,"result":result});
            connection
                .write_all(&serde_json::to_vec(&response).unwrap())
                .unwrap();
            connection.write_all(b"\n").unwrap();
        }
    });
    let watcher = WatcherState::new(
        "h".into(),
        TargetIdentity::herdr(
            socket.to_string_lossy().into_owned(),
            "server-1".into(),
            "ws".into(),
            "tab".into(),
            "pane".into(),
            "/dev/pts/8".into(),
            herdr_process(),
            HerdrWireProtocol::BridgeV1,
        ),
        WatcherLifecycle::Observing,
        0,
        0,
    );
    let result = GenericObserver.observe(watcher).await.unwrap();
    assert!(result.event.is_none());
    assert_eq!(result.herdr_after_sequence, None);
    server.join().unwrap();
    let methods = methods.lock().unwrap();
    let (_, params) = methods
        .iter()
        .find(|(method, _)| method == "pane_read")
        .unwrap();
    assert_eq!(params["max_lines"], 80);
    assert_eq!(params["max_bytes"], 32 * 1024);
}
