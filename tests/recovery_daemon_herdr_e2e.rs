#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;
use watchme::daemon::{GenericObserver, SystemPeerCredentialProvider};
use watchme::ipc::protocol::{Request, Response};
use watchme::model::{
    Action, ActionKind, Condition, ProcessIdentity, TargetIdentity, WatcherLifecycle, WatcherState,
};
use watchme::paths::WatchmePaths;
use watchme::recovery::action_store::JsonActionStore;
use watchme::recovery::engine::RecipeProvider;
use watchme::recovery::state_machine::{Budget, RecoveryMachine};
use watchme::recovery::transaction::{ActionPhase, ActionStore};

#[cfg(target_os = "linux")]
fn target_process() -> ProcessIdentity {
    use watchme::process::ProcessInspector;

    watchme::process::linux::LinuxProcessInspector::default()
        .inspect(std::process::id())
        .unwrap()
        .identity()
}

#[cfg(target_os = "macos")]
fn target_process() -> ProcessIdentity {
    use watchme::process::ProcessInspector;

    watchme::process::macos::MacOsProcessInspector::default()
        .inspect(std::process::id())
        .unwrap()
        .identity()
}

const PROTOCOL: &str = "watchme.herdr";

struct ConcreteHerdrRecipe {
    kind: ActionKind,
    expected_working: bool,
}

impl RecipeProvider for ConcreteHerdrRecipe {
    fn action_for(&self, watcher: &WatcherState) -> Option<Action> {
        let event = watcher.last_observation.as_ref()?;
        let mut action = Action::new(
            "test.herdr.recovery",
            self.kind.clone(),
            "schema-faithful Herdr recovery integration",
            event.evidence_fingerprint.clone(),
            2,
        );
        if self.expected_working {
            action.expected_outcomes = vec![Condition {
                kind: "AGENT_WORKING".into(),
                value: None,
            }];
        }
        Some(action)
    }
}

struct FakeHerdr {
    _directory: TempDir,
    path: String,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl Drop for FakeHerdr {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::os::unix::net::UnixStream::connect(&self.path);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("fake Herdr server panicked");
        }
    }
}

fn response(request: &Value, result: Value) -> Value {
    json!({
        "schema_version": 1,
        "protocol": PROTOCOL,
        "request_id": request["request_id"],
        "method": request["method"],
        "ok": true,
        "result": result,
    })
}

fn pane(process: &ProcessIdentity) -> Value {
    json!({
        "server_id": "server-e2e",
        "workspace_id": "workspace-e2e",
        "workspace_name": "workspace",
        "tab_id": "tab-e2e",
        "tab_title": "agents",
        "tab_index": 1,
        "pane_id": "pane-e2e",
        "pane_title": "target",
        "pane_index": 0,
        "tty": "/dev/pts/e2e",
        "current_command": "codex",
        "current_path": "/workspace",
        "process": {
            "pid": process.pid,
            "start_time": process.start_time,
            "executable": process.executable,
            "argv_digest": process.argv_digest,
            "uid": process.uid,
            "process_group_id": process.process_group_id,
            "session_leader_id": process.session_leader_id,
            "tty": process.tty,
            "parent_digest": process.parent_digest,
        },
    })
}

fn spawn_fake_herdr(
    process: ProcessIdentity,
    change_after_send: bool,
    working_after_send: bool,
    send_delay: Duration,
) -> FakeHerdr {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("herdr.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    let stop = Arc::new(AtomicBool::new(false));
    let should_stop = Arc::clone(&stop);
    let side_effect_committed = Arc::new(AtomicBool::new(false));
    let committed = Arc::clone(&side_effect_committed);
    let thread = thread::spawn(move || {
        for connection in listener.incoming() {
            let mut connection = connection.expect("fake Herdr accept failed");
            if should_stop.load(Ordering::SeqCst) {
                break;
            }
            let mut line = String::new();
            BufReader::new(connection.try_clone().unwrap())
                .read_line(&mut line)
                .expect("fake Herdr read failed");
            let request: Value =
                serde_json::from_str(&line).expect("fake Herdr got invalid NDJSON");
            recorded.lock().unwrap().push(request.clone());
            let result = match request["method"].as_str().expect("missing method") {
                "pane_info" => pane(&if change_after_send && committed.load(Ordering::SeqCst) {
                    let mut replacement = process.clone();
                    replacement.start_time = replacement.start_time.saturating_add(1);
                    replacement
                } else {
                    process.clone()
                }),
                "pane_read" => json!({"text":"\n", "bytes":1, "truncated":false}),
                "agent_state_events" => json!({
                    "state": if working_after_send && committed.load(Ordering::SeqCst) { "working" } else { "blocked" },
                    "events":[{"sequence":if working_after_send && committed.load(Ordering::SeqCst) { 8 } else { 7 },"kind":if working_after_send && committed.load(Ordering::SeqCst) { "turn" } else { "terminal" }}],
                }),
                "send_keys" => {
                    committed.store(true, Ordering::SeqCst);
                    if !send_delay.is_zero() {
                        thread::sleep(send_delay);
                    }
                    json!({"accepted":true})
                }
                method => panic!("unexpected Herdr method {method}"),
            };
            let bytes = serde_json::to_vec(&response(&request, result)).unwrap();
            connection.write_all(&bytes).unwrap();
            connection.write_all(b"\n").unwrap();
        }
    });
    FakeHerdr {
        _directory: directory,
        path: path.to_string_lossy().into_owned(),
        stop,
        thread: Some(thread),
        requests,
    }
}

fn watcher(socket: String, process: ProcessIdentity, id: &str) -> WatcherState {
    let target = TargetIdentity::herdr(
        socket,
        "server-e2e".into(),
        "workspace-e2e".into(),
        "tab-e2e".into(),
        "pane-e2e".into(),
        "/dev/pts/e2e".into(),
        process,
    );
    let mut watcher = WatcherState::new(id.into(), target, WatcherLifecycle::Registered, 0, 0);
    watcher.recovery = Some(RecoveryMachine::new(Budget {
        max_attempts: 2,
        max_cumulative_wait: Duration::from_secs(10),
        planner_calls: 0,
        cooldown: Duration::ZERO,
    }));
    watcher
}

async fn wait_for_socket(socket: &Path) {
    for _ in 0..300 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("daemon socket was not created");
}

async fn ipc(socket: &Path, request: Request) -> Response {
    ipc_with_timeout(socket, request, Duration::from_secs(1)).await
}

async fn ipc_with_timeout(socket: &Path, request: Request, timeout: Duration) -> Response {
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    watchme::ipc::write_request(&mut stream, &request, timeout)
        .await
        .unwrap();
    watchme::ipc::read_response(&mut stream, timeout)
        .await
        .unwrap()
}

async fn wait_for_phase(actions_path: &Path, target: &str, phase: ActionPhase) {
    for _ in 0..400 {
        if JsonActionStore::load(actions_path.to_path_buf())
            .unwrap()
            .audit(target)
            .unwrap()
            .iter()
            .any(|record| record.phase == phase)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    panic!(
        "timed out waiting for action phase {phase:?}; audit: {:?}",
        JsonActionStore::load(actions_path.to_path_buf())
            .unwrap()
            .audit(target)
            .unwrap()
    );
}

async fn start_daemon(
    paths: WatchmePaths,
    recipes: Arc<dyn RecipeProvider>,
) -> tokio::task::JoinHandle<std::io::Result<()>> {
    tokio::spawn(async move {
        watchme::daemon::run_with_components(
            &paths,
            Duration::from_secs(5),
            true,
            SystemPeerCredentialProvider,
            Arc::new(GenericObserver),
            recipes,
        )
        .await
    })
}

#[tokio::test(flavor = "current_thread")]
async fn daemon_runs_schema_faithful_herdr_recipe_and_persists_provenance_and_receipt() {
    let temp = TempDir::new().unwrap();
    let paths = WatchmePaths::resolve(
        temp.path(),
        Some(&temp.path().join("config")),
        Some(&temp.path().join("state")),
        Some(&temp.path().join("run")),
    )
    .unwrap();
    let process = target_process();
    let herdr = spawn_fake_herdr(process.clone(), false, false, Duration::ZERO);
    let daemon = start_daemon(
        paths.clone(),
        Arc::new(ConcreteHerdrRecipe {
            kind: ActionKind::Capture {
                source: "structured_state".into(),
                max_lines: 8,
            },
            expected_working: false,
        }),
    )
    .await;
    let daemon_socket = paths.runtime_dir().join("daemon.sock");
    wait_for_socket(&daemon_socket).await;
    let expected_process = process.clone();
    let watcher = watcher(herdr.path.clone(), process, "herdr-receipt");
    assert!(matches!(
        ipc(
            &daemon_socket,
            Request::Register {
                watcher: Box::new(watcher)
            }
        )
        .await,
        Response::Registered {
            existing: false,
            ..
        }
    ));
    assert_eq!(
        ipc(
            &daemon_socket,
            Request::WakeObservation {
                id: "herdr-receipt".into(),
                event_fingerprint: "0123456789abcdef".into(),
            },
        )
        .await,
        Response::Acknowledged
    );

    let actions_path = paths.state_file("actions.json").unwrap();
    wait_for_phase(&actions_path, "herdr-receipt", ActionPhase::Succeeded).await;
    let actions = JsonActionStore::load(actions_path).unwrap();
    let audit = actions.audit("herdr-receipt").unwrap();
    assert!(
        audit
            .iter()
            .any(|record| record.phase == ActionPhase::Prepared)
    );
    assert!(
        audit
            .iter()
            .any(|record| record.phase == ActionPhase::Begun)
    );
    assert!(audit.iter().any(|record| record.phase == ActionPhase::Sent));
    let succeeded = audit.last().unwrap();
    assert_eq!(succeeded.phase, ActionPhase::Succeeded);
    assert!(
        succeeded
            .output
            .as_deref()
            .is_some_and(|output| output.contains("captured"))
    );
    assert!(succeeded.snapshot.contains("typed_pane_state"));
    assert!(succeeded.snapshot.contains("authorized"));

    let persisted: Value =
        serde_json::from_slice(&std::fs::read(paths.state_file("watchers.json").unwrap()).unwrap())
            .unwrap();
    let target = &persisted["watchers"][0]["target"];
    assert_eq!(target["schema_version"], 2);
    assert_eq!(target["provider"], "herdr");
    assert_eq!(target["server"], herdr.path);
    assert_eq!(target["pane"], "pane-e2e");
    assert_eq!(target["session"], "workspace-e2e");
    assert_eq!(target["context"]["provider"], "herdr");
    assert_eq!(target["context"]["socket_path"], herdr.path);
    assert_eq!(target["context"]["server_instance"], "server-e2e");
    assert_eq!(target["context"]["workspace_id"], "workspace-e2e");
    assert_eq!(target["context"]["tab_id"], "tab-e2e");
    assert_eq!(target["context"]["pane_id"], "pane-e2e");
    assert_eq!(target["context"]["tty"], "/dev/pts/e2e");
    assert_eq!(target["process"]["schema_version"], 1);
    assert_eq!(target["process"]["pid"], expected_process.pid);
    assert_eq!(target["process"]["start_time"], expected_process.start_time);
    assert_eq!(
        target["process"]["executable"],
        json!(expected_process.executable)
    );

    {
        let requests = herdr.requests.lock().unwrap();
        assert!(
            requests.iter().all(|request| {
                request["schema_version"] == 1 && request["protocol"] == PROTOCOL
            })
        );
        assert!(
            requests
                .iter()
                .any(|request| request["method"] == "agent_state_events")
        );
        assert!(requests.iter().any(|request| {
            request["method"] == "agent_state_events"
                && request["params"]
                    == json!({"workspace_id":"workspace-e2e","tab_id":"tab-e2e","pane_id":"pane-e2e","after":7,"max_events":8})
        }));
    }
    assert_eq!(
        ipc(&daemon_socket, Request::Shutdown).await,
        Response::Stopped
    );
    daemon.await.unwrap().unwrap();
}

#[ignore = "timing-sensitive on GitHub Actions runners"]
#[tokio::test(flavor = "current_thread")]
async fn post_side_effect_herdr_adapter_error_becomes_durable_human_required_and_never_retries() {
    let temp = TempDir::new().unwrap();
    let paths = WatchmePaths::resolve(
        temp.path(),
        Some(&temp.path().join("config")),
        Some(&temp.path().join("state")),
        Some(&temp.path().join("run")),
    )
    .unwrap();
    let process = target_process();
    let herdr = spawn_fake_herdr(process.clone(), true, false, Duration::ZERO);
    let daemon = start_daemon(
        paths.clone(),
        Arc::new(ConcreteHerdrRecipe {
            kind: ActionKind::SendKeys {
                keys: vec!["ENTER".into()],
            },
            expected_working: false,
        }),
    )
    .await;
    let daemon_socket = paths.runtime_dir().join("daemon.sock");
    wait_for_socket(&daemon_socket).await;
    assert!(matches!(
        ipc(
            &daemon_socket,
            Request::Register {
                watcher: Box::new(watcher(herdr.path.clone(), process, "herdr-uncertain")),
            },
        )
        .await,
        Response::Registered {
            existing: false,
            ..
        }
    ));
    assert_eq!(
        ipc(
            &daemon_socket,
            Request::WakeObservation {
                id: "herdr-uncertain".into(),
                event_fingerprint: "abcdef0123456789".into(),
            },
        )
        .await,
        Response::Acknowledged
    );
    let actions_path = paths.state_file("actions.json").unwrap();
    wait_for_phase(&actions_path, "herdr-uncertain", ActionPhase::HumanRequired).await;
    let actions = JsonActionStore::load(actions_path).unwrap();
    let audit = actions.audit("herdr-uncertain").unwrap();
    assert!(!audit.iter().any(|record| record.phase == ActionPhase::Sent));
    assert!(
        audit
            .iter()
            .any(|record| record.phase == ActionPhase::Uncertain)
    );
    assert_eq!(audit.last().unwrap().phase, ActionPhase::HumanRequired);
    assert!(
        audit
            .last()
            .unwrap()
            .reason
            .contains("possible side effect")
    );

    let sends_before = herdr
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request["method"] == "send_keys")
        .count();
    assert_eq!(sends_before, 1);
    let status = ipc(
        &daemon_socket,
        Request::Status {
            id: Some("herdr-uncertain".into()),
        },
    )
    .await;
    assert!(matches!(status, Response::Status { ref watchers, .. }
        if matches!(watchers[0].lifecycle, WatcherLifecycle::HumanRequired { .. })));

    tokio::time::sleep(Duration::from_millis(1250)).await;
    let sends_after = herdr
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request["method"] == "send_keys")
        .count();
    assert_eq!(sends_after, 1, "uncertain input action must not be retried");
    assert_eq!(
        ipc(&daemon_socket, Request::Shutdown).await,
        Response::Stopped
    );
    daemon.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn input_recovery_waits_for_a_fresh_herdr_observation_before_succeeding() {
    let temp = TempDir::new().unwrap();
    let paths = WatchmePaths::resolve(
        temp.path(),
        Some(&temp.path().join("config")),
        Some(&temp.path().join("state")),
        Some(&temp.path().join("run")),
    )
    .unwrap();
    let process = target_process();
    let herdr = spawn_fake_herdr(process.clone(), false, true, Duration::ZERO);
    let daemon = start_daemon(
        paths.clone(),
        Arc::new(ConcreteHerdrRecipe {
            kind: ActionKind::SendKeys {
                keys: vec!["ENTER".into()],
            },
            expected_working: true,
        }),
    )
    .await;
    let daemon_socket = paths.runtime_dir().join("daemon.sock");
    wait_for_socket(&daemon_socket).await;
    assert!(matches!(
        ipc(
            &daemon_socket,
            Request::Register {
                watcher: Box::new(watcher(herdr.path.clone(), process, "herdr-input-success")),
            },
        )
        .await,
        Response::Registered {
            existing: false,
            ..
        }
    ));
    assert_eq!(
        ipc(
            &daemon_socket,
            Request::WakeObservation {
                id: "herdr-input-success".into(),
                event_fingerprint: "feedface01234567".into(),
            },
        )
        .await,
        Response::Acknowledged
    );
    let actions_path = paths.state_file("actions.json").unwrap();
    wait_for_phase(&actions_path, "herdr-input-success", ActionPhase::Succeeded).await;
    let audit = JsonActionStore::load(actions_path)
        .unwrap()
        .audit("herdr-input-success")
        .unwrap();
    assert!(
        audit
            .iter()
            .any(|record| record.phase == ActionPhase::Verifying)
    );
    assert_eq!(audit.last().unwrap().phase, ActionPhase::Succeeded);
    assert_eq!(
        herdr
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["method"] == "send_keys")
            .count(),
        1
    );
    assert_eq!(
        ipc(&daemon_socket, Request::Shutdown).await,
        Response::Stopped
    );
    daemon.await.unwrap().unwrap();
}

#[ignore = "timing-sensitive on GitHub Actions runners"]
#[tokio::test(flavor = "current_thread")]
async fn shutdown_waits_for_slow_recovery_to_reach_terminal_ledger_without_future_input() {
    let temp = TempDir::new().unwrap();
    let paths = WatchmePaths::resolve(
        temp.path(),
        Some(&temp.path().join("config")),
        Some(&temp.path().join("state")),
        Some(&temp.path().join("run")),
    )
    .unwrap();
    let process = target_process();
    let herdr = spawn_fake_herdr(process.clone(), false, false, Duration::from_millis(1_250));
    let daemon = start_daemon(
        paths.clone(),
        Arc::new(ConcreteHerdrRecipe {
            kind: ActionKind::SendKeys {
                keys: vec!["ENTER".into()],
            },
            expected_working: false,
        }),
    )
    .await;
    let daemon_socket = paths.runtime_dir().join("daemon.sock");
    wait_for_socket(&daemon_socket).await;
    assert!(matches!(
        ipc(
            &daemon_socket,
            Request::Register {
                watcher: Box::new(watcher(herdr.path.clone(), process, "slow-shutdown")),
            },
        )
        .await,
        Response::Registered { .. }
    ));
    assert_eq!(
        ipc(
            &daemon_socket,
            Request::WakeObservation {
                id: "slow-shutdown".into(),
                event_fingerprint: "1234567890abcdef".into(),
            },
        )
        .await,
        Response::Acknowledged
    );
    for _ in 0..200 {
        if herdr
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["method"] == "send_keys")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        herdr
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["method"] == "send_keys")
    );

    let mut shutdown = Box::pin(ipc_with_timeout(
        &daemon_socket,
        Request::Shutdown,
        Duration::from_secs(5),
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(250), &mut shutdown)
            .await
            .is_err()
    );
    assert_eq!(shutdown.await, Response::Stopped);
    daemon.await.unwrap().unwrap();

    let actions = JsonActionStore::load(paths.state_file("actions.json").unwrap()).unwrap();
    let audit = actions.audit("slow-shutdown").unwrap();
    assert_eq!(audit.last().unwrap().phase, ActionPhase::HumanRequired);
    let sends_at_stop = herdr
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request["method"] == "send_keys")
        .count();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        herdr
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["method"] == "send_keys")
            .count(),
        sends_at_stop,
        "no recovery input may occur after shutdown completes"
    );
}
