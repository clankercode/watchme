#![cfg(unix)]

//! A deterministic daemon harness for the full Claude wait/resume path.  It
//! uses the production recovery engine, transaction ledger, and Herdr mux
//! adapter; only time, observations, and the local Herdr peer are synthetic.

use std::future::Future;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tempfile::TempDir;
use watchme::agents::claude::{
    ClaudeRecipes, DEFAULT_RESUME, resume_candidate_event, trusted_menu_event,
    trusted_resume_progress_event,
};
use watchme::daemon::{
    ObservationClock, ObservationResult, Observer, SystemPeerCredentialProvider,
    run_with_components_and_clock,
};
use watchme::ipc::protocol::{Request, Response};
use watchme::model::{
    Event, EventCategory, EventReset, EventSource, PolicyHint, ProcessIdentity, SourceKind,
    TargetIdentity, WatcherLifecycle, WatcherState,
};
use watchme::paths::WatchmePaths;
use watchme::recovery::action_store::JsonActionStore;
use watchme::recovery::engine::RecipeProvider;
use watchme::recovery::state_machine::{Budget, RecoveryMachine, RecoveryState};
use watchme::recovery::transaction::{ActionPhase, ActionStore};

const PROTOCOL: &str = "watchme.herdr";
const WATCHER_ID: &str = "claude-flow";
const MENU: &str = "Choose an action\n> 1. Add funds\n  2. Stop and wait for limit to reset (resets at 3:20 PM Australia/Sydney)\n  3. Upgrade";

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

struct TestClaudeRecipe(ClaudeRecipes);
impl RecipeProvider for TestClaudeRecipe {
    fn action_for(&self, watcher: &WatcherState) -> Option<watchme::model::Action> {
        self.0.action_for(watcher)
    }
}

struct SyntheticClock {
    wall_ms: AtomicU64,
    mono_ms: AtomicU64,
}

impl SyntheticClock {
    fn new() -> Self {
        Self {
            wall_ms: AtomicU64::new(now_ms()),
            mono_ms: AtomicU64::new(0),
        }
    }

    fn now(&self) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(self.wall_ms.load(Ordering::Acquire) as i64).unwrap()
    }
}

impl ObservationClock for SyntheticClock {
    fn wall_now_ms(&self) -> u64 {
        self.wall_ms.load(Ordering::Acquire)
    }

    fn mono_now_ms(&self) -> u64 {
        self.mono_ms.load(Ordering::Acquire)
    }

    fn sleep_until_mono<'a>(
        &'a self,
        deadline: u64,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            const TICK_MS: u64 = 65_000;
            self.mono_ms
                .fetch_max(deadline.max(TICK_MS), Ordering::AcqRel);
            self.mono_ms.fetch_add(TICK_MS, Ordering::AcqRel);
            self.wall_ms.fetch_add(TICK_MS, Ordering::AcqRel);
            // Let the daemon's native recovery worker pass its dispatch
            // snapshot boundary before the next synthetic observation tick.
            tokio::time::sleep(Duration::from_millis(25)).await;
        })
    }
}

#[derive(Default)]
struct HerdrState {
    menu_selected: AtomicBool,
    literal_sent: AtomicBool,
    post_literal_reads: AtomicUsize,
    sent_keys: Mutex<Vec<String>>,
    literals: Mutex<Vec<String>>,
}

struct FakeHerdr {
    _directory: TempDir,
    path: String,
    state: Arc<HerdrState>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Drop for FakeHerdr {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = std::os::unix::net::UnixStream::connect(&self.path);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("fake Herdr server panicked");
        }
    }
}

fn pane(process: &ProcessIdentity) -> Value {
    json!({
        "server_id":"server-claude", "workspace_id":"workspace-claude", "workspace_name":"workspace",
        "tab_id":"tab-claude", "tab_title":"agent", "tab_index":0,
        "pane_id":"pane-claude", "pane_title":"Claude", "pane_index":0,
        "tty":"/dev/pts/claude", "current_command":"claude", "current_path":"/workspace",
        "process": {
            "pid":process.pid, "start_time":process.start_time, "executable":process.executable,
            "argv_digest":process.argv_digest, "uid":process.uid, "process_group_id":process.process_group_id,
            "session_leader_id":process.session_leader_id, "tty":process.tty, "parent_digest":process.parent_digest,
        }
    })
}

fn spawn_fake_herdr(process: ProcessIdentity) -> FakeHerdr {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("herdr.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let state = Arc::new(HerdrState::default());
    let stop = Arc::new(AtomicBool::new(false));
    let worker_state = state.clone();
    let worker_stop = stop.clone();
    let thread = thread::spawn(move || {
        for connection in listener.incoming() {
            let mut connection = connection.unwrap();
            if worker_stop.load(Ordering::Acquire) {
                break;
            }
            let mut line = String::new();
            BufReader::new(connection.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let result = match request["method"].as_str().unwrap() {
                "pane_info" => pane(&process),
                "pane_read" => {
                    let post_literal = worker_state.literal_sent.load(Ordering::Acquire)
                        && worker_state
                            .post_literal_reads
                            .fetch_add(1, Ordering::AcqRel)
                            >= 1;
                    let text = if post_literal { "Working...\n" } else { "\n" };
                    json!({"text":text,"bytes":text.len(),"truncated":false})
                }
                "send_keys" => {
                    let keys = request["params"]["keys"].as_array().unwrap();
                    let key = keys[0].as_str().unwrap().to_owned();
                    worker_state.sent_keys.lock().unwrap().push(key.clone());
                    if key == "Enter" {
                        worker_state.menu_selected.store(true, Ordering::Release);
                    }
                    json!({"accepted":true})
                }
                "send_text" => {
                    let text = request["params"]["text"].as_str().unwrap().to_owned();
                    worker_state.literals.lock().unwrap().push(text);
                    worker_state.literal_sent.store(true, Ordering::Release);
                    json!({"accepted":true})
                }
                method => panic!("unexpected Herdr method {method}"),
            };
            let response = json!({
                "schema_version":1, "protocol":PROTOCOL, "request_id":request["request_id"],
                "method":request["method"], "ok":true, "result":result,
            });
            connection
                .write_all(serde_json::to_string(&response).unwrap().as_bytes())
                .unwrap();
            connection.write_all(b"\n").unwrap();
        }
    });
    FakeHerdr {
        _directory: directory,
        path: socket.to_string_lossy().into_owned(),
        state,
        stop,
        thread: Some(thread),
    }
}

struct ClaudeFlowObserver {
    clock: Arc<SyntheticClock>,
    mux: Arc<HerdrState>,
    reset_at: String,
}

impl ClaudeFlowObserver {
    fn hook_limit(&self, watcher: &WatcherState) -> Event {
        let mut event = Event::new(
            "claude-hook-limit",
            self.clock.now().to_rfc3339(),
            watcher.watcher_id.clone(),
            target_hash(&watcher.target),
            EventSource::new(SourceKind::Hook, "claude_stop_failure", "StopFailure"),
            EventCategory::UsageLimit,
            1.0,
            true,
            "b".repeat(64),
            "correlated Claude reset time",
            PolicyHint::WaitAllowed,
        )
        .unwrap();
        event
            .metadata
            .insert("claude_reset_at".into(), json!(self.reset_at));
        event
            .metadata
            .insert("claude_resume_margin_seconds".into(), json!(7));
        event.reset = Some(EventReset {
            source_text: "resets at fixed time".into(),
            parsed_at: self.reset_at.clone(),
            timezone: Some("UTC".into()),
            confidence: 1.0,
            margin_seconds: Some(7),
        });
        event
    }

    fn working(&self, watcher: &WatcherState) -> Event {
        Event::new(
            "claude-working",
            self.clock.now().to_rfc3339(),
            watcher.watcher_id.clone(),
            target_hash(&watcher.target),
            EventSource::new(SourceKind::ScreenDetection, "claude", "working"),
            EventCategory::Working,
            0.7,
            false,
            "c".repeat(64),
            "fresh Claude working evidence",
            PolicyHint::ObserveOnly,
        )
        .unwrap()
    }

    fn resume_candidate(&self, watcher: &WatcherState) -> Option<Event> {
        let mut candidate = resume_candidate_event(watcher, self.clock.now())?;
        // The simulated clock decides whether the persisted reset deadline has
        // elapsed. The event itself is stamped at observation time so the
        // production fresh-tail proof can still reject a stale capture.
        candidate.observed_at = DateTime::<Utc>::from(SystemTime::now()).to_rfc3339();
        Some(candidate)
    }
}

impl Observer for ClaudeFlowObserver {
    fn observe<'a>(
        &'a self,
        watcher: WatcherState,
    ) -> Pin<Box<dyn Future<Output = Result<ObservationResult, String>> + Send + 'a>> {
        Box::pin(async move {
            let event = if self.mux.literal_sent.load(Ordering::Acquire) {
                Some(self.working(&watcher))
            } else if matches!(watcher.lifecycle, WatcherLifecycle::Waiting { .. })
                && watcher
                    .last_observation
                    .as_ref()
                    .is_some_and(|event| event.metadata.get("claude_resume") == Some(&json!(true)))
            {
                // A tick that races the wait transaction may first persist the
                // candidate while that transaction is still `Acting`. Replay
                // the same durable candidate once the wait has committed so
                // the recovery machine can perform its explicit rearm.
                watcher.last_observation.clone()
            } else if matches!(watcher.lifecycle, WatcherLifecycle::Waiting { .. })
                && watcher
                    .last_observation
                    .as_ref()
                    .is_some_and(|event| event.source.source_id == "claude_stop_failure")
            {
                self.resume_candidate(&watcher)
            } else if self.mux.menu_selected.load(Ordering::Acquire) {
                Some(self.hook_limit(&watcher))
            } else {
                trusted_menu_event(&watcher, MENU, MENU)
            };
            Ok(ObservationResult {
                event,
                herdr_after_sequence: None,
            })
        })
    }
}

fn watcher(socket: String, process: ProcessIdentity) -> WatcherState {
    let target = TargetIdentity::herdr(
        socket,
        "server-claude".into(),
        "workspace-claude".into(),
        "tab-claude".into(),
        "pane-claude".into(),
        "/dev/pts/claude".into(),
        process,
    );
    let mut watcher = WatcherState::new(
        WATCHER_ID.into(),
        target,
        WatcherLifecycle::Observing,
        0,
        now_ms(),
    );
    watcher.recovery = Some(RecoveryMachine::new(Budget {
        // Selection, durable waiting, and the one literal resume each consume
        // a transaction slot; leave one policy-visible slot for the resume
        // after `begin_action` has reserved it.
        max_attempts: 4,
        max_cumulative_wait: Duration::from_secs(3600),
        planner_calls: 0,
        cooldown: Duration::ZERO,
    }));
    watcher
}

fn target_hash(target: &TargetIdentity) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(serde_json::to_vec(target).unwrap()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn wait_for_socket(socket: &Path) {
    for _ in 0..300 {
        if socket.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("daemon socket was not created");
}

async fn ipc(socket: &Path, request: Request) -> Response {
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    watchme::ipc::write_request(&mut stream, &request, Duration::from_secs(1))
        .await
        .unwrap();
    watchme::ipc::read_response(&mut stream, Duration::from_secs(1))
        .await
        .unwrap()
}

async fn wait_for_actions(path: &Path, count: usize) {
    for _ in 0..500 {
        let audit = JsonActionStore::load(path.to_path_buf())
            .unwrap()
            .audit(WATCHER_ID)
            .unwrap();
        if audit
            .iter()
            .filter(|record| record.phase == ActionPhase::Succeeded)
            .count()
            >= count
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!(
        "timed out waiting for three successful Claude transactions: {:?}; watcher: {}",
        JsonActionStore::load(path.to_path_buf())
            .unwrap()
            .audit(WATCHER_ID)
            .unwrap(),
        std::fs::read_to_string(path.with_file_name("watchers.json")).unwrap()
    );
}

#[ignore = "timing-sensitive on GitHub Actions runners"]
#[tokio::test(flavor = "current_thread")]
async fn daemon_selects_wait_schedules_reset_and_resumes_once_after_verified_progress() {
    let temp = TempDir::new().unwrap();
    let paths = WatchmePaths::resolve(
        temp.path(),
        Some(&temp.path().join("config")),
        Some(&temp.path().join("state")),
        Some(&temp.path().join("run")),
    )
    .unwrap();
    let process = target_process();
    let herdr = spawn_fake_herdr(process.clone());
    let mux_state = herdr.state.clone();
    let clock = Arc::new(SyntheticClock::new());
    let reset_at =
        (DateTime::<Utc>::from(SystemTime::now()) + chrono::Duration::seconds(30)).to_rfc3339();
    let daemon_paths = paths.clone();
    let daemon = tokio::spawn(async move {
        run_with_components_and_clock(
            &daemon_paths,
            Duration::from_secs(5),
            true,
            SystemPeerCredentialProvider,
            Arc::new(ClaudeFlowObserver {
                clock: clock.clone(),
                mux: mux_state,
                reset_at,
            }),
            Arc::new(TestClaudeRecipe(ClaudeRecipes::default())),
            clock,
        )
        .await
    });
    let socket = paths.runtime_dir().join("daemon.sock");
    wait_for_socket(&socket).await;
    assert!(matches!(
        ipc(
            &socket,
            Request::Register {
                watcher: Box::new(watcher(herdr.path.clone(), process))
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
            &socket,
            Request::WakeObservation {
                id: WATCHER_ID.into(),
                event_fingerprint: "a".repeat(64)
            }
        )
        .await,
        Response::Acknowledged
    );

    let actions_path = paths.state_file("actions.json").unwrap();
    wait_for_actions(&actions_path, 3).await;
    let actions = JsonActionStore::load(actions_path)
        .unwrap()
        .audit(WATCHER_ID)
        .unwrap();
    assert_eq!(
        actions
            .iter()
            .filter(|record| record.action_id == "claude.select_wait_menu"
                && record.phase == ActionPhase::Succeeded)
            .count(),
        1
    );
    assert_eq!(
        actions
            .iter()
            .filter(|record| record.action_id == "claude.wait_for_reset"
                && record.phase == ActionPhase::Succeeded)
            .count(),
        1
    );
    assert_eq!(
        actions
            .iter()
            .filter(|record| record.action_id == "claude.resume_once"
                && record.phase == ActionPhase::Succeeded)
            .count(),
        1
    );
    assert_eq!(
        *herdr.state.sent_keys.lock().unwrap(),
        vec!["Down", "Enter"]
    );
    assert_eq!(*herdr.state.literals.lock().unwrap(), vec![DEFAULT_RESUME]);

    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(
        herdr.state.literals.lock().unwrap().len(),
        1,
        "later ticks must not resume twice"
    );
    let status = ipc(
        &socket,
        Request::Status {
            id: Some(WATCHER_ID.into()),
        },
    )
    .await;
    assert!(
        matches!(status, Response::Status { ref watchers, .. } if watchers[0].recovery.as_ref().is_some_and(|machine| machine.state() == RecoveryState::Recovered))
    );
    assert_eq!(ipc(&socket, Request::Shutdown).await, Response::Stopped);
    daemon.await.unwrap().unwrap();
}

#[test]
fn claude_resume_refusal_guards_never_create_an_input_recipe() {
    let process = target_process();
    let clock = Arc::new(SyntheticClock::new());
    let observer = ClaudeFlowObserver {
        clock,
        mux: Arc::new(HerdrState::default()),
        reset_at: "2026-07-11T00:00:00Z".into(),
    };
    let mut watcher = watcher("/tmp/watchme-refusal.sock".into(), process);
    watcher.lifecycle = WatcherLifecycle::Waiting {
        until_unix_ms: 0,
        reason: "test wait".into(),
    };
    watcher.last_observation = Some(observer.hook_limit(&watcher));

    let candidate = resume_candidate_event(
        &watcher,
        "2026-07-11T00:01:00Z".parse::<DateTime<Utc>>().unwrap(),
    )
    .unwrap();
    assert!(
        trusted_resume_progress_event(&watcher, &candidate, MENU, "2026-07-11T00:02:00Z",)
            .is_none(),
        "a still-visible wait menu is never progress proof"
    );

    watcher.lifecycle = WatcherLifecycle::HumanRequired {
        reason: "user intervention".into(),
    };
    assert!(
        resume_candidate_event(
            &watcher,
            "2026-07-11T00:01:00Z".parse::<DateTime<Utc>>().unwrap(),
        )
        .is_none(),
        "intervention cancels pending automatic resume"
    );

    let mut unparseable = observer.hook_limit(&watcher);
    unparseable.metadata.remove("claude_reset_at");
    unparseable.metadata.remove("claude_resume_margin_seconds");
    unparseable.reset = None;
    watcher.lifecycle = WatcherLifecycle::Observing;
    watcher.last_observation = Some(unparseable);
    assert!(
        ClaudeRecipes::default().action_for(&watcher).is_none(),
        "unparseable reset cannot schedule a wait or resume"
    );
}
