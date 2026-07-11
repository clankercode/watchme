#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use tempfile::TempDir;
use watchme::daemon::registry::{RegistrationOutcome, Registry};
use watchme::daemon::scheduler::{Scheduler, SchedulerEvent};
use watchme::daemon::{DaemonLock, MAX_CONNECTIONS, ProcessProbe};
use watchme::ipc::protocol::{MAX_FRAME_BYTES, Request, Response, decode_frame, encode_frame};
use watchme::ipc::{bind_owner_only, validate_peer_uid};
use watchme::model::{ProcessIdentity, TargetIdentity, WatcherLifecycle, WatcherState};
use watchme::paths::WatchmePaths;
use watchme::store::JsonStore;

fn state(id: &str, pid: u32, start: u64) -> WatcherState {
    WatcherState::new(
        id.into(),
        TargetIdentity::process(ProcessIdentity::new(pid, start)),
        WatcherLifecycle::Registered,
        0,
        1,
    )
}

fn sync_ipc(socket: &Path, request: &Request) -> Response {
    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    let bytes = encode_frame(request).unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
    let mut length = [0; 4];
    stream.read_exact(&mut length).unwrap();
    let mut response = vec![0; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut response).unwrap();
    decode_frame(&response).unwrap()
}

#[test]
fn protocol_is_versioned_bounded_and_rejects_malformed_frames() {
    let bytes = encode_frame(&Request::Status { id: None }).unwrap();
    assert_eq!(
        decode_frame::<Request>(&bytes).unwrap(),
        Request::Status { id: None }
    );
    assert!(decode_frame::<Request>(b"{oops").is_err());
    assert!(decode_frame::<Request>(&vec![b'x'; MAX_FRAME_BYTES + 1]).is_err());

    let mut wrong = serde_json::to_value(Request::Status { id: None }).unwrap();
    wrong["version"] = serde_json::json!(99);
    assert!(decode_frame::<Request>(&serde_json::to_vec(&wrong).unwrap()).is_err());
}

#[test]
fn socket_and_peer_validation_are_owner_only() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("daemon.sock");
    let listener = bind_owner_only(&socket).unwrap();
    assert_eq!(
        fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(listener);

    assert!(validate_peer_uid(1000, 1000).is_ok());
    assert!(validate_peer_uid(1001, 1000).is_err());
}

#[test]
fn registry_deduplicates_persists_transitions_and_replays_as_revalidation_required() {
    let temp = TempDir::new().unwrap();
    let store = JsonStore::new(temp.path().join("watchers.json"));
    let mut registry = Registry::load(store).unwrap();
    assert_eq!(
        registry.register(state("first", 42, 900)).unwrap(),
        RegistrationOutcome::Added("first".into())
    );
    assert_eq!(
        registry.register(state("duplicate", 42, 900)).unwrap(),
        RegistrationOutcome::Existing("first".into())
    );
    let mut enriched = state("enriched", 42, 900);
    let TargetIdentity::Process { process } = &mut enriched.target else {
        unreachable!()
    };
    process.executable = Some("/usr/bin/codex".into());
    assert_eq!(
        registry.register(enriched).unwrap(),
        RegistrationOutcome::Existing("first".into())
    );
    registry
        .transition("first", WatcherLifecycle::Observing, 2)
        .unwrap();

    let replayed = Registry::load(JsonStore::new(temp.path().join("watchers.json"))).unwrap();
    let watcher = replayed.get("first").unwrap();
    assert!(
        matches!(watcher.lifecycle, WatcherLifecycle::HumanRequired { ref reason } if reason.contains("revalidation"))
    );
    assert_eq!(watcher.revision, 2);
}

#[test]
fn registry_rejects_id_collision_without_overwriting_persisted_target() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("watchers.json");
    let mut registry = Registry::load(JsonStore::new(path.clone())).unwrap();
    registry.register(state("same-id", 42, 900)).unwrap();
    assert!(matches!(
        registry.register(state("same-id", 43, 901)),
        Err(watchme::daemon::registry::RegistryError::IdCollision(id)) if id == "same-id"
    ));

    let persisted = Registry::load(JsonStore::new(path)).unwrap();
    assert_eq!(persisted.list().len(), 1);
    assert_eq!(
        persisted.get("same-id").unwrap().target,
        state("ignored", 42, 900).target
    );
}

#[test]
fn replay_revision_overflow_fails_closed_without_panicking() {
    let temp = TempDir::new().unwrap();
    let store = JsonStore::new(temp.path().join("watchers.json"));
    store
        .write(&serde_json::json!({
            "version": 1,
            "watchers": [WatcherState::new(
                "overflow".into(),
                TargetIdentity::process(ProcessIdentity::new(44, 902)),
                WatcherLifecycle::Registered,
                u64::MAX,
                1,
            )]
        }))
        .unwrap();
    assert!(matches!(
        Registry::load(store),
        Err(watchme::daemon::registry::RegistryError::RevisionOverflow(id)) if id == "overflow"
    ));
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn scheduler_handles_pause_resume_stop_and_idle_shutdown() {
    let (handle, runner) = Scheduler::new(Duration::from_secs(5), false);
    let task = tokio::spawn(runner.run());
    handle.send(SchedulerEvent::Register("one".into())).unwrap();
    handle.send(SchedulerEvent::Pause("one".into())).unwrap();
    assert!(handle.snapshot().await.unwrap()[0].paused);
    handle.send(SchedulerEvent::Resume("one".into())).unwrap();
    assert!(!handle.snapshot().await.unwrap()[0].paused);
    handle.send(SchedulerEvent::Stop("one".into())).unwrap();
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;
    assert_eq!(task.await.unwrap(), Response::Stopped);
}

#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn framed_io_rejects_oversized_headers_and_times_out_stalled_peers() {
    use tokio::io::AsyncWriteExt;
    use watchme::ipc::{read_request, write_response};

    let (mut client, mut server) = tokio::io::duplex(MAX_FRAME_BYTES + 16);
    client
        .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
        .await
        .unwrap();
    assert!(
        read_request(&mut server, Duration::from_secs(1))
            .await
            .is_err()
    );

    let (_client, mut server) = tokio::io::duplex(1024);
    let read = tokio::spawn(async move { read_request(&mut server, Duration::from_secs(1)).await });
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(read.await.unwrap().is_err());

    let (mut client, mut server) = tokio::io::duplex(1024);
    write_response(&mut client, &Response::Stopped, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(
        watchme::ipc::read_response(&mut server, Duration::from_secs(1))
            .await
            .unwrap(),
        Response::Stopped
    );
}

struct FixedProbe(Option<u64>);

impl ProcessProbe for FixedProbe {
    fn start_time(&self, _pid: u32) -> std::io::Result<Option<u64>> {
        Ok(self.0)
    }
}

#[test]
fn stale_lock_recovery_requires_pid_and_start_time_identity() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("daemon.lock");
    fs::write(&path, r#"{"version":1,"pid":77,"start_time":100}"#).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(DaemonLock::acquire(&path, &FixedProbe(Some(100)), 88, 200).is_err());
    let lock = DaemonLock::acquire(&path, &FixedProbe(Some(101)), 88, 200).unwrap();
    assert_eq!(lock.identity().pid, 88);
}

#[test]
fn concurrent_daemon_startup_converges_and_shutdown_is_clean() {
    let temp = TempDir::new().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let binary = assert_cmd::cargo::cargo_bin!("watchme");
    let configure = |command: &mut Command| {
        command
            .env("HOME", temp.path())
            .env("XDG_CONFIG_HOME", temp.path().join("config"))
            .env("XDG_STATE_HOME", temp.path().join("state"))
            .env("XDG_RUNTIME_DIR", temp.path().join("run"));
    };
    fs::create_dir(temp.path().join("run")).unwrap();
    fs::set_permissions(temp.path().join("run"), fs::Permissions::from_mode(0o700)).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let spawn = |barrier: Arc<std::sync::Barrier>| {
        let binary = binary.to_path_buf();
        let root = temp.path().to_path_buf();
        std::thread::spawn(move || {
            let mut command = Command::new(binary);
            command
                .env("HOME", &root)
                .env("XDG_CONFIG_HOME", root.join("config"))
                .env("XDG_STATE_HOME", root.join("state"))
                .env("XDG_RUNTIME_DIR", root.join("run"));
            barrier.wait();
            command
                .args(["daemon", "run"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        })
    };
    let first_thread = spawn(barrier.clone());
    let second_thread = spawn(barrier.clone());
    barrier.wait();
    let mut first = first_thread.join().unwrap();
    let mut second_child = second_thread.join().unwrap();
    let socket = temp.path().join("run/watchme/daemon.sock");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists());

    let mut convergence = None;
    for _ in 0..100 {
        let states = (
            first.try_wait().unwrap().is_none(),
            second_child.try_wait().unwrap().is_none(),
        );
        if states.0 != states.1 {
            convergence = Some(states);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let (first_running, second_running) =
        convergence.expect("one startup must win within two seconds");
    assert_ne!(first_running, second_running);
    let mut status = Command::new(binary);
    configure(&mut status);
    let output = status.arg("status").output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "daemon: running\nwatchers: 0\n"
    );
    let mut missing_json = Command::new(binary);
    configure(&mut missing_json);
    let output = missing_json
        .args(["pause", "missing", "--json"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "{\"schema_version\":\"1.0\",\"ok\":false,\"error\":{\"code\":\"daemon_error\",\"message\":\"unknown watcher missing\"}}\n"
    );
    assert!(output.stderr.is_empty());
    let mut missing_human = Command::new(binary);
    configure(&mut missing_human);
    let output = missing_human.args(["pause", "missing"]).output().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "watchme: daemon_error: unknown watcher missing\n"
    );
    assert!(matches!(
        sync_ipc(
            &socket,
            &Request::Register {
                watcher: Box::new(state("cli-watcher", 61, 800))
            }
        ),
        Response::Registered {
            existing: false,
            ..
        }
    ));
    let mut pause = Command::new(binary);
    configure(&mut pause);
    let output = pause.args(["pause", "cli-watcher"]).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "cli-watcher\tpaused\n"
    );
    let mut resume = Command::new(binary);
    configure(&mut resume);
    let output = resume
        .args(["resume", "cli-watcher", "--json"])
        .output()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], "1.0");
    assert_eq!(value["ok"], true);
    assert_eq!(value["response"]["type"], "updated");
    assert_eq!(value["response"]["watcher"]["watcher_id"], "cli-watcher");
    assert_eq!(
        value["response"]["watcher"]["lifecycle"]["state"],
        "observing"
    );
    let mut stop_watcher = Command::new(binary);
    configure(&mut stop_watcher);
    let output = stop_watcher
        .args(["stop", "cli-watcher", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({
            "schema_version":"1.0", "ok":true, "response":{"type":"stopped"}
        })
    );
    let mut list = Command::new(binary);
    configure(&mut list);
    let output = list.args(["list", "--json"]).output().unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], "1.0");
    assert_eq!(value["ok"], true);
    assert_eq!(value["response"]["type"], "watchers");
    assert_eq!(
        value["response"]["watchers"][0]["watcher_id"],
        "cli-watcher"
    );
    assert_eq!(
        value["response"]["watchers"][0]["lifecycle"]["state"],
        "stopped"
    );
    let mut stop = Command::new(binary);
    configure(&mut stop);
    assert!(stop.args(["daemon", "stop"]).status().unwrap().success());
    let winner = if first_running {
        &mut first
    } else {
        &mut second_child
    };
    assert!(winner.wait().unwrap().success());
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

#[tokio::test(flavor = "current_thread")]
async fn live_ipc_dedupes_scopes_pause_resume_and_survives_disconnect() {
    let temp = TempDir::new().unwrap();
    let paths = WatchmePaths::resolve(
        temp.path(),
        Some(&temp.path().join("config")),
        Some(&temp.path().join("state")),
        Some(&temp.path().join("run")),
    )
    .unwrap();
    let daemon_paths = paths.clone();
    let task = tokio::spawn(async move {
        watchme::daemon::run(&daemon_paths, Duration::from_secs(5), true).await
    });
    let socket = paths.runtime_dir().join("daemon.sock");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let first = watchme::client::register_resolved(
        &paths,
        watchme::client::ResolvedRegistration {
            watcher: state("one", 51, 700),
        },
    );
    let second = watchme::client::register_resolved(
        &paths,
        watchme::client::ResolvedRegistration {
            watcher: state("duplicate", 51, 700),
        },
    );
    let (first, second) = tokio::join!(first, second);
    let responses = [first.unwrap(), second.unwrap()];
    assert_eq!(
        responses
            .iter()
            .filter(|response| matches!(
                response,
                Response::Registered {
                    existing: false,
                    ..
                }
            ))
            .count(),
        1
    );
    assert!(matches!(
        watchme::client::register_resolved(
            &paths,
            watchme::client::ResolvedRegistration {
                watcher: state("one", 52, 701),
            },
        )
        .await
        .unwrap(),
        Response::Error { code, message }
            if code == "daemon_error" && message == "watcher ID collision: one"
    ));
    assert_eq!(
        responses
            .iter()
            .filter(|response| matches!(response, Response::Registered { existing: true, .. }))
            .count(),
        1
    );
    assert!(matches!(
        ipc(&socket, Request::Pause { id: "one".into() }).await,
        Response::Updated { .. }
    ));
    let Response::Status { watchers, .. } = ipc(
        &socket,
        Request::Status {
            id: Some("one".into()),
        },
    )
    .await
    else {
        panic!()
    };
    assert!(matches!(watchers[0].lifecycle, WatcherLifecycle::Paused));

    let mut abandoned = tokio::net::UnixStream::connect(&socket).await.unwrap();
    use tokio::io::AsyncWriteExt;
    abandoned.write_all(&4_u32.to_be_bytes()).await.unwrap();
    abandoned.write_all(b"nope").await.unwrap();
    drop(abandoned);
    assert!(matches!(
        ipc(&socket, Request::Resume { id: "one".into() }).await,
        Response::Updated { .. }
    ));
    assert!(
        matches!(ipc(&socket, Request::Status { id: Some("missing".into()) }).await, Response::Status { watchers, .. } if watchers.is_empty())
    );
    assert!(matches!(
        ipc(&socket, Request::Status { id: Some(String::new()) }).await,
        Response::Error { code, .. } if code == "invalid_target"
    ));
    assert_eq!(
        ipc(
            &socket,
            Request::Stop {
                id: None,
                all: false,
            },
        )
        .await,
        Response::Error {
            code: "invalid_request".into(),
            message: "stop requires a watcher ID or --all".into(),
        }
    );
    assert_eq!(ipc(&socket, Request::Shutdown).await, Response::Stopped);
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn stalled_peer_does_not_block_status_or_shutdown() {
    let temp = TempDir::new().unwrap();
    let paths =
        WatchmePaths::resolve(temp.path(), None, None, Some(&temp.path().join("run"))).unwrap();
    let daemon_paths = paths.clone();
    let task = tokio::spawn(async move {
        watchme::daemon::run(&daemon_paths, Duration::from_secs(5), true).await
    });
    let socket = paths.runtime_dir().join("daemon.sock");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    use tokio::io::AsyncWriteExt;
    let mut stalled = tokio::net::UnixStream::connect(&socket).await.unwrap();
    stalled.write_all(&128_u32.to_be_bytes()).await.unwrap();
    stalled.write_all(b"{").await.unwrap();
    let status = tokio::time::timeout(
        Duration::from_millis(250),
        ipc(&socket, Request::Status { id: None }),
    )
    .await
    .expect("stalled peer must not monopolize the daemon");
    assert!(matches!(status, Response::Status { .. }));
    assert_eq!(ipc(&socket, Request::Shutdown).await, Response::Stopped);
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn daemon_bounds_simultaneous_connections() {
    let temp = TempDir::new().unwrap();
    let paths =
        WatchmePaths::resolve(temp.path(), None, None, Some(&temp.path().join("run"))).unwrap();
    let daemon_paths = paths.clone();
    let task = tokio::spawn(async move {
        watchme::daemon::run(&daemon_paths, Duration::from_secs(5), true).await
    });
    let socket = paths.runtime_dir().join("daemon.sock");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        held.push(tokio::net::UnixStream::connect(&socket).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut excess = tokio::net::UnixStream::connect(&socket).await.unwrap();
    use tokio::io::AsyncReadExt;
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_millis(250), excess.read(&mut byte))
        .await
        .expect("excess connection must be rejected promptly")
        .unwrap();
    assert_eq!(read, 0);
    drop(held);
    assert_eq!(ipc(&socket, Request::Shutdown).await, Response::Stopped);
    task.await.unwrap().unwrap();
}

#[derive(Clone)]
struct TogglePeer(Arc<AtomicBool>);

impl watchme::daemon::PeerCredentialProvider for TogglePeer {
    fn effective_uid(&self, _stream: &tokio::net::UnixStream) -> std::io::Result<u32> {
        Ok(rustix::process::geteuid().as_raw() + u32::from(!self.0.load(Ordering::SeqCst)))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn injected_peer_denial_is_isolated_and_empty_daemon_honors_idle_grace() {
    let temp = TempDir::new().unwrap();
    let paths =
        WatchmePaths::resolve(temp.path(), None, None, Some(&temp.path().join("run"))).unwrap();
    let daemon_paths = paths.clone();
    let allowed = Arc::new(AtomicBool::new(false));
    let provider = TogglePeer(allowed.clone());
    let task = tokio::spawn(async move {
        watchme::daemon::run_with_peer_provider(
            &daemon_paths,
            Duration::from_millis(150),
            false,
            provider,
        )
        .await
    });
    let socket = paths.runtime_dir().join("daemon.sock");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mut denied = tokio::net::UnixStream::connect(&socket).await.unwrap();
    watchme::ipc::write_request(
        &mut denied,
        &Request::Status { id: None },
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    drop(denied);
    allowed.store(true, Ordering::SeqCst);
    assert!(matches!(
        ipc(&socket, Request::Status { id: None }).await,
        Response::Status { .. }
    ));
    task.await.unwrap().unwrap();
    assert!(!socket.exists());
}

#[tokio::test(flavor = "current_thread")]
async fn live_stay_resident_survives_idle_grace_until_shutdown() {
    let temp = TempDir::new().unwrap();
    let paths =
        WatchmePaths::resolve(temp.path(), None, None, Some(&temp.path().join("run"))).unwrap();
    let daemon_paths = paths.clone();
    let task = tokio::spawn(async move {
        watchme::daemon::run(&daemon_paths, Duration::from_millis(50), true).await
    });
    let socket = paths.runtime_dir().join("daemon.sock");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(socket.exists());
    assert!(!task.is_finished());
    assert_eq!(ipc(&socket, Request::Shutdown).await, Response::Stopped);
    task.await.unwrap().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn replayed_stopped_watchers_do_not_prevent_live_idle_shutdown() {
    let temp = TempDir::new().unwrap();
    let paths =
        WatchmePaths::resolve(temp.path(), None, None, Some(&temp.path().join("run"))).unwrap();
    paths.create_owner_only().unwrap();
    let mut registry =
        Registry::load(JsonStore::new(paths.state_file("watchers.json").unwrap())).unwrap();
    registry.register(state("done", 91, 901)).unwrap();
    registry
        .transition(
            "done",
            WatcherLifecycle::Stopped {
                reason: "requested".into(),
            },
            2,
        )
        .unwrap();

    watchme::daemon::run(&paths, Duration::from_millis(50), false)
        .await
        .unwrap();
    assert!(!paths.runtime_dir().join("daemon.sock").exists());
}

#[tokio::test(flavor = "current_thread")]
async fn live_transition_revision_overflow_returns_typed_daemon_error() {
    let temp = TempDir::new().unwrap();
    let paths =
        WatchmePaths::resolve(temp.path(), None, None, Some(&temp.path().join("run"))).unwrap();
    paths.create_owner_only().unwrap();
    JsonStore::new(paths.state_file("watchers.json").unwrap())
        .write(&serde_json::json!({
            "version": 1,
            "watchers": [WatcherState::new(
                "overflow".into(),
                TargetIdentity::process(ProcessIdentity::new(92, 903)),
                WatcherLifecycle::Stopped { reason: "fixture".into() },
                u64::MAX,
                1,
            )]
        }))
        .unwrap();
    let daemon_paths = paths.clone();
    let task = tokio::spawn(async move {
        watchme::daemon::run(&daemon_paths, Duration::from_secs(5), true).await
    });
    let socket = paths.runtime_dir().join("daemon.sock");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        ipc(
            &socket,
            Request::Pause {
                id: "overflow".into(),
            },
        )
        .await,
        Response::Error {
            code: "daemon_error".into(),
            message: "watcher revision overflow: overflow".into(),
        }
    );
    assert_eq!(ipc(&socket, Request::Shutdown).await, Response::Stopped);
    task.await.unwrap().unwrap();
}
