#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::TempDir;
use watchme::daemon::registry::{RegistrationOutcome, Registry};
use watchme::daemon::scheduler::{Scheduler, SchedulerEvent};
use watchme::daemon::{DaemonLock, ProcessProbe};
use watchme::ipc::protocol::{MAX_FRAME_BYTES, Request, Response, decode_frame, encode_frame};
use watchme::ipc::{bind_owner_only, validate_peer_uid};
use watchme::model::{ProcessIdentity, TargetIdentity, WatcherLifecycle, WatcherState};
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

#[test]
fn protocol_is_versioned_bounded_and_rejects_malformed_frames() {
    let bytes = encode_frame(&Request::Status).unwrap();
    assert_eq!(decode_frame::<Request>(&bytes).unwrap(), Request::Status);
    assert!(decode_frame::<Request>(b"{oops").is_err());
    assert!(decode_frame::<Request>(&vec![b'x'; MAX_FRAME_BYTES + 1]).is_err());

    let mut wrong = serde_json::to_value(Request::Status).unwrap();
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
    let mut first_command = Command::new(binary);
    configure(&mut first_command);
    let mut first = first_command
        .args(["daemon", "run"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let socket = temp.path().join("run/watchme/daemon.sock");
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(socket.exists());

    let mut second = Command::new(binary);
    configure(&mut second);
    assert!(!second.args(["daemon", "run"]).status().unwrap().success());
    let mut stop = Command::new(binary);
    configure(&mut stop);
    assert!(stop.args(["daemon", "stop"]).status().unwrap().success());
    assert!(first.wait().unwrap().success());
}
