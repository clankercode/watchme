use std::process::Command;
use std::time::Duration;
use std::time::Instant;

use watchme::mux::tmux::{Tmux, TmuxSelector};
use watchme::mux::{
    ComposerSafety, ComposerState, Multiplexer, MuxError, MuxIdentity, SymbolicKey,
};

struct Composer(ComposerState);
impl ComposerSafety for Composer {
    fn observe(&self, _: &MuxIdentity) -> Result<ComposerState, MuxError> {
        Ok(self.0)
    }
}

struct ServerGuard(String);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = Command::new("tmux")
            .args(["-L", &self.0, "kill-server"])
            .output();
    }
}

#[test]
fn selector_diagnostics_reject_controls_and_accept_explicit_ids() {
    assert_eq!(TmuxSelector::parse("%12").unwrap().as_str(), "%12");
    assert_eq!(TmuxSelector::parse("$3").unwrap().as_str(), "$3");
    assert!(TmuxSelector::parse("pane\nother").is_err());
    assert!(TmuxSelector::parse("-L").is_err());
    assert!(TmuxSelector::parse("name:1.2").is_ok());
}

#[test]
fn private_tmux_server_captures_sends_and_refuses_stale_identity() {
    if Command::new("tmux").arg("-V").output().is_err() {
        eprintln!("skipping: tmux executable is absent");
        return;
    }
    let socket = format!("watchme-test-{}", std::process::id());
    let _guard = ServerGuard(socket.clone());
    let target = "watchme";
    let cleanup = || {
        let _ = Command::new("tmux")
            .args(["-L", &socket, "kill-server"])
            .output();
    };
    cleanup();
    let status = Command::new("tmux")
        .args([
            "-L",
            &socket,
            "new-session",
            "-d",
            "-s",
            target,
            "sh",
            "-c",
            "printf 'ready\\n'; while IFS= read -r line; do printf 'got:%s\\n' \"$line\"; done",
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        Command::new("tmux")
            .args([
                "-L",
                &socket,
                "new-window",
                "-d",
                "-t",
                target,
                "-n",
                "spare",
                "sleep",
                "30"
            ])
            .status()
            .unwrap()
            .success()
    );

    let tmux = Tmux::for_socket_name(socket.clone(), Duration::from_secs(2));
    let deadline = Instant::now() + Duration::from_secs(2);
    let identity = loop {
        let candidate = tmux
            .resolve_selector(&TmuxSelector::parse(target).unwrap())
            .unwrap();
        if candidate.process.executable.as_deref() != Some("/usr/bin/tmux")
            && tmux
                .capture_tail(&candidate, 40, 16 * 1024)
                .is_ok_and(|capture| capture.text.contains("ready"))
        {
            break candidate;
        }
        assert!(
            Instant::now() < deadline,
            "private tmux pane did not become ready"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let captured = tmux.capture_tail(&identity, 40, 16 * 1024).unwrap();
    assert!(captured.text.contains("ready"));
    let safe = Composer(ComposerState::Safe);
    tmux.send_literal(&identity, "hello ; $(false)", &safe)
        .unwrap();
    tmux.send_key(&identity, SymbolicKey::Enter, &safe).unwrap();
    for state in [
        ComposerState::Unsafe,
        ComposerState::Unknown,
        ComposerState::Stale,
    ] {
        assert!(
            tmux.send_literal(&identity, "blocked", &Composer(state))
                .is_err()
        );
    }
    for control in [
        '\0', '\u{1}', '\u{7}', '\u{8}', '\t', '\n', '\r', '\u{1b}', '\u{7f}', '\u{80}', '\u{9f}',
    ] {
        assert!(
            tmux.send_literal(&identity, &format!("bad{control}"), &safe)
                .is_err()
        );
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if tmux
            .capture_tail(&identity, 40, 16 * 1024)
            .unwrap()
            .text
            .contains("got:hello ; $(false)")
        {
            break;
        }
        assert!(Instant::now() < deadline, "fake agent did not echo input");
        std::thread::sleep(Duration::from_millis(10));
    }

    Command::new("tmux")
        .args(["-L", &socket, "kill-pane", "-t", &identity.pane_id])
        .status()
        .unwrap();
    assert!(
        Command::new("tmux")
            .args([
                "-L",
                &socket,
                "new-window",
                "-d",
                "-t",
                target,
                "sh",
                "-c",
                "printf replacement; sleep 30"
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(tmux.send_literal(&identity, "must refuse", &safe).is_err());
    assert!(
        Command::new("tmux")
            .args(["-L", &socket, "kill-server"])
            .status()
            .unwrap()
            .success()
    );
    let restart_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if Command::new("tmux")
            .args([
                "-L",
                &socket,
                "new-session",
                "-d",
                "-s",
                target,
                "sleep",
                "30",
            ])
            .output()
            .unwrap()
            .status
            .success()
        {
            break;
        }
        assert!(
            Instant::now() < restart_deadline,
            "private server could not restart"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let replacement = loop {
        let candidate = tmux
            .resolve_selector(&TmuxSelector::parse(target).unwrap())
            .unwrap();
        if candidate.process.executable.as_deref() != Some("/usr/bin/tmux") {
            break candidate;
        }
        assert!(
            Instant::now() < deadline,
            "replacement pane did not become ready"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(
        (
            &replacement.server,
            &replacement.session_id,
            &replacement.window_id,
            &replacement.pane_id
        ),
        (
            &identity.server,
            &identity.session_id,
            &identity.window_id,
            &identity.pane_id
        )
    );
    assert_ne!(
        (replacement.process.pid, replacement.process.start_time),
        (identity.process.pid, identity.process.start_time)
    );
    assert!(matches!(
        tmux.validate_identity(&identity),
        Err(MuxError::IdentityChanged(_))
    ));
}

#[test]
fn bare_watchme_registers_fake_codex_ancestor_in_private_tmux() {
    if Command::new("tmux").arg("-V").output().is_err() {
        eprintln!("skipping: tmux executable is absent");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let socket = format!("watchme-register-{}", std::process::id());
    let _guard = ServerGuard(socket.clone());
    let codex = root.path().join("codex");
    assert!(
        Command::new("rustc")
            .args(["--edition=2024", "tests/fixtures/fake_codex.rs", "-o"])
            .arg(&codex)
            .status()
            .unwrap()
            .success()
    );
    for dir in ["runtime", "state", "home"] {
        std::fs::create_dir(root.path().join(dir)).unwrap();
    }
    let watchme = env!("CARGO_BIN_EXE_watchme");
    let runtime = root.path().join("runtime");
    let state = root.path().join("state");
    let home = root.path().join("home");
    let status = Command::new("tmux")
        .args([
            "-L",
            &socket,
            "new-session",
            "-d",
            "-s",
            "registration",
            "env",
        ])
        .arg(format!("WATCHME_BIN={watchme}"))
        .arg(format!("XDG_RUNTIME_DIR={}", runtime.display()))
        .arg(format!("XDG_STATE_HOME={}", state.display()))
        .arg(format!("HOME={}", home.display()))
        .arg(&codex)
        .status()
        .unwrap();
    assert!(status.success());
    let state_file = state.join("watchme/watchers.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    let persisted = loop {
        if let Ok(bytes) = std::fs::read(&state_file)
            && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && value["watchers"]
                .as_array()
                .is_some_and(|watchers| !watchers.is_empty())
        {
            break value;
        }
        assert!(
            Instant::now() < deadline,
            "bare registration did not persist"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let watcher = &persisted["watchers"][0];
    assert_eq!(watcher["target"]["kind"], "multiplexer");
    assert_eq!(watcher["target"]["provider"], "tmux");
    assert_eq!(watcher["target"]["pane"], "%0");
    assert!(
        watcher["target"]["server"]
            .as_str()
            .unwrap()
            .contains(&socket)
    );
    assert_eq!(
        watcher["target"]["process"]["executable"],
        codex.to_str().unwrap()
    );
    let registered_tty = watcher["target"]["process"]["tty"].as_str().unwrap();
    let pane = Tmux::for_socket_name(socket.clone(), Duration::from_secs(2))
        .resolve_selector(&TmuxSelector::parse("registration").unwrap())
        .unwrap();
    assert_eq!(
        watcher["target"]["process"]["pid"].as_u64(),
        Some(pane.process.pid.into())
    );
    assert_eq!(pane.process.tty.as_deref(), Some(registered_tty));
    let status = Command::new(watchme)
        .args(["status", "--json"])
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("XDG_STATE_HOME", &state)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(status.status.success());
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(
        status_json["response"]["watchers"][0]["target"]["kind"],
        "multiplexer"
    );
    let stop = Command::new(watchme)
        .args(["daemon", "stop"])
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("XDG_STATE_HOME", &state)
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(stop.status.success());
}
