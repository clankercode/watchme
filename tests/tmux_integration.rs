use std::process::Command;
use std::time::Duration;

use watchme::mux::tmux::{Tmux, TmuxSelector};
use watchme::mux::{Multiplexer, SymbolicKey};

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
    let target = "watchme";
    let cleanup = || {
        let _ = Command::new("tmux")
            .args(["-L", &socket, "kill-server"])
            .status();
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

    let tmux = Tmux::for_socket_name(socket.clone(), Duration::from_secs(2));
    let identity = tmux
        .resolve_selector(&TmuxSelector::parse(target).unwrap())
        .unwrap();
    let captured = tmux.capture_tail(&identity, 40, 16 * 1024).unwrap();
    assert!(captured.text.contains("ready"));
    tmux.send_literal(&identity, "hello ; $(false)").unwrap();
    tmux.send_key(&identity, SymbolicKey::Enter).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        tmux.capture_tail(&identity, 40, 16 * 1024)
            .unwrap()
            .text
            .contains("got:hello ; $(false)")
    );

    Command::new("tmux")
        .args(["-L", &socket, "kill-pane", "-t", &identity.pane_id])
        .status()
        .unwrap();
    assert!(tmux.send_literal(&identity, "must refuse").is_err());
    cleanup();
}
