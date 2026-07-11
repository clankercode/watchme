use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn bare_watchme_outside_agent_explains_shell_escape_and_doctor() {
    Command::cargo_bin("watchme")
        .expect("binary exists")
        .env_remove("TMUX")
        .assert()
        .failure()
        .stderr(predicate::str::contains("!watchme"))
        .stderr(predicate::str::contains("watchme doctor"));
}

#[test]
fn start_is_not_a_command() {
    Command::cargo_bin("watchme")
        .expect("binary exists")
        .arg("start")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand 'start'"));
}

#[test]
fn administrative_commands_parse() {
    for arguments in [
        &["status", "--help"][..],
        &["list", "--help"],
        &["explain", "--help"],
        &["snapshot", "--help"],
        &["logs", "--help"],
        &["stop", "--help"],
        &["doctor", "--help"],
        &["providers", "--help"],
        &["config", "--help"],
        &["daemon", "--help"],
    ] {
        Command::cargo_bin("watchme")
            .expect("binary exists")
            .args(arguments)
            .assert()
            .success();
    }
}

#[test]
fn json_errors_are_versioned_envelopes() {
    let output = Command::cargo_bin("watchme")
        .expect("binary exists")
        .args(["list", "--json"])
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("valid JSON response");
    assert_eq!(envelope["schema_version"], "1.0");
    assert_eq!(envelope["ok"], false);
}
