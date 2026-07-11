use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn bare_watchme_outside_agent_explains_shell_escape_and_doctor() {
    Command::cargo_bin("watchme")
        .expect("binary exists")
        .env_remove("TMUX")
        .env_remove("WATCHME_TEST_AGENT_CONTEXT")
        .assert()
        .failure()
        .stderr(predicate::str::contains("!watchme"))
        .stderr(predicate::str::contains("watchme doctor"));
}

#[test]
fn test_context_environment_variable_cannot_bypass_detection() {
    Command::cargo_bin("watchme")
        .expect("binary exists")
        .env("WATCHME_TEST_AGENT_CONTEXT", "claude")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported context"))
        .stderr(predicate::str::contains("!watchme"));
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
        &["status", "watcher-1"][..],
        &["list"],
        &["explain", "watcher-1"],
        &["snapshot", "watcher-1", "--redacted"],
        &["logs", "watcher-1", "--follow"],
        &["stop", "--all"],
        &["doctor", "--strict"],
        &["providers"],
        &["config", "check"],
        &["daemon", "status"],
    ] {
        Command::cargo_bin("watchme")
            .expect("binary exists")
            .args(arguments)
            .assert()
            .failure()
            .stdout(predicate::str::is_empty())
            .stderr(predicate::eq(
                "watchme: capability unavailable: this administrative capability is not implemented yet\n",
            ));
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
    assert_eq!(
        envelope,
        serde_json::json!({
            "schema_version": "1.0",
            "ok": false,
            "error": {
                "code": "capability_unavailable",
                "message": "this administrative capability is not implemented yet"
            }
        })
    );
    assert!(output.stderr.is_empty());
}
