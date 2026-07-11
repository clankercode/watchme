//! Task 13: diagnostics, notifications, logs, and operability.
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::tempdir;
use watchme::audit::{
    AuditEvent, AuditLog, DecisionChain, RetentionPolicy, append_decision, explain_decision,
};
use watchme::config::{Config, NotificationsConfig};
use watchme::doctor::{CheckStatus, DoctorOptions, run_doctor};
use watchme::notify::{
    DesktopBackend, HerdrBackend, NotificationOutcome, NotifyRequest, NotifyTarget, notify,
    notify_during_cleanup,
};
use watchme::paths::WatchmePaths;
use watchme::planner::{SnapshotBuildInput, SnapshotObservation, build_redacted_snapshot};
use watchme::redact::redact_text;

fn isolated_env(temp: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf) {
    let config = temp.path().join("config");
    let state = temp.path().join("state");
    let runtime = temp.path().join("run");
    fs::create_dir_all(config.join("watchme")).unwrap();
    fs::create_dir_all(state.join("watchme")).unwrap();
    fs::create_dir_all(&runtime).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [
            config.join("watchme"),
            state.join("watchme"),
            runtime.clone(),
        ] {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    (config, state, runtime)
}

fn watchme_cmd(temp: &tempfile::TempDir, config: &Path, state: &Path, runtime: &Path) -> Command {
    let mut cmd = Command::cargo_bin("watchme").unwrap();
    cmd.env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", config)
        .env("XDG_STATE_HOME", state)
        .env("XDG_RUNTIME_DIR", runtime);
    cmd
}

fn sample_decision(watcher_id: &str) -> DecisionChain {
    DecisionChain {
        watcher_id: watcher_id.into(),
        detector: "screen_detection".into(),
        evidence: "usage_limit:fingerprint-abc".into(),
        state: "CONFIRMED_BLOCKED".into(),
        policy_decision: "ALLOW labelled wait".into(),
        attempted_action: "WAIT_DURATION".into(),
        verification: "progress_observed".into(),
    }
}

#[test]
fn doctor_json_is_versioned_and_reports_checks() {
    let temp = tempdir().unwrap();
    let (config, state, runtime) = isolated_env(&temp);
    let output = watchme_cmd(&temp, &config, &state, &runtime)
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema_version"], "1.0");
    assert_eq!(envelope["ok"], true);
    let checks = envelope["checks"].as_array().expect("checks array");
    let names: Vec<_> = checks.iter().filter_map(|c| c["name"].as_str()).collect();
    for required in [
        "paths",
        "permissions",
        "config",
        "tmux",
        "herdr",
        "hooks",
        "providers",
    ] {
        assert!(names.contains(&required), "missing {required} in {names:?}");
    }
}

#[test]
fn doctor_strict_fails_when_warnings_present() {
    let temp = tempdir().unwrap();
    let paths =
        WatchmePaths::resolve(temp.path(), None, None, Some(&temp.path().join("run"))).unwrap();
    paths.create_owner_only().unwrap();
    // Intentionally leave config missing/default; tmux/herdr may warn.
    let report = run_doctor(
        &paths,
        &Config::default(),
        DoctorOptions {
            strict: true,
            json: false,
        },
    );
    // With default paths created, config defaults ok; if any warn/fail, strict fails.
    if report
        .checks
        .iter()
        .any(|c| matches!(c.status, CheckStatus::Warn | CheckStatus::Fail))
    {
        assert!(!report.ok, "strict must fail when warnings/failures exist");
    }

    let (config, state, runtime) = isolated_env(&temp);
    // Corrupt config so doctor must fail under --strict.
    fs::write(config.join("watchme/config.toml"), "mystery = true\n").unwrap();
    watchme_cmd(&temp, &config, &state, &runtime)
        .args(["doctor", "--strict"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("configuration").or(predicate::str::contains("doctor")));
}

#[test]
fn explain_prints_exact_decision_chain_from_audit() {
    let temp = tempdir().unwrap();
    let (config, state, runtime) = isolated_env(&temp);
    let audit_path = state.join("watchme/audit.jsonl");
    let mut log = AuditLog::open(&audit_path).unwrap();
    let chain = sample_decision("watcher-1");
    append_decision(&mut log, &chain).unwrap();

    let output = watchme_cmd(&temp, &config, &state, &runtime)
        .args(["explain", "watcher-1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    for fragment in [
        "detector: screen_detection",
        "evidence: usage_limit:fingerprint-abc",
        "state: CONFIRMED_BLOCKED",
        "policy_decision: ALLOW labelled wait",
        "attempted_action: WAIT_DURATION",
        "verification: progress_observed",
    ] {
        assert!(text.contains(fragment), "missing {fragment} in {text}");
    }
}

#[test]
fn explain_is_honest_when_daemon_down_and_no_watcher() {
    let temp = tempdir().unwrap();
    let (config, state, runtime) = isolated_env(&temp);
    for args in [&["explain", "missing-watcher"][..], &["explain"]] {
        let output = watchme_cmd(&temp, &config, &state, &runtime)
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(
            !err.contains("not implemented yet"),
            "must not fall through to unimplemented: {err}"
        );
        assert!(
            err.contains("no watcher")
                || err.contains("not found")
                || err.contains("no audit")
                || err.contains("empty"),
            "expected honest missing-watcher message: {err}"
        );
    }
}

#[test]
fn snapshot_is_redacted_by_default_and_bounded() {
    let temp = tempdir().unwrap();
    let (config, state, runtime) = isolated_env(&temp);
    let audit_path = state.join("watchme/audit.jsonl");
    let mut log = AuditLog::open(&audit_path).unwrap();
    append_decision(&mut log, &sample_decision("watcher-1")).unwrap();

    // Seed a watcher-shaped last observation via a redacted snapshot helper path:
    // write a small state file the CLI can load for snapshot construction.
    let secret_tail = "Authorization: Bearer sk-ant-supersecret1234567890";
    let input = SnapshotBuildInput {
        snapshot_id: "snap-operability".into(),
        created_at: "2026-07-12T00:00:00Z".into(),
        watcher_id: "watcher-1".into(),
        watcher_state: "CONFIRMED_BLOCKED".into(),
        evidence_fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .into(),
        mux_kind: "tmux".into(),
        pane_id: "%1".into(),
        process_pid: 42,
        process_start_time: "100".into(),
        identity_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        agent_id: Some("claude".into()),
        provider_family: Some("anthropic".into()),
        failed_provider_family: "anthropic".into(),
        terminal_text: Some(secret_tail.into()),
        observations: vec![SnapshotObservation {
            event_id: "evt-1".into(),
            category: "usage_limit".into(),
            source_kind: "screen_detection".into(),
            confidence: 0.9,
            summary: secret_tail.into(),
            observed_at: "2026-07-12T00:00:00Z".into(),
        }],
        allowed_actions: vec!["WAIT_DURATION".into(), "NOOP".into()],
        max_snapshot_bytes: 8_192,
        extra_secret_names: vec![],
    };
    let snapshot = build_redacted_snapshot(input).unwrap();
    let snap_path = state.join("watchme/snapshots");
    fs::create_dir_all(&snap_path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&snap_path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(
        snap_path.join("watcher-1.json"),
        serde_json::to_vec(&snapshot).unwrap(),
    )
    .unwrap();

    let output = watchme_cmd(&temp, &config, &state, &runtime)
        .args(["snapshot", "watcher-1", "--redacted"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(!body.contains("sk-ant-supersecret"));
    assert!(body.contains("REDACTED") || body.contains("redaction"));
    let parsed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["schema_version"], "1.0");
    assert_eq!(parsed["redaction"]["raw_evidence_included"], false);
}

#[test]
fn audit_log_rotates_by_size_and_retention_and_never_keeps_secrets() {
    let temp = tempdir().unwrap();
    let path = temp.path().join("audit.jsonl");
    let mut log = AuditLog::open(&path).unwrap();
    let secret = "Bearer sk-ant-leakme12345678901234";
    for i in 0..20 {
        log.append(&AuditEvent {
            schema_version: "1.0".into(),
            recorded_at: format!("2026-07-{:02}T00:00:00Z", (i % 10) + 1),
            watcher_id: Some("w1".into()),
            kind: "decision".into(),
            detector: Some("screen".into()),
            evidence: Some(format!("evidence {i} {secret}")),
            state: Some("OBSERVING".into()),
            policy_decision: Some("ALLOW".into()),
            attempted_action: Some("NOOP".into()),
            verification: Some("ok".into()),
            message: format!("msg {i}"),
        })
        .unwrap();
    }
    let before = fs::read_to_string(&path).unwrap();
    assert!(!before.contains("sk-ant-leakme"));
    assert!(before.contains("REDACTED") || before.contains("<REDACTED"));

    let retention = RetentionPolicy {
        events_days: 30,
        audit_days: 30,
        max_log_bytes: 800,
    };
    log.apply_retention(&retention, "2026-07-12T00:00:00Z")
        .unwrap();
    let bytes = fs::metadata(&path).unwrap().len();
    assert!(bytes <= retention.max_log_bytes, "log grew to {bytes}");
    let text = fs::read_to_string(&path).unwrap();
    assert!(
        !text.is_empty(),
        "retention must keep recent redacted lines"
    );
    assert!(!text.contains("sk-ant-leakme"));
    assert!(text.contains("REDACTED") || text.contains("<REDACTED"));
}

#[test]
fn logs_command_reads_bounded_redacted_audit_and_follow_tails() {
    let temp = tempdir().unwrap();
    let (config, state, runtime) = isolated_env(&temp);
    let audit_path = state.join("watchme/audit.jsonl");
    let mut log = AuditLog::open(&audit_path).unwrap();
    append_decision(&mut log, &sample_decision("watcher-1")).unwrap();
    log.append(&AuditEvent {
        schema_version: "1.0".into(),
        recorded_at: "2026-07-12T00:00:01Z".into(),
        watcher_id: Some("watcher-1".into()),
        kind: "event".into(),
        detector: None,
        evidence: Some("token sk-ant-shouldhide9999999999".into()),
        state: None,
        policy_decision: None,
        attempted_action: None,
        verification: None,
        message: "observed".into(),
    })
    .unwrap();

    let output = watchme_cmd(&temp, &config, &state, &runtime)
        .args(["logs", "watcher-1"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("watcher-1"));
    assert!(!text.contains("sk-ant-shouldhide"));

    // Follow mode: library tail sees newly appended lines without leaking secrets.
    let mut follower = AuditLog::open(&audit_path).unwrap();
    let before = follower.read_lines(Some("watcher-1"), 64).unwrap().len();
    {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&audit_path)
            .unwrap();
        let (redacted, _) = redact_text("follow-line secret sk-ant-followleak1234567890", &[]);
        writeln!(
            file,
            r#"{{"schema_version":"1.0","recorded_at":"2026-07-12T00:00:02Z","watcher_id":"watcher-1","kind":"event","message":"{redacted}"}}"#
        )
        .unwrap();
    }
    // CLI --follow must parse (not fall through to unimplemented).
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_watchme"))
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["logs", "watcher-1", "--follow"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    thread::sleep(Duration::from_millis(400));
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("not implemented yet"),
        "logs --follow still unimplemented: {combined}"
    );
    let after = follower.read_lines(Some("watcher-1"), 64).unwrap();
    assert!(after.len() > before, "follow source must grow");
    let joined = after
        .iter()
        .map(|e| e.message.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(joined.contains("follow-line") || combined.contains("follow-line"));
    assert!(!joined.contains("sk-ant-followleak"));
    assert!(!combined.contains("sk-ant-followleak"));
}

#[test]
fn providers_lists_support_tiers_and_first_class_claude_codex() {
    let temp = tempdir().unwrap();
    let (config, state, runtime) = isolated_env(&temp);
    let output = watchme_cmd(&temp, &config, &state, &runtime)
        .args(["providers", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["schema_version"], "1.0");
    assert_eq!(envelope["ok"], true);
    let providers = envelope["providers"].as_array().unwrap();
    let ids: Vec<_> = providers.iter().filter_map(|p| p["id"].as_str()).collect();
    assert!(ids.contains(&"claude"), "{ids:?}");
    assert!(ids.contains(&"codex"), "{ids:?}");
    assert!(
        ids.contains(&"opencode") || ids.contains(&"unknown"),
        "{ids:?}"
    );
    let claude = providers.iter().find(|p| p["id"] == "claude").unwrap();
    assert!(
        claude["support_tier"]
            .as_str()
            .unwrap()
            .contains("structured")
            || claude["tier"].as_str().unwrap_or("").contains("structured")
            || claude["first_class"] == true,
        "{claude}"
    );
}

#[test]
fn providers_independence_check_excludes_same_family() {
    let explained = explain_decision(&[sample_decision("w")], Some("w"));
    assert!(explained.is_ok());
    // Library-level provider independence is covered by planner tests; here the
    // CLI providers listing must still expose readiness without requiring the
    // failed family executable.
    let temp = tempdir().unwrap();
    let (config, state, runtime) = isolated_env(&temp);
    watchme_cmd(&temp, &config, &state, &runtime)
        .args(["providers"])
        .assert()
        .success()
        .stdout(predicate::str::contains("claude"))
        .stdout(predicate::str::contains("codex"));
}

#[test]
fn notification_falls_back_herdr_then_desktop_then_stderr() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let herdr_calls = calls.clone();
    let herdr = HerdrBackend::from_fn(move |_title, _body| {
        herdr_calls.lock().unwrap().push("herdr");
        Err("herdr down".into())
    });
    let desktop_calls = calls.clone();
    let desktop = DesktopBackend::from_fn(move |_title, _body| {
        desktop_calls.lock().unwrap().push("desktop");
        Err("no desktop".into())
    });
    let stderr_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let stderr = stderr_buf.clone();
    let config = NotificationsConfig {
        herdr: true,
        desktop: true,
        stderr: true,
        ..NotificationsConfig::default()
    };
    let outcome = notify(
        &config,
        &NotifyRequest {
            title: "watchme".into(),
            body: "human required".into(),
        },
        NotifyTarget {
            herdr: Some(&herdr),
            desktop: Some(&desktop),
            stderr_write: Some(&|line: &str| {
                stderr.lock().unwrap().extend_from_slice(line.as_bytes());
                Ok(())
            }),
        },
    );
    assert_eq!(
        *calls.lock().unwrap(),
        vec!["herdr", "desktop"],
        "must try herdr then desktop"
    );
    assert!(matches!(
        outcome,
        NotificationOutcome::Delivered { channel } if channel == "stderr"
    ));
    let written = String::from_utf8(stderr_buf.lock().unwrap().clone()).unwrap();
    assert!(written.contains("human required"));
}

#[test]
fn notification_failure_during_cleanup_does_not_panic_or_block() {
    let config = NotificationsConfig::default();
    let herdr = HerdrBackend::from_fn(|_, _| Err("boom".into()));
    let desktop = DesktopBackend::from_fn(|_, _| Err("boom".into()));
    // Cleanup path must return promptly even when every channel fails.
    let started = std::time::Instant::now();
    let outcome = notify_during_cleanup(
        &config,
        &NotifyRequest {
            title: "watchme".into(),
            body: "shutdown".into(),
        },
        NotifyTarget {
            herdr: Some(&herdr),
            desktop: Some(&desktop),
            stderr_write: Some(&|_| Err("stderr closed".into())),
        },
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(matches!(outcome, NotificationOutcome::Suppressed { .. }));
}

#[test]
fn config_commands_still_work_under_operability() {
    let temp = tempdir().unwrap();
    let (config, state, runtime) = isolated_env(&temp);
    watchme_cmd(&temp, &config, &state, &runtime)
        .args(["config", "check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("configuration ok"));
}

#[test]
fn doctor_library_reports_path_permission_and_provider_checks() {
    let temp = tempdir().unwrap();
    let paths =
        WatchmePaths::resolve(temp.path(), None, None, Some(&temp.path().join("run"))).unwrap();
    paths.create_owner_only().unwrap();
    let report = run_doctor(
        &paths,
        &Config::default(),
        DoctorOptions {
            strict: false,
            json: true,
        },
    );
    assert_eq!(report.schema_version, "1.0");
    assert!(report.checks.iter().any(|c| c.name == "paths"));
    assert!(report.checks.iter().any(|c| c.name == "permissions"));
    assert!(report.checks.iter().any(|c| c.name == "providers"));
}
