//! Planner broker security and routing acceptance (H + I).
//!
//! These tests define the redacted alternate-provider planner contract:
//! independent-family routing, strict schema decode, subprocess isolation,
//! budgets, and policy rejection of hostile plans.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;
use watchme::config::{PlannerConfig, PlanningConfig, SecurityConfig};
use watchme::planner::process::{PlannerProcessRequest, run_planner_process, verify_process_gone};
use watchme::planner::router::{
    PlannerCapability, PlannerRouter, ResolvedPlanner, resolve_eligible_planners,
};
use watchme::planner::schema::{
    PlanValidationContext, RecoveryPlan, decode_recovery_plan, validate_recovery_plan,
};
use watchme::planner::{
    PlannerBroker, PlannerRequest, SnapshotBuildInput, SnapshotObservation, build_redacted_snapshot,
};
use watchme::policy::{CompiledPolicy, PolicyContext};
use watchme::redact::{redact_json, redact_text};

const VALID_PLAN: &str = include_str!("../fixtures/recovery-plan.valid.json");
const INVALID_PLAN: &str = include_str!("../fixtures/recovery-plan.invalid.json");
const MALICIOUS_TERMINAL: &str = include_str!("../fixtures/malicious-terminal-samples.txt");

fn write_executable(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, body).unwrap();
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).unwrap();
    path
}

fn plan_with_families(failed: &str, planner: &str) -> String {
    VALID_PLAN
        .replace(
            "\"failed_provider_family\": \"openai\"",
            &format!("\"failed_provider_family\": \"{failed}\""),
        )
        .replace(
            "\"planner_provider_family\": \"anthropic\"",
            &format!("\"planner_provider_family\": \"{planner}\""),
        )
}

fn write_plan_echo(dir: &Path, name: &str, plan: &str) -> PathBuf {
    // Avoid shell heredoc/quoting issues by writing the plan beside the script.
    let plan_path = dir.join(format!("{name}.json"));
    fs::write(&plan_path, plan).unwrap();
    write_executable(
        dir,
        name,
        &format!("#!/bin/sh\ncat \"{}\"\n", plan_path.display()),
    )
}

/// Trusted snapshot matching the VALID_PLAN target identity/evidence.
fn trusted_snapshot(allowed_actions: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "schema_version": "1.0",
        "snapshot_id": "snap-demo",
        "created_at": "2026-07-11T10:00:00Z",
        "watcher": {
            "watcher_id": "watcher-demo-001",
            "state": "PLANNING",
            "evidence_fingerprint": "0123456789abcdef0123456789abcdef"
        },
        "target": {
            "mux_kind": "tmux",
            "pane_id": "%7",
            "process_pid": 4242,
            "process_start_time": "2026-07-11T09:00:00Z",
            "identity_hash": "0123456789abcdef0123456789abcdef"
        },
        "agent": {
            "agent_id": "codex",
            "provider_family": "openai",
            "failed_provider_family": "openai"
        },
        "observations": [{
            "event_id": "evt-1",
            "category": "capacity_block",
            "source_kind": "screen_detection",
            "confidence": 0.9,
            "summary": "blocked",
            "observed_at": "2026-07-11T10:00:00Z"
        }],
        "attempts": [],
        "allowed_actions": allowed_actions,
        "redaction": {
            "performed": true,
            "replacement_count": 0,
            "categories": [],
            "raw_evidence_included": false
        }
    })
}

fn default_allowed_actions() -> Vec<&'static str> {
    vec![
        "WAIT_DURATION",
        "SEND_TEXT",
        "SEND_KEYS",
        "CHECK_STATUS",
        "CAPTURE",
        "NOOP",
    ]
}

/// Keep plan identity fixed but move validity into the far future so wall-clock checks pass.
fn with_future_validity(plan_json: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(plan_json).unwrap();
    value["generated_at"] = serde_json::json!("2099-01-01T00:00:00Z");
    value["valid_until"] = serde_json::json!("2099-01-01T00:05:00Z");
    value.to_string()
}

fn broker_request(
    executable: PathBuf,
    family: &str,
    failed: &str,
    snapshot: serde_json::Value,
    event_id: &str,
) -> PlannerRequest {
    PlannerRequest {
        session_id: "session-trust".into(),
        event_id: event_id.into(),
        failed_provider_family: failed.into(),
        snapshot_json: snapshot,
        day_key: "2026-07-12".into(),
        resolved: vec![ResolvedPlanner {
            id: "hermes".into(),
            executable,
            provider_family: family.into(),
            args: vec![],
        }],
    }
}

fn base_planning() -> PlanningConfig {
    PlanningConfig {
        enabled: true,
        max_calls_per_event: 1,
        allow_independent_second_opinion: false,
        max_calls_per_session_per_day: 4,
        max_concurrent_calls: 1,
        timeout_seconds: 2,
        max_output_bytes: 8_192,
        max_snapshot_bytes: 4_096,
        allow_unknown_provider_family: false,
        planner_priority: vec![
            "claude".into(),
            "opencode".into(),
            "hermes".into(),
            "pi".into(),
            "codex".into(),
        ],
        ..PlanningConfig::default()
    }
}

#[test]
fn redacts_secrets_signed_urls_cookies_and_environment() {
    let source = concat!(
        "Authorization: Bearer sk-test_abcdefghijklmnopqrstuvwxyz012345\n",
        "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789\n",
        "password=hunter2secret\n",
        "cookie=sessioncookievalue\n",
        "postgres://alice:swordfish@example.invalid/db\n",
        "https://example.invalid/file?X-Amz-Signature=abcdef&safe=value\n",
        "-----BEGIN PRIVATE KEY-----\nFAKESECRET\n-----END PRIVATE KEY-----\n",
        "MY_INTERNAL_TOKEN=custom-secret-value\n",
    );
    let (redacted, report) = redact_text(source, &["MY_INTERNAL_TOKEN".into()]);
    assert!(!redacted.contains("abcdefghijklmnopqrstuvwxyz012345"));
    assert!(!redacted.contains("hunter2secret"));
    assert!(!redacted.contains("swordfish"));
    assert!(!redacted.contains("abcdef"));
    assert!(!redacted.contains("sessioncookievalue"));
    assert!(!redacted.contains("FAKESECRET"));
    assert!(!redacted.contains("custom-secret-value"));
    assert!(redacted.contains("safe=value"));
    assert!(report.replacement_count >= 6);
    assert!(report.categories.contains("authorization_header"));
    assert!(report.categories.contains("signed_url"));

    let json = serde_json::json!({
        "session_id": "not-secret-id",
        "api_key": "very-secret-key",
        "nested": [{"cookie": "cookie-value", "message": "hello"}],
        "HOME": "/home/user",
        "PATH": "/usr/bin",
    });
    let (redacted_json, json_report) = redact_json(&json, &[]);
    assert_eq!(redacted_json["api_key"], "<REDACTED:FIELD>");
    assert_eq!(redacted_json["nested"][0]["cookie"], "<REDACTED:FIELD>");
    assert_eq!(redacted_json["session_id"], "not-secret-id");
    assert!(json_report.replacement_count >= 2);

    let (normal, empty) = redact_text(
        "let status = 503; const id = '123e4567-e89b-12d3-a456-426614174000';",
        &[],
    );
    assert_eq!(
        normal,
        "let status = 503; const id = '123e4567-e89b-12d3-a456-426614174000';"
    );
    assert_eq!(empty.replacement_count, 0);
}

#[test]
fn snapshots_are_bounded_and_redacted_before_planner_use() {
    let mut input = SnapshotBuildInput {
        snapshot_id: "snap-1".into(),
        created_at: "2026-07-11T10:00:00Z".into(),
        watcher_id: "watcher-1".into(),
        watcher_state: "PLANNING".into(),
        evidence_fingerprint: "0123456789abcdef0123456789abcdef".into(),
        mux_kind: "tmux".into(),
        pane_id: "%7".into(),
        process_pid: 4242,
        process_start_time: "2026-07-11T09:00:00Z".into(),
        identity_hash: "0123456789abcdef0123456789abcdef".into(),
        agent_id: Some("codex".into()),
        provider_family: Some("openai".into()),
        failed_provider_family: "openai".into(),
        terminal_text: Some(format!(
            "Authorization: Bearer sk-ant-abcdefghijklmnopqrstuvwxyz\n{}",
            "x".repeat(80_000)
        )),
        observations: vec![SnapshotObservation {
            event_id: "evt-1".into(),
            category: "capacity_block".into(),
            source_kind: "screen_detection".into(),
            confidence: 0.9,
            summary: "password=hunter2secret seen".into(),
            observed_at: "2026-07-11T10:00:00Z".into(),
        }],
        allowed_actions: vec![
            "WAIT_DURATION".into(),
            "CAPTURE".into(),
            "CHECK_STATUS".into(),
            "SEND_TEXT".into(),
        ],
        max_snapshot_bytes: 4_096,
        extra_secret_names: vec![],
    };
    let snapshot = build_redacted_snapshot(input.clone()).expect("bounded snapshot");
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    assert!(encoded.len() <= 4_096);
    let text = serde_json::to_string(&snapshot).unwrap();
    assert!(!text.contains("abcdefghijklmnopqrstuvwxyz"));
    assert!(!text.contains("hunter2secret"));
    assert!(snapshot.redaction.performed);
    assert!(!snapshot.redaction.raw_evidence_included);
    assert!(snapshot.redaction.replacement_count > 0);

    input.max_snapshot_bytes = 200;
    assert!(build_redacted_snapshot(input).is_err());
}

#[test]
fn anthropic_failure_only_selects_different_family_planners() {
    let planning = base_planning();
    let candidates = vec![
        PlannerCapability {
            id: "claude".into(),
            executable: PathBuf::from("/bin/true"),
            configured_family: "anthropic".into(),
            resolved_family: "anthropic".into(),
            available: true,
            unsafe_mode: false,
        },
        PlannerCapability {
            id: "opencode".into(),
            executable: PathBuf::from("/bin/true"),
            configured_family: "unknown".into(),
            resolved_family: "anthropic".into(),
            available: true,
            unsafe_mode: false,
        },
        PlannerCapability {
            id: "hermes".into(),
            executable: PathBuf::from("/bin/true"),
            configured_family: "unknown".into(),
            resolved_family: "openai".into(),
            available: true,
            unsafe_mode: false,
        },
    ];
    let eligible = resolve_eligible_planners(&planning, "anthropic", &candidates);
    assert_eq!(
        eligible.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
        vec!["hermes"]
    );
}

#[test]
fn openai_failure_excludes_openai_backed_pi() {
    let planning = base_planning();
    let candidates = vec![
        PlannerCapability {
            id: "pi".into(),
            executable: PathBuf::from("/bin/true"),
            configured_family: "unknown".into(),
            resolved_family: "openai".into(),
            available: true,
            unsafe_mode: false,
        },
        PlannerCapability {
            id: "claude".into(),
            executable: PathBuf::from("/bin/true"),
            configured_family: "anthropic".into(),
            resolved_family: "anthropic".into(),
            available: true,
            unsafe_mode: false,
        },
    ];
    let eligible = resolve_eligible_planners(&planning, "openai", &candidates);
    assert_eq!(
        eligible.iter().map(|p| p.id.as_str()).collect::<Vec<_>>(),
        vec!["claude"]
    );
}

#[test]
fn unknown_provider_family_is_ineligible_by_default() {
    let planning = base_planning();
    let candidates = vec![PlannerCapability {
        id: "hermes".into(),
        executable: PathBuf::from("/bin/true"),
        configured_family: "unknown".into(),
        resolved_family: "unknown".into(),
        available: true,
        unsafe_mode: false,
    }];
    assert!(resolve_eligible_planners(&planning, "anthropic", &candidates).is_empty());

    let mut allow = planning.clone();
    allow.allow_unknown_provider_family = true;
    assert_eq!(
        resolve_eligible_planners(&allow, "anthropic", &candidates)[0].id,
        "hermes"
    );
}

#[test]
fn unsafe_mode_planners_are_denied() {
    let planning = base_planning();
    let candidates = vec![PlannerCapability {
        id: "hermes".into(),
        executable: PathBuf::from("/bin/true"),
        configured_family: "openai".into(),
        resolved_family: "openai".into(),
        available: true,
        unsafe_mode: true,
    }];
    assert!(resolve_eligible_planners(&planning, "anthropic", &candidates).is_empty());
}

#[test]
fn no_independent_planner_returns_human_required() {
    let planning = base_planning();
    let router = PlannerRouter::new(planning);
    let outcome = router.select("anthropic", &[]);
    assert!(outcome.eligible.is_empty());
    assert!(outcome.human_required);
}

#[test]
fn planner_subprocess_uses_minimal_environment() {
    let dir = tempdir().unwrap();
    let script = write_executable(dir.path(), "envdump.sh", "#!/bin/sh\nenv | sort\n");
    let result = run_planner_process(&PlannerProcessRequest {
        executable: script,
        args: vec![],
        cwd: dir.path().to_path_buf(),
        stdin: b"".to_vec(),
        timeout: Duration::from_secs(2),
        max_output_bytes: 8_192,
        extra_env: BTreeMap::from([("PLANNER_AUTH".into(), "token-value".into())]),
    })
    .expect("env dump");
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(stdout.contains("PLANNER_AUTH=token-value"));
    assert!(!stdout.contains("HOME="));
    assert!(!stdout.contains("PATH="));
    assert!(!stdout.contains("SECRET_LEAK="));
    // Parent may have SECRET_LEAK; child must not inherit it.
    assert!(
        std::env::var_os("PATH").is_some(),
        "test parent still has PATH"
    );
}

#[test]
fn planner_timeout_and_huge_output_kill_process_tree() {
    let dir = tempdir().unwrap();
    let sleeper = write_executable(
        dir.path(),
        "sleeper.sh",
        "#!/bin/sh\ntrap '' TERM\n(sleep 30)&\nsleep 30\n",
    );
    let started = Instant::now();
    let err = run_planner_process(&PlannerProcessRequest {
        executable: sleeper.clone(),
        args: vec![],
        cwd: dir.path().to_path_buf(),
        stdin: Vec::new(),
        timeout: Duration::from_millis(200),
        max_output_bytes: 1_024,
        extra_env: BTreeMap::new(),
    })
    .expect_err("timeout");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(err.is_timeout() || err.is_output_limit());
    verify_process_gone(&sleeper).expect("timeout must kill sleeper tree");

    let huge = write_executable(
        dir.path(),
        "huge.sh",
        "#!/bin/sh\nwhile true; do printf 'A%.0s' $(seq 1 1000); done\n",
    );
    let err = run_planner_process(&PlannerProcessRequest {
        executable: huge.clone(),
        args: vec![],
        cwd: dir.path().to_path_buf(),
        stdin: Vec::new(),
        timeout: Duration::from_secs(2),
        max_output_bytes: 512,
        extra_env: BTreeMap::new(),
    })
    .expect_err("output capped");
    assert!(err.is_output_limit() || err.is_timeout());
    verify_process_gone(&huge).expect("output limit must kill huge tree");
}

#[test]
fn strict_json_rejects_duplicates_unknown_fields_and_hostile_fixture() {
    assert!(decode_recovery_plan(VALID_PLAN).is_ok());
    assert!(decode_recovery_plan(INVALID_PLAN).is_err());
    assert!(decode_recovery_plan("not-json").is_err());
    assert!(
        decode_recovery_plan("{\"schema_version\":\"1.0\",\"schema_version\":\"1.0\"}").is_err()
    );

    let mut unknown = VALID_PLAN.to_owned();
    unknown = unknown.replacen('{', "{\"surprise\":true,", 1);
    assert!(decode_recovery_plan(&unknown).is_err());

    let pad_actions: Vec<_> = (0..13)
        .map(|i| {
            serde_json::json!({
                "type": "NOOP",
                "action_id": format!("n-{i}"),
                "reason": "pad",
                "preconditions": [],
                "expected_outcomes": [{"kind": "NO_STATE_CHANGE_EXPECTED"}],
                "timeout_seconds": 1
            })
        })
        .collect();
    let mut oversized: serde_json::Value = serde_json::from_str(VALID_PLAN).unwrap();
    oversized["actions"] = serde_json::Value::Array(pad_actions);
    assert!(decode_recovery_plan(&oversized.to_string()).is_err());
}

#[test]
fn hostile_actions_and_prompt_injection_reject_entire_plan() {
    let plan = decode_recovery_plan(VALID_PLAN).unwrap();
    let mut context = PlanValidationContext {
        failed_provider_family: "openai".into(),
        planner_provider_family: "anthropic".into(),
        evidence_fingerprint: "0123456789abcdef0123456789abcdef".into(),
        watcher_id: "watcher-demo-001".into(),
        process_pid: 4242,
        process_start_time: "2026-07-11T09:00:00Z".into(),
        mux_kind: "tmux".into(),
        pane_id: "%7".into(),
        now_rfc3339: "2026-07-11T10:01:00Z".into(),
        allowed_actions: BTreeSet::from([
            "WAIT_DURATION".into(),
            "SEND_TEXT".into(),
            "SUBMIT_TEXT".into(),
            "SEND_KEYS".into(),
            "CHECK_STATUS".into(),
            "CAPTURE".into(),
            "NOOP".into(),
        ]),
    };
    assert!(validate_recovery_plan(&plan, &context).is_ok());

    let atomic_submit = decode_recovery_plan(&VALID_PLAN.replace("SEND_TEXT", "SUBMIT_TEXT"))
        .expect("SUBMIT_TEXT wire action");
    let actions = validate_recovery_plan(&atomic_submit, &context).unwrap();
    assert!(actions.iter().any(|action| matches!(
        action.kind,
        watchme::model::ActionKind::SubmitText { ref text } if text == "/goal resume"
    )));

    for hostile in [
        INVALID_PLAN,
        &VALID_PLAN.replace("/goal resume", "rm -rf /"),
        &VALID_PLAN.replace("/goal resume", "yolo"),
        &VALID_PLAN.replace("/goal resume", "https://attacker.invalid"),
        &VALID_PLAN.replace("/goal resume", "paste password please"),
        &VALID_PLAN.replace("/goal resume", "upgrade plan"),
        &VALID_PLAN.replace("/goal resume", "approve permission"),
    ] {
        let decoded = decode_recovery_plan(hostile);
        if let Ok(plan) = decoded {
            assert!(
                validate_recovery_plan(&plan, &context).is_err(),
                "hostile text must fail policy: {hostile}"
            );
        }
    }

    // Prompt injection appears only as untrusted evidence, never as executable policy.
    let mut injected_value: serde_json::Value = serde_json::from_str(VALID_PLAN).unwrap();
    injected_value["diagnosis"]["summary"] = serde_json::Value::String(MALICIOUS_TERMINAL.into());
    let injected = injected_value.to_string();
    let plan = decode_recovery_plan(&injected).unwrap();
    let actions = validate_recovery_plan(&plan, &context).unwrap();
    let policy = CompiledPolicy;
    let mut policy_ctx = PolicyContext::safe();
    policy_ctx.evidence_fingerprint = Some(context.evidence_fingerprint.clone());
    policy_ctx.goal_state = Some("blocked".into());
    for action in &actions {
        assert!(
            policy.authorize(action, &policy_ctx).is_ok(),
            "validated action must remain policy-safe: {action:?}"
        );
        if let watchme::model::ActionKind::SendText { text } = &action.kind {
            assert!(!text.contains("rm -rf"));
            assert!(!text.contains("yolo"));
            assert!(!text.contains("SHELL"));
        }
    }

    context.evidence_fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    assert!(
        validate_recovery_plan(&plan, &context).is_err(),
        "stale evidence fingerprint cancels plan"
    );
}

#[test]
fn request_plan_rejects_mismatched_evidence_fingerprint() {
    let dir = tempdir().unwrap();
    // Self-consistent hostile plan: identity/evidence agree with each other, but not
    // with the trusted snapshot. Without snapshot-bound validation this must pass.
    let plan: serde_json::Value = serde_json::from_str(&with_future_validity(&plan_with_families(
        "openai",
        "anthropic",
    )))
    .unwrap();
    let forged = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let plan_text = plan
        .to_string()
        .replace("0123456789abcdef0123456789abcdef", forged);
    let echo = write_plan_echo(dir.path(), "bad-evidence.sh", &plan_text);
    let broker = PlannerBroker::new(base_planning(), SecurityConfig::default());
    assert!(
        broker
            .request_plan(broker_request(
                echo,
                "anthropic",
                "openai",
                trusted_snapshot(&default_allowed_actions()),
                "evt-evidence",
            ))
            .is_err(),
        "plan evidence_fingerprint must be checked against trusted snapshot"
    );
}

#[test]
fn request_plan_rejects_mismatched_watcher_or_target() {
    let dir = tempdir().unwrap();
    let mut plan: serde_json::Value = serde_json::from_str(&with_future_validity(
        &plan_with_families("openai", "anthropic"),
    ))
    .unwrap();
    plan["target"]["watcher_id"] = serde_json::json!("watcher-attacker");
    plan["target"]["process_pid"] = serde_json::json!(9999);
    let echo = write_plan_echo(dir.path(), "bad-target.sh", &plan.to_string());
    let broker = PlannerBroker::new(base_planning(), SecurityConfig::default());
    assert!(
        broker
            .request_plan(broker_request(
                echo,
                "anthropic",
                "openai",
                trusted_snapshot(&default_allowed_actions()),
                "evt-target",
            ))
            .is_err(),
        "mismatched watcher/target must be rejected by request_plan"
    );
}

#[test]
fn request_plan_rejects_expired_plan_using_wall_clock() {
    let dir = tempdir().unwrap();
    // Fixture valid_until is 2026-07-11; wall clock is later. Old broker used
    // plan.generated_at as "now", which made expiry checks tautological.
    let echo = write_plan_echo(
        dir.path(),
        "expired-plan.sh",
        &plan_with_families("openai", "anthropic"),
    );
    let broker = PlannerBroker::new(base_planning(), SecurityConfig::default());
    assert!(
        broker
            .request_plan(broker_request(
                echo,
                "anthropic",
                "openai",
                trusted_snapshot(&default_allowed_actions()),
                "evt-expired",
            ))
            .is_err(),
        "expired plan must be rejected against trusted wall clock"
    );
}

#[test]
fn request_plan_restricts_actions_to_snapshot_allowlist() {
    let dir = tempdir().unwrap();
    let plan = with_future_validity(&plan_with_families("openai", "anthropic"));
    let echo = write_plan_echo(dir.path(), "restricted-actions.sh", &plan);
    let broker = PlannerBroker::new(base_planning(), SecurityConfig::default());
    // Snapshot omits SEND_TEXT/SEND_KEYS that the fixture plan includes.
    let snapshot = trusted_snapshot(&["WAIT_DURATION", "CAPTURE", "CHECK_STATUS", "NOOP"]);
    assert!(
        broker
            .request_plan(broker_request(
                echo,
                "anthropic",
                "openai",
                snapshot,
                "evt-allowlist",
            ))
            .is_err(),
        "actions outside snapshot allowed_actions must be rejected"
    );
}

#[test]
fn failed_planner_attempt_consumes_per_event_budget() {
    let dir = tempdir().unwrap();
    let echo = write_plan_echo(dir.path(), "fail-budget.sh", INVALID_PLAN);
    let mut planning = base_planning();
    planning.max_calls_per_event = 1;
    let broker = PlannerBroker::new(planning, SecurityConfig::default());
    let request = broker_request(
        echo,
        "anthropic",
        "openai",
        trusted_snapshot(&default_allowed_actions()),
        "evt-budget-fail",
    );
    assert!(broker.request_plan(request.clone()).is_err());
    let second = broker.request_plan(request);
    assert!(
        second.is_err(),
        "failed attempt must consume max_calls_per_event"
    );
    assert!(
        second
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("per-event"),
        "second call should hit per-event budget, got: {second:?}"
    );
}

#[test]
fn budgets_enforce_event_session_and_concurrency_limits() {
    let dir = tempdir().unwrap();
    let plan = with_future_validity(&plan_with_families("anthropic", "openai"));
    let echo = write_plan_echo(dir.path(), "echo-plan.sh", &plan);
    let mut planning = base_planning();
    planning.max_calls_per_event = 1;
    planning.max_calls_per_session_per_day = 2;
    planning.max_concurrent_calls = 1;
    planning.planners = BTreeMap::from([(
        "hermes".into(),
        PlannerConfig {
            enabled: true,
            executable: echo.to_string_lossy().into_owned(),
            provider_family: "openai".into(),
            provider: "openai".into(),
            model: "test".into(),
        },
    )]);
    planning.planner_priority = vec!["hermes".into()];

    let security = SecurityConfig::default();
    let broker = PlannerBroker::new(planning, security);
    let snapshot = trusted_snapshot(&default_allowed_actions());
    let request = PlannerRequest {
        session_id: "session-a".into(),
        event_id: "event-1".into(),
        failed_provider_family: "anthropic".into(),
        snapshot_json: snapshot.clone(),
        day_key: "2026-07-11".into(),
        resolved: vec![ResolvedPlanner {
            id: "hermes".into(),
            executable: echo.clone(),
            provider_family: "openai".into(),
            args: vec![],
        }],
    };

    let first = broker.request_plan(request.clone()).expect("first call");
    assert!(!first.actions.is_empty());
    assert!(broker.request_plan(request.clone()).is_err());

    let mut second_event = request.clone();
    second_event.event_id = "event-2".into();
    assert!(broker.request_plan(second_event.clone()).is_ok());
    assert!(broker.request_plan(second_event).is_err());

    // Concurrency: hold one slot while another request is denied.
    let mut planning = base_planning();
    planning.max_concurrent_calls = 1;
    planning.max_calls_per_event = 10;
    planning.max_calls_per_session_per_day = 10;
    let blocker = write_executable(
        dir.path(),
        "block.sh",
        "#!/bin/sh\nsleep 1\nprintf '%s\\n' '{\"schema_version\":\"1.0\"}'\n",
    );
    planning.planners.insert(
        "hermes".into(),
        PlannerConfig {
            enabled: true,
            executable: blocker.to_string_lossy().into_owned(),
            provider_family: "openai".into(),
            provider: "openai".into(),
            model: "test".into(),
        },
    );
    planning.planner_priority = vec!["hermes".into()];
    let broker = Arc::new(PlannerBroker::new(planning, SecurityConfig::default()));
    let barrier = Arc::new(Barrier::new(2));
    let slow_request = PlannerRequest {
        session_id: "session-b".into(),
        event_id: "event-slow".into(),
        failed_provider_family: "anthropic".into(),
        snapshot_json: snapshot,
        day_key: "2026-07-11".into(),
        resolved: vec![ResolvedPlanner {
            id: "hermes".into(),
            executable: blocker.clone(),
            provider_family: "openai".into(),
            args: vec![],
        }],
    };
    let broker_a = Arc::clone(&broker);
    let barrier_a = Arc::clone(&barrier);
    let slow = slow_request.clone();
    let handle = thread::spawn(move || {
        barrier_a.wait();
        broker_a.request_plan(slow)
    });
    barrier.wait();
    thread::sleep(Duration::from_millis(50));
    let denied = broker.request_plan(PlannerRequest {
        event_id: "event-fast".into(),
        ..slow_request
    });
    assert!(denied.is_err());
    let _ = handle.join().unwrap();
}

#[test]
fn optional_independent_fallback_cannot_override_policy() {
    let dir = tempdir().unwrap();
    let hostile = write_plan_echo(dir.path(), "hostile-plan.sh", INVALID_PLAN);
    let safe_plan = with_future_validity(&plan_with_families("xai", "anthropic"));
    let safe = write_plan_echo(dir.path(), "safe-plan.sh", &safe_plan);
    let mut planning = base_planning();
    planning.allow_independent_second_opinion = true;
    planning.max_calls_per_event = 2;
    planning.max_calls_per_session_per_day = 4;
    planning.planners = BTreeMap::from([
        (
            "hermes".into(),
            PlannerConfig {
                enabled: true,
                executable: hostile.to_string_lossy().into_owned(),
                provider_family: "openai".into(),
                provider: "openai".into(),
                model: "test".into(),
            },
        ),
        (
            "claude".into(),
            PlannerConfig {
                enabled: true,
                executable: safe.to_string_lossy().into_owned(),
                provider_family: "anthropic".into(),
                provider: "anthropic".into(),
                model: "test".into(),
            },
        ),
    ]);
    planning.planner_priority = vec!["hermes".into(), "claude".into()];
    let broker = PlannerBroker::new(planning, SecurityConfig::default());
    let request = PlannerRequest {
        session_id: "session-c".into(),
        event_id: "event-fallback".into(),
        failed_provider_family: "xai".into(),
        snapshot_json: trusted_snapshot(&default_allowed_actions()),
        day_key: "2026-07-11".into(),
        resolved: vec![
            ResolvedPlanner {
                id: "hermes".into(),
                executable: hostile,
                provider_family: "openai".into(),
                args: vec![],
            },
            ResolvedPlanner {
                id: "claude".into(),
                executable: safe,
                provider_family: "anthropic".into(),
                args: vec![],
            },
        ],
    };
    let plan = broker
        .request_plan(request)
        .expect("fallback to independent");
    assert_eq!(plan.planner_id, "claude");
    assert!(plan.used_second_opinion);
    let policy = CompiledPolicy;
    let mut ctx = PolicyContext::safe();
    ctx.evidence_fingerprint = Some("0123456789abcdef0123456789abcdef".into());
    ctx.goal_state = Some("blocked".into());
    ctx.failed_provider_family = Some("xai".into());
    ctx.planner_provider_family = Some("anthropic".into());
    for action in &plan.actions {
        assert!(policy.authorize(action, &ctx).is_ok());
    }
}

#[test]
fn router_uses_actual_resolved_family_not_executable_name() {
    let mut planning = base_planning();
    planning.planners.insert(
        "pi".into(),
        PlannerConfig {
            enabled: true,
            executable: "pi".into(),
            provider_family: "unknown".into(),
            provider: String::new(),
            model: String::new(),
        },
    );
    let router = PlannerRouter::new(planning);
    let probed = router.resolve_from_probes(
        "openai",
        &[PlannerCapability {
            id: "pi".into(),
            executable: PathBuf::from("/bin/true"),
            configured_family: "unknown".into(),
            resolved_family: "openai".into(),
            available: true,
            unsafe_mode: false,
        }],
    );
    assert!(probed.eligible.is_empty());
}

#[test]
fn recovery_plan_type_is_exported_for_callers() {
    let plan: RecoveryPlan = decode_recovery_plan(VALID_PLAN).unwrap();
    assert_eq!(plan.plan_id, "plan-demo-001");
    assert_eq!(plan.actions.len(), 4);
}

#[test]
fn child_environment_helper_is_minimal() {
    let env = watchme::planner::process::minimal_child_environment(&[("A".into(), "1".into())]);
    let keys: BTreeSet<_> = env.keys().cloned().collect();
    assert_eq!(
        keys,
        BTreeSet::from(["A".into(), "LANG".into(), "LC_ALL".into()])
    );
    assert_eq!(env.get("A").map(String::as_str), Some("1"));
    assert_eq!(env.get("LANG").map(String::as_str), Some("C"));
}
