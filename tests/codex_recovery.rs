use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tempfile::tempdir;
use watchme::agents::codex::{
    CodexRecipes, CodexRecoveryPlan, CodexSessionReference, ProbedCodexSource,
    capacity_backoff_seconds, classify_goal_snapshot, correlated_rollout_event, mark_resume_sent,
    normalize_structured_source, observe_codex_event, parse_fixture_record,
    probe_structured_source, resume_candidate_event, structured_goal_event,
    structured_value_from_snapshot, trusted_goal_progress_event,
};
use watchme::daemon::{GenericObserver, Observer};
use watchme::model::{
    ActionKind, Condition, Event, EventCategory, EventSource, PolicyHint, ProcessIdentity,
    SourceKind, TargetIdentity, WatcherLifecycle, WatcherState,
};
use watchme::policy::{CompiledPolicy, PolicyContext};
use watchme::recovery::engine::RecipeProvider;

fn fixtures_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/codex-goal-blocked-samples.jsonl")
}

fn load_fixture_lines() -> Vec<String> {
    fs::read_to_string(fixtures_path())
        .expect("codex fixtures")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

#[test]
fn fixture_classifications_match_expected_recovery_plans() {
    let lines = load_fixture_lines();
    assert_eq!(lines.len(), 5);
    let expected = [
        ("goal_active", CodexRecoveryPlan::None),
        (
            "goal_blocked_capacity",
            CodexRecoveryPlan::WaitThenGoalResume,
        ),
        (
            "goal_blocked_waiting_approval",
            CodexRecoveryPlan::HumanRequired,
        ),
        ("goal_completed", CodexRecoveryPlan::None),
        (
            "screen_claims_blocked_but_structured_active",
            CodexRecoveryPlan::None,
        ),
    ];
    for (line, (name, plan)) in lines.iter().zip(expected) {
        let record = parse_fixture_record(line).expect(name);
        assert_eq!(record.fixture, name);
        assert_eq!(classify_goal_snapshot(&record.snapshot), plan);
        assert_eq!(record.expected_action, plan);
    }
}

#[test]
fn app_server_events_normalize_ahead_of_screen_and_rollout_fallbacks() {
    let app_server = serde_json::json!({
        "source": "app_server",
        "thread_id": "thr_demo",
        "goal": {"text": "Finish the refactor", "status": "blocked"},
        "runtime_status": {"type": "idle", "active_flags": []},
        "last_error": {"category": "capacity_block", "terminal": true}
    });
    let rollout = serde_json::json!({
        "type": "codex.rollout.goal",
        "thread_id": "thr_demo",
        "goal": {"text": "Finish the refactor", "status": "blocked"},
        "runtime_status": {"type": "idle", "active_flags": []},
        "last_error": {"category": "capacity_block", "terminal": true}
    });
    let from_app = normalize_structured_source(&app_server, SourceKind::TypedApi)
        .expect("app server snapshot");
    let from_rollout =
        normalize_structured_source(&rollout, SourceKind::StructuredLog).expect("rollout snapshot");
    assert_eq!(
        classify_goal_snapshot(&from_app),
        CodexRecoveryPlan::WaitThenGoalResume
    );
    assert_eq!(
        classify_goal_snapshot(&from_rollout),
        CodexRecoveryPlan::WaitThenGoalResume
    );
    assert!(
        normalize_structured_source(
            &serde_json::json!({
                "screen_tail": "Goal status: blocked",
                "thread_id": "thr_demo"
            }),
            SourceKind::ScreenDetection
        )
        .is_none(),
        "screen-only claims are not structured goal evidence"
    );
}

#[test]
fn runtime_waiting_on_approval_and_auth_never_resume_even_when_goal_is_blocked() {
    let approval = parse_fixture_record(
        r#"{"fixture":"x","thread_id":"t","goal":{"text":"g","status":"blocked"},"runtime_status":{"type":"active","active_flags":["waitingOnApproval"]},"expected_action":"human_required"}"#,
    )
    .unwrap();
    assert_eq!(
        classify_goal_snapshot(&approval.snapshot),
        CodexRecoveryPlan::HumanRequired
    );

    let auth = serde_json::json!({
        "thread_id": "t",
        "goal": {"status": "blocked"},
        "runtime_status": {"type": "idle", "active_flags": []},
        "last_error": {"category": "auth", "terminal": true}
    });
    let snap = normalize_structured_source(&auth, SourceKind::TypedApi).unwrap();
    assert_eq!(
        classify_goal_snapshot(&snap),
        CodexRecoveryPlan::HumanRequired
    );

    let completed = parse_fixture_record(
        r#"{"fixture":"x","thread_id":"t","goal":{"text":"g","status":"completed"},"runtime_status":{"type":"idle","active_flags":[]},"expected_action":"none"}"#,
    )
    .unwrap();
    assert_eq!(
        classify_goal_snapshot(&completed.snapshot),
        CodexRecoveryPlan::None
    );

    let no_goal = serde_json::json!({
        "thread_id": "t",
        "runtime_status": {"type": "idle", "active_flags": []},
        "last_error": {"category": "capacity_block", "terminal": true}
    });
    let snap = normalize_structured_source(&no_goal, SourceKind::TypedApi).unwrap();
    assert_eq!(classify_goal_snapshot(&snap), CodexRecoveryPlan::None);
}

#[test]
fn screen_blocked_text_is_ignored_when_structured_goal_is_active() {
    let line = load_fixture_lines()
        .into_iter()
        .find(|line| line.contains("screen_claims_blocked_but_structured_active"))
        .unwrap();
    let record = parse_fixture_record(&line).unwrap();
    assert!(
        record
            .snapshot
            .screen_tail
            .as_deref()
            .is_some_and(|tail| tail.to_ascii_lowercase().contains("blocked"))
    );
    assert_eq!(
        classify_goal_snapshot(&record.snapshot),
        CodexRecoveryPlan::None
    );
    let mut watcher = codex_watcher(EventCategory::Idle, PolicyHint::ObserveOnly, false);
    let event = structured_goal_event(&watcher, &record.snapshot, SourceKind::TypedApi).unwrap();
    assert_ne!(event.category, EventCategory::BlockedGoal);
    watcher.last_observation = Some(event);
    assert!(CodexRecipes::default().action_for(&watcher).is_none());
}

#[test]
fn partial_and_rotated_rollout_files_are_not_evidence() {
    let temp = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let partial = temp.path().join("partial.jsonl");
    fs::write(
        &partial,
        r#"{"type":"codex.rollout.goal","thread_id":"thr_demo","goal":{"status":"blocked"}"#,
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).unwrap();
    let mut watcher = codex_watcher(EventCategory::Idle, PolicyHint::ObserveOnly, false);
    assert!(correlated_rollout_event(&watcher, &partial, "thr_demo").is_none());

    let complete = temp.path().join("rollout.jsonl");
    fs::write(
        &complete,
        concat!(
            r#"{"type":"codex.rollout.goal","thread_id":"thr_demo","goal":{"text":"Finish the refactor","status":"blocked"},"runtime_status":{"type":"idle","active_flags":[]},"last_error":{"category":"capacity_block","terminal":true}}"#,
            "\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&complete, fs::Permissions::from_mode(0o600)).unwrap();
    let event = correlated_rollout_event(&watcher, &complete, "thr_demo").expect("complete line");
    assert_eq!(event.category, EventCategory::CapacityBlock);
    assert_eq!(event.policy_hint, PolicyHint::WaitAllowed);

    // Replacement at the same path must invalidate prior correlation.
    fs::remove_file(&complete).unwrap();
    fs::write(
        &complete,
        concat!(
            r#"{"type":"codex.rollout.goal","thread_id":"thr_demo","goal":{"text":"Finish the refactor","status":"blocked"},"runtime_status":{"type":"idle","active_flags":[]},"last_error":{"category":"capacity_block","terminal":true}}"#,
            "\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&complete, fs::Permissions::from_mode(0o600)).unwrap();
    watcher.last_observation = Some(event);
    assert!(
        correlated_rollout_event(&watcher, &complete, "thr_demo").is_none()
            || correlated_rollout_event(&watcher, &complete, "thr_other").is_none()
    );
    assert!(correlated_rollout_event(&watcher, &complete, "thr_other").is_none());
}

#[test]
fn capacity_block_schedules_jittered_wait_before_any_goal_resume() {
    let line = load_fixture_lines()
        .into_iter()
        .find(|line| line.contains("goal_blocked_capacity"))
        .unwrap();
    let record = parse_fixture_record(&line).unwrap();
    let mut watcher = codex_watcher(EventCategory::Idle, PolicyHint::ObserveOnly, false);
    watcher.revision = 2;
    let event =
        structured_goal_event(&watcher, &record.snapshot, SourceKind::TypedApi).expect("event");
    assert_eq!(event.category, EventCategory::CapacityBlock);
    assert_eq!(event.policy_hint, PolicyHint::WaitAllowed);
    assert_eq!(event.metadata["goal_state"], "blocked");
    watcher.last_observation = Some(event);
    let action = CodexRecipes::default().action_for(&watcher).unwrap();
    assert_eq!(action.action_id, "codex.capacity_backoff_wait");
    let fingerprint = action_fingerprint(&action);
    match action.kind {
        ActionKind::WaitDuration { duration_seconds } => {
            assert!(duration_seconds >= 1);
            assert!(duration_seconds <= 300);
            assert_eq!(
                duration_seconds,
                capacity_backoff_seconds(2, hash64(&fingerprint), 300).max(1)
            );
        }
        other => panic!("expected wait, got {other:?}"),
    }
}

#[test]
fn resume_candidate_and_recipe_send_literal_goal_resume_exactly_once_per_fingerprint() {
    let mut watcher = codex_watcher(EventCategory::CapacityBlock, PolicyHint::WaitAllowed, true);
    watcher.lifecycle = WatcherLifecycle::Waiting {
        until_unix_ms: 1,
        reason: "capacity backoff".into(),
    };
    let event = watcher.last_observation.as_mut().unwrap();
    event.metadata.insert(
        "goal_state".into(),
        serde_json::Value::String("blocked".into()),
    );
    event
        .metadata
        .insert("codex_capacity_block".into(), serde_json::Value::Bool(true));
    event.metadata.insert(
        "codex_thread_id".into(),
        serde_json::Value::String("thr_demo".into()),
    );
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-12T00:05:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let candidate = resume_candidate_event(&watcher, now).expect("resume candidate");
    assert_eq!(candidate.category, EventCategory::WaitingForModel);
    assert_eq!(
        candidate.policy_hint,
        PolicyHint::DeterministicActionAllowed
    );
    assert_eq!(candidate.metadata["codex_resume"], true);
    assert_eq!(candidate.metadata["goal_state"], "blocked");

    watcher.last_observation = Some(candidate.clone());
    let action = CodexRecipes::default().action_for(&watcher).unwrap();
    assert_eq!(action.action_id, "codex.goal_resume_once");
    assert_eq!(
        action.kind,
        ActionKind::SendText {
            text: "/goal resume".into()
        }
    );
    assert!(
        action
            .preconditions
            .iter()
            .any(|c| c.kind == "COMPOSER_EMPTY")
    );
    assert!(
        action
            .preconditions
            .iter()
            .any(|c| c.kind == "NO_HUMAN_INTERVENTION")
    );
    assert!(action.preconditions.iter().any(|c| {
        c.kind == "GOAL_STATE_IS"
            && c.value.as_ref().and_then(serde_json::Value::as_str) == Some("blocked")
    }));
    assert_eq!(
        action.expected_outcomes,
        vec![Condition {
            kind: "GOAL_ACTIVE_OR_PURSUING".into(),
            value: None,
        }]
    );

    // After the resume fingerprint is recorded as sent, do not propose another send.
    let fingerprint = action_fingerprint(&action);
    let mut cooled = watcher.clone();
    cooled.last_observation.as_mut().unwrap().metadata.insert(
        "codex_resume_sent_fingerprint".into(),
        serde_json::Value::String(fingerprint),
    );
    assert!(CodexRecipes::default().action_for(&cooled).is_none());
}

#[test]
fn goal_resume_policy_requires_empty_composer_and_blocked_goal_state() {
    let mut watcher = codex_watcher(
        EventCategory::WaitingForModel,
        PolicyHint::DeterministicActionAllowed,
        false,
    );
    let event = watcher.last_observation.as_mut().unwrap();
    event.source = EventSource::new(SourceKind::TypedApi, "codex", "goal_resume");
    event
        .metadata
        .insert("codex_resume".into(), serde_json::Value::Bool(true));
    event.metadata.insert(
        "goal_state".into(),
        serde_json::Value::String("blocked".into()),
    );
    let action = CodexRecipes::default().action_for(&watcher).unwrap();
    let mut context = PolicyContext::safe();
    context.goal_state = Some("blocked".into());
    context.composer_empty = true;
    context.evidence_fingerprint = Some(action_fingerprint(&action));
    assert!(CompiledPolicy.authorize(&action, &context).is_ok());
    context.composer_empty = false;
    assert!(CompiledPolicy.authorize(&action, &context).is_err());
    context.composer_empty = true;
    context.goal_state = Some("active".into());
    assert!(CompiledPolicy.authorize(&action, &context).is_err());
}

#[test]
fn pursuing_verification_accepts_structured_active_or_pursuing_goal() {
    let mut watcher = codex_watcher(
        EventCategory::WaitingForModel,
        PolicyHint::DeterministicActionAllowed,
        false,
    );
    watcher.last_observation.as_mut().unwrap().metadata.insert(
        "codex_resume_session".into(),
        serde_json::Value::String("a".repeat(64)),
    );
    watcher.last_observation.as_mut().unwrap().metadata.insert(
        "codex_thread_id".into(),
        serde_json::Value::String("thr_demo".into()),
    );
    let baseline = watcher.last_observation.as_ref().unwrap().clone();
    let progress = trusted_goal_progress_event(
        &watcher,
        &baseline,
        &serde_json::json!({
            "thread_id": "thr_demo",
            "goal": {"status": "pursuing", "text": "Finish the refactor"},
            "runtime_status": {"type": "active", "active_flags": []}
        }),
        "2026-07-12T00:06:00Z",
    )
    .expect("pursuing proof");
    assert_eq!(progress.category, EventCategory::Working);
    assert_eq!(progress.metadata["goal_state"], "pursuing");
    assert_eq!(progress.metadata["codex_post_resume_progress"], true);

    assert!(
        trusted_goal_progress_event(
            &watcher,
            &baseline,
            &serde_json::json!({
                "thread_id": "thr_demo",
                "goal": {"status": "blocked"},
                "runtime_status": {"type": "idle", "active_flags": []}
            }),
            "2026-07-12T00:06:00Z",
        )
        .is_none()
    );
}

#[test]
fn recipes_never_propose_privileged_shell_or_exec_actions() {
    let line = load_fixture_lines()
        .into_iter()
        .find(|line| line.contains("goal_blocked_capacity"))
        .unwrap();
    let record = parse_fixture_record(&line).unwrap();
    let mut watcher = codex_watcher(EventCategory::Idle, PolicyHint::ObserveOnly, false);
    let event = structured_goal_event(&watcher, &record.snapshot, SourceKind::TypedApi).unwrap();
    watcher.last_observation = Some(event);
    let wait = CodexRecipes::default().action_for(&watcher).unwrap();
    assert!(matches!(wait.kind, ActionKind::WaitDuration { .. }));

    watcher.lifecycle = WatcherLifecycle::Waiting {
        until_unix_ms: 1,
        reason: "capacity backoff".into(),
    };
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-12T00:05:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    watcher.last_observation = Some(resume_candidate_event(&watcher, now).unwrap());
    let resume = CodexRecipes::default().action_for(&watcher).unwrap();
    assert!(matches!(
        resume.kind,
        ActionKind::SendText { ref text } if text == "/goal resume"
    ));
    assert!(
        !format!("{:?}", resume.kind)
            .to_ascii_lowercase()
            .contains("shell")
    );
    assert!(
        !format!("{:?}", resume.kind)
            .to_ascii_lowercase()
            .contains("exec")
    );
}

#[test]
fn human_required_capacity_lookalikes_produce_no_input_recipe() {
    for fixture in [
        "goal_blocked_waiting_approval",
        "goal_completed",
        "goal_active",
    ] {
        let line = load_fixture_lines()
            .into_iter()
            .find(|line| line.contains(fixture))
            .unwrap();
        let record = parse_fixture_record(&line).unwrap();
        let mut watcher = codex_watcher(EventCategory::Idle, PolicyHint::ObserveOnly, false);
        if let Some(event) = structured_goal_event(&watcher, &record.snapshot, SourceKind::TypedApi)
        {
            watcher.last_observation = Some(event);
            let action = CodexRecipes::default().action_for(&watcher);
            assert!(
                action.as_ref().is_none_or(|action| {
                    !matches!(
                        action.kind,
                        ActionKind::SendText { .. } | ActionKind::SendKeys { .. }
                    )
                }),
                "{fixture} must not send input"
            );
        }
    }
}

#[test]
fn app_server_probed_source_yields_trusted_progress_when_goal_active() {
    // Preferred App Server probe → post-resume verify must preserve goal.status
    // nesting. Serializing the flat CodexGoalSnapshot (as fresh_codex_progress
    // used to) must still produce a progress event when the goal is active.
    let cwd = std::env::current_dir().unwrap();
    let temp = tempfile::TempDir::new_in(&cwd).unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let snapshot_path = temp.path().join("app-server-goal.json");
    fs::write(
        &snapshot_path,
        r#"{"thread_id":"thr_demo","goal":{"text":"Finish the refactor","status":"active"},"runtime_status":{"type":"active","active_flags":[]}}"#,
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&snapshot_path, fs::Permissions::from_mode(0o600)).unwrap();

    let rollout = temp.path().join("rollout.jsonl");
    fs::write(&rollout, "").unwrap();
    #[cfg(unix)]
    fs::set_permissions(&rollout, fs::Permissions::from_mode(0o600)).unwrap();

    let mut watcher = bound_codex_watcher(temp.path(), &rollout, "thr_demo");
    watcher
        .codex_session
        .as_mut()
        .unwrap()
        .app_server_state_path = Some(snapshot_path.to_string_lossy().into());

    let probed = probe_structured_source(&watcher).expect("App Server probe");
    let ProbedCodexSource::AppServer { snapshot, .. } = probed else {
        panic!("expected App Server preferred source");
    };
    assert_eq!(snapshot.goal_status.as_deref(), Some("active"));

    let mut baseline = codex_watcher(
        EventCategory::WaitingForModel,
        PolicyHint::DeterministicActionAllowed,
        false,
    )
    .last_observation
    .unwrap();
    baseline
        .metadata
        .insert("codex_resume".into(), serde_json::Value::Bool(true));
    baseline.metadata.insert(
        "codex_thread_id".into(),
        serde_json::Value::String("thr_demo".into()),
    );
    baseline.metadata.insert(
        "codex_resume_session".into(),
        serde_json::Value::String("a".repeat(64)),
    );
    baseline.observed_at = "2026-07-12T00:05:00Z".into();

    // Mirror the App Server arm of fresh_codex_progress: rebuild nested JSON
    // (goal.status) from the flat snapshot, then verify trusted progress.
    let structured = structured_value_from_snapshot(&snapshot);
    let progress =
        trusted_goal_progress_event(&watcher, &baseline, &structured, "2026-07-12T00:06:00Z")
            .expect("App Server active goal must yield post-resume progress");
    assert_eq!(progress.category, EventCategory::Working);
    assert_eq!(progress.metadata["goal_state"], "active");
    assert_eq!(progress.metadata["codex_post_resume_progress"], true);
}

#[test]
fn capability_probe_prefers_app_server_snapshot_then_bound_rollout() {
    let cwd = std::env::current_dir().unwrap();
    let temp = tempfile::TempDir::new_in(&cwd).unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

    let snapshot = temp.path().join("app-server-goal.json");
    fs::write(
        &snapshot,
        r#"{"thread_id":"thr_demo","goal":{"text":"Finish the refactor","status":"blocked"},"runtime_status":{"type":"idle","active_flags":[]},"last_error":{"category":"capacity_block","terminal":true}}"#,
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o600)).unwrap();

    let rollout = temp.path().join("rollout.jsonl");
    fs::write(
        &rollout,
        concat!(
            r#"{"type":"codex.rollout.goal","thread_id":"thr_demo","goal":{"text":"Finish the refactor","status":"blocked"},"runtime_status":{"type":"idle","active_flags":[]},"last_error":{"category":"capacity_block","terminal":true}}"#,
            "\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&rollout, fs::Permissions::from_mode(0o600)).unwrap();

    let mut watcher = bound_codex_watcher(temp.path(), &rollout, "thr_demo");
    watcher
        .codex_session
        .as_mut()
        .unwrap()
        .app_server_state_path = Some(snapshot.to_string_lossy().into());

    let probed = probe_structured_source(&watcher).expect("probed source");
    assert!(
        probed.is_app_server(),
        "App Server / structured snapshot must win over rollout"
    );

    watcher
        .codex_session
        .as_mut()
        .unwrap()
        .app_server_state_path = None;
    let probed = probe_structured_source(&watcher).expect("rollout fallback");
    assert!(probed.is_rollout());

    // Ambiguous / rotated binding fails closed.
    fs::remove_file(&rollout).unwrap();
    fs::write(
        &rollout,
        concat!(
            r#"{"type":"codex.rollout.goal","thread_id":"thr_demo","goal":{"status":"blocked"},"runtime_status":{"type":"idle","active_flags":[]},"last_error":{"category":"capacity_block","terminal":true}}"#,
            "\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&rollout, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        probe_structured_source(&watcher).is_none(),
        "rotated rollout without matching binding must fail closed"
    );
}

#[test]
fn observe_codex_emits_capacity_block_then_resume_candidate_and_progress() {
    let cwd = std::env::current_dir().unwrap();
    let temp = tempfile::TempDir::new_in(&cwd).unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let rollout = temp.path().join("rollout.jsonl");
    fs::write(
        &rollout,
        concat!(
            r#"{"type":"codex.rollout.goal","thread_id":"thr_demo","goal":{"text":"Finish the refactor","status":"blocked"},"runtime_status":{"type":"idle","active_flags":[]},"last_error":{"category":"capacity_block","terminal":true}}"#,
            "\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&rollout, fs::Permissions::from_mode(0o600)).unwrap();

    let mut watcher = bound_codex_watcher(temp.path(), &rollout, "thr_demo");
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-12T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let blocked = observe_codex_event(&watcher, now).expect("capacity observation");
    assert_eq!(blocked.category, EventCategory::CapacityBlock);
    assert_eq!(blocked.policy_hint, PolicyHint::WaitAllowed);
    assert_eq!(blocked.metadata["codex_capacity_block"], true);
    assert_eq!(blocked.source.source_id, "codex");

    watcher.last_observation = Some(blocked);
    watcher.lifecycle = WatcherLifecycle::Waiting {
        until_unix_ms: 1,
        reason: "capacity backoff".into(),
    };
    let later = chrono::DateTime::parse_from_rfc3339("2026-07-12T00:05:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let candidate = observe_codex_event(&watcher, later).expect("resume candidate");
    assert_eq!(candidate.category, EventCategory::WaitingForModel);
    assert_eq!(candidate.metadata["codex_resume"], true);

    watcher.last_observation = Some(candidate.clone());
    let action = CodexRecipes::default().action_for(&watcher).unwrap();
    assert_eq!(
        action.kind,
        ActionKind::SendText {
            text: "/goal resume".into()
        }
    );
    let fingerprint = action_fingerprint(&action);
    mark_resume_sent(watcher.last_observation.as_mut().unwrap(), &fingerprint);
    assert!(
        CodexRecipes::default().action_for(&watcher).is_none(),
        "exactly-once fingerprint must suppress a second resume"
    );

    let progress = trusted_goal_progress_event(
        &watcher,
        &candidate,
        &serde_json::json!({
            "thread_id": "thr_demo",
            "goal": {"status": "active", "text": "Finish the refactor"},
            "runtime_status": {"type": "active", "active_flags": []}
        }),
        "2026-07-12T00:06:00Z",
    )
    .expect("post-resume progress");
    assert_eq!(progress.metadata["codex_post_resume_progress"], true);
    assert_eq!(progress.category, EventCategory::Working);
}

#[tokio::test]
async fn daemon_observer_emits_codex_capacity_block_from_bound_rollout() {
    let cwd = std::env::current_dir().unwrap();
    let temp = tempfile::TempDir::new_in(&cwd).unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let rollout = temp.path().join("rollout.jsonl");
    fs::write(
        &rollout,
        concat!(
            r#"{"type":"codex.rollout.goal","thread_id":"thr_demo","goal":{"text":"Finish the refactor","status":"blocked"},"runtime_status":{"type":"idle","active_flags":[]},"last_error":{"category":"capacity_block","terminal":true}}"#,
            "\n"
        ),
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&rollout, fs::Permissions::from_mode(0o600)).unwrap();

    let watcher = bound_codex_watcher(temp.path(), &rollout, "thr_demo");
    let result = GenericObserver.observe(watcher).await.unwrap();
    let event = result.event.expect("Codex observation");
    assert_eq!(event.source.source_id, "codex");
    assert_eq!(event.category, EventCategory::CapacityBlock);
    assert_eq!(event.policy_hint, PolicyHint::WaitAllowed);
}

fn bound_codex_watcher(bound_cwd: &Path, rollout: &Path, thread_id: &str) -> WatcherState {
    let mut process = ProcessIdentity::new(std::process::id(), 42);
    process.executable = Some("codex".into());
    let mut watcher = WatcherState::new(
        "codex-bound".into(),
        TargetIdentity::process(process),
        WatcherLifecycle::Observing,
        1,
        1,
    );
    let binding = watchme::agents::codex::bind_rollout(rollout).expect("rollout bind");
    // Bind the process CWD to the live process CWD so Linux /proc correlation
    // succeeds, while the rollout remains under the owner-only bound subtree.
    let live_cwd = std::env::current_dir().unwrap();
    assert!(
        rollout.starts_with(&live_cwd),
        "test rollout must stay under the live process CWD"
    );
    let _ = bound_cwd;
    watcher
        .set_codex_session(CodexSessionReference {
            thread_id: thread_id.into(),
            rollout_path: rollout.to_string_lossy().into(),
            process_start_time: 42,
            process_cwd: live_cwd.to_string_lossy().into(),
            target_session: None,
            rollout_binding: Some(binding),
            app_server_state_path: None,
            structured_state: None,
        })
        .unwrap();
    watcher
}

fn codex_watcher(category: EventCategory, hint: PolicyHint, terminal: bool) -> WatcherState {
    let target = TargetIdentity::process(ProcessIdentity::new(1, 2));
    let target_hash = format!("{:064x}", 1);
    let event = Event::new(
        "codex-event",
        "2026-07-11T00:00:00Z",
        "codex-watcher",
        target_hash,
        EventSource::new(SourceKind::TypedApi, "codex", "goal_status"),
        category,
        1.0,
        terminal,
        format!("{:064x}", 2),
        "Codex structured goal status",
        hint,
    )
    .unwrap();
    let mut watcher = WatcherState::new(
        "codex-watcher".into(),
        target,
        WatcherLifecycle::Observing,
        1,
        1,
    );
    watcher.last_observation = Some(event);
    watcher
}

fn action_fingerprint(action: &watchme::model::Action) -> String {
    action
        .preconditions
        .iter()
        .find(|condition| condition.kind == "EVIDENCE_FINGERPRINT_MATCHES")
        .and_then(|condition| condition.value.as_ref())
        .and_then(serde_json::Value::as_str)
        .expect("fingerprint precondition")
        .to_owned()
}

fn hash64(value: &str) -> u64 {
    value.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}
