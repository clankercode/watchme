use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::Duration;

use proptest::prelude::*;
use tempfile::tempdir;
use watchme::model::{
    Action, ActionKind, Event, EventCategory, EventSource, PolicyHint, SourceKind,
};
use watchme::observe::ObservationCadence;
use watchme::observe::jsonl::{JsonlCursor, ReadLimits};
use watchme::observe::screen::{ScreenDebouncer, sanitize_terminal};
use watchme::observe::{EvidenceMerger, evidence_fingerprint};
use watchme::policy::{CompiledPolicy, PolicyContext};
use watchme::recovery::state_machine::{Budget, ClockSnapshot, RecoveryMachine, RecoveryState};

fn event(source: SourceKind, category: EventCategory, confidence: f64) -> Event {
    Event::new(
        "evt-1",
        "2026-07-11T00:00:00Z",
        "watcher-1",
        "0123456789abcdef",
        EventSource::new(source, "fixture", "rule"),
        category,
        confidence,
        false,
        "0123456789abcdef",
        "redacted summary",
        PolicyHint::ObserveOnly,
    )
    .unwrap()
}

#[test]
fn normalized_event_is_strict_and_versioned() {
    let value = serde_json::to_value(event(
        SourceKind::StructuredLog,
        EventCategory::CapacityBlock,
        0.9,
    ))
    .unwrap();
    assert_eq!(value["schema_version"], "1.0");
    let mut unknown = value.clone();
    unknown
        .as_object_mut()
        .unwrap()
        .insert("surprise".into(), true.into());
    assert!(serde_json::from_value::<Event>(unknown).is_err());
    let mut invalid = value;
    invalid["confidence"] = 2.into();
    assert!(serde_json::from_value::<Event>(invalid).is_err());
}

#[test]
fn jsonl_reader_handles_partial_malformed_truncate_and_replace() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    fs::write(&path, b"{\"n\":1}\n{\"n\":").unwrap();
    let mut cursor = JsonlCursor::new(path.clone(), ReadLimits::default());
    assert_eq!(cursor.read_new().unwrap().records.len(), 1);
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"2}\nnot-json\n")
        .unwrap();
    let batch = cursor.read_new().unwrap();
    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.malformed, 1);
    fs::write(&path, b"{\"n\":3}\n").unwrap();
    assert_eq!(cursor.read_new().unwrap().records[0]["n"], 3);
    fs::rename(&path, dir.path().join("old")).unwrap();
    fs::write(&path, b"{\"n\":4}\n").unwrap();
    assert_eq!(cursor.read_new().unwrap().records[0]["n"], 4);
}

#[test]
fn jsonl_reader_detects_same_inode_copy_truncate_and_regrow() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    fs::write(&path, b"{\"old\":1}\n{\"old\":2}\n").unwrap();
    let mut cursor = JsonlCursor::new(path.clone(), ReadLimits::default());
    assert_eq!(cursor.read_new().unwrap().records.len(), 2);

    let inode_before = fs::metadata(&path).unwrap();
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap()
        .write_all(b"{\"new\":1}\n{\"new\":2}\n{\"new\":3}\n")
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(inode_before.ino(), fs::metadata(&path).unwrap().ino());
    }

    let batch = cursor.read_new().unwrap();
    assert_eq!(batch.records.len(), 3);
    assert_eq!(batch.records[0]["new"], 1);
}

#[test]
fn jsonl_generation_guard_detects_rewrite_that_preserves_consumed_tail() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let old_prefix = format!("{{\"old\":\"{}\"}}\n", "a".repeat(12_000));
    let preserved_tail = format!("{{\"tail\":\"{}\"}}\n", "t".repeat(5_000));
    fs::write(&path, format!("{old_prefix}{preserved_tail}")).unwrap();
    let mut cursor = JsonlCursor::new(
        path.clone(),
        ReadLimits {
            max_read_bytes: 64 * 1024,
            max_record_bytes: 32 * 1024,
            max_records: 8,
        },
    );
    assert_eq!(cursor.read_new().unwrap().records.len(), 2);

    let replacement_prefix = format!("{{\"new\":\"{}\"}}\n", "b".repeat(12_000));
    let replacement = format!("{replacement_prefix}{preserved_tail}");
    assert_eq!(replacement.len(), old_prefix.len() + preserved_tail.len());
    OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .unwrap()
        .write_all(replacement.as_bytes())
        .unwrap();

    let batch = cursor.read_new().unwrap();
    assert_eq!(batch.records.len(), 2);
    assert!(batch.records[0].get("new").is_some());
}

#[test]
fn jsonl_generation_guard_does_not_reset_on_ordinary_append() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    fs::write(&path, b"{\"n\":1}\n").unwrap();
    let mut cursor = JsonlCursor::new(path.clone(), ReadLimits::default());
    assert_eq!(cursor.read_new().unwrap().records[0]["n"], 1);
    OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"{\"n\":2}\n")
        .unwrap();
    let batch = cursor.read_new().unwrap();
    assert_eq!(batch.records.len(), 1);
    assert_eq!(batch.records[0]["n"], 2);
}

#[test]
fn sanitizer_strips_terminal_protocol_and_bounds_output() {
    let hostile =
        b"ok\x1b[31mred\x1b[0m\x1b]52;c;SECRET\x07\x1bPpayload\x1b\\\r\n\xe2\x80\xaeevil\0end";
    let clean = sanitize_terminal(hostile, 64, 3);
    assert_eq!(clean, "okred\nevilend");
    assert!(!clean.contains("SECRET"));
}

#[test]
fn split_sequences_and_malformed_utf8_cannot_reveal_terminal_payloads() {
    let samples: &[&[u8]] = &[b"\x1b]52;c;SECRET\x07", b"\x1bPSECRET\x1b\\"];
    for sample in samples {
        for split in 0..=sample.len() {
            let mut sanitizer = watchme::observe::screen::TerminalSanitizer::default();
            let mut clean = sanitizer.feed(&sample[..split], 128, 4);
            clean.push_str(&sanitizer.feed(&sample[split..], 128 - clean.len(), 4));
            assert!(!clean.contains("SECRET"));
        }
    }
    let mut sanitizer = watchme::observe::screen::TerminalSanitizer::default();
    let _ = sanitizer.feed(&[0xe2], 128, 4);
    assert!(
        !sanitizer
            .feed(b"\x1b]52;c;SECRET\x07", 128, 4)
            .contains("SECRET")
    );
}

#[test]
fn incremental_sanitizer_emits_only_complete_utf8_scalars() {
    for scalar in ["¢", "€", "🦀"] {
        let bytes = scalar.as_bytes();
        for split in 1..bytes.len() {
            let mut sanitizer = watchme::observe::screen::TerminalSanitizer::default();
            assert_eq!(sanitizer.feed(&bytes[..split], 128, 4), "");
            assert_eq!(sanitizer.feed(&bytes[split..], 128, 4), scalar);
        }
    }

    let mut sanitizer = watchme::observe::screen::TerminalSanitizer::default();
    assert_eq!(sanitizer.feed(&[0xe2], 128, 4), "");
    assert_eq!(sanitizer.feed(b"\x1b]52;c;SECRET\x07safe", 128, 4), "safe");
}

#[test]
fn screen_requires_two_stable_observations_but_terminal_failure_is_immediate() {
    let mut debounce = ScreenDebouncer::new(2);
    assert!(!debounce.observe("fp", false));
    assert!(debounce.observe("fp", false));
    assert!(debounce.observe("other", true));
}

#[test]
fn higher_rank_contradiction_suppresses_action() {
    let low = event(
        SourceKind::ScreenDetection,
        EventCategory::CapacityBlock,
        0.95,
    );
    let high = event(SourceKind::TypedApi, EventCategory::Working, 0.8);
    assert!(EvidenceMerger.select_actionable(&[low, high]).is_none());
}

#[test]
fn fingerprint_is_stable_and_does_not_embed_evidence() {
    let first = evidence_fingerprint("structured_log", "capacity", b"token=secret");
    let second = evidence_fingerprint("structured_log", "capacity", b"token=secret");
    assert_eq!(first, second);
    assert_eq!(first.len(), 64);
    assert!(!first.contains("secret"));
}

#[test]
fn compiled_policy_is_deny_by_default() {
    let policy = CompiledPolicy;
    for text in [
        "login now",
        "upgrade plan",
        "add funds",
        "approve permission",
        "yolo",
        "sudo rm -rf /",
    ] {
        let action = Action::send_text("a", text, "reason", "fp");
        assert!(policy.authorize(&action, &PolicyContext::safe()).is_err());
    }
    let unknown: Result<Action, _> = serde_json::from_str(
        r#"{"schema_version":"1.0","action_id":"x","type":"SHELL","reason":"x","evidence_fingerprint":"0123456789abcdef","timeout_seconds":1}"#,
    );
    assert!(unknown.is_err());
    let mut matching_context = PolicyContext::safe();
    matching_context.evidence_fingerprint = Some("fp".into());
    assert!(
        policy
            .authorize(
                &Action::new(
                    "a",
                    ActionKind::Capture {
                        source: "screen_recent".into(),
                        max_lines: 20
                    },
                    "reason",
                    "fp",
                    10
                ),
                &matching_context
            )
            .is_ok()
    );
}

#[test]
fn action_constructors_bind_and_enforce_the_supplied_evidence_fingerprint() {
    let action = Action::send_text("a", "continue", "reason", "fresh-fingerprint");
    assert!(action.preconditions.iter().any(|condition| {
        condition.kind == "EVIDENCE_FINGERPRINT_MATCHES"
            && condition.value.as_ref().and_then(serde_json::Value::as_str)
                == Some("fresh-fingerprint")
    }));

    let policy = CompiledPolicy;
    let mut context = PolicyContext::safe();
    context.evidence_fingerprint = Some("stale-fingerprint".into());
    assert_eq!(
        policy.authorize(&action, &context),
        Err("declared precondition failed")
    );
    context.evidence_fingerprint = Some("fresh-fingerprint".into());
    assert!(policy.authorize(&action, &context).is_ok());
}

#[test]
fn policy_bounds_wait_until_against_parsed_wall_time_and_wait_budget() {
    let action = Action::new(
        "wait",
        ActionKind::WaitUntil {
            at: "2026-07-11T00:01:00Z".into(),
        },
        "bounded wait",
        "fp",
        60,
    );
    let mut context = PolicyContext::safe();
    context.evidence_fingerprint = Some("fp".into());
    context.wall_time_rfc3339 = Some("2026-07-11T00:00:00Z".into());
    context.cumulative_wait_remaining_seconds = 60;
    assert!(CompiledPolicy.authorize(&action, &context).is_ok());
    context.cumulative_wait_remaining_seconds = 59;
    assert_eq!(
        CompiledPolicy.authorize(&action, &context),
        Err("cumulative wait budget denied")
    );
    context.wall_time_rfc3339 = Some("invalid".into());
    assert!(CompiledPolicy.authorize(&action, &context).is_err());
}

#[test]
fn alternate_planner_escalation_requires_independent_provider_and_planner_budgets() {
    let action = Action::new(
        "alternate",
        ActionKind::Escalate {
            level: "alternate_planner".into(),
        },
        "independent review",
        "fp",
        30,
    );
    let mut context = PolicyContext::safe();
    context.evidence_fingerprint = Some("fp".into());
    context.failed_provider_family = Some("provider-a".into());
    context.planner_provider_family = Some("provider-b".into());
    assert!(CompiledPolicy.authorize(&action, &context).is_ok());
    context.planner_provider_family = Some("provider-a".into());
    assert!(CompiledPolicy.authorize(&action, &context).is_err());
    context.planner_provider_family = None;
    assert!(CompiledPolicy.authorize(&action, &context).is_err());
    context.planner_provider_family = Some("provider-b".into());
    context.planner_calls_remaining = 0;
    assert!(CompiledPolicy.authorize(&action, &context).is_err());
}

#[test]
fn independent_second_opinion_requires_two_calls_and_every_safe_context_gate() {
    let action = Action::new(
        "second-opinion",
        ActionKind::Escalate {
            level: "independent_second_opinion".into(),
        },
        "independent review",
        "fp",
        30,
    );
    let mut safe = PolicyContext::safe();
    safe.evidence_fingerprint = Some("fp".into());
    safe.failed_provider_family = Some("provider-a".into());
    safe.planner_provider_family = Some("provider-b".into());
    safe.planner_calls_remaining = 2;
    assert!(CompiledPolicy.authorize(&action, &safe).is_ok());

    for mutate in [
        |context: &mut PolicyContext| context.planner_calls_remaining = 1,
        |context: &mut PolicyContext| context.planner_provider_family = None,
        |context: &mut PolicyContext| context.failed_provider_family = None,
        |context: &mut PolicyContext| context.planner_provider_family = Some("provider-a".into()),
        |context: &mut PolicyContext| context.evidence_current = false,
        |context: &mut PolicyContext| context.evidence_fingerprint = Some("stale".into()),
        |context: &mut PolicyContext| context.target_revalidated = false,
        |context: &mut PolicyContext| context.process_alive = false,
        |context: &mut PolicyContext| context.pane_matches = false,
        |context: &mut PolicyContext| context.human_intervened = true,
        |context: &mut PolicyContext| context.composer_empty = false,
        |context: &mut PolicyContext| context.cooldown_ready = false,
        |context: &mut PolicyContext| context.attempts_remaining = 0,
        |context: &mut PolicyContext| context.planner_concurrency_available = false,
        |context: &mut PolicyContext| {
            context.source_rank = 0;
            context.contradictory_source_rank = Some(1);
        },
    ] {
        let mut denied = safe.clone();
        mutate(&mut denied);
        assert!(CompiledPolicy.authorize(&action, &denied).is_err());
    }
}

#[test]
fn canonical_recovery_plan_actions_match_wire_contract() {
    let valid: serde_json::Value = serde_json::from_str(include_str!(
        "/home/xertrov/Downloads/WatchMe-one-shot-bundle/fixtures/recovery-plan.valid.json"
    ))
    .unwrap();
    for value in valid["actions"].as_array().unwrap() {
        let action: Action = serde_json::from_value(value.clone()).unwrap();
        action.validate().unwrap();
    }
    let invalid: serde_json::Value = serde_json::from_str(include_str!(
        "/home/xertrov/Downloads/WatchMe-one-shot-bundle/fixtures/recovery-plan.invalid.json"
    ))
    .unwrap();
    assert!(serde_json::from_value::<Action>(invalid["actions"][0].clone()).is_err());
}

#[test]
fn recovery_snapshot_round_trip_restarts_fail_closed_with_audit() {
    let budget = Budget {
        max_attempts: 2,
        max_cumulative_wait: Duration::from_secs(30),
        planner_calls: 1,
        cooldown: Duration::from_secs(10),
    };
    let mut machine = RecoveryMachine::new(budget);
    machine.revalidated().unwrap();
    machine.confirm("fp").unwrap();
    let encoded = serde_json::to_vec(&machine).unwrap();
    let restored: RecoveryMachine = serde_json::from_slice(&encoded).unwrap();
    let mut restored = restored.restore_for_restart().unwrap();
    assert_eq!(restored.state(), RecoveryState::NeedsRevalidation);
    assert!(
        restored
            .begin_action("fp", ClockSnapshot::new(100, 100))
            .is_err()
    );
    assert!(
        restored
            .audit()
            .iter()
            .any(|entry| entry.reason.contains("restart"))
    );
}

#[test]
fn jsonl_preserves_records_beyond_per_read_limit() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("many.jsonl");
    fs::write(&path, b"{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n").unwrap();
    let mut cursor = JsonlCursor::new(
        path,
        ReadLimits {
            max_read_bytes: 1024,
            max_record_bytes: 128,
            max_records: 1,
        },
    );
    assert_eq!(cursor.read_new().unwrap().records[0]["n"], 1);
    assert_eq!(cursor.read_new().unwrap().records[0]["n"], 2);
    assert_eq!(cursor.read_new().unwrap().records[0]["n"], 3);
}

#[test]
fn recovery_machine_enforces_revalidation_idempotency_cooldown_and_budgets() {
    let budget = Budget {
        max_attempts: 2,
        max_cumulative_wait: Duration::from_secs(30),
        planner_calls: 1,
        cooldown: Duration::from_secs(10),
    };
    let mut machine = RecoveryMachine::new(budget);
    assert_eq!(machine.state(), RecoveryState::NeedsRevalidation);
    assert!(
        machine
            .begin_action("fp", ClockSnapshot::new(100, 100))
            .is_err()
    );
    machine.revalidated().unwrap();
    machine.confirm("fp").unwrap();
    machine
        .begin_action("fp", ClockSnapshot::new(100, 100))
        .unwrap();
    machine
        .action_failed("fp", Duration::from_secs(5), ClockSnapshot::new(101, 101))
        .unwrap();
    assert!(
        machine
            .begin_action("fp", ClockSnapshot::new(105, 5000))
            .is_err()
    );
    machine
        .begin_action("fp", ClockSnapshot::new(112, 50))
        .unwrap();
    machine.action_succeeded("fp").unwrap();
    assert!(
        machine
            .begin_action("fp", ClockSnapshot::new(200, 200))
            .is_err()
    );
}

proptest! {
    #[test]
    fn arbitrary_terminal_bytes_are_bounded(bytes in prop::collection::vec(any::<u8>(), 0..20_000)) {
        let clean = sanitize_terminal(&bytes, 1024, 20);
        prop_assert!(clean.len() <= 1026);
        prop_assert!(clean.lines().count() <= 20);
        prop_assert!(!clean.chars().any(|character| character == char::from(27)));
    }

    #[test]
    fn arbitrary_jsonl_fragments_do_not_panic(chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..128), 0..16)) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fuzz.jsonl");
        fs::write(&path, []).unwrap();
        let mut cursor = JsonlCursor::new(path.clone(), ReadLimits { max_read_bytes: 4096, max_record_bytes: 512, max_records: 32 });
        for chunk in chunks {
            OpenOptions::new().append(true).open(&path).unwrap().write_all(&chunk).unwrap();
            let batch = cursor.read_new().unwrap();
            prop_assert!(batch.records.len() <= 32);
        }
    }
}

#[test]
fn malicious_fixture_never_authorizes_an_action() {
    let fixture = include_str!("../fixtures/malicious-terminal-samples.txt");
    let policy = CompiledPolicy;
    for line in fixture.lines().filter(|line| !line.trim().is_empty()) {
        let action = Action::send_text("fixture", line, "untrusted terminal", "fp");
        assert!(policy.authorize(&action, &PolicyContext::safe()).is_err());
    }
}

#[test]
fn observation_cadence_checks_once_per_target_and_supports_event_wake() {
    let mut cadence = ObservationCadence::new(60, 5);
    cadence.register("a", 100, 0);
    cadence.register("b", 100, 5);
    assert_eq!(cadence.due(159), Vec::<String>::new());
    assert_eq!(cadence.due(160), vec!["a"]);
    assert_eq!(cadence.due(160), Vec::<String>::new());
    cadence.wake("b");
    assert_eq!(cadence.due(160), vec!["b"]);
}
