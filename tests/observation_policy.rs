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
fn sanitizer_strips_terminal_protocol_and_bounds_output() {
    let hostile =
        b"ok\x1b[31mred\x1b[0m\x1b]52;c;SECRET\x07\x1bPpayload\x1b\\\r\n\xe2\x80\xaeevil\0end";
    let clean = sanitize_terminal(hostile, 64, 3);
    assert_eq!(clean, "okred\nevilend");
    assert!(!clean.contains("SECRET"));
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
    assert!(
        policy
            .authorize(
                &Action::new(
                    "a",
                    ActionKind::Capture { max_lines: 20 },
                    "reason",
                    "fp",
                    10
                ),
                &PolicyContext::safe()
            )
            .is_ok()
    );
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
