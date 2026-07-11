use std::collections::VecDeque;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use watchme::model::{
    Action, ActionKind, Condition, Event, EventCategory, EventSource, PolicyHint, SourceKind,
};
use watchme::recovery::action_store::JsonActionStore;
use watchme::recovery::actuator::{
    ActionExecutor, ExecutionError, ExecutionOutput, RuntimeActuator, RuntimeServices,
};
use watchme::recovery::transaction::{
    ActionPhase, ActionRecord, ActionStore, Clock, EvidenceReader, LiveEvidence, OwnerIdentity,
    PersistedEvidenceReader, ProcessProbe, RecoveryContext, Transaction, TransactionError,
};

#[derive(Clone, Default)]
struct MemoryStore(Arc<Mutex<Ledger>>);
#[derive(Default)]
struct Ledger {
    active: Option<String>,
    audit: Vec<ActionRecord>,
    fail_on_append: Option<usize>,
}
impl ActionStore for MemoryStore {
    fn claim_prepared(&self, target: &str, record: ActionRecord) -> Result<bool, String> {
        let mut state = self.0.lock().unwrap();
        if state.active.is_some()
            || state
                .audit
                .iter()
                .any(|entry| entry.idempotency_key == record.idempotency_key)
        {
            return Ok(false);
        }
        state.active = Some(target.into());
        state.audit.push(record);
        Ok(true)
    }
    fn append(&self, target: &str, record: ActionRecord) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        if state.fail_on_append == Some(state.audit.len()) {
            return Err("injected store failure".into());
        }
        if state.active.as_deref() != Some(target) {
            return Err("lost active claim".into());
        }
        state.audit.push(record.clone());
        if record.phase.is_terminal() {
            state.active = None;
        }
        Ok(())
    }
    fn active(&self, target: &str) -> Result<Option<ActionRecord>, String> {
        let state = self.0.lock().unwrap();
        Ok((state.active.as_deref() == Some(target))
            .then(|| state.audit.last().cloned())
            .flatten())
    }
    fn audit(&self, _: &str) -> Result<Vec<ActionRecord>, String> {
        Ok(self.0.lock().unwrap().audit.clone())
    }
}

#[derive(Clone)]
struct Evidence(Arc<Mutex<VecDeque<LiveEvidence>>>);
impl EvidenceReader for Evidence {
    fn read(&self) -> Result<LiveEvidence, String> {
        let mut values = self.0.lock().unwrap();
        if values.len() > 1 {
            Ok(values.pop_front().unwrap())
        } else {
            values
                .front()
                .cloned()
                .ok_or_else(|| "missing evidence".into())
        }
    }
}

#[derive(Default)]
struct Executor {
    calls: Mutex<usize>,
    result: Mutex<Option<Result<ExecutionOutput, ExecutionError>>>,
}
impl ActionExecutor for Executor {
    fn execute(&self, _: &Action) -> Result<ExecutionOutput, ExecutionError> {
        *self.calls.lock().unwrap() += 1;
        self.result
            .lock()
            .unwrap()
            .take()
            .unwrap_or(Ok(ExecutionOutput::Committed))
    }
}
#[derive(Clone, Default)]
struct TestClock(Arc<Mutex<u64>>);
impl Clock for TestClock {
    fn monotonic_ms(&self) -> u64 {
        *self.0.lock().unwrap()
    }
    fn wall_time_rfc3339(&self) -> String {
        "2026-07-11T00:00:00Z".into()
    }
    fn sleep_ms(&self, duration: u64) {
        *self.0.lock().unwrap() += duration;
    }
}
struct Probe(bool);
impl ProcessProbe for Probe {
    fn matches(&self, _: &OwnerIdentity) -> bool {
        self.0
    }
}

fn event(category: EventCategory, fingerprint: &str, confidence: f64, source: SourceKind) -> Event {
    Event::new(
        "evt",
        "2026-07-11T00:00:00Z",
        "watcher",
        "a".repeat(64),
        EventSource::new(source, "test", "state"),
        category,
        confidence,
        false,
        fingerprint,
        "state",
        PolicyHint::DeterministicActionAllowed,
    )
    .unwrap()
}
fn live(category: EventCategory, fingerprint: &str, confidence: f64) -> LiveEvidence {
    LiveEvidence {
        identity: target_identity(),
        composer_safe: true,
        human_intervened: false,
        event: event(category, fingerprint, confidence, SourceKind::StructuredLog),
    }
}
fn target_identity() -> String {
    "tmux:/tmp/tmux.sock:$1:@2:%3:pid=7:start=99".into()
}
fn evidence(values: Vec<LiveEvidence>) -> Evidence {
    Evidence(Arc::new(Mutex::new(values.into())))
}
fn owner() -> OwnerIdentity {
    OwnerIdentity {
        pid: 42,
        process_start_time: 1234,
        nonce: "daemon-a".into(),
    }
}
fn context() -> RecoveryContext {
    RecoveryContext {
        attempts_remaining: 2,
        cumulative_wait_remaining_seconds: 300,
        planner_calls_remaining: 0,
        planner_concurrency_available: false,
        cooldown_ready: true,
        session_id: Some("session".into()),
        failed_provider_family: None,
        planner_provider_family: None,
    }
}
fn send_action() -> Action {
    let mut action = Action::send_text("resume-1", "/goal resume", "resume", "b".repeat(64));
    action.expected_outcomes = vec![Condition {
        kind: "GOAL_ACTIVE_OR_PURSUING".into(),
        value: None,
    }];
    action
}

#[test]
fn preparation_and_all_phases_are_append_only_and_precede_send() {
    let store = MemoryStore::default();
    let reader = evidence(vec![
        live(EventCategory::BlockedGoal, &"b".repeat(64), 0.8),
        live(EventCategory::BlockedGoal, &"b".repeat(64), 0.8),
        live(EventCategory::BlockedGoal, &"b".repeat(64), 0.8),
        live(EventCategory::Working, &"c".repeat(64), 0.8),
    ]);
    let executor = Executor::default();
    let result = Transaction::new(&store, &reader, &executor, &TestClock::default())
        .run("target", owner(), send_action(), context())
        .unwrap();
    assert_eq!(result.phase, ActionPhase::Succeeded);
    assert_eq!(
        store
            .audit("target")
            .unwrap()
            .iter()
            .map(|r| r.phase)
            .collect::<Vec<_>>(),
        vec![
            ActionPhase::Prepared,
            ActionPhase::Begun,
            ActionPhase::Sent,
            ActionPhase::Verifying,
            ActionPhase::Succeeded
        ]
    );
    assert_eq!(*executor.calls.lock().unwrap(), 1);
}

#[test]
fn real_concurrent_claim_has_one_winner() {
    let store = MemoryStore::default();
    let barrier = Arc::new(Barrier::new(3));
    let wins = Arc::new(Mutex::new(0));
    let mut joins = Vec::new();
    for nonce in ["a", "b"] {
        let store = store.clone();
        let barrier = barrier.clone();
        let wins = wins.clone();
        joins.push(thread::spawn(move || {
            let record = ActionRecord::prepared(
                "action",
                "same-key",
                "target",
                owner_with(nonce),
                0,
                100,
                "identity",
                "fingerprint",
                "snapshot",
            );
            barrier.wait();
            if store.claim_prepared("target", record).unwrap() {
                *wins.lock().unwrap() += 1;
            }
        }));
    }
    barrier.wait();
    for join in joins {
        join.join().unwrap();
    }
    assert_eq!(*wins.lock().unwrap(), 1);
}
fn owner_with(nonce: &str) -> OwnerIdentity {
    OwnerIdentity {
        nonce: nonce.into(),
        ..owner()
    }
}

#[test]
fn failure_after_possible_side_effect_is_uncertain_and_never_retryable() {
    let store = MemoryStore::default();
    let reader = evidence(vec![
        live(EventCategory::BlockedGoal, &"b".repeat(64), 0.8);
        3
    ]);
    let executor = Executor::default();
    *executor.result.lock().unwrap() = Some(Err(ExecutionError::PossibleSideEffect(
        "second key failed".into(),
    )));
    let mut action = send_action();
    action.kind = ActionKind::SendKeys {
        keys: vec!["DOWN".into(), "ENTER".into()],
    };
    assert!(matches!(
        Transaction::new(&store, &reader, &executor, &TestClock::default()).run(
            "target",
            owner(),
            action.clone(),
            context()
        ),
        Err(TransactionError::Uncertain(_))
    ));
    assert_eq!(
        store.audit("target").unwrap().last().unwrap().phase,
        ActionPhase::HumanRequired
    );
    assert!(matches!(
        Transaction::new(&store, &reader, &executor, &TestClock::default()).run(
            "target",
            owner(),
            action,
            context()
        ),
        Err(TransactionError::Duplicate)
    ));
}

#[test]
fn immediate_checks_detect_second_composer_identity_evidence_and_human_changes() {
    for changed in ["composer", "identity", "evidence", "human"] {
        let first = live(EventCategory::BlockedGoal, &"b".repeat(64), 0.8);
        let mut second = first.clone();
        match changed {
            "composer" => second.composer_safe = false,
            "identity" => second.identity = "reused-pane".into(),
            "evidence" => second.event.evidence_fingerprint = "d".repeat(64),
            _ => second.human_intervened = true,
        }
        let executor = Executor::default();
        let result = Transaction::new(
            &MemoryStore::default(),
            &evidence(vec![first, second]),
            &executor,
            &TestClock::default(),
        )
        .run("target", owner(), send_action(), context());
        assert!(result.is_err(), "{changed}");
        assert_eq!(*executor.calls.lock().unwrap(), 0, "{changed}");
    }
}

#[test]
fn lower_rank_or_unchanged_working_does_not_verify_but_equal_changed_does() {
    let baseline = live(EventCategory::BlockedGoal, &"b".repeat(64), 0.8);
    let lower = live(EventCategory::Working, &"c".repeat(64), 0.7);
    let store = MemoryStore::default();
    let err = Transaction::new(
        &store,
        &evidence(vec![
            baseline.clone(),
            baseline.clone(),
            baseline.clone(),
            lower,
        ]),
        &Executor::default(),
        &TestClock::default(),
    )
    .run("target", owner(), send_action(), context())
    .unwrap_err();
    assert!(matches!(err, TransactionError::Uncertain(_)));
    let unchanged_working = live(EventCategory::Working, &"b".repeat(64), 0.8);
    let mut action = send_action();
    action.preconditions[0].value = Some(serde_json::Value::String("b".repeat(64)));
    let store = MemoryStore::default();
    assert!(
        Transaction::new(
            &store,
            &evidence(vec![unchanged_working.clone(); 4]),
            &Executor::default(),
            &TestClock::default()
        )
        .run("other", owner(), action, context())
        .is_err()
    );
}

#[test]
fn stale_lease_uses_pid_and_start_identity() {
    let store = MemoryStore::default();
    let prepared = ActionRecord::prepared(
        "a",
        "key",
        "target",
        owner(),
        0,
        10,
        "identity",
        "fingerprint",
        "snapshot",
    );
    store.claim_prepared("target", prepared).unwrap();
    let reader = evidence(vec![live(EventCategory::BlockedGoal, &"f".repeat(64), 0.8)]);
    let executor = Executor::default();
    let clock = TestClock(Arc::new(Mutex::new(20)));
    let tx = Transaction::new(&store, &reader, &executor, &clock);
    assert!(matches!(
        tx.recover_stale("target", &Probe(true)),
        Err(TransactionError::ActiveOwner)
    ));
    assert_eq!(
        tx.recover_stale("target", &Probe(false))
            .unwrap()
            .unwrap()
            .phase,
        ActionPhase::Failed
    );
}

#[test]
fn restart_after_begun_is_human_required_but_prepared_is_cancelled() {
    for (phase, expected) in [
        (ActionPhase::Prepared, ActionPhase::Failed),
        (ActionPhase::Begun, ActionPhase::HumanRequired),
        (ActionPhase::Sent, ActionPhase::HumanRequired),
    ] {
        let store = MemoryStore::default();
        let mut record = ActionRecord::prepared(
            "a",
            "key",
            "target",
            owner(),
            0,
            10,
            "identity",
            "fingerprint",
            "snapshot",
        );
        store.claim_prepared("target", record.clone()).unwrap();
        if phase != ActionPhase::Prepared {
            record = record.next(phase, "phase");
            store.append("target", record).unwrap();
        }
        let reader = evidence(vec![live(EventCategory::BlockedGoal, &"f".repeat(64), 0.8)]);
        let executor = Executor::default();
        let clock = TestClock::default();
        let tx = Transaction::new(&store, &reader, &executor, &clock);
        assert_eq!(
            tx.recover_after_restart("target").unwrap().unwrap().phase,
            expected
        );
    }
}

#[test]
fn store_failure_after_send_is_never_reported_failed_or_success() {
    let store = MemoryStore::default();
    store.0.lock().unwrap().fail_on_append = Some(3);
    let reader = evidence(vec![
        live(EventCategory::BlockedGoal, &"b".repeat(64), 0.8);
        3
    ]);
    let result = Transaction::new(&store, &reader, &Executor::default(), &TestClock::default())
        .run("target", owner(), send_action(), context());
    assert!(matches!(result, Err(TransactionError::Uncertain(_))));
}

#[test]
fn json_action_store_survives_reload_with_append_only_audit() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("actions.json");
    let store = JsonActionStore::load(path.clone()).unwrap();
    let record = ActionRecord::prepared(
        "a",
        "key",
        "target",
        owner(),
        0,
        10,
        "identity",
        &"f".repeat(64),
        "snapshot",
    );
    assert!(store.claim_prepared("target", record.clone()).unwrap());
    store
        .append("target", record.next(ActionPhase::Failed, "cancelled"))
        .unwrap();
    drop(store);
    let reloaded = JsonActionStore::load(path).unwrap();
    assert_eq!(reloaded.audit("target").unwrap().len(), 2);
    assert!(reloaded.active("target").unwrap().is_none());
    assert!(
        !reloaded
            .claim_prepared(
                "target",
                ActionRecord::prepared(
                    "a",
                    "key",
                    "target",
                    owner(),
                    20,
                    30,
                    "identity",
                    &"f".repeat(64),
                    "snapshot"
                )
            )
            .unwrap()
    );
}

#[derive(Default)]
struct Services(Mutex<Vec<String>>);
impl RuntimeServices for Services {
    fn schedule(&self, deadline: &str) -> Result<(), String> {
        self.0.lock().unwrap().push(format!("schedule:{deadline}"));
        Ok(())
    }
    fn capture(&self, source: &str, lines: u16) -> Result<String, String> {
        self.0
            .lock()
            .unwrap()
            .push(format!("capture:{source}:{lines}"));
        Ok("bounded".into())
    }
    fn check(&self, kind: &str, value: Option<&str>) -> Result<bool, String> {
        self.0
            .lock()
            .unwrap()
            .push(format!("check:{kind}:{value:?}"));
        Ok(true)
    }
    fn notify(&self, severity: &str, message: &str) -> Result<(), String> {
        self.0
            .lock()
            .unwrap()
            .push(format!("notify:{severity}:{message}"));
        Ok(())
    }
    fn escalate(&self, level: &str) -> Result<(), String> {
        self.0.lock().unwrap().push(format!("escalate:{level}"));
        Ok(())
    }
    fn stop_watching(&self) -> Result<(), String> {
        self.0.lock().unwrap().push("stop".into());
        Ok(())
    }
}

#[test]
fn every_non_input_action_dispatches_to_a_concrete_service() {
    let services = Services::default();
    let actuator = RuntimeActuator::new(&services);
    let actions = [
        ActionKind::WaitDuration {
            duration_seconds: 2,
        },
        ActionKind::WaitUntil {
            at: "2026-07-12T00:00:00Z".into(),
        },
        ActionKind::Capture {
            source: "structured_state".into(),
            max_lines: 5,
        },
        ActionKind::CheckStatus {
            check: watchme::model::StatusCheck {
                kind: "PROCESS_ALIVE".into(),
                value: None,
            },
        },
        ActionKind::Notify {
            severity: "warning".into(),
            message: "needs attention".into(),
        },
        ActionKind::Escalate {
            level: "human_required".into(),
        },
        ActionKind::StopWatching,
        ActionKind::Noop,
    ];
    for (index, kind) in actions.into_iter().enumerate() {
        let action = Action::new(format!("a{index}"), kind, "test", "f".repeat(64), 30);
        actuator.execute(&action).unwrap();
    }
    let calls = services.0.lock().unwrap();
    assert_eq!(calls.len(), 7, "NOOP alone has no external service effect");
    assert!(calls.iter().any(|call| call == "stop"));
}

#[test]
fn persisted_evidence_reader_seeds_current_event_then_reads_live_observer() {
    let seed = live(EventCategory::BlockedGoal, &"b".repeat(64), 0.8);
    let observer = evidence(vec![live(EventCategory::Working, &"c".repeat(64), 0.8)]);
    let reader = PersistedEvidenceReader::new(seed.clone(), observer);
    assert_eq!(reader.read().unwrap().event, seed.event);
    assert_eq!(
        reader.read().unwrap().event.category,
        EventCategory::Working
    );
}
