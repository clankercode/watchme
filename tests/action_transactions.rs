use std::sync::{Arc, Mutex};

use watchme::model::{
    Action, ActionKind, Event, EventCategory, EventSource, PolicyHint, SourceKind,
};
use watchme::policy::PolicyContext;
use watchme::recovery::actuator::{ActionExecutor, ExecutionError, ExecutionOutput};
use watchme::recovery::transaction::{
    ActionRecord, ActionStore, Clock, EvidenceReader, LiveEvidence, OwnerIdentity, RecordState,
    Transaction, TransactionError,
};

#[derive(Clone, Default)]
struct FakeStore(Arc<Mutex<Option<ActionRecord>>>);
impl ActionStore for FakeStore {
    fn load(&self, _: &str) -> Result<Option<ActionRecord>, String> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn compare_and_swap(
        &self,
        _: &str,
        old: Option<&ActionRecord>,
        new: &ActionRecord,
    ) -> Result<bool, String> {
        let mut value = self.0.lock().unwrap();
        if value.as_ref() != old {
            return Ok(false);
        }
        *value = Some(new.clone());
        Ok(true)
    }
}

#[derive(Clone)]
struct FakeEvidence(Arc<Mutex<LiveEvidence>>);
impl EvidenceReader for FakeEvidence {
    fn read(&self) -> Result<LiveEvidence, String> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[derive(Default)]
struct FakeExecutor {
    sends: Mutex<usize>,
    mutate: Option<FakeEvidence>,
}
impl ActionExecutor for FakeExecutor {
    fn execute(&self, _: &Action) -> Result<ExecutionOutput, ExecutionError> {
        *self.sends.lock().unwrap() += 1;
        if let Some(evidence) = &self.mutate {
            evidence.0.lock().unwrap().event.category = EventCategory::Working;
        }
        Ok(ExecutionOutput::Committed)
    }
}

struct FakeClock;
impl Clock for FakeClock {
    fn monotonic_ms(&self) -> u64 {
        1000
    }
}

fn event(category: EventCategory, fingerprint: &str, confidence: f64) -> Event {
    Event::new(
        "evt",
        "2026-07-11T00:00:00Z",
        "watcher",
        "a".repeat(64),
        EventSource::new(SourceKind::StructuredLog, "fake", "state"),
        category,
        confidence,
        false,
        fingerprint,
        "state",
        PolicyHint::DeterministicActionAllowed,
    )
    .unwrap()
}
fn evidence(category: EventCategory, fingerprint: &str, confidence: f64) -> LiveEvidence {
    LiveEvidence {
        identity: "server/session/pane/pid:7/start:99".into(),
        composer_safe: true,
        human_intervened: false,
        event: event(category, fingerprint, confidence),
    }
}
fn fingerprint() -> String {
    "b".repeat(64)
}
fn action() -> Action {
    Action::send_text("resume-1", "/goal resume", "resume", fingerprint())
}
fn policy() -> PolicyContext {
    let mut p = PolicyContext::safe();
    p.evidence_fingerprint = Some(fingerprint());
    p
}
fn owner() -> OwnerIdentity {
    OwnerIdentity {
        pid: 42,
        process_start_time: 1234,
        nonce: "owner".into(),
    }
}

#[test]
fn durable_begin_precedes_send_and_verified_outcome_is_success() {
    let store = FakeStore::default();
    let evidence = FakeEvidence(Arc::new(Mutex::new(evidence(
        EventCategory::BlockedGoal,
        &fingerprint(),
        0.8,
    ))));
    let executor = FakeExecutor {
        mutate: Some(evidence.clone()),
        ..Default::default()
    };
    let result = Transaction::new(&store, &evidence, &executor, &FakeClock)
        .run("target", owner(), action(), policy())
        .unwrap();
    assert_eq!(result.state, RecordState::Succeeded);
    assert_eq!(*executor.sends.lock().unwrap(), 1);
}

#[test]
fn concurrent_claim_allows_exactly_one_send() {
    let store = FakeStore::default();
    let evidence = FakeEvidence(Arc::new(Mutex::new(evidence(
        EventCategory::BlockedGoal,
        &fingerprint(),
        0.8,
    ))));
    let executor = FakeExecutor {
        mutate: Some(evidence.clone()),
        ..Default::default()
    };
    let tx = Transaction::new(&store, &evidence, &executor, &FakeClock);
    tx.run("target", owner(), action(), policy()).unwrap();
    assert!(matches!(
        tx.run("target", owner(), action(), policy()),
        Err(TransactionError::Duplicate)
    ));
    assert_eq!(*executor.sends.lock().unwrap(), 1);
}

#[test]
fn identity_or_composer_change_fails_before_send() {
    let store = FakeStore::default();
    let mut live = evidence(EventCategory::BlockedGoal, &fingerprint(), 0.8);
    live.composer_safe = false;
    let evidence = FakeEvidence(Arc::new(Mutex::new(live)));
    let executor = FakeExecutor::default();
    assert!(
        Transaction::new(&store, &evidence, &executor, &FakeClock)
            .run("target", owner(), action(), policy())
            .is_err()
    );
    assert_eq!(*executor.sends.lock().unwrap(), 0);
}

#[test]
fn lower_confidence_postcondition_is_not_success() {
    let store = FakeStore::default();
    let evidence = FakeEvidence(Arc::new(Mutex::new(evidence(
        EventCategory::BlockedGoal,
        &fingerprint(),
        0.8,
    ))));
    let executor = FakeExecutor::default();
    let error = Transaction::new(&store, &evidence, &executor, &FakeClock)
        .run("target", owner(), action(), policy())
        .unwrap_err();
    assert!(matches!(error, TransactionError::VerificationFailed));
    assert_eq!(
        store.0.lock().unwrap().as_ref().unwrap().state,
        RecordState::Failed
    );
}

#[test]
fn unsafe_literal_and_non_allowlisted_keys_are_rejected() {
    let mut bad = action();
    bad.kind = ActionKind::SendText {
        text: "x\0y".into(),
    };
    assert!(watchme::recovery::actuator::validate_action(&bad).is_err());
    let mut keys = action();
    keys.kind = ActionKind::SendKeys {
        keys: vec!["CTRL_C".into()],
    };
    assert!(watchme::recovery::actuator::validate_action(&keys).is_err());
}

#[test]
fn restart_marks_inflight_action_uncertain_and_never_resends() {
    let store = FakeStore::default();
    *store.0.lock().unwrap() = Some(ActionRecord {
        action_id: "resume-1".into(),
        fingerprint: fingerprint(),
        identity: "server/session/pane/pid:7/start:99".into(),
        owner: owner(),
        lease_started_ms: 1,
        state: RecordState::Begun,
        reason: "begin".into(),
    });
    let evidence = FakeEvidence(Arc::new(Mutex::new(evidence(
        EventCategory::BlockedGoal,
        &fingerprint(),
        0.8,
    ))));
    let executor = FakeExecutor::default();
    let tx = Transaction::new(&store, &evidence, &executor, &FakeClock);
    assert_eq!(
        tx.recover_after_restart("target").unwrap().unwrap().state,
        RecordState::Uncertain
    );
    assert!(matches!(
        tx.run("target", owner(), action(), policy()),
        Err(TransactionError::Duplicate)
    ));
    assert_eq!(*executor.sends.lock().unwrap(), 0);
}
