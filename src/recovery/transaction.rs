use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{Action, Event, EventCategory};
use crate::policy::{CompiledPolicy, PolicyContext};
use crate::recovery::actuator::{ActionExecutor, validate_action};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OwnerIdentity {
    pub pid: u32,
    pub process_start_time: u64,
    pub nonce: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordState {
    Begun,
    Sent,
    Succeeded,
    Failed,
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionRecord {
    pub action_id: String,
    pub fingerprint: String,
    pub identity: String,
    pub owner: OwnerIdentity,
    pub lease_started_ms: u64,
    pub state: RecordState,
    pub reason: String,
}

pub trait ActionStore {
    fn load(&self, target: &str) -> Result<Option<ActionRecord>, String>;
    fn compare_and_swap(
        &self,
        target: &str,
        old: Option<&ActionRecord>,
        new: &ActionRecord,
    ) -> Result<bool, String>;
}

#[derive(Clone, Debug)]
pub struct LiveEvidence {
    pub identity: String,
    pub composer_safe: bool,
    pub human_intervened: bool,
    pub event: Event,
}
pub trait EvidenceReader {
    fn read(&self) -> Result<LiveEvidence, String>;
}
pub trait Clock {
    fn monotonic_ms(&self) -> u64;
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("duplicate or in-flight action")]
    Duplicate,
    #[error("live state changed: {0}")]
    Revalidation(&'static str),
    #[error("policy denied action: {0}")]
    Policy(&'static str),
    #[error("action execution failed: {0}")]
    Execution(String),
    #[error("postcondition verification failed")]
    VerificationFailed,
    #[error("durable store failed: {0}")]
    Store(String),
}

pub struct Transaction<'a, S, E, X, C> {
    store: &'a S,
    evidence: &'a E,
    executor: &'a X,
    clock: &'a C,
}

impl<'a, S: ActionStore, E: EvidenceReader, X: ActionExecutor, C: Clock>
    Transaction<'a, S, E, X, C>
{
    pub const fn new(store: &'a S, evidence: &'a E, executor: &'a X, clock: &'a C) -> Self {
        Self {
            store,
            evidence,
            executor,
            clock,
        }
    }

    /// Cancels an action found in-flight after a daemon restart. A begun action may
    /// already have reached the multiplexer even when its outcome record was lost,
    /// so restart recovery never retries it automatically.
    pub fn recover_after_restart(
        &self,
        target: &str,
    ) -> Result<Option<ActionRecord>, TransactionError> {
        let Some(mut record) = self.store.load(target).map_err(TransactionError::Store)? else {
            return Ok(None);
        };
        if matches!(record.state, RecordState::Begun | RecordState::Sent) {
            let old = record.clone();
            record.state = RecordState::Uncertain;
            record.reason = "restart cancelled in-flight action; human review required".into();
            if !self
                .store
                .compare_and_swap(target, Some(&old), &record)
                .map_err(TransactionError::Store)?
            {
                return Err(TransactionError::Duplicate);
            }
        }
        Ok(Some(record))
    }

    pub fn run(
        &self,
        target: &str,
        owner: OwnerIdentity,
        action: Action,
        mut context: PolicyContext,
    ) -> Result<ActionRecord, TransactionError> {
        validate_action(&action).map_err(|error| TransactionError::Execution(error.to_string()))?;
        let prepared = self.live(&action, None)?;
        context_from_live(&mut context, &prepared);
        CompiledPolicy
            .authorize(&action, &context)
            .map_err(TransactionError::Policy)?;
        let policy_checked = self.live(&action, Some(&prepared))?;
        let prior = self.store.load(target).map_err(TransactionError::Store)?;
        if prior.as_ref().is_some_and(|record| {
            record.action_id == action.action_id
                || record.fingerprint == prepared.event.evidence_fingerprint
                || matches!(
                    record.state,
                    RecordState::Begun
                        | RecordState::Sent
                        | RecordState::Succeeded
                        | RecordState::Uncertain
                )
        }) {
            return Err(TransactionError::Duplicate);
        }
        let mut record = ActionRecord {
            action_id: action.action_id.clone(),
            fingerprint: prepared.event.evidence_fingerprint.clone(),
            identity: prepared.identity.clone(),
            owner,
            lease_started_ms: self.clock.monotonic_ms(),
            state: RecordState::Begun,
            reason: "begin_action durable before commit".into(),
        };
        if !self
            .store
            .compare_and_swap(target, prior.as_ref(), &record)
            .map_err(TransactionError::Store)?
        {
            return Err(TransactionError::Duplicate);
        }
        if let Err(error) = self.live(&action, Some(&policy_checked)) {
            return self.fail(target, record, error);
        }
        if let Err(error) = self.executor.execute(&action) {
            return self.fail(
                target,
                record,
                TransactionError::Execution(error.to_string()),
            );
        }
        let begun = record.clone();
        record.state = RecordState::Sent;
        record.reason = "single action committed".into();
        if !self
            .store
            .compare_and_swap(target, Some(&begun), &record)
            .map_err(TransactionError::Store)?
        {
            return Err(TransactionError::Store(
                "sent outcome was not durable; human review required".into(),
            ));
        }
        let after = self.evidence.read().map_err(TransactionError::Store)?;
        if !verified(&prepared, &after) {
            return self.fail(target, record, TransactionError::VerificationFailed);
        }
        let sent = record.clone();
        record.state = RecordState::Succeeded;
        record.reason = "postcondition verified with equal or higher confidence".into();
        if !self
            .store
            .compare_and_swap(target, Some(&sent), &record)
            .map_err(TransactionError::Store)?
        {
            return Err(TransactionError::Store(
                "success outcome persistence failed".into(),
            ));
        }
        Ok(record)
    }

    fn live(
        &self,
        action: &Action,
        baseline: Option<&LiveEvidence>,
    ) -> Result<LiveEvidence, TransactionError> {
        let live = self.evidence.read().map_err(TransactionError::Store)?;
        if live.human_intervened {
            return Err(TransactionError::Revalidation("human intervention"));
        }
        if !live.composer_safe {
            return Err(TransactionError::Revalidation("composer unsafe"));
        }
        if live.event.evidence_fingerprint != action_fingerprint(action) {
            return Err(TransactionError::Revalidation(
                "evidence fingerprint changed",
            ));
        }
        if baseline.is_some_and(|old| {
            old.identity != live.identity
                || old.event.source != live.event.source
                || old.event.confidence != live.event.confidence
        }) {
            return Err(TransactionError::Revalidation(
                "identity or evidence changed",
            ));
        }
        Ok(live)
    }

    fn fail(
        &self,
        target: &str,
        mut record: ActionRecord,
        error: TransactionError,
    ) -> Result<ActionRecord, TransactionError> {
        let old = record.clone();
        record.state = RecordState::Failed;
        record.reason = error.to_string();
        self.store
            .compare_and_swap(target, Some(&old), &record)
            .map_err(TransactionError::Store)?;
        Err(error)
    }
}

fn action_fingerprint(action: &Action) -> &str {
    action
        .preconditions
        .iter()
        .find(|condition| condition.kind == "EVIDENCE_FINGERPRINT_MATCHES")
        .and_then(|condition| condition.value.as_ref())
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}
fn context_from_live(context: &mut PolicyContext, live: &LiveEvidence) {
    context.target_revalidated = true;
    context.pane_matches = true;
    context.process_alive = true;
    context.composer_empty = live.composer_safe;
    context.human_intervened = live.human_intervened;
    context.evidence_current = true;
    context.evidence_fingerprint = Some(live.event.evidence_fingerprint.clone());
    context.source_rank = live.event.source.kind.rank();
    context.session_id = live.event.session_id.clone();
}
fn verified(before: &LiveEvidence, after: &LiveEvidence) -> bool {
    before.identity == after.identity
        && !after.human_intervened
        && after.event.confidence >= before.event.confidence
        && after.event.source.kind.rank() >= before.event.source.kind.rank()
        && progress(after.event.category)
}
fn progress(category: EventCategory) -> bool {
    matches!(
        category,
        EventCategory::Working | EventCategory::Idle | EventCategory::Recovered
    )
}
