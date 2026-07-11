use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{Action, ActionKind, Condition, Event, EventCategory};
use crate::policy::{CompiledPolicy, PolicyContext};
use crate::recovery::actuator::{ActionExecutor, ExecutionError, ExecutionOutput, validate_action};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OwnerIdentity {
    pub pid: u32,
    pub process_start_time: u64,
    pub nonce: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionPhase {
    Prepared,
    Begun,
    Sent,
    Verifying,
    Succeeded,
    Failed,
    Uncertain,
    HumanRequired,
}
impl ActionPhase {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::HumanRequired)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionRecord {
    pub action_id: String,
    pub idempotency_key: String,
    pub target: String,
    pub identity: String,
    pub fingerprint: String,
    pub owner: OwnerIdentity,
    pub prepared_at_ms: u64,
    pub lease_deadline_ms: u64,
    pub phase: ActionPhase,
    pub reason: String,
    pub snapshot: String,
    pub output: Option<String>,
}
impl ActionRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn prepared(
        action_id: &str,
        idempotency_key: &str,
        target: &str,
        owner: OwnerIdentity,
        now: u64,
        lease_deadline: u64,
        identity: &str,
        fingerprint: &str,
        snapshot: &str,
    ) -> Self {
        Self {
            action_id: action_id.into(),
            idempotency_key: idempotency_key.into(),
            target: target.into(),
            identity: identity.into(),
            fingerprint: fingerprint.into(),
            owner,
            prepared_at_ms: now,
            lease_deadline_ms: lease_deadline,
            phase: ActionPhase::Prepared,
            reason: "policy, evidence, identity and preconditions confirmed".into(),
            snapshot: snapshot.into(),
            output: None,
        }
    }
    pub fn next(&self, phase: ActionPhase, reason: impl Into<String>) -> Self {
        let mut next = self.clone();
        next.phase = phase;
        next.reason = reason.into();
        next
    }
}

/// Implementations must atomically claim one active transaction per target and
/// retain every appended record. `Ok` means the record is durable, never merely queued.
pub trait ActionStore: Send + Sync {
    fn claim_prepared(&self, target: &str, record: ActionRecord) -> Result<bool, String>;
    fn append(&self, target: &str, record: ActionRecord) -> Result<(), String>;
    fn active(&self, target: &str) -> Result<Option<ActionRecord>, String>;
    fn audit(&self, target: &str) -> Result<Vec<ActionRecord>, String>;
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
    fn wall_time_rfc3339(&self) -> String;
    fn sleep_ms(&self, duration: u64);
}
pub trait ProcessProbe {
    fn matches(&self, owner: &OwnerIdentity) -> bool;
}

#[derive(Clone, Debug)]
pub struct RecoveryContext {
    pub attempts_remaining: u32,
    pub cumulative_wait_remaining_seconds: u64,
    pub planner_calls_remaining: u32,
    pub planner_concurrency_available: bool,
    pub cooldown_ready: bool,
    pub session_id: Option<String>,
    pub failed_provider_family: Option<String>,
    pub planner_provider_family: Option<String>,
}
impl RecoveryContext {
    pub fn from_watcher(
        watcher: &crate::model::WatcherState,
        now_monotonic_seconds: u64,
    ) -> Result<Self, &'static str> {
        let machine = watcher
            .recovery
            .as_ref()
            .ok_or("missing recovery machine")?;
        let event = watcher
            .last_observation
            .as_ref()
            .ok_or("missing current evidence")?;
        if machine.state() != crate::recovery::state_machine::RecoveryState::Confirmed
            || !event.category.is_actionable()
        {
            return Err("recovery is not confirmed");
        }
        let budget = machine.budget();
        Ok(Self {
            attempts_remaining: budget.max_attempts.saturating_sub(machine.attempts()),
            cumulative_wait_remaining_seconds: budget
                .max_cumulative_wait
                .saturating_sub(machine.cumulative_wait())
                .as_secs(),
            planner_calls_remaining: budget.planner_calls.saturating_sub(machine.planner_calls()),
            planner_concurrency_available: false,
            cooldown_ready: machine.last_attempt_monotonic_seconds().is_none_or(|last| {
                now_monotonic_seconds.saturating_sub(last) >= budget.cooldown.as_secs()
            }),
            session_id: event.session_id.clone(),
            failed_provider_family: event.provider_family.clone(),
            planner_provider_family: None,
        })
    }
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("duplicate or in-flight action")]
    Duplicate,
    #[error("active transaction owner is still alive")]
    ActiveOwner,
    #[error("live state changed: {0}")]
    Revalidation(&'static str),
    #[error("policy denied action: {0}")]
    Policy(&'static str),
    #[error("action execution failed: {0}")]
    Execution(String),
    #[error("postcondition verification failed")]
    VerificationFailed,
    #[error("action outcome is uncertain: {0}")]
    Uncertain(String),
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
    const LEASE_MS: u64 = 30_000;
    const POLL_MS: u64 = 100;
    pub const fn new(store: &'a S, evidence: &'a E, executor: &'a X, clock: &'a C) -> Self {
        Self {
            store,
            evidence,
            executor,
            clock,
        }
    }

    pub fn recover_after_restart(
        &self,
        target: &str,
    ) -> Result<Option<ActionRecord>, TransactionError> {
        let Some(record) = self.store.active(target).map_err(TransactionError::Store)? else {
            return Ok(None);
        };
        let (phase, reason) = if record.phase == ActionPhase::Prepared {
            (
                ActionPhase::Failed,
                "restart cancelled prepared action before side effect",
            )
        } else {
            (
                ActionPhase::HumanRequired,
                "restart found action after commit boundary; blind retry forbidden",
            )
        };
        let terminal = record.next(phase, reason);
        self.store
            .append(target, terminal.clone())
            .map_err(TransactionError::Store)?;
        Ok(Some(terminal))
    }

    pub fn recover_stale(
        &self,
        target: &str,
        probe: &dyn ProcessProbe,
    ) -> Result<Option<ActionRecord>, TransactionError> {
        let Some(record) = self.store.active(target).map_err(TransactionError::Store)? else {
            return Ok(None);
        };
        if self.clock.monotonic_ms() <= record.lease_deadline_ms || probe.matches(&record.owner) {
            return Err(TransactionError::ActiveOwner);
        }
        let phase = if record.phase == ActionPhase::Prepared {
            ActionPhase::Failed
        } else {
            ActionPhase::HumanRequired
        };
        let terminal = record.next(
            phase,
            "expired lease owned by a different pid/start identity",
        );
        self.store
            .append(target, terminal.clone())
            .map_err(TransactionError::Store)?;
        Ok(Some(terminal))
    }

    pub fn run(
        &self,
        target: &str,
        owner: OwnerIdentity,
        action: Action,
        recovery: RecoveryContext,
    ) -> Result<ActionRecord, TransactionError> {
        validate_action(&action).map_err(|error| TransactionError::Execution(error.to_string()))?;
        let baseline = self.revalidate(&action, None)?;
        let policy = policy_context(&baseline, &recovery, self.clock.wall_time_rfc3339());
        CompiledPolicy
            .authorize(&action, &policy)
            .map_err(TransactionError::Policy)?;
        let confirmed = self.revalidate(&action, Some(&baseline))?;
        let now = self.clock.monotonic_ms();
        let key = format!(
            "{}:{}:{}",
            target, action.action_id, baseline.event.evidence_fingerprint
        );
        let snapshot = serde_json::to_string(&serde_json::json!({"policy":"authorized","source":baseline.event.source,"confidence":baseline.event.confidence,"preconditions":action.preconditions})).map_err(|e| TransactionError::Store(e.to_string()))?;
        let mut record = ActionRecord::prepared(
            &action.action_id,
            &key,
            target,
            owner,
            now,
            now.saturating_add(Self::LEASE_MS),
            &baseline.identity,
            &baseline.event.evidence_fingerprint,
            &snapshot,
        );
        if !self
            .store
            .claim_prepared(target, record.clone())
            .map_err(TransactionError::Store)?
        {
            return Err(TransactionError::Duplicate);
        }
        if let Err(error) = self.revalidate(&action, Some(&confirmed)) {
            return self.terminate(target, record, ActionPhase::Failed, error);
        }
        record = self.persist(
            target,
            record,
            ActionPhase::Begun,
            "commit boundary entered",
        )?;
        let output = match self.executor.execute(&action) {
            Ok(output) => output,
            Err(ExecutionError::PossibleSideEffect(reason)) => {
                return self.uncertain(target, record, reason);
            }
            Err(error) => {
                return self.terminate(
                    target,
                    record,
                    ActionPhase::Failed,
                    TransactionError::Execution(error.to_string()),
                );
            }
        };
        record.output = Some(output_summary(&output));
        record = match self.persist(
            target,
            record,
            ActionPhase::Sent,
            "executor completed action unit",
        ) {
            Ok(record) => record,
            Err(error) => return Err(TransactionError::Uncertain(error.to_string())),
        };
        if !needs_progress_verification(&action.kind) {
            return self.persist(
                target,
                record,
                ActionPhase::Succeeded,
                "non-input action completed durably",
            );
        }
        record = match self.persist(
            target,
            record,
            ActionPhase::Verifying,
            "polling canonical expected outcomes",
        ) {
            Ok(record) => record,
            Err(error) => return Err(TransactionError::Uncertain(error.to_string())),
        };
        let deadline = self
            .clock
            .monotonic_ms()
            .saturating_add(action.timeout_seconds.saturating_mul(1000));
        loop {
            let after = self
                .evidence
                .read()
                .map_err(|e| TransactionError::Uncertain(e.to_string()))?;
            if after.human_intervened || after.identity != baseline.identity {
                return self.uncertain(
                    target,
                    record,
                    "human intervention or identity contradiction during verification".into(),
                );
            }
            if verified(&baseline, &after, &action.expected_outcomes) {
                return self.persist(
                    target,
                    record,
                    ActionPhase::Succeeded,
                    "canonical expected outcome verified",
                );
            }
            if self.clock.monotonic_ms() >= deadline {
                return self.uncertain(
                    target,
                    record,
                    "verification timed out after possible side effect".into(),
                );
            }
            self.clock.sleep_ms(Self::POLL_MS);
        }
    }

    fn persist(
        &self,
        target: &str,
        record: ActionRecord,
        phase: ActionPhase,
        reason: &str,
    ) -> Result<ActionRecord, TransactionError> {
        let next = record.next(phase, reason);
        self.store
            .append(target, next.clone())
            .map_err(TransactionError::Store)?;
        Ok(next)
    }
    fn terminate(
        &self,
        target: &str,
        record: ActionRecord,
        phase: ActionPhase,
        error: TransactionError,
    ) -> Result<ActionRecord, TransactionError> {
        let next = record.next(phase, error.to_string());
        self.store
            .append(target, next)
            .map_err(TransactionError::Store)?;
        Err(error)
    }
    fn uncertain(
        &self,
        target: &str,
        record: ActionRecord,
        reason: String,
    ) -> Result<ActionRecord, TransactionError> {
        let uncertain = record.next(ActionPhase::Uncertain, &reason);
        if self.store.append(target, uncertain.clone()).is_ok() {
            let human = uncertain.next(
                ActionPhase::HumanRequired,
                "possible side effect requires human review",
            );
            let _ = self.store.append(target, human);
        }
        Err(TransactionError::Uncertain(reason))
    }
    fn revalidate(
        &self,
        action: &Action,
        baseline: Option<&LiveEvidence>,
    ) -> Result<LiveEvidence, TransactionError> {
        let live = self.evidence.read().map_err(TransactionError::Store)?;
        if live.human_intervened {
            return Err(TransactionError::Revalidation("human intervention"));
        }
        if requires_composer(&action.kind) && !live.composer_safe {
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
                "identity or evidence source changed",
            ));
        }
        Ok(live)
    }
}

fn requires_composer(kind: &ActionKind) -> bool {
    matches!(
        kind,
        ActionKind::SendText { .. } | ActionKind::SendKeys { .. }
    )
}
fn needs_progress_verification(kind: &ActionKind) -> bool {
    requires_composer(kind)
}
fn action_fingerprint(action: &Action) -> &str {
    action
        .preconditions
        .iter()
        .find(|c| c.kind == "EVIDENCE_FINGERPRINT_MATCHES")
        .and_then(|c| c.value.as_ref())
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}
fn policy_context(live: &LiveEvidence, recovery: &RecoveryContext, wall: String) -> PolicyContext {
    let mut context = PolicyContext::safe();
    context.composer_empty = live.composer_safe;
    context.human_intervened = live.human_intervened;
    context.source_rank = live.event.source.kind.rank();
    context.attempts_remaining = recovery.attempts_remaining;
    context.cumulative_wait_remaining_seconds = recovery.cumulative_wait_remaining_seconds;
    context.planner_calls_remaining = recovery.planner_calls_remaining;
    context.planner_concurrency_available = recovery.planner_concurrency_available;
    context.cooldown_ready = recovery.cooldown_ready;
    context.session_id = recovery.session_id.clone();
    context.failed_provider_family = recovery.failed_provider_family.clone();
    context.planner_provider_family = recovery.planner_provider_family.clone();
    context.evidence_fingerprint = Some(live.event.evidence_fingerprint.clone());
    context.event_category = Some(format!("{:?}", live.event.category).to_ascii_uppercase());
    context.wall_time_rfc3339 = Some(wall);
    context
}
fn output_summary(output: &ExecutionOutput) -> String {
    match output {
        ExecutionOutput::Captured(text) => format!("captured {} bytes", text.len()),
        other => format!("{other:?}"),
    }
}
fn verified(before: &LiveEvidence, after: &LiveEvidence, outcomes: &[Condition]) -> bool {
    if after.event.source.kind.rank() < before.event.source.kind.rank()
        || after.event.confidence < before.event.confidence
        || after.event.evidence_fingerprint == before.event.evidence_fingerprint
    {
        return false;
    }
    outcomes.iter().any(|outcome| match outcome.kind.as_str() {
        "AGENT_WORKING" | "GOAL_ACTIVE_OR_PURSUING" => {
            after.event.category == EventCategory::Working
        }
        "AGENT_IDLE" => after.event.category == EventCategory::Idle,
        "BLOCK_CLEARED" | "MENU_DISMISSED" => !after.event.category.is_actionable(),
        "PROCESS_TERMINATED" => after.event.category == EventCategory::Terminated,
        _ => false,
    })
}
