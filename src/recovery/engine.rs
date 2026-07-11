use crate::model::{Action, ActionKind, Condition, EventCategory, PolicyHint, WatcherState};
use crate::recovery::actuator::ActionExecutor;
use crate::recovery::transaction::{
    ActionRecord, ActionStore, Clock, EvidenceReader, OwnerIdentity, ProcessProbe, RecoveryContext,
    Transaction, TransactionError,
};

/// Deterministic adapters supply recipes in later slices. The production daemon
/// still owns this engine now, so observations and durable recovery share one path.
pub trait RecipeProvider: Send + Sync {
    fn action_for(&self, watcher: &WatcherState) -> Option<Action>;
}

impl RecipeProvider for std::sync::Arc<dyn RecipeProvider> {
    fn action_for(&self, watcher: &WatcherState) -> Option<Action> {
        self.as_ref().action_for(watcher)
    }
}
/// Provider-independent recipes are intentionally limited to scheduling a
/// future observation. Input recovery belongs to the provider adapters, which
/// have the structured evidence needed to justify it.
pub struct BuiltinRecipes;
impl RecipeProvider for BuiltinRecipes {
    fn action_for(&self, watcher: &WatcherState) -> Option<Action> {
        let event = watcher.last_observation.as_ref()?;
        if event.policy_hint != PolicyHint::WaitAllowed
            || !matches!(
                event.category,
                EventCategory::WaitingForModel | EventCategory::WaitingForTool
            )
        {
            return None;
        }
        let mut action = Action::new(
            "builtin.wait",
            ActionKind::WaitDuration {
                duration_seconds: 60,
            },
            "explicit wait-allowed observation",
            event.evidence_fingerprint.clone(),
            30,
        );
        action.preconditions.extend([
            Condition {
                kind: "PROCESS_ALIVE".into(),
                value: None,
            },
            Condition {
                kind: "EVENT_CATEGORY_IS".into(),
                value: Some(serde_json::Value::String(
                    format!("{:?}", event.category).to_ascii_uppercase(),
                )),
            },
        ]);
        action.expected_outcomes = vec![Condition {
            kind: "WAIT_STATE_RECORDED".into(),
            value: None,
        }];
        Some(action)
    }
}

pub struct RecoveryEngine<S, P> {
    store: S,
    recipes: P,
}
impl<S, P> RecoveryEngine<S, P> {
    pub const fn new(store: S, recipes: P) -> Self {
        Self { store, recipes }
    }
    pub const fn store(&self) -> &S {
        &self.store
    }
}
impl<S: ActionStore, P: RecipeProvider> RecoveryEngine<S, P> {
    pub fn proposed_action(&self, watcher: &WatcherState) -> Option<Action> {
        self.recipes.action_for(watcher)
    }
    pub fn execute<E: EvidenceReader, X: ActionExecutor, C: Clock>(
        &self,
        watcher: &WatcherState,
        owner: OwnerIdentity,
        evidence: &E,
        executor: &X,
        clock: &C,
    ) -> Result<Option<ActionRecord>, TransactionError> {
        let Some(action) = self.proposed_action(watcher) else {
            return Ok(None);
        };
        let context = RecoveryContext::from_watcher(watcher, clock.monotonic_ms() / 1000)
            .map_err(TransactionError::Policy)?;
        Transaction::new(&self.store, evidence, executor, clock)
            .run(&watcher.watcher_id, owner, action, context)
            .map(Some)
    }
    pub fn recover_after_restart<E: EvidenceReader, X: ActionExecutor, C: Clock>(
        &self,
        target: &str,
        evidence: &E,
        executor: &X,
        clock: &C,
    ) -> Result<Option<ActionRecord>, TransactionError> {
        Transaction::new(&self.store, evidence, executor, clock).recover_after_restart(target)
    }
    pub fn recover_stale<E: EvidenceReader, X: ActionExecutor, C: Clock>(
        &self,
        target: &str,
        probe: &dyn ProcessProbe,
        evidence: &E,
        executor: &X,
        clock: &C,
    ) -> Result<Option<ActionRecord>, TransactionError> {
        Transaction::new(&self.store, evidence, executor, clock).recover_stale(target, probe)
    }
}
