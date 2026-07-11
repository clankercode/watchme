use crate::model::{Action, WatcherState};
use crate::recovery::actuator::ActionExecutor;
use crate::recovery::transaction::{
    ActionRecord, ActionStore, Clock, EvidenceReader, OwnerIdentity, RecoveryContext, Transaction,
    TransactionError,
};

/// Deterministic adapters supply recipes in later slices. The production daemon
/// still owns this engine now, so observations and durable recovery share one path.
pub trait RecipeProvider: Send + Sync {
    fn action_for(&self, watcher: &WatcherState) -> Option<Action>;
}
pub struct NoRecipes;
impl RecipeProvider for NoRecipes {
    fn action_for(&self, _: &WatcherState) -> Option<Action> {
        None
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
}
