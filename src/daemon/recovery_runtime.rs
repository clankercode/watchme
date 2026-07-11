use super::{
    DaemonRuntimeServices, Registry, SystemRecoveryClock, WatcherLifecycle, capture_mux_target,
    execute_mux_action, mux_identity_key, now_ms, process_identity_key, target_identity_hash,
    target_process_is_alive, validate_mux_target, watcher_mux_identity,
};
use crate::mux::ComposerSafety;
use crate::recovery::actuator::{ActionExecutor, ExecutionError, ExecutionOutput, RuntimeActuator};
use crate::recovery::transaction::{EvidenceReader, LiveEvidence, OwnerIdentity};

/// Reads the durable watcher at every transaction boundary. A revision or
/// lifecycle change is evidence of concurrent ownership and fails closed.
pub(super) struct FreshTargetEvidence {
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    watcher_id: String,
    expected_revision: u64,
    expected_lifecycle: WatcherLifecycle,
}

impl FreshTargetEvidence {
    pub(super) fn new(
        registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
        watcher_id: String,
        expected_revision: u64,
        expected_lifecycle: WatcherLifecycle,
    ) -> Self {
        Self {
            registry,
            watcher_id,
            expected_revision,
            expected_lifecycle,
        }
    }

    fn watcher(&self) -> Result<crate::model::WatcherState, String> {
        self.registry
            .blocking_lock()
            .get(&self.watcher_id)
            .cloned()
            .ok_or_else(|| "recovery watcher disappeared".to_owned())
    }

    fn unchanged(&self, watcher: &crate::model::WatcherState) -> bool {
        watcher.revision == self.expected_revision && watcher.lifecycle == self.expected_lifecycle
    }
}

impl EvidenceReader for FreshTargetEvidence {
    fn read(&self) -> Result<LiveEvidence, String> {
        let watcher = self.watcher()?;
        let event = watcher
            .last_observation
            .clone()
            .ok_or_else(|| "missing current observation".to_owned())?;
        let unchanged = self.unchanged(&watcher);
        let process_alive = target_process_is_alive(&watcher.target);
        let (target_revalidated, pane_matches, identity, composer_safe) =
            match watcher_mux_identity(&watcher) {
                Ok(Some(identity)) => {
                    let validated = validate_mux_target(&watcher, &identity).is_ok();
                    let composer_safe = validated
                        && RuntimeComposerSafety::new(watcher.clone())
                            .observe(&identity)
                            .is_ok_and(|state| state == crate::mux::ComposerState::Safe);
                    (
                        validated,
                        validated,
                        mux_identity_key(&identity),
                        composer_safe,
                    )
                }
                Ok(None) => (
                    process_alive,
                    true,
                    process_identity_key(&watcher.target),
                    false,
                ),
                Err(_) => (false, false, process_identity_key(&watcher.target), false),
            };
        let event_matches = event.watcher_id == watcher.watcher_id
            && event.target_identity_hash == target_identity_hash(&watcher.target);
        let human_intervened = !unchanged
            || matches!(
                watcher.lifecycle,
                WatcherLifecycle::Paused
                    | WatcherLifecycle::Stopped { .. }
                    | WatcherLifecycle::HumanRequired { .. }
                    | WatcherLifecycle::TargetTerminated
            )
            || event.category == crate::model::EventCategory::HumanIntervention;
        Ok(LiveEvidence {
            identity,
            target_revalidated,
            process_alive,
            pane_matches,
            evidence_current: unchanged && event_matches,
            composer_safe,
            human_intervened,
            event,
        })
    }
}

pub(super) struct RuntimeComposerSafety {
    watcher: crate::model::WatcherState,
}

impl RuntimeComposerSafety {
    pub(super) fn new(watcher: crate::model::WatcherState) -> Self {
        Self { watcher }
    }
}

impl ComposerSafety for RuntimeComposerSafety {
    fn observe(
        &self,
        identity: &crate::mux::MuxIdentity,
    ) -> Result<crate::mux::ComposerState, crate::mux::MuxError> {
        let capture = capture_mux_target(&self.watcher, identity, 3, 1_024)?;
        Ok(
            if capture
                .text
                .lines()
                .next_back()
                .is_none_or(|line| line.trim().is_empty())
            {
                crate::mux::ComposerState::Safe
            } else {
                crate::mux::ComposerState::Unsafe
            },
        )
    }
}

struct DaemonActionExecutor {
    services: DaemonRuntimeServices,
    evidence: FreshTargetEvidence,
}

impl DaemonActionExecutor {
    fn new(
        registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
        watcher: &crate::model::WatcherState,
    ) -> Self {
        Self {
            services: DaemonRuntimeServices::new(registry.clone(), watcher.watcher_id.clone()),
            evidence: FreshTargetEvidence::new(
                registry,
                watcher.watcher_id.clone(),
                watcher.revision,
                watcher.lifecycle.clone(),
            ),
        }
    }

    fn live_watcher(&self) -> Result<crate::model::WatcherState, ExecutionError> {
        let live = self.evidence.read().map_err(ExecutionError::Integration)?;
        if live.human_intervened
            || !live.target_revalidated
            || !live.process_alive
            || !live.pane_matches
        {
            return Err(ExecutionError::Unsafe("target changed before dispatch"));
        }
        self.evidence.watcher().map_err(ExecutionError::Integration)
    }
}

impl ActionExecutor for DaemonActionExecutor {
    fn execute(&self, action: &crate::model::Action) -> Result<ExecutionOutput, ExecutionError> {
        use crate::model::ActionKind;
        match &action.kind {
            ActionKind::SendText { .. } | ActionKind::SendKeys { .. } => {
                let watcher = self.live_watcher()?;
                execute_mux_action(&watcher, action)
            }
            ActionKind::Capture { source, max_lines } => {
                let watcher = self.live_watcher()?;
                execute_capture(&watcher, source, *max_lines)
            }
            ActionKind::Notify { .. } => Err(ExecutionError::Unsafe(
                "notification is not an autonomous recovery action",
            )),
            _ => RuntimeActuator::new(&self.services).execute(action),
        }
    }
}

fn execute_capture(
    watcher: &crate::model::WatcherState,
    source: &str,
    max_lines: u16,
) -> Result<ExecutionOutput, ExecutionError> {
    if source != "screen_detection" && source != "screen_recent" {
        return Err(ExecutionError::Unsafe(
            "unsupported capture source for target",
        ));
    }
    let identity = watcher_mux_identity(watcher)
        .map_err(|error| ExecutionError::Integration(error.to_string()))?
        .ok_or(ExecutionError::Unsafe(
            "capture requires a multiplexer target",
        ))?;
    capture_mux_target(watcher, &identity, usize::from(max_lines), 32 * 1024)
        .map(|capture| ExecutionOutput::Captured(capture.text))
        .map_err(|error| ExecutionError::Integration(error.to_string()))
}

pub(super) fn execute_recovery_action(
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    engine: std::sync::Arc<
        crate::recovery::engine::RecoveryEngine<
            crate::recovery::action_store::JsonActionStore,
            crate::recovery::engine::BuiltinRecipes,
        >,
    >,
    watcher: crate::model::WatcherState,
    owner: OwnerIdentity,
) {
    let Some(action) = engine.proposed_action(&watcher) else {
        return;
    };
    let fingerprint = action
        .preconditions
        .iter()
        .find(|condition| condition.kind == "EVIDENCE_FINGERPRINT_MATCHES")
        .and_then(|condition| condition.value.as_ref())
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if fingerprint.is_empty() {
        return;
    }
    let clock = SystemRecoveryClock::new();
    let current = {
        let mut guard = registry.blocking_lock();
        let snapshot = crate::recovery::state_machine::ClockSnapshot::new(
            crate::recovery::transaction::Clock::monotonic_ms(&clock) / 1_000,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        );
        if crate::recovery::coordinator::RecoveryCoordinator::new(&mut guard)
            .begin_action(&watcher.watcher_id, &fingerprint, snapshot, now_ms())
            .is_err()
        {
            return;
        }
        guard.get(&watcher.watcher_id).cloned()
    };
    let Some(current) = current else { return };
    let evidence = FreshTargetEvidence::new(
        registry.clone(),
        current.watcher_id.clone(),
        current.revision,
        current.lifecycle.clone(),
    );
    let executor = DaemonActionExecutor::new(registry.clone(), &current);
    match engine.execute(&current, owner, &evidence, &executor, &clock) {
        Ok(Some(record))
            if record.phase == crate::recovery::transaction::ActionPhase::Succeeded =>
        {
            let _ = crate::recovery::coordinator::RecoveryCoordinator::new(
                &mut registry.blocking_lock(),
            )
            .action_succeeded(&current.watcher_id, &fingerprint, now_ms());
        }
        Ok(_) => {}
        Err(error) => {
            let _ = registry.blocking_lock().transition(
                &current.watcher_id,
                WatcherLifecycle::HumanRequired {
                    reason: format!("recovery action requires review: {error}"),
                },
                now_ms(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::registry::Registry;
    use crate::model::{
        Event, EventCategory, EventSource, PolicyHint, ProcessIdentity, SourceKind, TargetIdentity,
        WatcherState,
    };
    use crate::store::JsonStore;

    #[test]
    fn durable_reader_rejects_pause_after_its_baseline_revision() {
        let temp = tempfile::tempdir().unwrap();
        let mut registry =
            Registry::load(JsonStore::new(temp.path().join("watchers.json"))).unwrap();
        let target = TargetIdentity::process(ProcessIdentity::new(std::process::id(), 1));
        let mut watcher = WatcherState::new(
            "live-reader".into(),
            target.clone(),
            WatcherLifecycle::Observing,
            0,
            1,
        );
        watcher.last_observation = Some(
            Event::new(
                "event",
                "2026-07-11T00:00:00Z",
                "live-reader",
                target_identity_hash(&target),
                EventSource::new(SourceKind::StructuredLog, "test", "state"),
                EventCategory::BlockedGoal,
                1.0,
                false,
                "a".repeat(64),
                "blocked",
                PolicyHint::DeterministicActionAllowed,
            )
            .unwrap(),
        );
        registry.register(watcher).unwrap();
        let revision = registry.get("live-reader").unwrap().revision;
        let registry = std::sync::Arc::new(tokio::sync::Mutex::new(registry));
        let reader = FreshTargetEvidence::new(
            registry.clone(),
            "live-reader".into(),
            revision,
            WatcherLifecycle::Observing,
        );
        registry
            .blocking_lock()
            .transition("live-reader", WatcherLifecycle::Paused, 2)
            .unwrap();

        let current = reader.read().unwrap();
        assert!(current.human_intervened);
        assert!(!current.evidence_current);
    }
}
