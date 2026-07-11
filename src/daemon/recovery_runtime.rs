use super::{
    DaemonRuntimeServices, Registry, SystemRecoveryClock, WatcherLifecycle, capture_mux_target,
    execute_mux_action, mux_identity_key, now_ms, process_identity_key, target_identity_hash,
    target_process_is_alive, validate_mux_target, watcher_mux_identity,
};
use crate::daemon::registry::DispatchSnapshot;
use crate::mux::ComposerSafety;
use crate::recovery::actuator::{ActionExecutor, ExecutionError, ExecutionOutput, RuntimeActuator};
use crate::recovery::transaction::{EvidenceReader, LiveEvidence, OwnerIdentity};

/// Reads the durable watcher at every transaction boundary. Target and
/// lifecycle changes are evidence of concurrent ownership and fail closed;
/// a new observation of the same live target is instead the evidence needed
/// to verify a dispatched input action.
pub(super) struct FreshTargetEvidence {
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    snapshot: DispatchSnapshot,
}

impl FreshTargetEvidence {
    pub(super) fn new(
        registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
        snapshot: DispatchSnapshot,
    ) -> Self {
        Self { registry, snapshot }
    }

    fn watcher(&self) -> Result<crate::model::WatcherState, String> {
        self.registry
            .blocking_lock()
            .get(&self.snapshot.watcher().watcher_id)
            .cloned()
            .ok_or_else(|| "recovery watcher disappeared".to_owned())
    }

    fn target_and_lifecycle_are_stable(&self, watcher: &crate::model::WatcherState) -> bool {
        watcher.target == self.snapshot.watcher().target
            && watcher.lifecycle == self.snapshot.watcher().lifecycle
    }
}

impl EvidenceReader for FreshTargetEvidence {
    fn read(&self) -> Result<LiveEvidence, String> {
        let watcher = self.watcher()?;
        let event = watcher
            .last_observation
            .clone()
            .ok_or_else(|| "missing current observation".to_owned())?;
        let target_and_lifecycle_are_stable = self.target_and_lifecycle_are_stable(&watcher);
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
        let human_intervened = !target_and_lifecycle_are_stable
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
            evidence_current: event_matches,
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
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    services: DaemonRuntimeServices,
    evidence: FreshTargetEvidence,
    snapshot: DispatchSnapshot,
    #[cfg(test)]
    before_mux_dispatch: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

impl DaemonActionExecutor {
    fn new(
        registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
        snapshot: DispatchSnapshot,
    ) -> Self {
        Self {
            services: DaemonRuntimeServices::new(
                registry.clone(),
                snapshot.watcher().watcher_id.clone(),
            ),
            evidence: FreshTargetEvidence::new(registry.clone(), snapshot.clone()),
            registry,
            snapshot,
            #[cfg(test)]
            before_mux_dispatch: None,
        }
    }

    #[cfg(test)]
    fn with_before_mux_dispatch(
        registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
        snapshot: DispatchSnapshot,
        hook: std::sync::Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        let mut executor = Self::new(registry, snapshot);
        executor.before_mux_dispatch = Some(hook);
        executor
    }

    fn before_mux_dispatch(&self) {
        #[cfg(test)]
        if let Some(hook) = &self.before_mux_dispatch {
            hook();
        }
    }

    fn confirm_live_evidence(&self) -> Result<(), ExecutionError> {
        let live = self.evidence.read().map_err(ExecutionError::Integration)?;
        if live.human_intervened
            || !live.target_revalidated
            || !live.process_alive
            || !live.pane_matches
        {
            return Err(ExecutionError::Unsafe("target changed before dispatch"));
        }
        Ok(())
    }

    fn locked_snapshot_watcher(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, Registry>, ExecutionError> {
        let guard = self.registry.blocking_lock();
        if !guard.matches_dispatch_snapshot(&self.snapshot) {
            return Err(ExecutionError::Unsafe("target changed before dispatch"));
        }
        Ok(guard)
    }
}

impl ActionExecutor for DaemonActionExecutor {
    fn execute(&self, action: &crate::model::Action) -> Result<ExecutionOutput, ExecutionError> {
        use crate::model::ActionKind;
        match &action.kind {
            ActionKind::SendText { .. } | ActionKind::SendKeys { .. } => {
                self.confirm_live_evidence()?;
                self.before_mux_dispatch();
                // Keep the registry lock through the mux command.  Retarget,
                // pause, and stop all require this same lock, making the
                // revision check and external side effect one critical region.
                let guard = self.locked_snapshot_watcher()?;
                let result = execute_mux_action(self.snapshot.watcher(), action);
                drop(guard);
                result
            }
            ActionKind::Capture { source, max_lines } => {
                self.confirm_live_evidence()?;
                let guard = self.locked_snapshot_watcher()?;
                let result = execute_capture(self.snapshot.watcher(), source, *max_lines);
                drop(guard);
                result
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
    if !capture_source_matches(watcher, source) {
        return Err(ExecutionError::Unsafe(
            "capture source does not match current adapter observation",
        ));
    }
    let identity = watcher_mux_identity(watcher)
        .map_err(|error| ExecutionError::Integration(error.to_string()))?
        .ok_or(ExecutionError::Unsafe(
            "capture requires a multiplexer target",
        ))?;
    if source == "structured_state" {
        return capture_herdr_structured_state(watcher, &identity, max_lines);
    }
    capture_mux_target(watcher, &identity, usize::from(max_lines), 32 * 1024)
        .map(|capture| ExecutionOutput::Captured(capture.text))
        .map_err(|error| ExecutionError::Integration(error.to_string()))
}

/// A capture recipe is allowed to read only the concrete subsystem that
/// produced the current durable evidence.  There is deliberately no generic
/// `log_tail` path: no adapter currently provides a correlated log reader.
fn capture_source_matches(watcher: &crate::model::WatcherState, requested: &str) -> bool {
    let Some(event) = watcher.last_observation.as_ref() else {
        return false;
    };
    match (requested, watcher.target.observation_context()) {
        (
            "screen_detection" | "screen_recent",
            Some(crate::model::MultiplexerContext::Tmux { .. }),
        ) => {
            event.source.kind == crate::model::SourceKind::ScreenDetection
                && event.source.source_id == "tmux"
        }
        ("structured_state", Some(crate::model::MultiplexerContext::Herdr { .. })) => {
            event.source.kind == crate::model::SourceKind::HerdrAgentState
                && event.source.source_id == "herdr"
                && event.source.rule_or_field == "typed_pane_state"
        }
        // A correlated log reader has not been implemented, so this source
        // remains intentionally unavailable rather than falling back to a
        // pane capture that could belong to another session.
        ("log_tail", _) | (_, _) => false,
    }
}

fn capture_herdr_structured_state(
    watcher: &crate::model::WatcherState,
    identity: &crate::mux::MuxIdentity,
    max_events: u16,
) -> Result<ExecutionOutput, ExecutionError> {
    let Some(crate::model::MultiplexerContext::Herdr {
        socket_path,
        workspace_id,
        tab_id,
        pane_id,
        ..
    }) = watcher.target.observation_context()
    else {
        return Err(ExecutionError::Unsafe(
            "structured state requires a Herdr target",
        ));
    };
    let event = watcher
        .last_observation
        .as_ref()
        .ok_or(ExecutionError::Unsafe("missing current observation"))?;
    if event.source.kind != crate::model::SourceKind::HerdrAgentState
        || event.source.source_id != "herdr"
        || event.source.rule_or_field != "typed_pane_state"
    {
        return Err(ExecutionError::Unsafe(
            "structured state source is not Herdr typed state",
        ));
    }
    let herdr = crate::mux::herdr::Herdr::new(
        crate::mux::herdr::HerdrContext {
            socket_path: socket_path.clone(),
            workspace_id: workspace_id.clone(),
            tab_id: tab_id.clone(),
            pane_id: pane_id.clone(),
        },
        std::time::Duration::from_secs(2),
    )
    .map_err(|error| ExecutionError::Integration(error.to_string()))?;
    let after = watcher.observation_schedule.herdr_after_sequence;
    let state = herdr
        .agent_state_events(identity, after, usize::from(max_events))
        .map_err(|error| ExecutionError::Integration(error.to_string()))?;
    serde_json::to_string(&state)
        .map(ExecutionOutput::Captured)
        .map_err(|error| ExecutionError::Integration(error.to_string()))
}

pub(super) fn execute_recovery_action(
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    engine: std::sync::Arc<super::DaemonRecoveryEngine>,
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
    let dispatch = {
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
        guard.dispatch_snapshot(&watcher.watcher_id).ok()
    };
    let Some(dispatch) = dispatch else { return };
    let current = dispatch.watcher().clone();
    let evidence = FreshTargetEvidence::new(registry.clone(), dispatch.clone());
    let executor = DaemonActionExecutor::new(registry.clone(), dispatch);
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
        Action, ActionKind, Event, EventCategory, EventSource, PolicyHint, ProcessIdentity,
        SourceKind, TargetIdentity, WatcherState,
    };
    use crate::mux::{
        Multiplexer,
        tmux::{Tmux, TmuxSelector},
    };
    use crate::recovery::action_store::JsonActionStore;
    use crate::recovery::coordinator::RecoveryCoordinator;
    use crate::recovery::engine::{RecipeProvider, RecoveryEngine};
    use crate::recovery::state_machine::{Budget, RecoveryCommand, RecoveryMachine};
    use crate::recovery::transaction::{ActionPhase, ActionStore, OwnerIdentity, TransactionError};
    use crate::store::JsonStore;
    use std::process::Command;
    use std::time::{Duration, Instant};

    struct CaptureRecipe;
    impl RecipeProvider for CaptureRecipe {
        fn action_for(&self, watcher: &WatcherState) -> Option<Action> {
            let event = watcher.last_observation.as_ref()?;
            Some(Action::new(
                "test.capture",
                ActionKind::Capture {
                    source: "screen_recent".into(),
                    max_lines: 8,
                },
                "test concrete mux recovery",
                event.evidence_fingerprint.clone(),
                5,
            ))
        }
    }

    struct InputRecipe;
    impl RecipeProvider for InputRecipe {
        fn action_for(&self, watcher: &WatcherState) -> Option<Action> {
            let event = watcher.last_observation.as_ref()?;
            Some(Action::send_text(
                "test.input",
                "continue",
                "test dispatch-boundary interleaving",
                event.evidence_fingerprint.clone(),
            ))
        }
    }

    enum DispatchMutation {
        Pause,
        HumanRevision,
        RetargetPaneReuse,
    }

    struct TmuxServerGuard(String);
    impl Drop for TmuxServerGuard {
        fn drop(&mut self) {
            let _ = Command::new("tmux")
                .args(["-L", &self.0, "kill-server"])
                .output();
        }
    }

    #[test]
    fn injected_recipe_executes_a_real_tmux_capture_and_persists_its_receipt() {
        if Command::new("tmux").arg("-V").output().is_err() {
            return;
        }
        let socket = format!("watchme-recovery-{}", std::process::id());
        let _server = TmuxServerGuard(socket.clone());
        let status = Command::new("tmux")
            .args([
                "-f",
                "/dev/null",
                "-L",
                &socket,
                "new-session",
                "-d",
                "-s",
                "recovery",
                "sh",
                "-c",
                "printf 'recovery-ready\\n'; while IFS= read -r _; do :; done",
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let tmux = Tmux::for_socket_name(socket.clone(), Duration::from_secs(2));
        let deadline = Instant::now() + Duration::from_secs(2);
        let identity = loop {
            let candidate = tmux
                .resolve_selector(&TmuxSelector::parse("recovery").unwrap())
                .unwrap();
            if tmux
                .capture_tail(&candidate, 8, 1_024)
                .is_ok_and(|capture| capture.text.contains("recovery-ready"))
            {
                break candidate;
            }
            assert!(
                Instant::now() < deadline,
                "test tmux pane did not become ready"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let target = TargetIdentity::tmux(
            identity.server,
            identity.server_instance,
            identity.session_id,
            identity.window_id,
            identity.pane_id,
            identity.tty,
            identity.process,
            None,
        );
        let fingerprint = "c".repeat(64);
        let mut machine = RecoveryMachine::new(Budget {
            max_attempts: 2,
            max_cumulative_wait: Duration::from_secs(60),
            planner_calls: 0,
            cooldown: Duration::ZERO,
        });
        machine.apply(RecoveryCommand::Revalidated).unwrap();
        machine
            .apply(RecoveryCommand::Confirm {
                fingerprint: fingerprint.clone(),
            })
            .unwrap();
        let mut watcher = WatcherState::new(
            "real-tmux-recovery".into(),
            target.clone(),
            WatcherLifecycle::Observing,
            0,
            1,
        );
        watcher.recovery = Some(machine);
        watcher.last_observation = Some(
            Event::new(
                "event",
                "2026-07-11T00:00:00Z",
                "real-tmux-recovery",
                target_identity_hash(&target),
                EventSource::new(SourceKind::ScreenDetection, "tmux", "generic_tail"),
                EventCategory::BlockedGoal,
                0.9,
                false,
                fingerprint,
                "blocked",
                PolicyHint::DeterministicActionAllowed,
            )
            .unwrap(),
        );
        let temporary = tempfile::tempdir().unwrap();
        let mut registry =
            Registry::load(JsonStore::new(temporary.path().join("watchers.json"))).unwrap();
        registry.register(watcher.clone()).unwrap();
        let registry = std::sync::Arc::new(tokio::sync::Mutex::new(registry));
        let store = JsonActionStore::load(temporary.path().join("actions.json")).unwrap();
        let engine = std::sync::Arc::new(RecoveryEngine::new(
            store,
            std::sync::Arc::new(CaptureRecipe) as std::sync::Arc<dyn RecipeProvider>,
        ));

        execute_recovery_action(
            registry.clone(),
            engine.clone(),
            watcher,
            OwnerIdentity {
                pid: std::process::id(),
                process_start_time: 0,
                nonce: "test".into(),
            },
        );

        let audit = engine.store().audit("real-tmux-recovery").unwrap();
        assert!(
            audit
                .iter()
                .any(|entry| entry.phase == ActionPhase::Succeeded)
        );
        assert!(
            audit
                .last()
                .unwrap()
                .output
                .as_deref()
                .is_some_and(|output| output.contains("captured"))
        );
    }

    #[test]
    fn final_mux_dispatch_interleavings_cancel_before_input_and_never_retry() {
        if Command::new("tmux").arg("-V").output().is_err() {
            return;
        }
        for mutation in [
            DispatchMutation::Pause,
            DispatchMutation::HumanRevision,
            DispatchMutation::RetargetPaneReuse,
        ] {
            assert_final_mux_interleaving_cancels(mutation);
        }
    }

    fn assert_final_mux_interleaving_cancels(mutation: DispatchMutation) {
        let socket = format!(
            "watchme-interleave-{}-{}",
            std::process::id(),
            match mutation {
                DispatchMutation::Pause => "pause",
                DispatchMutation::HumanRevision => "human",
                DispatchMutation::RetargetPaneReuse => "reuse",
            }
        );
        let _server = TmuxServerGuard(socket.clone());
        assert!(
            Command::new("tmux")
                .args([
                    "-f",
                    "/dev/null",
                    "-L",
                    &socket,
                    "new-session",
                    "-d",
                    "-s",
                    "recovery",
                    "sh",
                    "-c",
                    "printf 'recovery-ready\\n'; while IFS= read -r line; do printf 'INPUT:%s\\n' \"$line\"; done",
                ])
                .status()
                .unwrap()
                .success()
        );
        let tmux = Tmux::for_socket_name(socket.clone(), Duration::from_secs(2));
        let deadline = Instant::now() + Duration::from_secs(2);
        let identity = loop {
            let candidate = tmux
                .resolve_selector(&TmuxSelector::parse("recovery").unwrap())
                .unwrap();
            if tmux
                .capture_tail(&candidate, 8, 1_024)
                .is_ok_and(|capture| capture.text.contains("recovery-ready"))
            {
                break candidate;
            }
            assert!(
                Instant::now() < deadline,
                "test tmux pane did not become ready"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let target = TargetIdentity::tmux(
            identity.server,
            identity.server_instance,
            identity.session_id,
            identity.window_id,
            identity.pane_id,
            identity.tty,
            identity.process,
            None,
        );
        let fingerprint = "d".repeat(64);
        let mut machine = RecoveryMachine::new(Budget {
            max_attempts: 2,
            max_cumulative_wait: Duration::from_secs(60),
            planner_calls: 0,
            cooldown: Duration::ZERO,
        });
        machine.apply(RecoveryCommand::Revalidated).unwrap();
        machine
            .apply(RecoveryCommand::Confirm {
                fingerprint: fingerprint.clone(),
            })
            .unwrap();
        let mut watcher = WatcherState::new(
            format!("interleave-{socket}"),
            target.clone(),
            WatcherLifecycle::Observing,
            0,
            1,
        );
        watcher.recovery = Some(machine);
        watcher.last_observation = Some(
            Event::new(
                "event",
                "2026-07-11T00:00:00Z",
                watcher.watcher_id.clone(),
                target_identity_hash(&target),
                EventSource::new(SourceKind::ScreenDetection, "tmux", "generic_tail"),
                EventCategory::BlockedGoal,
                0.9,
                false,
                fingerprint.clone(),
                "blocked",
                PolicyHint::DeterministicActionAllowed,
            )
            .unwrap(),
        );
        let temporary = tempfile::tempdir().unwrap();
        let mut initial =
            Registry::load(JsonStore::new(temporary.path().join("watchers.json"))).unwrap();
        initial.register(watcher.clone()).unwrap();
        RecoveryCoordinator::new(&mut initial)
            .begin_action(
                &watcher.watcher_id,
                &fingerprint,
                crate::recovery::state_machine::ClockSnapshot::new(0, 0),
                1,
            )
            .unwrap();
        let dispatch = initial.dispatch_snapshot(&watcher.watcher_id).unwrap();
        let current = dispatch.watcher().clone();
        let registry = std::sync::Arc::new(tokio::sync::Mutex::new(initial));
        let target_id = current.watcher_id.clone();
        let registry_for_hook = registry.clone();
        let hook = std::sync::Arc::new(move || {
            let mut guard = registry_for_hook.blocking_lock();
            match mutation {
                DispatchMutation::Pause => guard
                    .transition(&target_id, WatcherLifecycle::Paused, 2)
                    .unwrap(),
                DispatchMutation::HumanRevision => guard
                    .transition(
                        &target_id,
                        WatcherLifecycle::HumanRequired {
                            reason: "human changed pane after baseline".into(),
                        },
                        2,
                    )
                    .unwrap(),
                DispatchMutation::RetargetPaneReuse => guard
                    .retarget_process(&target_id, ProcessIdentity::new(u32::MAX, u64::MAX), 2)
                    .unwrap(),
            }
        });
        let evidence = FreshTargetEvidence::new(registry.clone(), dispatch.clone());
        let executor =
            DaemonActionExecutor::with_before_mux_dispatch(registry.clone(), dispatch, hook);
        let store = JsonActionStore::load(temporary.path().join("actions.json")).unwrap();
        let engine = RecoveryEngine::new(store, InputRecipe);
        let clock = SystemRecoveryClock::new();
        let result = engine.execute(
            &current,
            OwnerIdentity {
                pid: std::process::id(),
                process_start_time: 0,
                nonce: "interleaving".into(),
            },
            &evidence,
            &executor,
            &clock,
        );
        assert!(matches!(result, Err(TransactionError::Execution(_))));
        let audit = engine.store().audit(&current.watcher_id).unwrap();
        assert!(
            audit
                .iter()
                .any(|record| record.phase == ActionPhase::Prepared)
        );
        assert_eq!(audit.last().unwrap().phase, ActionPhase::Failed);
        assert!(
            !tmux
                .capture_tail(&watcher_mux_identity(&current).unwrap().unwrap(), 16, 2_048,)
                .unwrap()
                .text
                .contains("INPUT:")
        );
        let retries = engine.execute(
            &current,
            OwnerIdentity {
                pid: std::process::id(),
                process_start_time: 0,
                nonce: "interleaving-retry".into(),
            },
            &evidence,
            &executor,
            &clock,
        );
        assert!(retries.is_err(), "stale dispatch must not execute on retry");
        assert!(
            !tmux
                .capture_tail(&watcher_mux_identity(&current).unwrap().unwrap(), 16, 2_048,)
                .unwrap()
                .text
                .contains("INPUT:")
        );
    }

    #[test]
    fn capture_source_must_be_bound_to_the_current_adapter_observation() {
        let target = TargetIdentity::herdr(
            "/tmp/herdr.sock".into(),
            "server".into(),
            "workspace".into(),
            "tab".into(),
            "pane".into(),
            "/dev/pts/1".into(),
            ProcessIdentity::new(1, 2),
        );
        let mut watcher = WatcherState::new(
            "bound".into(),
            target.clone(),
            WatcherLifecycle::Observing,
            1,
            1,
        );
        watcher.last_observation = Some(
            Event::new(
                "event",
                "2026-07-11T00:00:00Z",
                "bound",
                target_identity_hash(&target),
                EventSource::new(SourceKind::HerdrAgentState, "herdr", "typed_pane_state"),
                EventCategory::BlockedGoal,
                1.0,
                false,
                "a".repeat(64),
                "blocked",
                PolicyHint::DeterministicActionAllowed,
            )
            .unwrap(),
        );

        assert!(capture_source_matches(&watcher, "structured_state"));
        assert!(!capture_source_matches(&watcher, "screen_recent"));
        assert!(!capture_source_matches(&watcher, "log_tail"));
    }

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
        let dispatch = registry.dispatch_snapshot("live-reader").unwrap();
        let registry = std::sync::Arc::new(tokio::sync::Mutex::new(registry));
        let reader = FreshTargetEvidence::new(registry.clone(), dispatch);
        registry
            .blocking_lock()
            .transition("live-reader", WatcherLifecycle::Paused, 2)
            .unwrap();

        let current = reader.read().unwrap();
        assert!(current.human_intervened);
        assert!(current.evidence_current);
    }
}
