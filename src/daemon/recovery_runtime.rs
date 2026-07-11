use super::runtime_services::{
    DaemonRuntimeServices, SystemRecoveryClock, target_process_is_alive,
};
use super::{
    Registry, WatcherLifecycle, capture_mux_target, execute_mux_action, mux_identity_key, now_ms,
    process_identity_key, target_identity_hash, validate_mux_target, watcher_mux_identity,
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
        let (target_revalidated, pane_matches, identity, mut composer_safe) =
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
        // A stable, adapter-bounded Claude menu has no text composer to
        // protect. The menu recipe still requires the persisted debounce and
        // dispatches allowlisted symbolic keys only.
        composer_safe |= event.source.kind == crate::model::SourceKind::ScreenDetection
            && event.source.source_id == "claude"
            && event
                .metadata
                .get("claude_menu_moves")
                .is_some_and(|moves| {
                    moves
                        .as_i64()
                        .and_then(|value| i8::try_from(value).ok())
                        .is_some()
                });
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

    fn read_verification(&self, baseline: &LiveEvidence) -> Result<LiveEvidence, String> {
        let mut evidence = self.read()?;
        let watcher = self.watcher()?;
        if let Some(progress) = fresh_claude_progress(&watcher, &baseline.event) {
            evidence.event = progress;
        } else if let Some(progress) = fresh_codex_progress(&watcher, &baseline.event) {
            evidence.event = progress;
        }
        Ok(evidence)
    }
}

/// A lower-ranked terminal proof is only usable for the one Claude resume
/// action. It is captured after input dispatch from the same revalidated mux
/// identity and carries the exact action session from the durable baseline.
fn fresh_claude_progress(
    watcher: &crate::model::WatcherState,
    baseline: &crate::model::Event,
) -> Option<crate::model::Event> {
    if baseline.metadata.get("claude_resume") != Some(&serde_json::Value::Bool(true)) {
        return None;
    }
    let identity = watcher_mux_identity(watcher).ok()??;
    validate_mux_target(watcher, &identity).ok()?;
    let capture = capture_mux_target(watcher, &identity, 40, 16 * 1024).ok()?;
    let clean = crate::observe::screen::sanitize_terminal(capture.text.as_bytes(), 16 * 1024, 40);
    let live_tail = match watcher.target.observation_context() {
        Some(crate::model::MultiplexerContext::Tmux { .. }) => {
            watcher.target.tmux_chrome().and_then(|chrome| {
                crate::observe::screen::trusted_tmux_screen(&clean, chrome).actionable_bottom(40)
            })
        }
        Some(crate::model::MultiplexerContext::Herdr { .. }) => Some(clean),
        _ => None,
    }?;
    let observed: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    crate::agents::claude::trusted_resume_progress_event(
        watcher,
        baseline,
        &live_tail,
        &observed.to_rfc3339(),
    )
}

/// Post-resume Codex proof prefers the capability-probed App Server / rollout
/// snapshot over screen text so `GOAL_ACTIVE_OR_PURSUING` can verify.
fn fresh_codex_progress(
    watcher: &crate::model::WatcherState,
    baseline: &crate::model::Event,
) -> Option<crate::model::Event> {
    if baseline.metadata.get("codex_resume") != Some(&serde_json::Value::Bool(true)) {
        return None;
    }
    let source = crate::agents::codex::probe_structured_source(watcher)?;
    let structured = match source {
        crate::agents::codex::ProbedCodexSource::AppServer { snapshot, .. } => {
            crate::agents::codex::structured_value_from_snapshot(&snapshot)
        }
        crate::agents::codex::ProbedCodexSource::Rollout { path, thread_id } => {
            let event = crate::agents::codex::correlated_rollout_event(watcher, &path, &thread_id)?;
            serde_json::json!({
                "thread_id": event.metadata.get("codex_thread_id")?.as_str()?,
                "goal": {
                    "status": event.metadata.get("goal_state")?.as_str()?,
                },
                "runtime_status": {"type": "active", "active_flags": []}
            })
        }
    };
    let observed: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    crate::agents::codex::trusted_goal_progress_event(
        watcher,
        baseline,
        &structured,
        &observed.to_rfc3339(),
    )
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
    cancellation: std::sync::Arc<std::sync::atomic::AtomicBool>,
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
            cancellation: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            before_mux_dispatch: None,
        }
    }

    fn with_cancellation(
        registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
        snapshot: DispatchSnapshot,
        cancellation: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        let mut executor = Self::new(registry, snapshot);
        executor.cancellation = cancellation;
        executor
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

    fn cancellation_requested(&self) -> bool {
        self.cancellation.load(std::sync::atomic::Ordering::Acquire)
    }

    fn reject_if_cancelled(&self) -> Result<(), ExecutionError> {
        if self.cancellation_requested() {
            return Err(ExecutionError::Unsafe("recovery cancellation requested"));
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
        self.reject_if_cancelled()?;
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
                if self.cancellation_requested() {
                    return Err(ExecutionError::PossibleSideEffect(
                        "recovery cancellation arrived after multiplexer dispatch".into(),
                    ));
                }
                result
            }
            ActionKind::Capture { source, max_lines } => {
                self.confirm_live_evidence()?;
                let guard = self.locked_snapshot_watcher()?;
                let result = execute_capture(self.snapshot.watcher(), source, *max_lines);
                drop(guard);
                self.reject_if_cancelled()?;
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

#[cfg(test)]
pub(super) fn execute_recovery_action(
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    engine: std::sync::Arc<super::DaemonRecoveryEngine>,
    watcher: crate::model::WatcherState,
    owner: OwnerIdentity,
) {
    execute_recovery_action_with_cancellation(
        registry,
        engine,
        watcher,
        owner,
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    );
}

pub(super) fn execute_recovery_action_with_cancellation(
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    engine: std::sync::Arc<super::DaemonRecoveryEngine>,
    watcher: crate::model::WatcherState,
    owner: OwnerIdentity,
    cancellation: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    if cancellation.load(std::sync::atomic::Ordering::Acquire) {
        return;
    }
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
        if let Some(mut event) = guard
            .get(&watcher.watcher_id)
            .and_then(|current| current.last_observation.clone())
            .filter(|event| {
                event.metadata.get("codex_resume") == Some(&serde_json::Value::Bool(true))
            })
        {
            crate::agents::codex::mark_resume_sent(&mut event, &fingerprint);
            let _ = guard.persist_observation_event(&watcher.watcher_id, event, now_ms());
        }
        guard.dispatch_snapshot(&watcher.watcher_id).ok()
    };
    let Some(dispatch) = dispatch else { return };
    let current = dispatch.watcher().clone();
    let evidence = FreshTargetEvidence::new(registry.clone(), dispatch.clone());
    let executor =
        DaemonActionExecutor::with_cancellation(registry.clone(), dispatch, cancellation);
    match engine.execute(&current, owner, &evidence, &executor, &clock) {
        Ok(Some(record))
            if record.phase == crate::recovery::transaction::ActionPhase::Succeeded =>
        {
            if executor.cancellation_requested() {
                let _ = registry.blocking_lock().transition(
                    &current.watcher_id,
                    WatcherLifecycle::HumanRequired {
                        reason: "recovery cancellation followed a completed side effect".into(),
                    },
                    now_ms(),
                );
                return;
            }
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
    fn app_server_fresh_codex_progress_emits_when_goal_active() {
        use crate::agents::codex::CodexSessionReference;
        use std::fs;
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let cwd = std::env::current_dir().unwrap();
        let temp = tempfile::TempDir::new_in(&cwd).unwrap();
        #[cfg(unix)]
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();

        let snapshot_path = temp.path().join("app-server-goal.json");
        fs::write(
            &snapshot_path,
            r#"{"thread_id":"thr_demo","goal":{"text":"Finish the refactor","status":"pursuing"},"runtime_status":{"type":"active","active_flags":[]}}"#,
        )
        .unwrap();
        #[cfg(unix)]
        fs::set_permissions(&snapshot_path, fs::Permissions::from_mode(0o600)).unwrap();

        let rollout = temp.path().join("rollout.jsonl");
        fs::write(&rollout, "").unwrap();
        #[cfg(unix)]
        fs::set_permissions(&rollout, fs::Permissions::from_mode(0o600)).unwrap();

        let mut process = ProcessIdentity::new(std::process::id(), 42);
        process.executable = Some("codex".into());
        let mut watcher = WatcherState::new(
            "codex-app-server-progress".into(),
            TargetIdentity::process(process),
            WatcherLifecycle::Observing,
            1,
            1,
        );
        let binding = crate::agents::codex::bind_rollout(&rollout).expect("rollout bind");
        watcher
            .set_codex_session(CodexSessionReference {
                thread_id: "thr_demo".into(),
                rollout_path: rollout.to_string_lossy().into(),
                process_start_time: 42,
                process_cwd: cwd.to_string_lossy().into(),
                target_session: None,
                rollout_binding: Some(binding),
                app_server_state_path: Some(snapshot_path.to_string_lossy().into()),
            })
            .unwrap();

        let mut baseline = Event::new(
            "codex-resume",
            "2020-01-01T00:00:00Z",
            watcher.watcher_id.clone(),
            target_identity_hash(&watcher.target),
            EventSource::new(SourceKind::TypedApi, "codex", "goal_resume"),
            EventCategory::WaitingForModel,
            1.0,
            false,
            "a".repeat(64),
            "Codex resume candidate",
            PolicyHint::DeterministicActionAllowed,
        )
        .unwrap();
        baseline
            .metadata
            .insert("codex_resume".into(), serde_json::Value::Bool(true));
        baseline.metadata.insert(
            "codex_thread_id".into(),
            serde_json::Value::String("thr_demo".into()),
        );
        baseline.metadata.insert(
            "codex_resume_session".into(),
            serde_json::Value::String("a".repeat(64)),
        );

        let progress = fresh_codex_progress(&watcher, &baseline)
            .expect("App Server pursuing goal must verify post-resume progress");
        assert_eq!(progress.category, EventCategory::Working);
        assert_eq!(progress.metadata["goal_state"], "pursuing");
        assert_eq!(progress.metadata["codex_post_resume_progress"], true);
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
