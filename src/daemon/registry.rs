use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{ProcessIdentity, TargetIdentity, WatcherLifecycle, WatcherState};
use crate::recovery::state_machine::Budget;
use crate::recovery::state_machine::{RecoveryCommand, RecoveryMachine, RecoveryState};
use crate::store::{JsonStore, LoadOutcome, StoreError};

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("unknown watcher {0}")]
    Unknown(String),
    #[error("watcher ID collision: {0}")]
    IdCollision(String),
    #[error("watcher revision overflow: {0}")]
    RevisionOverflow(String),
    #[error("corrupt watcher registry quarantined at {0}")]
    Corrupt(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum RegistrationOutcome {
    Added(String),
    Existing(String),
    Revalidated(String),
}

const RESTART_REVALIDATION_REASON: &str = "target revalidation required after daemon restart";

/// Immutable authorization token for one daemon action.  Policy, evidence,
/// and dispatch all bind to this same watcher image; any durable mutation
/// invalidates the token.
#[derive(Clone, Debug, PartialEq)]
pub struct DispatchSnapshot {
    watcher: WatcherState,
}

impl DispatchSnapshot {
    pub const fn watcher(&self) -> &WatcherState {
        &self.watcher
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRegistry {
    version: u16,
    watchers: Vec<WatcherState>,
}

pub struct Registry {
    store: JsonStore,
    watchers: BTreeMap<String, WatcherState>,
    audit_paths: Option<crate::paths::WatchmePaths>,
    #[cfg(test)]
    fail_next_persist: bool,
}

impl Registry {
    pub fn load(store: JsonStore) -> Result<Self, RegistryError> {
        Self::load_inner(store, None)
    }

    pub fn load_with_audit(
        store: JsonStore,
        paths: crate::paths::WatchmePaths,
    ) -> Result<Self, RegistryError> {
        Self::load_inner(store, Some(paths))
    }

    fn load_inner(
        store: JsonStore,
        audit_paths: Option<crate::paths::WatchmePaths>,
    ) -> Result<Self, RegistryError> {
        let mut watchers = match store.load::<PersistedRegistry>()? {
            LoadOutcome::Missing => BTreeMap::new(),
            LoadOutcome::Corrupt { quarantine } => {
                return Err(RegistryError::Corrupt(quarantine.display().to_string()));
            }
            LoadOutcome::Present(saved) if saved.version == 1 => saved
                .watchers
                .into_iter()
                .map(|watcher| (watcher.watcher_id.clone(), watcher))
                .collect(),
            LoadOutcome::Present(_) => {
                return Err(RegistryError::Corrupt(
                    "unsupported registry version".into(),
                ));
            }
        };
        let mut replay_transitioned = false;
        for watcher in watchers.values_mut() {
            if watcher.target.needs_revalidation() && watcher.recovery.is_none() {
                watcher.recovery = Some(RecoveryMachine::new(Budget {
                    max_attempts: 3,
                    max_cumulative_wait: std::time::Duration::from_secs(300),
                    planner_calls: 0,
                    cooldown: std::time::Duration::from_secs(60),
                }));
                replay_transitioned = true;
            }
            if let Some(recovery) = watcher.recovery.take() {
                watcher.recovery = Some(
                    recovery
                        .restore_for_restart()
                        .map_err(|_| RegistryError::Corrupt("invalid recovery state".into()))?,
                );
                replay_transitioned = true;
            }
            if !matches!(
                watcher.lifecycle,
                WatcherLifecycle::Stopped { .. }
                    | WatcherLifecycle::TargetTerminated
                    | WatcherLifecycle::HumanRequired { .. }
            ) {
                watcher.lifecycle = WatcherLifecycle::HumanRequired {
                    reason: RESTART_REVALIDATION_REASON.into(),
                };
                watcher.revision = next_revision(watcher)?;
                replay_transitioned = true;
            }
        }
        if replay_transitioned {
            store.write(&PersistedRegistry {
                version: 1,
                watchers: watchers.values().cloned().collect(),
            })?;
        }
        Ok(Self {
            store,
            watchers,
            audit_paths,
            #[cfg(test)]
            fail_next_persist: false,
        })
    }

    pub fn register(
        &mut self,
        watcher: WatcherState,
    ) -> Result<RegistrationOutcome, RegistryError> {
        if let Some(existing) = self.watchers.get(&watcher.watcher_id).cloned() {
            if stable_target_eq(&existing.target, &watcher.target) {
                return self.refresh_existing(&existing.watcher_id, watcher);
            }
            return Err(RegistryError::IdCollision(watcher.watcher_id));
        }
        if let Some(existing_id) = self
            .watchers
            .values()
            .find(|existing| stable_target_eq(&existing.target, &watcher.target))
            .map(|existing| existing.watcher_id.clone())
        {
            return self.refresh_existing(&existing_id, watcher);
        }
        if let Some(existing) = self
            .watchers
            .values()
            .find(|existing| exact_process_eq(&existing.target, &watcher.target))
            .cloned()
        {
            if is_richer_target(&existing.target, &watcher.target) {
                return self.refresh_existing(&existing.watcher_id, watcher);
            }
            if is_richer_target(&watcher.target, &existing.target) {
                return Ok(RegistrationOutcome::Existing(existing.watcher_id));
            }
            return Err(RegistryError::IdCollision(watcher.watcher_id));
        }
        let id = watcher.watcher_id.clone();
        let mut updated = self.watchers.clone();
        updated.insert(id.clone(), watcher);
        self.persist_watchers(&updated)?;
        self.watchers = updated;
        if let Some(watcher) = self.watchers.get(&id) {
            self.audit_lifecycle(watcher, "watcher registered");
        }
        Ok(RegistrationOutcome::Added(id))
    }

    fn refresh_existing(
        &mut self,
        existing_id: &str,
        fresh: WatcherState,
    ) -> Result<RegistrationOutcome, RegistryError> {
        let existing = self
            .watchers
            .get(existing_id)
            .ok_or_else(|| RegistryError::Unknown(existing_id.into()))?;
        let process_promotion = is_richer_target(&existing.target, &fresh.target);
        let target_upgraded =
            existing.target.needs_revalidation() && !fresh.target.needs_revalidation();
        let replay_revalidated = matches!(
            &existing.lifecycle,
            WatcherLifecycle::HumanRequired { reason } if reason == RESTART_REVALIDATION_REASON
        );
        if !process_promotion && !target_upgraded && !replay_revalidated {
            return Ok(RegistrationOutcome::Existing(existing_id.into()));
        }
        if process_promotion
            && (!compatible_attachment(&existing.codex_session, &fresh.codex_session)
                || !compatible_attachment(&existing.claude_session, &fresh.claude_session))
        {
            return Err(RegistryError::IdCollision(fresh.watcher_id));
        }

        let mut updated = self.watchers.clone();
        let refreshed = updated
            .get_mut(existing_id)
            .ok_or_else(|| RegistryError::Unknown(existing_id.into()))?;
        refreshed.target = fresh.target;
        if process_promotion {
            refreshed.lifecycle = WatcherLifecycle::Registered;
            refreshed.recovery = None;
            refreshed.last_observation = None;
            refreshed.observation_schedule.event_wake_pending = true;
            if fresh.codex_session.is_some() {
                refreshed.codex_session = fresh.codex_session;
            }
            if fresh.claude_session.is_some() {
                refreshed.claude_session = fresh.claude_session;
            }
        } else if replay_revalidated {
            refreshed.lifecycle = WatcherLifecycle::Registered;
            refreshed.recovery = fresh.recovery;
        }
        refreshed.revision = next_revision(refreshed)?;
        refreshed.updated_at_unix_ms = fresh.updated_at_unix_ms;
        self.persist_watchers(&updated)?;
        self.watchers = updated;

        if let Some(watcher) = self.watchers.get(existing_id) {
            self.audit_lifecycle(
                watcher,
                if process_promotion {
                    "watcher promoted"
                } else {
                    "watcher resumed"
                },
            );
        }

        if process_promotion || replay_revalidated {
            Ok(RegistrationOutcome::Revalidated(existing_id.into()))
        } else {
            Ok(RegistrationOutcome::Existing(existing_id.into()))
        }
    }

    pub fn transition(
        &mut self,
        id: &str,
        lifecycle: WatcherLifecycle,
        now: u64,
    ) -> Result<(), RegistryError> {
        let mut updated = self.watchers.clone();
        let watcher = updated
            .get_mut(id)
            .ok_or_else(|| RegistryError::Unknown(id.into()))?;
        watcher.lifecycle = lifecycle;
        watcher.revision = next_revision(watcher)?;
        watcher.updated_at_unix_ms = now;
        self.persist_watchers(&updated)?;
        self.watchers = updated;
        if let Some(watcher) = self.watchers.get(id) {
            self.audit_lifecycle(watcher, lifecycle_message(&watcher.lifecycle));
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&WatcherState> {
        self.watchers.get(id)
    }

    pub fn dispatch_snapshot(&self, id: &str) -> Result<DispatchSnapshot, RegistryError> {
        self.get(id)
            .cloned()
            .map(|watcher| DispatchSnapshot { watcher })
            .ok_or_else(|| RegistryError::Unknown(id.into()))
    }

    /// Call while holding the registry lock immediately before an external
    /// side effect.  Equality includes target identity, lifecycle, revision,
    /// and the current evidence used for authorization.
    pub fn matches_dispatch_snapshot(&self, snapshot: &DispatchSnapshot) -> bool {
        self.get(&snapshot.watcher.watcher_id)
            .is_some_and(|current| current == snapshot.watcher())
    }

    #[cfg(test)]
    pub fn fail_next_persist(&mut self) {
        self.fail_next_persist = true;
    }

    pub fn retarget_process(
        &mut self,
        id: &str,
        process: ProcessIdentity,
        now: u64,
    ) -> Result<(), RegistryError> {
        let mut updated = self.watchers.clone();
        let watcher = updated
            .get_mut(id)
            .ok_or_else(|| RegistryError::Unknown(id.into()))?;
        match &mut watcher.target {
            TargetIdentity::Process { process: target }
            | TargetIdentity::Multiplexer {
                process: target, ..
            } => *target = process,
        }
        watcher.revision = next_revision(watcher)?;
        watcher.updated_at_unix_ms = now;
        self.persist_watchers(&updated)?;
        self.watchers = updated;
        Ok(())
    }
    pub fn list(&self) -> Vec<WatcherState> {
        self.watchers.values().cloned().collect()
    }
    pub fn persist_recovery(
        &mut self,
        id: &str,
        recovery: RecoveryMachine,
        now: u64,
    ) -> Result<(), RegistryError> {
        let mut updated = self.watchers.clone();
        let watcher = updated
            .get_mut(id)
            .ok_or_else(|| RegistryError::Unknown(id.into()))?;
        watcher.recovery = Some(recovery);
        watcher.revision = next_revision(watcher)?;
        watcher.updated_at_unix_ms = now;
        self.persist_watchers(&updated)?;
        self.watchers = updated;
        Ok(())
    }
    pub fn apply_recovery_transition(
        &mut self,
        id: &str,
        command: RecoveryCommand,
        now: u64,
    ) -> Result<RecoveryState, RegistryError> {
        let mut updated = self.watchers.clone();
        let watcher = updated
            .get_mut(id)
            .ok_or_else(|| RegistryError::Unknown(id.into()))?;
        let machine = watcher
            .recovery
            .as_mut()
            .ok_or_else(|| RegistryError::Corrupt("missing recovery state".into()))?;
        machine
            .apply(command)
            .map_err(|reason| RegistryError::Corrupt(reason.into()))?;
        let state = machine.state();
        watcher.revision = next_revision(watcher)?;
        watcher.updated_at_unix_ms = now;
        self.persist_watchers(&updated)?;
        self.watchers = updated;
        Ok(state)
    }
    pub fn persist_observation_schedule(
        &mut self,
        id: &str,
        schedule: crate::model::ObservationSchedule,
        now: u64,
    ) -> Result<(), RegistryError> {
        let mut updated = self.watchers.clone();
        let watcher = updated
            .get_mut(id)
            .ok_or_else(|| RegistryError::Unknown(id.into()))?;
        watcher.observation_schedule = schedule;
        watcher.revision = next_revision(watcher)?;
        watcher.updated_at_unix_ms = now;
        self.persist_watchers(&updated)?;
        self.watchers = updated;
        Ok(())
    }
    pub fn persist_observation_event(
        &mut self,
        id: &str,
        event: crate::model::Event,
        now: u64,
    ) -> Result<(), RegistryError> {
        let mut updated = self.watchers.clone();
        let watcher = updated
            .get_mut(id)
            .ok_or_else(|| RegistryError::Unknown(id.into()))?;
        watcher.last_observation = Some(event);
        watcher.revision = next_revision(watcher)?;
        watcher.updated_at_unix_ms = now;
        self.persist_watchers(&updated)?;
        self.watchers = updated;
        Ok(())
    }
    pub fn complete_observation(
        &mut self,
        id: &str,
        event: Option<crate::model::Event>,
        now: u64,
    ) -> Result<(), RegistryError> {
        let mut updated = self.watchers.clone();
        let watcher = updated
            .get_mut(id)
            .ok_or_else(|| RegistryError::Unknown(id.into()))?;
        if let Some(event) = event {
            watcher.last_observation = Some(event)
        }
        if watcher.observation_schedule.event_wake_pending {
            watcher.observation_schedule.last_wake_completed_wall_ms = Some(now);
        }
        watcher.observation_schedule.event_wake_pending = false;
        watcher.revision = next_revision(watcher)?;
        watcher.updated_at_unix_ms = now;
        self.persist_watchers(&updated)?;
        self.watchers = updated;
        Ok(())
    }
    pub fn commit_observation(
        &mut self,
        id: &str,
        mut schedule: crate::model::ObservationSchedule,
        event: Option<crate::model::Event>,
        now: u64,
    ) -> Result<(), RegistryError> {
        let mut updated = self.watchers.clone();
        let watcher = updated
            .get_mut(id)
            .ok_or_else(|| RegistryError::Unknown(id.into()))?;
        if schedule.event_wake_pending {
            schedule.last_wake_completed_wall_ms = Some(now);
        }
        schedule.event_wake_pending = false;
        watcher.observation_schedule = schedule;
        if let Some(event) = event {
            if let Some(machine) = watcher.recovery.as_mut() {
                if machine.state() == RecoveryState::NeedsRevalidation {
                    machine
                        .apply(RecoveryCommand::Revalidated)
                        .map_err(|reason| RegistryError::Corrupt(reason.into()))?;
                    watcher.lifecycle = WatcherLifecycle::Observing;
                }
                let fresh_claude_limit_after_menu = machine.state() == RecoveryState::Recovered
                    && event.source.kind == crate::model::SourceKind::Hook
                    && event.source.source_id == "claude_stop_failure"
                    && event.policy_hint == crate::model::PolicyHint::WaitAllowed
                    && event.metadata.contains_key("claude_reset_at")
                    && machine.current_fingerprint() != Some(event.evidence_fingerprint.as_str());
                if machine.state() == RecoveryState::Recovered
                    && ((matches!(watcher.lifecycle, WatcherLifecycle::Waiting { .. })
                        && (event.metadata.get("claude_resume")
                            == Some(&serde_json::Value::Bool(true))
                            || event.metadata.get("codex_resume")
                                == Some(&serde_json::Value::Bool(true))))
                        || fresh_claude_limit_after_menu)
                {
                    machine
                        .apply(RecoveryCommand::RearmAfterWait)
                        .map_err(|reason| RegistryError::Corrupt(reason.into()))?;
                }
                let screen_is_stable = event.source.kind
                    != crate::model::SourceKind::ScreenDetection
                    || watcher.observation_schedule.screen_stable_count >= 2;
                if event.category.is_actionable()
                    && screen_is_stable
                    && machine.state() == RecoveryState::Observing
                {
                    machine
                        .apply(RecoveryCommand::Confirm {
                            fingerprint: event.evidence_fingerprint.clone(),
                        })
                        .map_err(|reason| RegistryError::Corrupt(reason.into()))?;
                }
            }
            watcher.last_observation = Some(event);
        }
        watcher.revision = next_revision(watcher)?;
        watcher.updated_at_unix_ms = now;
        self.persist_watchers(&updated)?;
        self.watchers = updated;
        Ok(())
    }
    pub fn wake_observation(
        &mut self,
        id: &str,
        fingerprint: &str,
        now: u64,
    ) -> Result<(), RegistryError> {
        if fingerprint.len() < 16
            || fingerprint.len() > 128
            || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(RegistryError::Corrupt("invalid wake fingerprint".into()));
        }
        let watcher = self
            .get(id)
            .ok_or_else(|| RegistryError::Unknown(id.into()))?;
        const WAKE_COOLDOWN_MS: u64 = 60_000;
        let duplicate_in_cooldown = watcher
            .observation_schedule
            .last_wake_fingerprint
            .as_deref()
            == Some(fingerprint)
            && watcher
                .observation_schedule
                .last_wake_completed_wall_ms
                .is_some_and(|completed| now < completed.saturating_add(WAKE_COOLDOWN_MS));
        if watcher.observation_schedule.event_wake_pending || duplicate_in_cooldown {
            return Ok(());
        }
        let mut schedule = watcher.observation_schedule.clone();
        schedule.event_wake_pending = true;
        schedule.last_wake_fingerprint = Some(fingerprint.into());
        self.persist_observation_schedule(id, schedule, now)
    }

    fn persist_watchers(
        &mut self,
        watchers: &BTreeMap<String, WatcherState>,
    ) -> Result<(), RegistryError> {
        #[cfg(test)]
        if self.fail_next_persist {
            // Test-only injected durability failure at the exact registry write boundary.
            // The state map is only replaced after a successful write, so this remains
            // representative of an atomic-store failure.
            self.fail_next_persist = false;
            return Err(RegistryError::Corrupt(
                "injected persistence failure".into(),
            ));
        }
        self.store.write(&PersistedRegistry {
            version: 1,
            watchers: watchers.values().cloned().collect(),
        })?;
        Ok(())
    }

    fn audit_lifecycle(&self, watcher: &WatcherState, message: &str) {
        let Some(paths) = self.audit_paths.as_ref() else {
            return;
        };
        if let Err(error) = crate::audit::record_lifecycle(paths, watcher, message) {
            eprintln!("watchme daemon: lifecycle audit failed: {error}");
        }
    }
}

fn lifecycle_message(lifecycle: &WatcherLifecycle) -> &'static str {
    match lifecycle {
        WatcherLifecycle::Registered | WatcherLifecycle::Observing => "watcher resumed",
        WatcherLifecycle::Paused => "watcher paused",
        WatcherLifecycle::Waiting { .. } => "capacity wait scheduled",
        WatcherLifecycle::HumanRequired { .. } => "human handoff",
        WatcherLifecycle::TargetTerminated => "target terminated",
        WatcherLifecycle::Stopped { .. } => "watcher stopped",
        WatcherLifecycle::Recovering { .. } => "watcher lifecycle changed",
    }
}

fn next_revision(watcher: &WatcherState) -> Result<u64, RegistryError> {
    watcher
        .revision
        .checked_add(1)
        .ok_or_else(|| RegistryError::RevisionOverflow(watcher.watcher_id.clone()))
}

fn stable_target_eq(left: &TargetIdentity, right: &TargetIdentity) -> bool {
    match (left, right) {
        (TargetIdentity::Process { process: left }, TargetIdentity::Process { process: right }) => {
            left.pid == right.pid && left.start_time == right.start_time
        }
        (
            TargetIdentity::Multiplexer {
                provider: left_provider,
                server: left_server,
                pane: left_pane,
                process: left_process,
                ..
            },
            TargetIdentity::Multiplexer {
                provider: right_provider,
                server: right_server,
                pane: right_pane,
                process: right_process,
                ..
            },
        ) => {
            left_provider == right_provider
                && left_server == right_server
                && left_pane == right_pane
                && left_process.pid == right_process.pid
                && left_process.start_time == right_process.start_time
        }
        _ => false,
    }
}

fn exact_process_eq(left: &TargetIdentity, right: &TargetIdentity) -> bool {
    let left = target_process(left);
    let right = target_process(right);
    left.pid == right.pid && left.start_time == right.start_time
}

fn target_process(target: &TargetIdentity) -> &ProcessIdentity {
    match target {
        TargetIdentity::Process { process } | TargetIdentity::Multiplexer { process, .. } => {
            process
        }
    }
}

fn is_richer_target(existing: &TargetIdentity, fresh: &TargetIdentity) -> bool {
    matches!(existing, TargetIdentity::Process { .. })
        && matches!(
            fresh,
            TargetIdentity::Multiplexer {
                context: Some(_),
                needs_revalidation: false,
                ..
            }
        )
}

fn compatible_attachment<T: PartialEq>(existing: &Option<T>, fresh: &Option<T>) -> bool {
    existing.is_none() || fresh.is_none() || existing == fresh
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process_watcher(id: &str, pid: u32, start_time: u64) -> WatcherState {
        WatcherState::new(
            id.into(),
            TargetIdentity::process(ProcessIdentity::new(pid, start_time)),
            WatcherLifecycle::Observing,
            0,
            1,
        )
    }

    fn native_herdr_watcher(id: &str, pid: u32, start_time: u64) -> WatcherState {
        WatcherState::new(
            id.into(),
            TargetIdentity::herdr(
                "/tmp/herdr.sock".into(),
                "native-0.7.4-protocol-16-1-2".into(),
                "workspace".into(),
                "tab".into(),
                "pane".into(),
                "/dev/pts/8".into(),
                ProcessIdentity::new(pid, start_time),
                crate::model::HerdrWireProtocol::Native16,
            ),
            WatcherLifecycle::Registered,
            0,
            2,
        )
    }

    fn codex_reference(thread_id: &str, start_time: u64) -> crate::model::CodexSessionReference {
        crate::model::CodexSessionReference {
            thread_id: thread_id.into(),
            rollout_path: "/tmp/rollout.jsonl".into(),
            process_start_time: start_time,
            process_cwd: "/tmp".into(),
            target_session: None,
            rollout_binding: None,
            app_server_state_path: None,
            structured_state: None,
        }
    }

    #[test]
    fn process_watcher_is_promoted_to_verified_native_herdr() {
        let temp = tempfile::tempdir().unwrap();
        let mut registry =
            Registry::load(JsonStore::new(temp.path().join("watchers.json"))).unwrap();
        assert_eq!(
            registry
                .register(process_watcher("process-10-20", 10, 20))
                .unwrap(),
            RegistrationOutcome::Added("process-10-20".into())
        );

        let mut fresh = native_herdr_watcher("herdr-pane-10-20", 10, 20);
        fresh.codex_session = Some(codex_reference("thread", 20));
        let outcome = registry.register(fresh).unwrap();

        assert_eq!(
            outcome,
            RegistrationOutcome::Revalidated("process-10-20".into())
        );
        assert_eq!(registry.list().len(), 1);
        let watcher = registry.get("process-10-20").unwrap();
        assert!(matches!(
            watcher.target.observation_context(),
            Some(crate::model::MultiplexerContext::Herdr {
                wire_protocol: crate::model::HerdrWireProtocol::Native16,
                ..
            })
        ));
        assert!(watcher.last_observation.is_none());
        assert!(watcher.observation_schedule.event_wake_pending);
        assert_eq!(
            watcher
                .codex_session
                .as_ref()
                .map(|value| value.thread_id.as_str()),
            Some("thread")
        );
    }

    #[test]
    fn verified_mux_target_cannot_be_downgraded_or_conflicted() {
        let temp = tempfile::tempdir().unwrap();
        let mut registry =
            Registry::load(JsonStore::new(temp.path().join("watchers.json"))).unwrap();
        registry
            .register(native_herdr_watcher("native", 10, 20))
            .unwrap();

        assert_eq!(
            registry
                .register(process_watcher("process", 10, 20))
                .unwrap(),
            RegistrationOutcome::Existing("native".into())
        );
        let mut conflicting = native_herdr_watcher("other-pane", 10, 20);
        if let TargetIdentity::Multiplexer { pane, .. } = &mut conflicting.target {
            *pane = "different-pane".into();
        }
        assert!(matches!(
            registry.register(conflicting),
            Err(RegistryError::IdCollision(_))
        ));
        assert_eq!(registry.list().len(), 1);
    }

    #[test]
    fn promotion_rejects_conflicting_codex_thread_attachment() {
        let temp = tempfile::tempdir().unwrap();
        let mut registry =
            Registry::load(JsonStore::new(temp.path().join("watchers.json"))).unwrap();
        let mut existing = process_watcher("process", 10, 20);
        existing.codex_session = Some(codex_reference("thread-one", 20));
        registry.register(existing).unwrap();
        let mut fresh = native_herdr_watcher("native", 10, 20);
        fresh.codex_session = Some(codex_reference("thread-two", 20));

        assert!(matches!(
            registry.register(fresh),
            Err(RegistryError::IdCollision(_))
        ));
        assert!(matches!(
            registry.get("process").unwrap().target,
            TargetIdentity::Process { .. }
        ));
    }

    #[test]
    fn audited_registry_records_fixed_lifecycle_transitions() {
        let temp = tempfile::tempdir().unwrap();
        let paths = crate::paths::WatchmePaths::resolve(
            temp.path(),
            None,
            None,
            Some(&temp.path().join("run")),
        )
        .unwrap();
        paths.create_owner_only().unwrap();
        let mut registry = Registry::load_with_audit(
            JsonStore::new(paths.state_dir().join("watchers.json")),
            paths.clone(),
        )
        .unwrap();
        registry
            .register(process_watcher("watcher", 10, 20))
            .unwrap();
        registry
            .transition(
                "watcher",
                WatcherLifecycle::Waiting {
                    until_unix_ms: 100,
                    reason: "untrusted prompt text".into(),
                },
                2,
            )
            .unwrap();

        let mut log =
            crate::audit::AuditLog::open(paths.state_file("audit.jsonl").unwrap()).unwrap();
        let events = log.read_lines(Some("watcher"), 10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].message, "watcher registered");
        assert_eq!(events[1].message, "capacity wait scheduled");
        assert!(events.iter().all(|event| !event.message.contains("prompt")));
    }

    #[test]
    fn dispatch_snapshot_refuses_a_retargeted_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let mut registry =
            Registry::load(JsonStore::new(temp.path().join("watchers.json"))).unwrap();
        registry
            .register(WatcherState::new(
                "watcher".into(),
                TargetIdentity::process(ProcessIdentity::new(10, 20)),
                WatcherLifecycle::Observing,
                0,
                1,
            ))
            .unwrap();
        let token = registry.dispatch_snapshot("watcher").unwrap();

        registry
            .retarget_process("watcher", ProcessIdentity::new(11, 21), 2)
            .unwrap();

        assert!(!registry.matches_dispatch_snapshot(&token));
    }
}
