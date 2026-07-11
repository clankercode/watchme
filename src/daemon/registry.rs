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
}

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
    #[cfg(test)]
    fail_next_persist: bool,
}

impl Registry {
    pub fn load(store: JsonStore) -> Result<Self, RegistryError> {
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
                    reason: "target revalidation required after daemon restart".into(),
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
                if existing.target.needs_revalidation() && !watcher.target.needs_revalidation() {
                    let mut updated = self.watchers.clone();
                    let upgraded = updated
                        .get_mut(&watcher.watcher_id)
                        .ok_or_else(|| RegistryError::Unknown(watcher.watcher_id.clone()))?;
                    upgraded.target = watcher.target;
                    upgraded.revision = next_revision(upgraded)?;
                    upgraded.updated_at_unix_ms = watcher.updated_at_unix_ms;
                    self.persist_watchers(&updated)?;
                    self.watchers = updated;
                }
                return Ok(RegistrationOutcome::Existing(existing.watcher_id.clone()));
            }
            return Err(RegistryError::IdCollision(watcher.watcher_id));
        }
        if let Some(existing) = self
            .watchers
            .values()
            .find(|existing| stable_target_eq(&existing.target, &watcher.target))
        {
            return Ok(RegistrationOutcome::Existing(existing.watcher_id.clone()));
        }
        let id = watcher.watcher_id.clone();
        let mut updated = self.watchers.clone();
        updated.insert(id.clone(), watcher);
        self.persist_watchers(&updated)?;
        self.watchers = updated;
        Ok(RegistrationOutcome::Added(id))
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

#[cfg(test)]
mod tests {
    use super::*;

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
