use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{ProcessIdentity, TargetIdentity, WatcherLifecycle, WatcherState};
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistrationOutcome {
    Added(String),
    Existing(String),
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
        Ok(Self { store, watchers })
    }

    pub fn register(
        &mut self,
        watcher: WatcherState,
    ) -> Result<RegistrationOutcome, RegistryError> {
        if let Some(existing) = self.watchers.get(&watcher.watcher_id) {
            if stable_target_eq(&existing.target, &watcher.target) {
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
        watcher.observation_schedule.last_wake_fingerprint = None;
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
        if watcher.observation_schedule.event_wake_pending
            || watcher
                .observation_schedule
                .last_wake_fingerprint
                .as_deref()
                == Some(fingerprint)
        {
            return Ok(());
        }
        let mut schedule = watcher.observation_schedule.clone();
        schedule.event_wake_pending = true;
        schedule.last_wake_fingerprint = Some(fingerprint.into());
        self.persist_observation_schedule(id, schedule, now)
    }

    fn persist_watchers(
        &self,
        watchers: &BTreeMap<String, WatcherState>,
    ) -> Result<(), RegistryError> {
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
