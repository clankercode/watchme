use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::{TargetIdentity, WatcherLifecycle, WatcherState};
use crate::store::{JsonStore, LoadOutcome, StoreError};

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("unknown watcher {0}")]
    Unknown(String),
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
            if !matches!(
                watcher.lifecycle,
                WatcherLifecycle::Stopped { .. }
                    | WatcherLifecycle::TargetTerminated
                    | WatcherLifecycle::HumanRequired { .. }
            ) {
                watcher.lifecycle = WatcherLifecycle::HumanRequired {
                    reason: "target revalidation required after daemon restart".into(),
                };
                watcher.revision += 1;
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
        watcher.revision += 1;
        watcher.updated_at_unix_ms = now;
        self.persist_watchers(&updated)?;
        self.watchers = updated;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&WatcherState> {
        self.watchers.get(id)
    }
    pub fn list(&self) -> Vec<WatcherState> {
        self.watchers.values().cloned().collect()
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
