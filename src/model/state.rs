use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use super::TargetIdentity;

pub const WATCHER_STATE_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WatcherLifecycle {
    Registered,
    Observing,
    Recovering { evidence_fingerprint: String },
    Waiting { until_unix_ms: u64, reason: String },
    HumanRequired { reason: String },
    TargetTerminated,
    Stopped { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherState {
    schema_version: u16,
    pub watcher_id: String,
    pub target: TargetIdentity,
    pub lifecycle: WatcherLifecycle,
    pub revision: u64,
    pub updated_at_unix_ms: u64,
}

impl WatcherState {
    pub const fn new(
        watcher_id: String,
        target: TargetIdentity,
        lifecycle: WatcherLifecycle,
        revision: u64,
        updated_at_unix_ms: u64,
    ) -> Self {
        Self {
            schema_version: WATCHER_STATE_SCHEMA_VERSION,
            watcher_id,
            target,
            lifecycle,
            revision,
            updated_at_unix_ms,
        }
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }
}

impl<'de> Deserialize<'de> for WatcherState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: u16,
            watcher_id: String,
            target: TargetIdentity,
            lifecycle: WatcherLifecycle,
            revision: u64,
            updated_at_unix_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.schema_version != WATCHER_STATE_SCHEMA_VERSION {
            return Err(D::Error::custom(format_args!(
                "unsupported watcher state schema version {}",
                wire.schema_version
            )));
        }
        Ok(Self::new(
            wire.watcher_id,
            wire.target,
            wire.lifecycle,
            wire.revision,
            wire.updated_at_unix_ms,
        ))
    }
}
