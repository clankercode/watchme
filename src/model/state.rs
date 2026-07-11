use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use super::TargetIdentity;
use crate::recovery::state_machine::RecoveryMachine;

pub const WATCHER_STATE_SCHEMA_VERSION: u16 = 1;
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSchedule {
    pub next_due_monotonic_ms: u64,
    pub last_check_monotonic_ms: Option<u64>,
    pub event_wake_pending: bool,
    pub interval_sequence: u64,
}
impl ObservationSchedule {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum WatcherLifecycle {
    Registered,
    Observing,
    Paused,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryMachine>,
    #[serde(default, skip_serializing_if = "ObservationSchedule::is_default")]
    pub observation_schedule: ObservationSchedule,
}

impl WatcherState {
    pub fn new(
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
            recovery: None,
            observation_schedule: ObservationSchedule::default(),
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
            #[serde(default)]
            recovery: Option<RecoveryMachine>,
            #[serde(default)]
            observation_schedule: ObservationSchedule,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.schema_version != WATCHER_STATE_SCHEMA_VERSION {
            return Err(D::Error::custom(format_args!(
                "unsupported watcher state schema version {}",
                wire.schema_version
            )));
        }
        let mut state = Self::new(
            wire.watcher_id,
            wire.target,
            wire.lifecycle,
            wire.revision,
            wire.updated_at_unix_ms,
        );
        state.recovery = wire.recovery;
        state.observation_schedule = wire.observation_schedule;
        Ok(state)
    }
}
