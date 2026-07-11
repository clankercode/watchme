use serde::{Deserialize, Serialize};

use super::TargetIdentity;

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatcherState {
    pub schema_version: u16,
    pub watcher_id: String,
    pub target: TargetIdentity,
    pub lifecycle: WatcherLifecycle,
    pub revision: u64,
    pub updated_at_unix_ms: u64,
}
