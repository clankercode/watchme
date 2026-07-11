use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use super::TargetIdentity;
use crate::recovery::state_machine::RecoveryMachine;

pub const WATCHER_STATE_SCHEMA_VERSION: u16 = 1;
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSchedule {
    pub next_due_wall_ms: u64,
    pub last_check_wall_ms: Option<u64>,
    pub event_wake_pending: bool,
    pub interval_sequence: u64,
    pub last_wake_fingerprint: Option<String>,
    pub last_wake_completed_wall_ms: Option<u64>,
    pub herdr_after_sequence: u64,
    pub screen_fingerprint: Option<String>,
    pub screen_stable_count: u8,
}

/// A Claude session reference is established at registration from a hook/API
/// payload or a process-correlated open transcript.  It is never populated by
/// a newest-file search.  The daemon needs all four values before reading a
/// StopFailure marker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeSessionReference {
    pub session_id: String,
    pub transcript_path: String,
    pub marker_path: String,
    pub process_start_time: u64,
    pub process_cwd: String,
    /// The registered multiplexer session, when present. It prevents a hook
    /// marker from surviving a pane/session retarget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_session: Option<String>,
    /// Captured at registration. Legacy references without this proof remain
    /// readable but are intentionally ineligible for hook recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_binding: Option<TranscriptBinding>,
}

/// A Codex session reference binds a durable thread to an owner-only rollout or
/// App Server snapshot. It is never filled by a newest-file search.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexSessionReference {
    pub thread_id: String,
    pub rollout_path: String,
    pub process_start_time: u64,
    pub process_cwd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_session: Option<String>,
    /// Captured at registration. Missing bindings remain readable but are
    /// ineligible for correlated rollout recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollout_binding: Option<CodexRolloutBinding>,
    /// Optional App Server / structured state snapshot path. Prefer this over
    /// rollout when present, owner-only, and under the bound CWD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_server_state_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptBinding {
    pub canonical_path: String,
    pub device: u64,
    pub inode: u64,
}

/// Identity of a Codex rollout JSONL file at registration time. Size and mtime
/// participate so a replaced file at the same path fails closed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexRolloutBinding {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_secs: i64,
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

#[derive(Clone, Debug, PartialEq, Serialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_observation: Option<crate::model::Event>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claude_session: Option<ClaudeSessionReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub codex_session: Option<CodexSessionReference>,
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
            last_observation: None,
            claude_session: None,
            codex_session: None,
        }
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub fn set_claude_session(&mut self, reference: ClaudeSessionReference) -> Result<(), String> {
        if reference.session_id.is_empty()
            || reference.session_id.len() > 256
            || !std::path::Path::new(&reference.transcript_path).is_absolute()
            || !std::path::Path::new(&reference.marker_path).is_absolute()
            || !std::path::Path::new(&reference.process_cwd).is_absolute()
            || reference
                .target_session
                .as_deref()
                .is_some_and(|session| session.is_empty() || session.len() > 256)
        {
            return Err("invalid trusted Claude session reference".into());
        }
        self.claude_session = Some(reference);
        Ok(())
    }

    pub fn set_codex_session(&mut self, reference: CodexSessionReference) -> Result<(), String> {
        if reference.thread_id.is_empty()
            || reference.thread_id.len() > 256
            || !std::path::Path::new(&reference.rollout_path).is_absolute()
            || !std::path::Path::new(&reference.process_cwd).is_absolute()
            || reference
                .target_session
                .as_deref()
                .is_some_and(|session| session.is_empty() || session.len() > 256)
            || reference
                .app_server_state_path
                .as_deref()
                .is_some_and(|path| !std::path::Path::new(path).is_absolute())
        {
            return Err("invalid trusted Codex session reference".into());
        }
        self.codex_session = Some(reference);
        Ok(())
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
            #[serde(default)]
            last_observation: Option<crate::model::Event>,
            #[serde(default)]
            claude_session: Option<ClaudeSessionReference>,
            #[serde(default)]
            codex_session: Option<CodexSessionReference>,
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
        state.last_observation = wire.last_observation;
        state.claude_session = wire.claude_session;
        state.codex_session = wire.codex_session;
        Ok(state)
    }
}
