//! Append-only, redacted, retention-bounded audit and event logs.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::model::{SourceKind, TargetIdentity, WatcherLifecycle, WatcherState};
use crate::paths::WatchmePaths;
use crate::planner::{SnapshotBuildInput, SnapshotObservation, build_redacted_snapshot};
use crate::redact::redact_text;

pub const AUDIT_SCHEMA_VERSION: &str = "1.0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub schema_version: String,
    pub recorded_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watcher_id: Option<String>,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecisionChain {
    pub watcher_id: String,
    pub detector: String,
    pub evidence: String,
    pub state: String,
    pub policy_decision: String,
    pub attempted_action: String,
    pub verification: String,
}

/// Recovery decision phases persisted for `explain` / `logs`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionPhase {
    PolicyAllow,
    PolicyDeny,
    ActionBegin,
    ActionVerify,
    ActionCancel,
}

impl DecisionPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyAllow => "policy_allow",
            Self::PolicyDeny => "policy_deny",
            Self::ActionBegin => "action_begin",
            Self::ActionVerify => "action_verify",
            Self::ActionCancel => "action_cancel",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    pub events_days: u32,
    pub audit_days: u32,
    pub max_log_bytes: u64,
}

impl From<&crate::config::RetentionConfig> for RetentionPolicy {
    fn from(value: &crate::config::RetentionConfig) -> Self {
        Self {
            events_days: value.events_days,
            audit_days: value.audit_days,
            max_log_bytes: value.max_log_bytes,
        }
    }
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        if !path.exists() {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&path)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
            }
        }
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&mut self, event: &AuditEvent) -> io::Result<()> {
        let redacted = redact_event(event);
        let mut line = serde_json::to_string(&redacted)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        line.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        file.write_all(line.as_bytes())?;
        file.flush()?;
        Ok(())
    }

    pub fn apply_retention(
        &mut self,
        policy: &RetentionPolicy,
        now_rfc3339: &str,
    ) -> io::Result<()> {
        let cutoff_days = policy.audit_days.max(policy.events_days);
        let now = parse_rfc3339(now_rfc3339).unwrap_or_else(SystemTime::now);
        let cutoff = now
            .checked_sub(Duration::from_secs(
                u64::from(cutoff_days).saturating_mul(86_400),
            ))
            .unwrap_or(UNIX_EPOCH);

        let events = self.read_all()?;
        let mut kept: Vec<AuditEvent> = events
            .into_iter()
            .filter(|event| {
                parse_rfc3339(&event.recorded_at)
                    .map(|stamp| stamp >= cutoff)
                    .unwrap_or(true)
            })
            .map(|event| redact_event(&event))
            .collect();

        while encoded_size(&kept) > policy.max_log_bytes && !kept.is_empty() {
            kept.remove(0);
        }

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        for event in &kept {
            let mut line = serde_json::to_string(event)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            line.push('\n');
            file.write_all(line.as_bytes())?;
        }
        file.flush()?;
        Ok(())
    }

    pub fn read_lines(
        &mut self,
        watcher_id: Option<&str>,
        max_lines: usize,
    ) -> io::Result<Vec<AuditEvent>> {
        let mut events = self.read_all()?;
        if let Some(id) = watcher_id {
            events.retain(|event| event.watcher_id.as_deref() == Some(id));
        }
        if events.len() > max_lines {
            events = events.split_off(events.len() - max_lines);
        }
        Ok(events
            .into_iter()
            .map(|event| redact_event(&event))
            .collect())
    }

    pub fn follow_from(
        &self,
        offset: u64,
        watcher_id: Option<&str>,
        max_bytes: usize,
    ) -> io::Result<(Vec<AuditEvent>, u64)> {
        let mut file = File::open(&self.path)?;
        let len = file.metadata()?.len();
        let start = offset.min(len);
        file.seek(SeekFrom::Start(start))?;
        let mut buf = Vec::new();
        file.take(max_bytes as u64 + 1).read_to_end(&mut buf)?;
        if buf.len() > max_bytes {
            buf.truncate(max_bytes);
        }
        let text = String::from_utf8_lossy(&buf);
        let mut events = Vec::new();
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<AuditEvent>(line) {
                let event = redact_event(&event);
                if watcher_id.is_none_or(|id| event.watcher_id.as_deref() == Some(id)) {
                    events.push(event);
                }
            }
        }
        Ok((events, start + buf.len() as u64))
    }

    fn read_all(&self) -> io::Result<Vec<AuditEvent>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEvent>(&line) {
                Ok(event) => events.push(redact_event(&event)),
                Err(_) => continue,
            }
        }
        Ok(events)
    }
}

pub fn append_decision(log: &mut AuditLog, chain: &DecisionChain) -> io::Result<()> {
    log.append(&AuditEvent {
        schema_version: AUDIT_SCHEMA_VERSION.into(),
        recorded_at: now_rfc3339(),
        watcher_id: Some(chain.watcher_id.clone()),
        kind: "decision".into(),
        detector: Some(chain.detector.clone()),
        evidence: Some(chain.evidence.clone()),
        state: Some(chain.state.clone()),
        policy_decision: Some(chain.policy_decision.clone()),
        attempted_action: Some(chain.attempted_action.clone()),
        verification: Some(chain.verification.clone()),
        message: "decision chain".into(),
    })
}

/// Persist a recovery decision into audit.jsonl and a redacted snapshot file
/// where CLI `explain` / `logs` / `snapshot` already look.
pub fn record_recovery_decision(
    paths: &WatchmePaths,
    watcher: &WatcherState,
    phase: DecisionPhase,
    policy_decision: &str,
    attempted_action: &str,
    verification: &str,
) -> io::Result<()> {
    let _ = paths.create_owner_only();
    let chain = decision_chain_from_watcher(
        watcher,
        phase,
        policy_decision,
        attempted_action,
        verification,
    );
    let audit_path = paths.state_file("audit.jsonl")?;
    let mut log = AuditLog::open(audit_path)?;
    append_decision(&mut log, &chain)?;
    persist_watcher_snapshot(paths, watcher)?;
    Ok(())
}

/// Build the decision-chain record daemon recovery emits for operability CLI.
pub fn decision_chain_from_watcher(
    watcher: &WatcherState,
    phase: DecisionPhase,
    policy_decision: &str,
    attempted_action: &str,
    verification: &str,
) -> DecisionChain {
    let event = watcher.last_observation.as_ref();
    let detector = event
        .map(|event| format!("{:?}", event.source.kind))
        .unwrap_or_else(|| "none".into());
    let evidence = event
        .map(|event| {
            format!(
                "{}:{}",
                format!("{:?}", event.category).to_ascii_lowercase(),
                event.evidence_fingerprint
            )
        })
        .unwrap_or_else(|| "none".into());
    DecisionChain {
        watcher_id: watcher.watcher_id.clone(),
        detector: detector.to_ascii_lowercase(),
        evidence,
        state: format!("{phase:?}:{}", lifecycle_label(&watcher.lifecycle)),
        policy_decision: policy_decision.into(),
        attempted_action: attempted_action.into(),
        verification: verification.into(),
    }
}

/// Write a redacted planner-shaped snapshot to `state/snapshots/{watcher_id}.json`.
pub fn persist_watcher_snapshot(paths: &WatchmePaths, watcher: &WatcherState) -> io::Result<()> {
    let snap_dir = paths.state_dir().join("snapshots");
    fs::create_dir_all(&snap_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&snap_dir, fs::Permissions::from_mode(0o700));
    }
    let snapshot = build_watcher_snapshot(watcher).map_err(io::Error::other)?;
    let encoded = serde_json::to_vec_pretty(&snapshot)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let path = snap_dir.join(format!("{}.json", watcher.watcher_id));
    let tmp = snap_dir.join(format!("{}.json.tmp", watcher.watcher_id));
    fs::write(&tmp, &encoded)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn build_watcher_snapshot(watcher: &WatcherState) -> Result<serde_json::Value, String> {
    let event = watcher.last_observation.as_ref();
    let (mux_kind, pane_id, process) = match &watcher.target {
        TargetIdentity::Process { process } => ("process".into(), "none".into(), process),
        TargetIdentity::Multiplexer {
            provider,
            pane,
            process,
            ..
        } => (provider.clone(), pane.clone(), process),
    };
    let identity_hash = {
        use sha2::{Digest, Sha256};
        let bytes = serde_json::to_vec(&watcher.target).unwrap_or_default();
        format!("{:x}", Sha256::digest(bytes))
    };
    let observations = event
        .map(|event| {
            vec![SnapshotObservation {
                event_id: event.event_id.clone(),
                category: format!("{:?}", event.category).to_ascii_lowercase(),
                source_kind: source_kind_label(event.source.kind),
                confidence: event.confidence,
                summary: event.summary.clone(),
                observed_at: event.observed_at.clone(),
            }]
        })
        .unwrap_or_default();
    let input = SnapshotBuildInput {
        snapshot_id: format!("snap-{}", watcher.watcher_id),
        created_at: now_rfc3339(),
        watcher_id: watcher.watcher_id.clone(),
        watcher_state: lifecycle_label(&watcher.lifecycle),
        evidence_fingerprint: event
            .map(|event| event.evidence_fingerprint.clone())
            .unwrap_or_else(|| "0".repeat(64)),
        mux_kind,
        pane_id,
        process_pid: process.pid,
        process_start_time: process.start_time.to_string(),
        identity_hash,
        agent_id: event.and_then(|event| event.agent_id.clone()),
        provider_family: event.and_then(|event| event.provider_family.clone()),
        failed_provider_family: event
            .and_then(|event| event.provider_family.clone())
            .unwrap_or_else(|| "unknown".into()),
        terminal_text: event.map(|event| event.summary.clone()),
        observations,
        allowed_actions: vec![
            "WAIT_DURATION".into(),
            "CAPTURE".into(),
            "CHECK_STATUS".into(),
            "NOTIFY".into(),
            "NOOP".into(),
        ],
        max_snapshot_bytes: 50_000,
        extra_secret_names: vec![],
    };
    let snapshot = build_redacted_snapshot(input).map_err(|error| error.to_string())?;
    serde_json::to_value(snapshot).map_err(|error| error.to_string())
}

fn lifecycle_label(lifecycle: &WatcherLifecycle) -> String {
    match lifecycle {
        WatcherLifecycle::Registered => "REGISTERED".into(),
        WatcherLifecycle::Observing => "OBSERVING".into(),
        WatcherLifecycle::Paused => "PAUSED".into(),
        WatcherLifecycle::Recovering { .. } => "RECOVERING".into(),
        WatcherLifecycle::Waiting { .. } => "WAITING".into(),
        WatcherLifecycle::HumanRequired { .. } => "HUMAN_REQUIRED".into(),
        WatcherLifecycle::TargetTerminated => "TARGET_TERMINATED".into(),
        WatcherLifecycle::Stopped { .. } => "STOPPED".into(),
    }
}

fn source_kind_label(kind: SourceKind) -> String {
    match kind {
        SourceKind::ScreenDetection => "screen_detection",
        SourceKind::StructuredLog => "structured_log",
        SourceKind::Hook => "hook",
        SourceKind::TypedApi => "typed_api",
        SourceKind::HerdrAgentState => "herdr_agent_state",
        SourceKind::ProcessMetadata => "process_metadata",
        SourceKind::Planner => "planner",
        SourceKind::Internal => "internal",
    }
    .into()
}

pub fn explain_decision(
    chains: &[DecisionChain],
    watcher_id: Option<&str>,
) -> Result<DecisionChain, String> {
    let selected = match watcher_id {
        Some(id) => chains.iter().rev().find(|chain| chain.watcher_id == id),
        None => chains.last(),
    };
    selected
        .cloned()
        .ok_or_else(|| "no watcher decision chain found in audit".to_owned())
}

pub fn load_decision_chains(log: &mut AuditLog) -> io::Result<Vec<DecisionChain>> {
    let events = log.read_lines(None, 10_000)?;
    Ok(events
        .into_iter()
        .filter(|event| event.kind == "decision")
        .filter_map(|event| {
            Some(DecisionChain {
                watcher_id: event.watcher_id?,
                detector: event.detector.unwrap_or_else(|| "unknown".into()),
                evidence: event.evidence.unwrap_or_else(|| "none".into()),
                state: event.state.unwrap_or_else(|| "unknown".into()),
                policy_decision: event.policy_decision.unwrap_or_else(|| "unknown".into()),
                attempted_action: event.attempted_action.unwrap_or_else(|| "none".into()),
                verification: event.verification.unwrap_or_else(|| "none".into()),
            })
        })
        .collect())
}

fn redact_event(event: &AuditEvent) -> AuditEvent {
    let redact = |value: &Option<String>| value.as_ref().map(|text| redact_text(text, &[]).0);
    AuditEvent {
        schema_version: event.schema_version.clone(),
        recorded_at: event.recorded_at.clone(),
        watcher_id: event.watcher_id.clone(),
        kind: event.kind.clone(),
        detector: redact(&event.detector),
        evidence: redact(&event.evidence),
        state: event.state.clone(),
        policy_decision: redact(&event.policy_decision),
        attempted_action: redact(&event.attempted_action),
        verification: redact(&event.verification),
        message: redact_text(&event.message, &[]).0,
    }
}

fn encoded_size(events: &[AuditEvent]) -> u64 {
    events
        .iter()
        .map(|event| {
            serde_json::to_string(event)
                .map(|s| s.len() as u64 + 1)
                .unwrap_or(0)
        })
        .sum()
}

fn now_rfc3339() -> String {
    let now: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
    now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn parse_rfc3339(value: &str) -> Option<SystemTime> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|stamp| SystemTime::UNIX_EPOCH + Duration::from_secs(stamp.timestamp().max(0) as u64))
}
