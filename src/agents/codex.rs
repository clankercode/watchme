//! Codex durable-goal classification and recovery recipes.
//! Prefer App Server / structured rollout events over screen text. Never use
//! privileged shell APIs; recovery is wait-then-literal `/goal resume` only.

use crate::model::{
    Action, ActionKind, CodexRolloutBinding, Condition, Event, EventCategory, EventSource,
    PolicyHint, SourceKind, WatcherState,
};
use crate::recovery::engine::{BuiltinRecipes, RecipeProvider};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub use crate::model::{CodexRolloutBinding as RolloutBinding, CodexSessionReference};

pub const DEFAULT_RESUME: &str = "/goal resume";
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;
pub const DEFAULT_COOLDOWN_SECONDS: u64 = 300;
pub const DEFAULT_BACKOFF_CAP_SECONDS: u64 = 300;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexRecoveryPlan {
    None,
    WaitThenGoalResume,
    HumanRequired,
}

impl CodexRecoveryPlan {
    pub fn as_fixture_action(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::WaitThenGoalResume => "wait_then_goal_resume",
            Self::HumanRequired => "human_required",
        }
    }

    pub fn from_fixture_action(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "wait_then_goal_resume" => Some(Self::WaitThenGoalResume),
            "human_required" => Some(Self::HumanRequired),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CodexGoalSnapshot {
    pub thread_id: String,
    pub goal_status: Option<String>,
    pub goal_text: Option<String>,
    pub runtime_type: Option<String>,
    pub active_flags: Vec<String>,
    pub last_error_category: Option<String>,
    pub last_error_terminal: bool,
    pub screen_tail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexFixtureRecord {
    pub fixture: String,
    pub snapshot: CodexGoalSnapshot,
    pub expected_action: CodexRecoveryPlan,
}

/// Capability-probed Codex structured source. Prefer App Server / typed state
/// when locally bound; otherwise correlated rollout JSONL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProbedCodexSource {
    AppServer {
        snapshot: CodexGoalSnapshot,
        path: PathBuf,
    },
    Rollout {
        path: PathBuf,
        thread_id: String,
    },
}

impl ProbedCodexSource {
    pub fn is_app_server(&self) -> bool {
        matches!(self, Self::AppServer { .. })
    }

    pub fn is_rollout(&self) -> bool {
        matches!(self, Self::Rollout { .. })
    }
}

/// Classify a normalized goal/runtime snapshot. Structured goal status wins over
/// any screen wording that happens to contain "blocked".
pub fn classify_goal_snapshot(snapshot: &CodexGoalSnapshot) -> CodexRecoveryPlan {
    let Some(goal_status) = snapshot.goal_status.as_deref().map(normalize_status) else {
        return CodexRecoveryPlan::None;
    };
    if matches!(
        goal_status.as_str(),
        "active" | "pursuing" | "completed" | "cancelled" | "canceled"
    ) {
        return CodexRecoveryPlan::None;
    }
    if !matches!(goal_status.as_str(), "blocked" | "paused") {
        return CodexRecoveryPlan::None;
    }
    if snapshot
        .active_flags
        .iter()
        .any(|flag| normalize_status(flag) == "waitingonapproval")
        || snapshot
            .runtime_type
            .as_deref()
            .is_some_and(|value| normalize_status(value) == "waitingonapproval")
    {
        return CodexRecoveryPlan::HumanRequired;
    }
    match snapshot
        .last_error_category
        .as_deref()
        .map(normalize_status)
        .as_deref()
    {
        Some("capacity_block" | "capacity" | "overloaded" | "model_capacity") => {
            CodexRecoveryPlan::WaitThenGoalResume
        }
        Some("auth" | "authentication" | "authentication_failure" | "billing" | "safety") => {
            CodexRecoveryPlan::HumanRequired
        }
        Some(_) | None => CodexRecoveryPlan::HumanRequired,
    }
}

pub fn parse_fixture_record(line: &str) -> Option<CodexFixtureRecord> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let fixture = value.get("fixture")?.as_str()?.to_owned();
    let expected = CodexRecoveryPlan::from_fixture_action(value.get("expected_action")?.as_str()?)?;
    let snapshot = snapshot_from_value(&value)?;
    Some(CodexFixtureRecord {
        fixture,
        snapshot,
        expected_action: expected,
    })
}

/// Prefer TypedApi (App Server) and StructuredLog (rollout). Screen-only payloads
/// are intentionally rejected so quoted scrollback cannot drive `/goal resume`.
pub fn normalize_structured_source(
    value: &serde_json::Value,
    source: SourceKind,
) -> Option<CodexGoalSnapshot> {
    match source {
        SourceKind::TypedApi | SourceKind::StructuredLog | SourceKind::Hook => {
            snapshot_from_value(value)
        }
        SourceKind::ScreenDetection => None,
        _ => snapshot_from_value(value).filter(|snap| snap.goal_status.is_some()),
    }
}

fn snapshot_from_value(value: &serde_json::Value) -> Option<CodexGoalSnapshot> {
    let thread_id = value
        .get("thread_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    if thread_id.is_empty() {
        return None;
    }
    let goal = value.get("goal");
    let runtime = value.get("runtime_status");
    let error = value.get("last_error");
    let active_flags = runtime
        .and_then(|runtime| runtime.get("active_flags"))
        .and_then(serde_json::Value::as_array)
        .map(|flags| {
            flags
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Some(CodexGoalSnapshot {
        thread_id,
        goal_status: goal
            .and_then(|goal| goal.get("status"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        goal_text: goal
            .and_then(|goal| goal.get("text"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        runtime_type: runtime
            .and_then(|runtime| runtime.get("type"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        active_flags,
        last_error_category: error
            .and_then(|error| error.get("category"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        last_error_terminal: error
            .and_then(|error| error.get("terminal"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        screen_tail: value
            .get("screen_tail")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    })
}

/// Rebuild nested App Server / rollout JSON from a flat goal snapshot.
/// Same shape as the Rollout arm of post-resume verify so
/// [`normalize_structured_source`] / [`trusted_goal_progress_event`] can read
/// `goal.status` rather than a Serialize-flat `goal_status` field.
pub fn structured_value_from_snapshot(snapshot: &CodexGoalSnapshot) -> serde_json::Value {
    let mut goal = serde_json::Map::new();
    if let Some(status) = &snapshot.goal_status {
        goal.insert("status".into(), serde_json::Value::String(status.clone()));
    }
    if let Some(text) = &snapshot.goal_text {
        goal.insert("text".into(), serde_json::Value::String(text.clone()));
    }
    let mut runtime = serde_json::Map::new();
    if let Some(runtime_type) = &snapshot.runtime_type {
        runtime.insert(
            "type".into(),
            serde_json::Value::String(runtime_type.clone()),
        );
    }
    runtime.insert(
        "active_flags".into(),
        serde_json::Value::Array(
            snapshot
                .active_flags
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    let mut value = serde_json::Map::new();
    value.insert(
        "thread_id".into(),
        serde_json::Value::String(snapshot.thread_id.clone()),
    );
    value.insert("goal".into(), serde_json::Value::Object(goal));
    value.insert("runtime_status".into(), serde_json::Value::Object(runtime));
    if snapshot.last_error_category.is_some() || snapshot.last_error_terminal {
        let mut error = serde_json::Map::new();
        if let Some(category) = &snapshot.last_error_category {
            error.insert(
                "category".into(),
                serde_json::Value::String(category.clone()),
            );
        }
        error.insert(
            "terminal".into(),
            serde_json::Value::Bool(snapshot.last_error_terminal),
        );
        value.insert("last_error".into(), serde_json::Value::Object(error));
    }
    if let Some(tail) = &snapshot.screen_tail {
        value.insert(
            "screen_tail".into(),
            serde_json::Value::String(tail.clone()),
        );
    }
    serde_json::Value::Object(value)
}

fn normalize_status(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub fn capacity_backoff_seconds(attempt: u32, entropy: u64, cap: u64) -> u64 {
    let ceiling = (1_u64 << attempt.min(10)).saturating_mul(5).min(cap.max(1));
    entropy % ceiling.saturating_add(1)
}

pub fn bind_rollout(path: &Path) -> Option<CodexRolloutBinding> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(CodexRolloutBinding {
            device: meta.dev(),
            inode: meta.ino(),
            size: meta.len(),
            mtime_secs: meta.mtime(),
        })
    }
    #[cfg(not(unix))]
    {
        let modified = meta.modified().ok()?;
        let mtime_secs = modified
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs() as i64;
        Some(CodexRolloutBinding {
            device: 0,
            inode: 0,
            size: meta.len(),
            mtime_secs,
        })
    }
}

pub fn rollout_matches_binding(path: &Path, binding: &CodexRolloutBinding) -> bool {
    bind_rollout(path).is_some_and(|current| current == *binding)
}

/// Convert only complete, thread-correlated rollout JSONL into an event.
/// Partial trailing lines and rotated/replaced files are not evidence.
pub fn correlated_rollout_event(
    watcher: &WatcherState,
    path: &Path,
    thread_id: &str,
) -> Option<Event> {
    if thread_id.is_empty() {
        return None;
    }
    let binding = bind_rollout(path)?;
    if let Some(previous) = watcher.last_observation.as_ref()
        && previous
            .metadata
            .get("codex_rollout_path")
            .and_then(serde_json::Value::as_str)
            == Some(path.to_string_lossy().as_ref())
    {
        let previous_binding = previous.metadata.get("codex_rollout_binding")?;
        let previous_binding: CodexRolloutBinding =
            serde_json::from_value(previous_binding.clone()).ok()?;
        if previous_binding != binding {
            return None;
        }
    }
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() > 1_048_576 {
        return None;
    }
    let text = std::str::from_utf8(&bytes).ok()?;
    if !text.is_empty() && !text.ends_with('\n') {
        // A truncated final line is not durable evidence.
        return None;
    }
    let mut matched = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            return None;
        };
        let Some(snapshot) = normalize_structured_source(&value, SourceKind::StructuredLog) else {
            continue;
        };
        if snapshot.thread_id == thread_id {
            matched = Some(snapshot);
        }
    }
    let snapshot = matched?;
    let mut event = structured_goal_event(watcher, &snapshot, SourceKind::StructuredLog)?;
    event.metadata.insert(
        "codex_rollout_path".into(),
        serde_json::Value::String(path.to_string_lossy().into_owned()),
    );
    event.metadata.insert(
        "codex_rollout_binding".into(),
        serde_json::to_value(&binding).ok()?,
    );
    Some(event)
}

/// Prefer App Server / structured snapshot when bound and owner-only; otherwise
/// correlated rollout JSONL under the process CWD. Missing, ambiguous, rotated,
/// or world-readable paths fail closed.
pub fn probe_structured_source(watcher: &WatcherState) -> Option<ProbedCodexSource> {
    let reference = watcher.codex_session.as_ref()?;
    let process = match &watcher.target {
        crate::model::TargetIdentity::Process { process }
        | crate::model::TargetIdentity::Multiplexer { process, .. } => process,
    };
    if process.start_time != reference.process_start_time
        || current_target_session(&watcher.target) != reference.target_session
        || !process_cwd_matches(process.pid, &reference.process_cwd)
    {
        return None;
    }
    let cwd = Path::new(&reference.process_cwd);
    if let Some(path) = reference.app_server_state_path.as_deref() {
        let path = Path::new(path);
        if owner_only_bound_regular(path, cwd).is_some()
            && let Ok(bytes) = std::fs::read(path)
            && bytes.len() <= 1_048_576
            && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && let Some(snapshot) = normalize_structured_source(&value, SourceKind::TypedApi)
            && snapshot.thread_id == reference.thread_id
        {
            return Some(ProbedCodexSource::AppServer {
                snapshot,
                path: path.to_path_buf(),
            });
        }
    }
    let rollout = Path::new(&reference.rollout_path);
    let binding = reference.rollout_binding.as_ref()?;
    let path = owner_only_bound_regular(rollout, cwd)?;
    if !rollout_matches_binding(&path, binding) {
        return None;
    }
    Some(ProbedCodexSource::Rollout {
        path,
        thread_id: reference.thread_id.clone(),
    })
}

/// Production observation entry: resume candidate after wait, else probed
/// App Server / correlated rollout event.
pub fn observe_codex_event(
    watcher: &WatcherState,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Event> {
    if resume_candidate_event(watcher, now).is_some() {
        // A capacity wait that elapsed still needs the durable goal to remain
        // blocked before we re-emit a resume candidate; re-probe when possible.
        if let Some(source) = probe_structured_source(watcher) {
            match source {
                ProbedCodexSource::AppServer { snapshot, .. } => {
                    if matches!(
                        classify_goal_snapshot(&snapshot),
                        CodexRecoveryPlan::WaitThenGoalResume
                    ) {
                        return resume_candidate_event(watcher, now);
                    }
                    return structured_goal_event(watcher, &snapshot, SourceKind::TypedApi);
                }
                ProbedCodexSource::Rollout { path, thread_id } => {
                    if let Some(event) = correlated_rollout_event(watcher, &path, &thread_id) {
                        if event.category == EventCategory::CapacityBlock {
                            return resume_candidate_event(watcher, now);
                        }
                        return Some(event);
                    }
                }
            }
        } else {
            return resume_candidate_event(watcher, now);
        }
    }
    match probe_structured_source(watcher)? {
        ProbedCodexSource::AppServer { snapshot, .. } => {
            structured_goal_event(watcher, &snapshot, SourceKind::TypedApi)
        }
        ProbedCodexSource::Rollout { path, thread_id } => {
            correlated_rollout_event(watcher, &path, &thread_id)
        }
    }
}

/// Durable exactly-once marker written when a Codex `/goal resume` is committed.
pub fn mark_resume_sent(event: &mut Event, fingerprint: &str) {
    if fingerprint.is_empty() {
        return;
    }
    event.metadata.insert(
        "codex_resume_sent_fingerprint".into(),
        serde_json::Value::String(fingerprint.into()),
    );
}

fn current_target_session(target: &crate::model::TargetIdentity) -> Option<String> {
    match target {
        crate::model::TargetIdentity::Process { .. } => None,
        crate::model::TargetIdentity::Multiplexer { session, .. } => session.clone(),
    }
}

fn process_cwd_matches(pid: u32, expected: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(actual) = std::fs::read_link(format!("/proc/{pid}/cwd")) else {
            return false;
        };
        actual == Path::new(expected)
            || std::fs::canonicalize(expected)
                .ok()
                .is_some_and(|path| path == actual)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        std::fs::canonicalize(expected)
            .ok()
            .is_some_and(|path| path.is_dir())
    }
}

/// Resolve `path` only when it is a regular, owner-only file whose canonical
/// location stays under the bound CWD. Symlinks that escape the binding fail.
fn owner_only_bound_regular(path: &Path, cwd: &Path) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = std::fs::symlink_metadata(path).ok()?;
        if !meta.file_type().is_file() || meta.permissions().mode() & 0o077 != 0 {
            return None;
        }
        let uid = rustix::process::getuid().as_raw();
        if meta.uid() != uid {
            return None;
        }
        let canonical = std::fs::canonicalize(path).ok()?;
        let cwd = std::fs::canonicalize(cwd).ok()?;
        if !canonical.starts_with(&cwd) {
            return None;
        }
        let opened = std::fs::metadata(&canonical).ok()?;
        if opened.dev() != meta.dev() || opened.ino() != meta.ino() {
            return None;
        }
        Some(canonical)
    }
    #[cfg(not(unix))]
    {
        let _ = cwd;
        path.is_file().then(|| path.to_path_buf())
    }
}

pub fn structured_goal_event(
    watcher: &WatcherState,
    snapshot: &CodexGoalSnapshot,
    source_kind: SourceKind,
) -> Option<Event> {
    let plan = classify_goal_snapshot(snapshot);
    let (category, hint, terminal) = match plan {
        CodexRecoveryPlan::None => {
            let status = snapshot.goal_status.as_deref().map(normalize_status)?;
            if matches!(status.as_str(), "active" | "pursuing") {
                (EventCategory::Working, PolicyHint::ObserveOnly, false)
            } else if matches!(status.as_str(), "completed" | "cancelled" | "canceled") {
                (EventCategory::Idle, PolicyHint::ObserveOnly, false)
            } else {
                return None;
            }
        }
        CodexRecoveryPlan::WaitThenGoalResume => {
            (EventCategory::CapacityBlock, PolicyHint::WaitAllowed, true)
        }
        CodexRecoveryPlan::HumanRequired => {
            (EventCategory::BlockedGoal, PolicyHint::HumanRequired, true)
        }
    };
    let target_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&watcher.target).ok()?)
    );
    let observed: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    let evidence = serde_json::to_vec(snapshot).ok()?;
    let mut event = Event::new(
        format!("codex-goal-{}", watcher.watcher_id),
        observed.to_rfc3339(),
        watcher.watcher_id.clone(),
        target_hash,
        EventSource::new(source_kind, "codex", "goal_status"),
        category,
        if source_kind == SourceKind::TypedApi {
            1.0
        } else {
            0.9
        },
        terminal,
        crate::observe::evidence_fingerprint("codex_goal", &snapshot.thread_id, &evidence),
        "Codex durable goal status",
        hint,
    )
    .ok()?;
    event.session_id = Some(snapshot.thread_id.clone());
    event.metadata.insert(
        "codex_thread_id".into(),
        serde_json::Value::String(snapshot.thread_id.clone()),
    );
    if let Some(status) = &snapshot.goal_status {
        event.metadata.insert(
            "goal_state".into(),
            serde_json::Value::String(normalize_status(status)),
        );
    }
    if let Some(text) = &snapshot.goal_text {
        event.metadata.insert(
            "codex_goal_text".into(),
            serde_json::Value::String(text.clone()),
        );
    }
    if matches!(plan, CodexRecoveryPlan::WaitThenGoalResume) {
        event
            .metadata
            .insert("codex_capacity_block".into(), serde_json::Value::Bool(true));
    }
    if let Some(category) = &snapshot.last_error_category {
        event.metadata.insert(
            "codex_error_category".into(),
            serde_json::Value::String(category.clone()),
        );
    }
    Some(event)
}

/// After a capacity backoff wait, emit a single resume-revalidation candidate.
pub fn resume_candidate_event(
    watcher: &WatcherState,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Event> {
    if !matches!(
        watcher.lifecycle,
        crate::model::WatcherLifecycle::Waiting { .. }
    ) {
        return None;
    }
    let previous = watcher.last_observation.as_ref()?;
    if previous.source.source_id != "codex"
        || previous.category != EventCategory::CapacityBlock
        || previous.policy_hint != PolicyHint::WaitAllowed
        || previous.metadata.get("codex_capacity_block") != Some(&serde_json::Value::Bool(true))
    {
        return None;
    }
    if previous
        .metadata
        .get("goal_state")
        .and_then(serde_json::Value::as_str)
        != Some("blocked")
        && previous
            .metadata
            .get("goal_state")
            .and_then(serde_json::Value::as_str)
            != Some("paused")
    {
        return None;
    }
    let mut event = previous.clone();
    event.event_id = format!("codex-resume-{}", watcher.watcher_id);
    event.observed_at = now.to_rfc3339();
    event.category = EventCategory::WaitingForModel;
    event.terminal = false;
    event.policy_hint = PolicyHint::DeterministicActionAllowed;
    event.evidence_fingerprint = crate::observe::evidence_fingerprint(
        "codex_resume",
        &previous.evidence_fingerprint,
        now.to_rfc3339().as_bytes(),
    );
    event.summary = "Codex capacity backoff elapsed; goal resume revalidation candidate".into();
    event
        .metadata
        .insert("codex_resume".into(), serde_json::Value::Bool(true));
    event.metadata.insert(
        "codex_resume_session".into(),
        serde_json::Value::String(event.evidence_fingerprint.clone()),
    );
    Some(event)
}

/// Post-send proof that the durable goal returned to active/pursuing.
pub fn trusted_goal_progress_event(
    watcher: &WatcherState,
    baseline: &Event,
    structured: &serde_json::Value,
    observed_at: &str,
) -> Option<Event> {
    let snapshot = normalize_structured_source(structured, SourceKind::TypedApi)
        .or_else(|| normalize_structured_source(structured, SourceKind::StructuredLog))?;
    let status = snapshot.goal_status.as_deref().map(normalize_status)?;
    if !matches!(status.as_str(), "active" | "pursuing") {
        return None;
    }
    if chrono::DateTime::parse_from_rfc3339(observed_at).ok()?
        <= chrono::DateTime::parse_from_rfc3339(&baseline.observed_at).ok()?
    {
        return None;
    }
    let session = baseline
        .metadata
        .get("codex_resume_session")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            baseline
                .metadata
                .get("codex_thread_id")
                .and_then(serde_json::Value::as_str)
        })?;
    let mut event = Event::new(
        format!("codex-progress-{}", watcher.watcher_id),
        observed_at,
        watcher.watcher_id.clone(),
        baseline.target_identity_hash.clone(),
        EventSource::new(SourceKind::TypedApi, "codex", "post_resume_progress"),
        EventCategory::Working,
        1.0,
        false,
        crate::observe::evidence_fingerprint(
            "codex_progress",
            session,
            serde_json::to_vec(&snapshot).ok()?.as_slice(),
        ),
        "Codex durable goal active/pursuing after resume",
        PolicyHint::ObserveOnly,
    )
    .ok()?;
    event.metadata.insert(
        "goal_state".into(),
        serde_json::Value::String(status.clone()),
    );
    event.metadata.insert(
        "codex_post_resume_progress".into(),
        serde_json::Value::Bool(true),
    );
    event.metadata.insert(
        "codex_resume_session".into(),
        serde_json::Value::String(session.into()),
    );
    if let Some(thread_id) = baseline
        .metadata
        .get("codex_thread_id")
        .cloned()
        .or(Some(serde_json::Value::String(snapshot.thread_id)))
    {
        event.metadata.insert("codex_thread_id".into(), thread_id);
    }
    Some(event)
}

/// Codex owns durable-goal capacity recovery before provider-independent waits.
pub struct CodexRecipes {
    generic: BuiltinRecipes,
    resume_command: String,
    backoff_cap_seconds: u64,
}

impl Default for CodexRecipes {
    fn default() -> Self {
        Self {
            generic: BuiltinRecipes,
            resume_command: DEFAULT_RESUME.into(),
            backoff_cap_seconds: DEFAULT_BACKOFF_CAP_SECONDS,
        }
    }
}

impl RecipeProvider for CodexRecipes {
    fn action_for(&self, watcher: &WatcherState) -> Option<Action> {
        let event = watcher.last_observation.as_ref()?;
        if event.source.source_id != "codex" {
            return self.generic.action_for(watcher);
        }
        if event.category == EventCategory::CapacityBlock
            && event.policy_hint == PolicyHint::WaitAllowed
            && event.metadata.get("codex_capacity_block") == Some(&serde_json::Value::Bool(true))
        {
            return Some(capacity_wait(
                event,
                watcher.revision,
                self.backoff_cap_seconds,
            ));
        }
        if event.category == EventCategory::WaitingForModel
            && event.policy_hint == PolicyHint::DeterministicActionAllowed
            && event.metadata.get("codex_resume") == Some(&serde_json::Value::Bool(true))
        {
            if event
                .metadata
                .get("codex_resume_sent_fingerprint")
                .and_then(serde_json::Value::as_str)
                == Some(event.evidence_fingerprint.as_str())
            {
                return None;
            }
            return resume_action(event, &self.resume_command);
        }
        if event.policy_hint == PolicyHint::HumanRequired {
            return None;
        }
        self.generic.action_for(watcher)
    }
}

fn capacity_wait(event: &Event, revision: u64, cap: u64) -> Action {
    let seconds =
        capacity_backoff_seconds(revision as u32, hash64(&event.evidence_fingerprint), cap).max(1);
    let mut action = Action::new(
        "codex.capacity_backoff_wait",
        ActionKind::WaitDuration {
            duration_seconds: seconds,
        },
        "transient Codex capacity block with durable blocked goal",
        event.evidence_fingerprint.clone(),
        30,
    );
    action.expected_outcomes = vec![Condition {
        kind: "WAIT_STATE_RECORDED".into(),
        value: None,
    }];
    action
}

fn resume_action(event: &Event, resume_command: &str) -> Option<Action> {
    let goal_state = event.metadata.get("goal_state")?.as_str()?;
    if !matches!(goal_state, "blocked" | "paused") {
        return None;
    }
    let mut action = Action::send_text(
        "codex.goal_resume_once",
        resume_command,
        "durable Codex goal blocked after capacity backoff; composer revalidated",
        event.evidence_fingerprint.clone(),
    );
    action.preconditions.extend([
        Condition {
            kind: "PROCESS_ALIVE".into(),
            value: None,
        },
        Condition {
            kind: "NO_HUMAN_INTERVENTION".into(),
            value: None,
        },
        Condition {
            kind: "COMPOSER_EMPTY".into(),
            value: None,
        },
        Condition {
            kind: "GOAL_STATE_IS".into(),
            value: Some(serde_json::Value::String(goal_state.into())),
        },
    ]);
    action.expected_outcomes = vec![Condition {
        kind: "GOAL_ACTIVE_OR_PURSUING".into(),
        value: None,
    }];
    Some(action)
}

fn hash64(value: &str) -> u64 {
    value.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// Tries Claude recipes, then Codex, then manifest-driven recoveries, preserving
/// Claude's Builtin fallthrough for non-Claude wait-allowed observations that
/// Codex and manifests do not claim.
pub struct CompositeRecipes {
    claude: crate::agents::claude::ClaudeRecipes,
    codex: CodexRecipes,
    manifests: crate::agents::manifest::ManifestRecipes,
}

impl Default for CompositeRecipes {
    fn default() -> Self {
        Self {
            claude: crate::agents::claude::ClaudeRecipes::default(),
            codex: CodexRecipes::default(),
            manifests: crate::agents::manifest::ManifestRecipes::bundled()
                .unwrap_or_else(|_| crate::agents::manifest::ManifestRecipes::empty()),
        }
    }
}

impl RecipeProvider for CompositeRecipes {
    fn action_for(&self, watcher: &WatcherState) -> Option<Action> {
        let event = watcher.last_observation.as_ref()?;
        if event.source.source_id == "codex"
            || event.source.source_id.starts_with("codex")
            || event.metadata.contains_key("codex_capacity_block")
            || event.metadata.contains_key("codex_resume")
        {
            return self.codex.action_for(watcher);
        }
        self.claude
            .action_for(watcher)
            .or_else(|| self.codex.action_for(watcher))
            .or_else(|| self.manifests.action_for(watcher))
    }
}
