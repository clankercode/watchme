//! Codex durable-goal classification and recovery recipes.
//! Prefer App Server / structured rollout events over screen text. Never use
//! privileged shell APIs; recovery is wait-then-literal `/goal resume` only.

use crate::model::{
    Action, ActionKind, Condition, Event, EventCategory, EventSource, PolicyHint, SourceKind,
    WatcherState,
};
use crate::recovery::engine::{BuiltinRecipes, RecipeProvider};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RolloutBinding {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub mtime_secs: i64,
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

fn normalize_status(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub fn capacity_backoff_seconds(attempt: u32, entropy: u64, cap: u64) -> u64 {
    let ceiling = (1_u64 << attempt.min(10)).saturating_mul(5).min(cap.max(1));
    entropy % ceiling.saturating_add(1)
}

pub fn bind_rollout(path: &Path) -> Option<RolloutBinding> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(RolloutBinding {
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
        Some(RolloutBinding {
            device: 0,
            inode: 0,
            size: meta.len(),
            mtime_secs,
        })
    }
}

pub fn rollout_matches_binding(path: &Path, binding: &RolloutBinding) -> bool {
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
    if let Some(previous) = watcher.last_observation.as_ref() {
        if previous
            .metadata
            .get("codex_rollout_path")
            .and_then(serde_json::Value::as_str)
            == Some(path.to_string_lossy().as_ref())
        {
            let previous_binding = previous.metadata.get("codex_rollout_binding")?;
            let previous_binding: RolloutBinding =
                serde_json::from_value(previous_binding.clone()).ok()?;
            if previous_binding != binding {
                return None;
            }
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

/// Tries Claude recipes, then Codex, preserving Claude's Builtin fallthrough for
/// non-Claude wait-allowed observations that Codex does not claim.
#[derive(Default)]
pub struct CompositeRecipes {
    claude: crate::agents::claude::ClaudeRecipes,
    codex: CodexRecipes,
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
    }
}
