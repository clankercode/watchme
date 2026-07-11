//! Conservative Claude Code classification and labelled-menu planning.
//! Terminal captures are only eligible when supplied by a trusted live screen adapter.

use crate::model::{
    Action, ActionKind, Condition, Event, EventCategory, EventReset, EventSource, PolicyHint,
    SourceKind, WatcherState,
};
use crate::recovery::engine::{BuiltinRecipes, RecipeProvider};
use crate::recovery::reset_time::parse_reset;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaudeClass {
    UsageLimit,
    SessionLimit,
    WeeklyLimit,
    TerminalOverload,
    NativeRetry,
    HumanRequired,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WaitMenu {
    pub moves: i8,
}

const WAIT_LABEL: &str = "stop and wait for limit to reset";

pub fn classify_stop_failure(error_type: &str, detail: &str, native_retry: bool) -> ClaudeClass {
    let error = error_type.to_ascii_lowercase();
    let text = detail.to_ascii_lowercase();
    if native_retry || text.contains("retrying") {
        return ClaudeClass::NativeRetry;
    }
    if contains_any(
        &error,
        &[
            "auth",
            "billing",
            "credit",
            "invalid",
            "safety",
            "model_not_found",
            "not_found",
        ],
    ) || contains_any(
        &text,
        &[
            "sign in",
            "login",
            "billing",
            "add funds",
            "credit",
            "upgrade",
            "invalid request",
            "safety",
            "model unavailable",
        ],
    ) {
        return ClaudeClass::HumanRequired;
    }
    if contains_any(&text, &["weekly usage limit", "weekly limit"]) {
        return ClaudeClass::WeeklyLimit;
    }
    if contains_any(&text, &["session limit"]) {
        return ClaudeClass::SessionLimit;
    }
    if contains_any(&error, &["rate_limit"])
        || contains_any(&text, &["usage limit", "limit to reset", "resets in"])
    {
        return ClaudeClass::UsageLimit;
    }
    if contains_any(&error, &["overloaded", "server_error"])
        || contains_any(
            &text,
            &[
                "api error: 529",
                "overloaded",
                "service capacity",
                "api error: 500",
                "api error: 502",
                "api error: 503",
                "api error: 504",
            ],
        )
    {
        return ClaudeClass::TerminalOverload;
    }
    ClaudeClass::Unknown
}

pub fn classify_screen(first: &str, second: &str) -> ClaudeClass {
    if labelled_wait_menu(first, second).is_some() {
        let text = first.to_ascii_lowercase();
        if text.contains("weekly") {
            ClaudeClass::WeeklyLimit
        } else if text.contains("session") {
            ClaudeClass::SessionLimit
        } else {
            ClaudeClass::UsageLimit
        }
    } else if first == second && !looks_quoted(first) {
        classify_stop_failure("", first, false)
    } else {
        ClaudeClass::Unknown
    }
}

/// Both captures must be byte-identical after adapter sanitization.  The selected
/// line and cursor are parsed from current UI rows; numeric values are never used.
pub fn labelled_wait_menu(first: &str, second: &str) -> Option<WaitMenu> {
    if first != second || first.len() > 16_384 || looks_quoted(first) {
        return None;
    }
    let rows: Vec<_> = first.lines().filter_map(menu_row).collect();
    let target = rows.iter().position(|row| is_wait_label(&row.1))?;
    let cursor = rows.iter().position(|row| row.0)?;
    // Account-changing choices may be present but are never selected. Refuse
    // ambiguous duplicate labels/cursors and wrapped/malformed rows.
    if rows.iter().filter(|row| is_wait_label(&row.1)).count() != 1
        || rows.iter().filter(|row| row.0).count() != 1
    {
        return None;
    }
    i8::try_from(target)
        .ok()?
        .checked_sub(i8::try_from(cursor).ok()?)
        .map(|moves| WaitMenu { moves })
}

fn menu_row(line: &str) -> Option<(bool, String)> {
    let trimmed = line.trim();
    let (cursor, rest) = if let Some(rest) = trimmed
        .strip_prefix('>')
        .or_else(|| trimmed.strip_prefix('›'))
    {
        (true, rest.trim_start())
    } else {
        (false, trimmed)
    };
    // A row number proves this is current UI chrome. It is intentionally
    // discarded: selection is derived from row order and the semantic label.
    let (number, label) = rest.split_once('.')?;
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let label = label.trim().to_ascii_lowercase();
    (!label.is_empty() && label.len() <= 200).then_some((cursor, label))
}
fn looks_quoted(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("documentation below")
        || lower.contains("untrusted tool output")
        || lower.lines().any(|line| line.trim_start().starts_with('"'))
}
fn is_wait_label(label: &str) -> bool {
    label == WAIT_LABEL
        || label.strip_prefix(WAIT_LABEL).is_some_and(|suffix| {
            let suffix = suffix.trim_start();
            suffix.starts_with('(') || suffix.starts_with('-') || suffix.starts_with('–')
        })
}
fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

/// Capped full-jitter delay. The deterministic entropy input makes tests and
/// audits reproducible while avoiding synchronized retry waves in production.
pub fn overload_backoff_seconds(attempt: u32, entropy: u64, cap: u64) -> u64 {
    let ceiling = (1_u64 << attempt.min(10)).saturating_mul(5).min(cap.max(1));
    entropy % ceiling.saturating_add(1)
}

/// The only Claude input recipes. Callers must execute each action via the
/// durable transaction layer and re-observe between phases.
pub fn menu_keys(menu: &WaitMenu) -> Vec<&'static str> {
    let key = if menu.moves.is_negative() {
        "UP"
    } else {
        "DOWN"
    };
    std::iter::repeat_n(key, menu.moves.unsigned_abs() as usize)
        .chain(std::iter::once("ENTER"))
        .collect()
}

/// Convert only an exactly correlated, owner-private StopFailure marker into a
/// normalized event.  Missing, rotated, partial, or untrusted marker files are
/// not evidence and therefore produce no action.
pub fn correlated_hook_event(watcher: &WatcherState) -> Option<Event> {
    let reference = watcher.claude_session.as_ref()?;
    let binding = reference.transcript_binding.as_ref()?;
    let process = match &watcher.target {
        crate::model::TargetIdentity::Process { process }
        | crate::model::TargetIdentity::Multiplexer { process, .. } => process,
    };
    if process.start_time != reference.process_start_time
        || !process_cwd_matches(process.pid, &reference.process_cwd)
        || current_target_session(&watcher.target) != reference.target_session
        || !crate::hooks::claude::transcript_matches_binding(
            std::path::Path::new(&reference.transcript_path),
            std::path::Path::new(&reference.transcript_path),
            binding,
        )
    {
        return None;
    }
    let markers =
        crate::hooks::claude::read_markers(std::path::Path::new(&reference.marker_path)).ok()?;
    let marker = crate::hooks::claude::correlate_marker(
        &markers,
        &reference.session_id,
        std::path::Path::new(&reference.transcript_path),
    )?;
    let class = classify_stop_failure(&marker.error_type, &marker.detail, false);
    let (category, hint, terminal) = match class {
        ClaudeClass::UsageLimit => (EventCategory::UsageLimit, PolicyHint::WaitAllowed, true),
        ClaudeClass::SessionLimit => (EventCategory::SessionLimit, PolicyHint::WaitAllowed, true),
        ClaudeClass::WeeklyLimit => (EventCategory::WeeklyLimit, PolicyHint::WaitAllowed, true),
        ClaudeClass::TerminalOverload => (
            EventCategory::TransientOverload,
            PolicyHint::WaitAllowed,
            true,
        ),
        ClaudeClass::NativeRetry => return None,
        ClaudeClass::HumanRequired => (
            EventCategory::TerminalFailure,
            PolicyHint::HumanRequired,
            true,
        ),
        ClaudeClass::Unknown => return None,
    };
    let target_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&watcher.target).ok()?)
    );
    let fingerprint = crate::observe::evidence_fingerprint(
        "claude_stop_failure",
        &marker.error_type,
        format!("{}:{}", marker.session_id, marker.transcript_path).as_bytes(),
    );
    let observed: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    let mut event = Event::new(
        format!("claude-hook-{}", watcher.watcher_id),
        observed.to_rfc3339(),
        watcher.watcher_id.clone(),
        target_hash,
        EventSource::new(SourceKind::Hook, "claude_stop_failure", "StopFailure"),
        category,
        1.0,
        terminal,
        fingerprint,
        "correlated Claude StopFailure",
        hint,
    )
    .ok()?;
    event.session_id = Some(reference.session_id.clone());
    if let Some(reset) = parse_reset(&marker.detail, observed.fixed_offset()) {
        event.metadata.insert(
            "claude_reset_at".into(),
            serde_json::Value::String(reset.at.to_rfc3339()),
        );
        event.reset = Some(EventReset {
            source_text: "Claude StopFailure reset".into(),
            parsed_at: reset.at.to_rfc3339(),
            timezone: Some(reset.timezone),
            confidence: f64::from(reset.confidence_milli) / 1000.0,
            margin_seconds: Some(reset.margin_seconds),
        });
        event.metadata.insert(
            "claude_resume_margin_seconds".into(),
            serde_json::Value::Number(reset.margin_seconds.into()),
        );
    }
    Some(event)
}

fn current_target_session(target: &crate::model::TargetIdentity) -> Option<String> {
    match target {
        crate::model::TargetIdentity::Process { .. } => None,
        crate::model::TargetIdentity::Multiplexer { session, .. } => session.clone(),
    }
}

/// Creates a distinct, correlated resume candidate only after the persisted
/// reset time and margin. It is deliberately not a terminal-menu heuristic:
/// the action transaction still revalidates target, user intervention, and
/// composer state before literal input can be sent.
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
    if previous.source.kind != SourceKind::Hook
        || previous.source.source_id != "claude_stop_failure"
        || !matches!(
            previous.category,
            EventCategory::UsageLimit | EventCategory::SessionLimit | EventCategory::WeeklyLimit
        )
    {
        return None;
    }
    let reset_text = previous.metadata.get("claude_reset_at")?.as_str()?;
    let reset = chrono::DateTime::parse_from_rfc3339(reset_text)
        .ok()?
        .with_timezone(&chrono::Utc);
    let margin = previous
        .metadata
        .get("claude_resume_margin_seconds")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| {
            previous
                .reset
                .as_ref()
                .and_then(|reset| reset.margin_seconds)
        })
        .unwrap_or(30);
    if now < reset + chrono::Duration::seconds(i64::try_from(margin).ok()?) {
        return None;
    }
    let mut event = previous.clone();
    event.event_id = format!("claude-resume-{}", watcher.watcher_id);
    event.observed_at = now.to_rfc3339();
    event.category = EventCategory::WaitingForModel;
    event.terminal = false;
    // A StopFailure marker has hook rank 7.  There is currently no equally
    // trustworthy Claude "working" proof available after reset, so a generic
    // lower-ranked liveness observation could never verify an input action.
    // Keep the elapsed-reset signal observable, but fail closed rather than
    // sending text whose outcome cannot be proven.
    event.policy_hint = PolicyHint::ObserveOnly;
    event.evidence_fingerprint = crate::observe::evidence_fingerprint(
        "claude_resume",
        &previous.evidence_fingerprint,
        reset.to_rfc3339().as_bytes(),
    );
    event.summary = "Claude reset elapsed; resume revalidation candidate".into();
    event
        .metadata
        .insert("claude_resume".into(), serde_json::Value::Bool(true));
    event.metadata.insert(
        "agent_state".into(),
        serde_json::Value::String("WORKING".into()),
    );
    Some(event)
}

/// Converts two identical trusted live screen captures into a narrow menu
/// event. Callers must provide only the adapter-defined live bottom; this
/// parser never treats arbitrary terminal history as interactive chrome.
pub fn trusted_menu_event(watcher: &WatcherState, first: &str, second: &str) -> Option<Event> {
    let menu = labelled_wait_menu(first, second)?;
    let category = classify_screen(first, second);
    if !matches!(
        category,
        ClaudeClass::UsageLimit | ClaudeClass::SessionLimit | ClaudeClass::WeeklyLimit
    ) {
        return None;
    }
    let target_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&watcher.target).ok()?)
    );
    let observed: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    let category = match category {
        ClaudeClass::UsageLimit => EventCategory::UsageLimit,
        ClaudeClass::SessionLimit => EventCategory::SessionLimit,
        ClaudeClass::WeeklyLimit => EventCategory::WeeklyLimit,
        _ => return None,
    };
    let mut event = Event::new(
        format!("claude-menu-{}", watcher.watcher_id),
        observed.to_rfc3339(),
        watcher.watcher_id.clone(),
        target_hash,
        EventSource::new(SourceKind::ScreenDetection, "claude", "labelled_wait_menu"),
        category,
        0.7,
        true,
        crate::observe::evidence_fingerprint("claude_menu", "wait", first.as_bytes()),
        "trusted Claude labelled wait menu",
        PolicyHint::DeterministicActionAllowed,
    )
    .ok()?;
    event.metadata.insert(
        "claude_menu_moves".into(),
        serde_json::Value::Number(i64::from(menu.moves).into()),
    );
    Some(event)
}

fn process_cwd_matches(pid: u32, expected: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(actual) = std::fs::read_link(format!("/proc/{pid}/cwd")) else {
            return false;
        };
        actual == std::path::Path::new(expected)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS has no Linux /proc open-file proof. Registration instead binds
        // the session to the resolved PID/start time and an injected canonical
        // CWD; at observation time we can still reject a vanished or replaced
        // owner-only CWD while the daemon's normal target revalidation checks
        // process/multiplexer identity.
        let _ = pid;
        std::fs::canonicalize(expected)
            .ok()
            .is_some_and(|path| path.is_dir())
    }
}

/// Claude owns structured limits and terminal-overload decisions before the
/// provider-independent wait recipe.  Only a correlated Claude Hook event can
/// reach these actions; unknown, native-retrying, and account-sensitive events
/// never fall through into an input action.
pub struct ClaudeRecipes {
    generic: BuiltinRecipes,
}

impl Default for ClaudeRecipes {
    fn default() -> Self {
        Self {
            generic: BuiltinRecipes,
        }
    }
}

impl RecipeProvider for ClaudeRecipes {
    fn action_for(&self, watcher: &WatcherState) -> Option<Action> {
        let event = watcher.last_observation.as_ref()?;
        if event.source.kind == crate::model::SourceKind::ScreenDetection
            && event.source.source_id == "claude"
            && matches!(
                event.category,
                EventCategory::UsageLimit
                    | EventCategory::SessionLimit
                    | EventCategory::WeeklyLimit
            )
            && event.policy_hint == PolicyHint::DeterministicActionAllowed
        {
            return menu_action(event);
        }
        if event.source.kind != crate::model::SourceKind::Hook
            || event.source.source_id != "claude_stop_failure"
        {
            return self.generic.action_for(watcher);
        }
        match event.category {
            EventCategory::UsageLimit
            | EventCategory::SessionLimit
            | EventCategory::WeeklyLimit
                if event.policy_hint == PolicyHint::WaitAllowed =>
            {
                wait_for_reset(event)
            }
            EventCategory::TransientOverload if event.terminal => {
                Some(overload_wait(event, watcher.revision))
            }
            // Internal Claude retry, auth/billing/safety, credit exhaustion,
            // malformed hook data, and unrecognised events require observation
            // or a human rather than a generic speculative recovery.
            _ => None,
        }
    }
}

fn menu_action(event: &crate::model::Event) -> Option<Action> {
    let moves = event
        .metadata
        .get("claude_menu_moves")?
        .as_i64()
        .and_then(|value| i8::try_from(value).ok())?;
    let menu = WaitMenu { moves };
    let mut action = Action::new(
        "claude.select_wait_menu",
        ActionKind::SendKeys {
            keys: menu_keys(&menu).into_iter().map(str::to_owned).collect(),
        },
        "trusted stable Claude labelled wait menu",
        event.evidence_fingerprint.clone(),
        30,
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
            kind: "MENU_STABLE".into(),
            value: None,
        },
    ]);
    action.expected_outcomes = vec![Condition {
        kind: "MENU_DISMISSED".into(),
        value: None,
    }];
    Some(action)
}

fn wait_for_reset(event: &crate::model::Event) -> Option<Action> {
    let at = event.metadata.get("claude_reset_at")?.as_str()?;
    let reset = chrono::DateTime::parse_from_rfc3339(at).ok()?;
    let margin = event
        .reset
        .as_ref()
        .and_then(|reset| reset.margin_seconds)
        .unwrap_or(30);
    let at = (reset + chrono::Duration::seconds(i64::try_from(margin).ok()?)).to_rfc3339();
    let mut action = Action::new(
        "claude.wait_for_reset",
        ActionKind::WaitUntil { at },
        "correlated Claude reset time",
        event.evidence_fingerprint.clone(),
        30,
    );
    action.expected_outcomes = vec![Condition {
        kind: "WAIT_STATE_RECORDED".into(),
        value: None,
    }];
    Some(action)
}

fn overload_wait(event: &crate::model::Event, revision: u64) -> Action {
    let seconds =
        overload_backoff_seconds(revision as u32, hash64(&event.evidence_fingerprint), 300).max(1);
    let mut action = Action::new(
        "claude.terminal_overload_wait",
        ActionKind::WaitDuration {
            duration_seconds: seconds,
        },
        "terminal Claude overload after native retry ended",
        event.evidence_fingerprint.clone(),
        30,
    );
    action.expected_outcomes = vec![Condition {
        kind: "WAIT_STATE_RECORDED".into(),
        value: None,
    }];
    action
}

fn hash64(value: &str) -> u64 {
    value.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}
