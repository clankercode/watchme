//! Conservative Claude Code classification and labelled-menu planning.
//! Terminal captures are only eligible when supplied by a trusted live screen adapter.

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
    let target = rows.iter().position(|row| row.1 == WAIT_LABEL)?;
    let cursor = rows.iter().position(|row| row.0)?;
    // Account-changing choices may be present but are never selected. Refuse
    // ambiguous duplicate labels/cursors and wrapped/malformed rows.
    if rows.iter().filter(|row| row.1 == WAIT_LABEL).count() != 1
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
    let (cursor, rest) = if let Some(rest) = trimmed.strip_prefix('>') {
        (true, rest.trim_start())
    } else {
        (false, trimmed)
    };
    let (_, label) = rest.split_once('.')?;
    let label = label.trim().to_ascii_lowercase();
    (!label.is_empty() && label.len() <= 200).then_some((cursor, label))
}
fn looks_quoted(text: &str) -> bool {
    let trimmed = text.trim_start();
    trimmed.starts_with('"')
        || trimmed.starts_with('>')
        || trimmed.contains("documentation below")
        || trimmed.contains("UNTRUSTED TOOL OUTPUT")
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

pub const DEFAULT_RESUME: &str = "Continue exactly where you left off.";
