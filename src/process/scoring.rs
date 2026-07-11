use super::{AgentKind, CandidateHints, ProcessRecord};

pub(crate) const MINIMUM_CONFIDENCE: i32 = 10;

pub(crate) fn identify_agent(executable: &str) -> Option<AgentKind> {
    let name = executable
        .rsplit('/')
        .next()
        .unwrap_or(executable)
        .to_ascii_lowercase();
    if matches!(name.as_str(), "claude" | "claude-code") || name.starts_with("claude-") {
        Some(AgentKind::Claude)
    } else if matches!(name.as_str(), "codex" | "codex-cli") || name.starts_with("codex-") {
        Some(AgentKind::Codex)
    } else {
        None
    }
}

pub(crate) fn score(
    process: &ProcessRecord,
    hints: &CandidateHints,
    ancestry_distance: Option<usize>,
) -> Option<(i32, Vec<String>)> {
    let mut total = 8;
    let mut correlations = 0;
    let mut reasons = vec!["known agent executable (+8)".into()];
    if let Some(distance) = ancestry_distance {
        let points = 6_i32.saturating_sub(distance.min(4) as i32);
        total += points;
        reasons.push(format!("agent ancestor distance {distance} (+{points})"));
    }
    correlate(
        &mut total,
        &mut correlations,
        &mut reasons,
        "tty",
        process.tty.as_ref(),
        hints.tty.as_ref(),
        4,
    )?;
    correlate(
        &mut total,
        &mut correlations,
        &mut reasons,
        "process group",
        process.process_group_id.as_ref(),
        hints.process_group_id.as_ref(),
        2,
    )?;
    correlate(
        &mut total,
        &mut correlations,
        &mut reasons,
        "session",
        process.session_leader_id.as_ref(),
        hints.session_leader_id.as_ref(),
        2,
    )?;
    correlate(
        &mut total,
        &mut correlations,
        &mut reasons,
        "uid",
        process.uid.as_ref(),
        hints.uid.as_ref(),
        2,
    )?;
    if let (Some(executable), Some(hint)) = (&process.executable, &hints.executable_hint) {
        if executable.rsplit('/').next() != Some(hint.as_str()) {
            return None;
        }
        correlations += 1;
        total += 2;
        reasons.push("pane executable hint (+2)".into());
    }
    (correlations > 0).then_some((total, reasons))
}

fn correlate<T: PartialEq>(
    total: &mut i32,
    correlations: &mut usize,
    reasons: &mut Vec<String>,
    label: &str,
    actual: Option<&T>,
    expected: Option<&T>,
    points: i32,
) -> Option<()> {
    if let (Some(actual), Some(expected)) = (actual, expected) {
        if actual != expected {
            return None;
        }
        *correlations += 1;
        *total += points;
        reasons.push(format!("{label} matches pane (+{points})"));
    }
    Some(())
}
