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
) -> (i32, Vec<String>) {
    let mut total = 8;
    let mut reasons = vec!["known agent executable (+8)".into()];
    if let Some(distance) = ancestry_distance {
        let points = 6_i32.saturating_sub(distance.min(4) as i32);
        total += points;
        reasons.push(format!("agent ancestor distance {distance} (+{points})"));
    }
    add_match(
        &mut total,
        &mut reasons,
        "tty",
        process.tty.as_ref(),
        hints.tty.as_ref(),
        4,
    );
    add_match(
        &mut total,
        &mut reasons,
        "process group",
        process.process_group_id.as_ref(),
        hints.process_group_id.as_ref(),
        2,
    );
    add_match(
        &mut total,
        &mut reasons,
        "session",
        process.session_leader_id.as_ref(),
        hints.session_leader_id.as_ref(),
        2,
    );
    add_match(
        &mut total,
        &mut reasons,
        "uid",
        process.uid.as_ref(),
        hints.uid.as_ref(),
        2,
    );
    if let (Some(executable), Some(hint)) = (&process.executable, &hints.executable_hint)
        && executable.rsplit('/').next() == Some(hint.as_str())
    {
        total += 2;
        reasons.push("pane executable hint (+2)".into());
    }
    (total, reasons)
}

fn add_match<T: PartialEq>(
    total: &mut i32,
    reasons: &mut Vec<String>,
    label: &str,
    actual: Option<&T>,
    expected: Option<&T>,
    points: i32,
) {
    if actual.is_some() && expected.is_some() && actual == expected {
        *total += points;
        reasons.push(format!("{label} matches pane (+{points})"));
    }
}
