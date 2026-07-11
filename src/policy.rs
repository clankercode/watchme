use crate::model::{Action, ActionKind};
#[derive(Clone, Debug)]
pub struct PolicyContext {
    pub target_revalidated: bool,
    pub evidence_current: bool,
    pub human_intervened: bool,
    pub source_rank: u8,
    pub contradictory_source_rank: Option<u8>,
    pub process_alive: bool,
    pub pane_matches: bool,
    pub composer_empty: bool,
    pub failed_provider_family: Option<String>,
    pub planner_provider_family: Option<String>,
    pub attempts_remaining: u32,
    pub cumulative_wait_remaining_seconds: u64,
    pub planner_calls_remaining: u32,
    pub planner_concurrency_available: bool,
    pub cooldown_ready: bool,
    pub session_id: Option<String>,
    pub evidence_fingerprint: Option<String>,
    pub menu_stable: bool,
    pub agent_state: Option<String>,
    pub goal_state: Option<String>,
    pub event_category: Option<String>,
    pub wall_time_rfc3339: Option<String>,
}
impl PolicyContext {
    pub const fn safe() -> Self {
        Self {
            target_revalidated: true,
            evidence_current: true,
            human_intervened: false,
            source_rank: u8::MAX,
            contradictory_source_rank: None,
            process_alive: true,
            pane_matches: true,
            composer_empty: true,
            failed_provider_family: None,
            planner_provider_family: None,
            attempts_remaining: 1,
            cumulative_wait_remaining_seconds: 86_400,
            planner_calls_remaining: 1,
            planner_concurrency_available: true,
            cooldown_ready: true,
            session_id: None,
            evidence_fingerprint: None,
            menu_stable: true,
            agent_state: None,
            goal_state: None,
            event_category: None,
            wall_time_rfc3339: None,
        }
    }
}
#[derive(Default)]
pub struct CompiledPolicy;
impl CompiledPolicy {
    pub fn authorize(&self, action: &Action, context: &PolicyContext) -> Result<(), &'static str> {
        action.validate()?;
        if !context.target_revalidated
            || !context.evidence_current
            || context.human_intervened
            || !context.process_alive
            || !context.pane_matches
        {
            return Err("revalidation required");
        }
        if matches!(action.kind, ActionKind::Escalate { ref level } if level != "human_required")
            && (context.failed_provider_family.is_none()
                || context.planner_provider_family.is_none()
                || context.failed_provider_family == context.planner_provider_family)
        {
            return Err("same-provider planner denied");
        }
        if context.attempts_remaining == 0 || !context.cooldown_ready {
            return Err("attempt or cooldown budget denied");
        }
        if matches!(action.kind, ActionKind::WaitDuration { duration_seconds } if duration_seconds > context.cumulative_wait_remaining_seconds)
        {
            return Err("cumulative wait budget denied");
        }
        if let ActionKind::WaitUntil { at } = &action.kind {
            let Some(wait_seconds) = wait_until_seconds(at, context.wall_time_rfc3339.as_deref())
            else {
                return Err("valid wall time required");
            };
            if wait_seconds > context.cumulative_wait_remaining_seconds {
                return Err("cumulative wait budget denied");
            }
        }
        if matches!(action.kind, ActionKind::Escalate { ref level } if level != "human_required")
            && context.planner_calls_remaining == 0
        {
            return Err("planner budget denied");
        }
        if matches!(action.kind, ActionKind::Escalate { ref level } if level == "independent_second_opinion")
            && (context.planner_calls_remaining < 2
                || !context.planner_concurrency_available
                || !context.composer_empty)
        {
            return Err("independent second opinion budget denied");
        }
        if !action
            .preconditions
            .iter()
            .all(|condition| precondition_holds(condition, context))
        {
            return Err("declared precondition failed");
        }
        if context
            .contradictory_source_rank
            .is_some_and(|r| r > context.source_rank)
        {
            return Err("higher-ranked contradiction");
        }
        match &action.kind {
            ActionKind::WaitUntil { .. } => Ok(()),
            ActionKind::WaitDuration { duration_seconds } if *duration_seconds <= 86400 => Ok(()),
            ActionKind::Capture { max_lines, .. } if *max_lines <= 300 => Ok(()),
            ActionKind::CheckStatus { .. }
            | ActionKind::Notify { .. }
            | ActionKind::StopWatching
            | ActionKind::Noop => Ok(()),
            ActionKind::Escalate { level } if level == "human_required" => Ok(()),
            ActionKind::Escalate { level } if level == "alternate_planner" => Ok(()),
            ActionKind::Escalate { level } if level == "independent_second_opinion" => Ok(()),
            ActionKind::SendKeys { keys }
                if context.composer_empty
                    && keys.iter().all(|k| {
                        matches!(
                            k.as_str(),
                            "ENTER"
                                | "ESCAPE"
                                | "UP"
                                | "DOWN"
                                | "LEFT"
                                | "RIGHT"
                                | "TAB"
                                | "BACKTAB"
                                | "HOME"
                                | "END"
                                | "PAGE_UP"
                                | "PAGE_DOWN"
                        )
                    }) =>
            {
                Ok(())
            }
            ActionKind::SendText { text } if context.composer_empty && safe_text(text) => Ok(()),
            _ => Err("action denied by compiled policy"),
        }
    }
}

fn wait_until_seconds(at: &str, now: Option<&str>) -> Option<u64> {
    let at = chrono::DateTime::parse_from_rfc3339(at).ok()?;
    let now = chrono::DateTime::parse_from_rfc3339(now?).ok()?;
    u64::try_from((at - now).num_seconds()).ok()
}
fn precondition_holds(condition: &crate::model::Condition, context: &PolicyContext) -> bool {
    let text = || condition.value.as_ref().and_then(serde_json::Value::as_str);
    match condition.kind.as_str() {
        "TARGET_IDENTITY_MATCHES" => context.target_revalidated && context.pane_matches,
        "PROCESS_ALIVE" => context.process_alive,
        "SESSION_ID_MATCHES" => text() == context.session_id.as_deref(),
        "EVIDENCE_FINGERPRINT_MATCHES" => text() == context.evidence_fingerprint.as_deref(),
        "COMPOSER_EMPTY" => context.composer_empty,
        "MENU_STABLE" => context.menu_stable,
        "AGENT_STATE_IS" => text() == context.agent_state.as_deref(),
        "GOAL_STATE_IS" => text() == context.goal_state.as_deref(),
        "EVENT_CATEGORY_IS" => text() == context.event_category.as_deref(),
        "NO_HUMAN_INTERVENTION" => !context.human_intervened,
        "CURRENT_TIME_AT_OR_AFTER" => text()
            .zip(context.wall_time_rfc3339.as_deref())
            .is_some_and(|(required, current)| {
                chrono::DateTime::parse_from_rfc3339(required)
                    .ok()
                    .zip(chrono::DateTime::parse_from_rfc3339(current).ok())
                    .is_some_and(|(required, current)| current >= required)
            }),
        _ => false,
    }
}
fn safe_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    !text.chars().any(|c| c.is_control())
        && ![
            "login",
            "sign in",
            "billing",
            "fund",
            "credit",
            "upgrade",
            "approve",
            "permission",
            "yolo",
            "sudo",
            "rm -rf",
            "password",
            "token",
            "secret",
        ]
        .iter()
        .any(|word| lower.contains(word))
        && matches!(text, "/goal resume" | "continue" | "retry")
}
