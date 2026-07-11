use crate::model::{Action, ActionKind};
#[derive(Clone, Debug)]
pub struct PolicyContext {
    pub target_revalidated: bool,
    pub evidence_current: bool,
    pub human_intervened: bool,
    pub source_rank: u8,
    pub contradictory_source_rank: Option<u8>,
}
impl PolicyContext {
    pub const fn safe() -> Self {
        Self {
            target_revalidated: true,
            evidence_current: true,
            human_intervened: false,
            source_rank: u8::MAX,
            contradictory_source_rank: None,
        }
    }
}
#[derive(Default)]
pub struct CompiledPolicy;
impl CompiledPolicy {
    pub fn authorize(&self, action: &Action, context: &PolicyContext) -> Result<(), &'static str> {
        if !context.target_revalidated || !context.evidence_current || context.human_intervened {
            return Err("revalidation required");
        }
        if context
            .contradictory_source_rank
            .is_some_and(|r| r > context.source_rank)
        {
            return Err("higher-ranked contradiction");
        }
        match &action.kind {
            ActionKind::WaitDuration { duration_seconds } if *duration_seconds <= 86400 => Ok(()),
            ActionKind::Capture { max_lines } if *max_lines <= 300 => Ok(()),
            ActionKind::CheckStatus { .. }
            | ActionKind::Notify { .. }
            | ActionKind::StopWatching
            | ActionKind::Noop => Ok(()),
            ActionKind::Escalate { level } if level == "human_required" => Ok(()),
            ActionKind::SendKeys { keys }
                if keys.iter().all(|k| {
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
            ActionKind::SendText { text } if safe_text(text) => Ok(()),
            _ => Err("action denied by compiled policy"),
        }
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
