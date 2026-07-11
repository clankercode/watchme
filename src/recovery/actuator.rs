use std::time::Duration;

use thiserror::Error;

use crate::model::{Action, ActionKind};
use crate::mux::{ComposerSafety, Multiplexer, MuxIdentity, SymbolicKey};

const MAX_CAPTURE_LINES: u16 = 300;
const MAX_CAPTURE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionOutput {
    Committed,
    Scheduled(Duration),
    Captured(String),
    Status(serde_json::Value),
    Notified,
    Escalated,
}

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("unsafe action: {0}")]
    Unsafe(&'static str),
    #[error("multiplexer operation failed: {0}")]
    Integration(String),
}

pub trait ActionExecutor {
    fn execute(&self, action: &Action) -> Result<ExecutionOutput, ExecutionError>;
}

pub fn validate_action(action: &Action) -> Result<(), ExecutionError> {
    action.validate().map_err(ExecutionError::Unsafe)?;
    match &action.kind {
        ActionKind::SendText { text } if text.chars().any(forbidden_literal_character) => Err(
            ExecutionError::Unsafe("literal text contains C0/C1 control"),
        ),
        ActionKind::SendKeys { keys } if !keys.iter().all(|key| symbolic_key(key).is_some()) => {
            Err(ExecutionError::Unsafe("symbolic key is not allowlisted"))
        }
        ActionKind::Capture { max_lines, .. } if *max_lines > MAX_CAPTURE_LINES => {
            Err(ExecutionError::Unsafe("capture exceeds bound"))
        }
        ActionKind::StopWatching | ActionKind::Noop => Err(ExecutionError::Unsafe(
            "action is not executable by actuator",
        )),
        _ => Ok(()),
    }
}

fn forbidden_literal_character(character: char) -> bool {
    matches!(character as u32, 0..=0x1f | 0x7f..=0x9f)
}

fn symbolic_key(key: &str) -> Option<SymbolicKey> {
    match key {
        "ENTER" => Some(SymbolicKey::Enter),
        "ESCAPE" => Some(SymbolicKey::Escape),
        "UP" => Some(SymbolicKey::Up),
        "DOWN" => Some(SymbolicKey::Down),
        "LEFT" => Some(SymbolicKey::Left),
        "RIGHT" => Some(SymbolicKey::Right),
        "TAB" => Some(SymbolicKey::Tab),
        "BACKTAB" => None,
        _ => None,
    }
}

pub struct MuxActuator<'a, M: Multiplexer> {
    mux: &'a M,
    identity: &'a MuxIdentity,
    composer: &'a dyn ComposerSafety,
}

impl<'a, M: Multiplexer> MuxActuator<'a, M> {
    pub const fn new(
        mux: &'a M,
        identity: &'a MuxIdentity,
        composer: &'a dyn ComposerSafety,
    ) -> Self {
        Self {
            mux,
            identity,
            composer,
        }
    }
}

impl<M: Multiplexer> ActionExecutor for MuxActuator<'_, M> {
    fn execute(&self, action: &Action) -> Result<ExecutionOutput, ExecutionError> {
        validate_action(action)?;
        self.mux
            .validate_identity(self.identity)
            .map_err(integration)?;
        match &action.kind {
            ActionKind::SendText { text } => {
                self.mux
                    .send_literal(self.identity, text, self.composer)
                    .map_err(integration)?;
                Ok(ExecutionOutput::Committed)
            }
            ActionKind::SendKeys { keys } => {
                for key in keys {
                    self.mux
                        .send_key(
                            self.identity,
                            symbolic_key(key).expect("validated"),
                            self.composer,
                        )
                        .map_err(integration)?;
                }
                Ok(ExecutionOutput::Committed)
            }
            ActionKind::Capture { max_lines, .. } => self
                .mux
                .capture_tail(self.identity, usize::from(*max_lines), MAX_CAPTURE_BYTES)
                .map(|capture| ExecutionOutput::Captured(capture.text))
                .map_err(integration),
            ActionKind::WaitDuration { duration_seconds } => Ok(ExecutionOutput::Scheduled(
                Duration::from_secs(*duration_seconds),
            )),
            ActionKind::WaitUntil { .. } => Ok(ExecutionOutput::Scheduled(Duration::ZERO)),
            ActionKind::CheckStatus { check } => Ok(ExecutionOutput::Status(
                serde_json::json!({"kind": check.kind, "value": check.value}),
            )),
            ActionKind::Notify { .. } => Ok(ExecutionOutput::Notified),
            ActionKind::Escalate { .. } => Ok(ExecutionOutput::Escalated),
            ActionKind::StopWatching | ActionKind::Noop => unreachable!("validated"),
        }
    }
}

fn integration(error: crate::mux::MuxError) -> ExecutionError {
    ExecutionError::Integration(error.to_string())
}
