use std::time::Duration;

use thiserror::Error;

use crate::model::{Action, ActionKind, EventSource, SourceKind};
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
    #[error("operation may have committed a side effect: {0}")]
    PossibleSideEffect(String),
}

pub trait ActionExecutor {
    fn execute(&self, action: &Action) -> Result<ExecutionOutput, ExecutionError>;
}

/// Narrow daemon services used by non-input actions. Implementations persist
/// scheduling and state transitions before returning success.
pub trait RuntimeServices: Send + Sync {
    fn schedule(&self, deadline: &str) -> Result<(), String>;
    fn capture(&self, source: &str, lines: u16) -> Result<String, String>;
    fn check(&self, kind: &str, value: Option<&str>) -> Result<bool, String>;
    fn notify(&self, severity: &str, message: &str) -> Result<(), String>;
    fn escalate(&self, level: &str) -> Result<(), String>;
    fn stop_watching(&self) -> Result<(), String>;
}

pub struct RuntimeActuator<'a> {
    services: &'a dyn RuntimeServices,
}
impl<'a> RuntimeActuator<'a> {
    pub const fn new(services: &'a dyn RuntimeServices) -> Self {
        Self { services }
    }
}
impl ActionExecutor for RuntimeActuator<'_> {
    fn execute(&self, action: &Action) -> Result<ExecutionOutput, ExecutionError> {
        validate_action(action)?;
        match &action.kind {
            ActionKind::WaitUntil { at } => {
                runtime(self.services.schedule(at))?;
                Ok(ExecutionOutput::Scheduled(Duration::ZERO))
            }
            ActionKind::WaitDuration { duration_seconds } => {
                runtime(
                    self.services
                        .schedule(&format!("monotonic+{duration_seconds}s")),
                )?;
                Ok(ExecutionOutput::Scheduled(Duration::from_secs(
                    *duration_seconds,
                )))
            }
            ActionKind::Capture { source, max_lines } => {
                runtime(self.services.capture(source, *max_lines)).map(ExecutionOutput::Captured)
            }
            ActionKind::CheckStatus { check } => {
                runtime(self.services.check(&check.kind, check.value.as_deref())).map(|matches| {
                    ExecutionOutput::Status(
                        serde_json::json!({"matches":matches,"kind":check.kind}),
                    )
                })
            }
            ActionKind::Notify { severity, message } => {
                runtime(self.services.notify(severity, message))?;
                Ok(ExecutionOutput::Notified)
            }
            ActionKind::Escalate { level } => {
                runtime(self.services.escalate(level))?;
                Ok(ExecutionOutput::Escalated)
            }
            ActionKind::StopWatching => {
                runtime(self.services.stop_watching())?;
                Ok(ExecutionOutput::Committed)
            }
            ActionKind::Noop => Ok(ExecutionOutput::Committed),
            ActionKind::SendText { .. } | ActionKind::SendKeys { .. } => Err(
                ExecutionError::Unsafe("input action requires multiplexer actuator"),
            ),
        }
    }
}

fn runtime<T>(result: Result<T, String>) -> Result<T, ExecutionError> {
    result.map_err(ExecutionError::Integration)
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
        ActionKind::StopWatching | ActionKind::Noop => Ok(()),
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
    source: &'a EventSource,
}

impl<'a, M: Multiplexer> MuxActuator<'a, M> {
    pub const fn new(
        mux: &'a M,
        identity: &'a MuxIdentity,
        composer: &'a dyn ComposerSafety,
        source: &'a EventSource,
    ) -> Self {
        Self {
            mux,
            identity,
            composer,
            source,
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
                    .map_err(possible_side_effect)?;
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
                        .map_err(possible_side_effect)?;
                }
                Ok(ExecutionOutput::Committed)
            }
            ActionKind::Capture { source, max_lines } => {
                if !mux_capture_source_matches(source, self.source) {
                    return Err(ExecutionError::Unsafe(
                        "capture source is not the bound mux screen observation",
                    ));
                }
                self.mux
                    .capture_tail(self.identity, usize::from(*max_lines), MAX_CAPTURE_BYTES)
                    .map(|capture| ExecutionOutput::Captured(capture.text))
                    .map_err(integration)
            }
            ActionKind::WaitDuration { duration_seconds } => Ok(ExecutionOutput::Scheduled(
                Duration::from_secs(*duration_seconds),
            )),
            ActionKind::WaitUntil { .. } => Ok(ExecutionOutput::Scheduled(Duration::ZERO)),
            ActionKind::CheckStatus { check } => Ok(ExecutionOutput::Status(
                serde_json::json!({"kind": check.kind, "value": check.value}),
            )),
            ActionKind::Notify { .. } => Ok(ExecutionOutput::Notified),
            ActionKind::Escalate { .. } => Ok(ExecutionOutput::Escalated),
            ActionKind::StopWatching | ActionKind::Noop => Ok(ExecutionOutput::Committed),
        }
    }
}

fn integration(error: crate::mux::MuxError) -> ExecutionError {
    ExecutionError::Integration(error.to_string())
}

fn possible_side_effect(error: crate::mux::MuxError) -> ExecutionError {
    ExecutionError::PossibleSideEffect(error.to_string())
}

fn mux_capture_source_matches(requested: &str, source: &EventSource) -> bool {
    matches!(requested, "screen_detection" | "screen_recent")
        && source.kind == SourceKind::ScreenDetection
        && source.source_id == "tmux"
}

#[cfg(test)]
mod tests {
    use super::mux_capture_source_matches;
    use crate::model::{EventSource, SourceKind};

    #[test]
    fn mux_capture_accepts_only_its_bound_screen_source() {
        let screen = EventSource::new(SourceKind::ScreenDetection, "tmux", "generic_tail");
        let typed = EventSource::new(SourceKind::HerdrAgentState, "herdr", "typed_pane_state");

        assert!(mux_capture_source_matches("screen_recent", &screen));
        assert!(!mux_capture_source_matches("structured_state", &typed));
        assert!(!mux_capture_source_matches("log_tail", &screen));
    }
}
