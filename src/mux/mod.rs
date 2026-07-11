pub mod fake;
pub mod tmux;

use std::time::Duration;

use thiserror::Error;

use crate::model::ProcessIdentity;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MuxIdentity {
    pub provider: String,
    pub server: String,
    pub session_id: String,
    pub window_id: String,
    pub pane_id: String,
    pub tty: String,
    pub process: ProcessIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaneInfo {
    pub identity: MuxIdentity,
    pub session_name: String,
    pub window_name: String,
    pub window_index: u32,
    pub pane_index: u32,
    pub current_command: String,
    pub current_path: String,
    pub dead: bool,
    pub dead_status: Option<i32>,
    pub started_at: Option<u64>,
    pub dead_at: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capture {
    pub text: String,
    pub bytes: usize,
    pub truncated: bool,
    pub elapsed: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolicKey {
    Enter,
    Escape,
    Up,
    Down,
    Left,
    Right,
    Tab,
    Backspace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComposerState {
    Safe,
    Unsafe,
    Unknown,
    Stale,
}

pub trait ComposerSafety {
    fn observe(&self, identity: &MuxIdentity) -> Result<ComposerState, MuxError>;
}

impl SymbolicKey {
    pub(crate) const fn tmux_name(self) -> &'static str {
        match self {
            Self::Enter => "Enter",
            Self::Escape => "Escape",
            Self::Up => "Up",
            Self::Down => "Down",
            Self::Left => "Left",
            Self::Right => "Right",
            Self::Tab => "Tab",
            Self::Backspace => "BSpace",
        }
    }
}

#[derive(Debug, Error)]
pub enum MuxError {
    #[error("invalid tmux selector: {0}")]
    InvalidSelector(String),
    #[error("tmux command timed out")]
    Timeout,
    #[error("tmux command failed: {0}")]
    Command(String),
    #[error("malformed tmux metadata: {0}")]
    Malformed(String),
    #[error("target identity changed: {0}")]
    IdentityChanged(String),
    #[error("captured output is not valid UTF-8")]
    InvalidUtf8,
}

pub trait Multiplexer {
    type Selector;
    fn current_target(&self) -> Result<MuxIdentity, MuxError>;
    fn resolve_selector(&self, selector: &Self::Selector) -> Result<MuxIdentity, MuxError>;
    fn pane_info(&self, identity: &MuxIdentity) -> Result<PaneInfo, MuxError>;
    fn validate_identity(&self, identity: &MuxIdentity) -> Result<(), MuxError>;
    fn capture_tail(
        &self,
        identity: &MuxIdentity,
        lines: usize,
        max_bytes: usize,
    ) -> Result<Capture, MuxError>;
    fn send_literal(
        &self,
        identity: &MuxIdentity,
        text: &str,
        safety: &dyn ComposerSafety,
    ) -> Result<(), MuxError>;
    fn send_key(
        &self,
        identity: &MuxIdentity,
        key: SymbolicKey,
        safety: &dyn ComposerSafety,
    ) -> Result<(), MuxError>;
}
