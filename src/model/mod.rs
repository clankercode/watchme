mod action;
mod event;
mod identity;
mod state;

pub use action::{Action, ActionKind, Condition, StatusCheck};
pub use event::{Event, EventCategory, EventReset, EventSource, PolicyHint, SourceKind};

pub use identity::{
    MultiplexerContext, PROCESS_IDENTITY_SCHEMA_VERSION, ProcessIdentity,
    TARGET_IDENTITY_SCHEMA_VERSION, TargetIdentity,
};
pub use state::{
    ClaudeSessionReference, ObservationSchedule, WATCHER_STATE_SCHEMA_VERSION, WatcherLifecycle,
    WatcherState,
};
