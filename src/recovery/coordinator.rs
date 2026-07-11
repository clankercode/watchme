use crate::daemon::registry::{Registry, RegistryError};
use crate::recovery::state_machine::{ClockSnapshot, RecoveryCommand, RecoveryState};
use std::time::Duration;

/// Durable production entry point for recovery state changes.
pub struct RecoveryCoordinator<'a> {
    registry: &'a mut Registry,
}

impl<'a> RecoveryCoordinator<'a> {
    pub fn new(registry: &'a mut Registry) -> Self {
        Self { registry }
    }

    pub fn begin_action(
        &mut self,
        id: &str,
        fingerprint: &str,
        clock: ClockSnapshot,
        now_ms: u64,
    ) -> Result<RecoveryState, RegistryError> {
        self.apply(
            id,
            RecoveryCommand::BeginAction {
                fingerprint: fingerprint.into(),
                clock,
            },
            now_ms,
        )
    }

    pub fn action_failed(
        &mut self,
        id: &str,
        fingerprint: &str,
        wait: Duration,
        clock: ClockSnapshot,
        now_ms: u64,
    ) -> Result<RecoveryState, RegistryError> {
        self.apply(
            id,
            RecoveryCommand::ActionFailed {
                fingerprint: fingerprint.into(),
                wait,
                clock,
            },
            now_ms,
        )
    }

    pub fn action_succeeded(
        &mut self,
        id: &str,
        fingerprint: &str,
        now_ms: u64,
    ) -> Result<RecoveryState, RegistryError> {
        self.apply(
            id,
            RecoveryCommand::ActionSucceeded {
                fingerprint: fingerprint.into(),
            },
            now_ms,
        )
    }

    pub fn planner_consulted(
        &mut self,
        id: &str,
        now_ms: u64,
    ) -> Result<RecoveryState, RegistryError> {
        self.apply(id, RecoveryCommand::ReservePlanner, now_ms)
    }

    fn apply(
        &mut self,
        id: &str,
        command: RecoveryCommand,
        now_ms: u64,
    ) -> Result<RecoveryState, RegistryError> {
        self.registry.apply_recovery_transition(id, command, now_ms)
    }
}
