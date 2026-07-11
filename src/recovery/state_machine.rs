use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    NeedsRevalidation,
    Observing,
    Confirmed,
    Acting,
    Waiting,
    Verifying,
    Recovered,
    HumanRequired,
    Stopped,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Budget {
    pub max_attempts: u32,
    pub max_cumulative_wait: Duration,
    pub planner_calls: u32,
    pub cooldown: Duration,
}
#[derive(Clone, Copy, Debug)]
pub struct ClockSnapshot {
    pub monotonic_seconds: u64,
    pub wall_seconds: i64,
}
#[derive(Clone, Debug)]
pub enum RecoveryCommand {
    Revalidated,
    Confirm {
        fingerprint: String,
    },
    BeginAction {
        fingerprint: String,
        clock: ClockSnapshot,
    },
    ActionFailed {
        fingerprint: String,
        wait: Duration,
        clock: ClockSnapshot,
    },
    ActionSucceeded {
        fingerprint: String,
    },
    ReservePlanner,
}
impl RecoveryMachine {
    pub fn apply(&mut self, command: RecoveryCommand) -> Result<(), &'static str> {
        match command {
            RecoveryCommand::Revalidated => self.revalidated(),
            RecoveryCommand::Confirm { fingerprint } => self.confirm(&fingerprint),
            RecoveryCommand::BeginAction { fingerprint, clock } => {
                self.begin_action(&fingerprint, clock)
            }
            RecoveryCommand::ActionFailed {
                fingerprint,
                wait,
                clock,
            } => self.action_failed(&fingerprint, wait, clock),
            RecoveryCommand::ActionSucceeded { fingerprint } => self.action_succeeded(&fingerprint),
            RecoveryCommand::ReservePlanner => self.reserve_planner_call(),
        }
    }
}
impl ClockSnapshot {
    pub const fn new(monotonic_seconds: u64, wall_seconds: i64) -> Self {
        Self {
            monotonic_seconds,
            wall_seconds,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditTransition {
    pub from: RecoveryState,
    pub to: RecoveryState,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryMachine {
    schema_version: u16,
    state: RecoveryState,
    budget: Budget,
    attempts: u32,
    cumulative_wait: Duration,
    last_attempt_mono: Option<u64>,
    completed: BTreeSet<String>,
    current: Option<String>,
    planner_calls: u32,
    audit: Vec<AuditTransition>,
}
impl RecoveryMachine {
    pub fn new(budget: Budget) -> Self {
        Self {
            schema_version: 1,
            state: RecoveryState::NeedsRevalidation,
            budget,
            attempts: 0,
            cumulative_wait: Duration::ZERO,
            last_attempt_mono: None,
            completed: BTreeSet::new(),
            current: None,
            planner_calls: 0,
            audit: Vec::new(),
        }
    }
    pub const fn state(&self) -> RecoveryState {
        self.state
    }
    pub const fn budget(&self) -> Budget {
        self.budget
    }
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }
    pub const fn cumulative_wait(&self) -> Duration {
        self.cumulative_wait
    }
    pub const fn planner_calls(&self) -> u32 {
        self.planner_calls
    }
    pub const fn last_attempt_monotonic_seconds(&self) -> Option<u64> {
        self.last_attempt_mono
    }
    pub fn restore_for_restart(mut self) -> Result<Self, &'static str> {
        if self.schema_version != 1 {
            return Err("unsupported recovery schema");
        }
        let from = self.state;
        self.state = RecoveryState::NeedsRevalidation;
        self.audit.push(AuditTransition {
            from,
            to: self.state,
            reason: "restart requires live revalidation".into(),
        });
        Ok(self)
    }
    pub fn audit(&self) -> &[AuditTransition] {
        &self.audit
    }
    pub fn revalidated(&mut self) -> Result<(), &'static str> {
        self.transition(RecoveryState::Observing)
    }
    pub fn confirm(&mut self, fingerprint: &str) -> Result<(), &'static str> {
        self.transition(RecoveryState::Confirmed)?;
        self.current = Some(fingerprint.into());
        Ok(())
    }
    pub fn begin_action(
        &mut self,
        fingerprint: &str,
        now: ClockSnapshot,
    ) -> Result<(), &'static str> {
        if self.state == RecoveryState::NeedsRevalidation {
            return Err("revalidation required");
        }
        if self.completed.contains(fingerprint) {
            return Err("duplicate action");
        }
        if self.current.as_deref() != Some(fingerprint) {
            return Err("stale evidence");
        }
        if self.attempts >= self.budget.max_attempts {
            return Err("attempt budget exhausted");
        }
        if self.last_attempt_mono.is_some_and(|last| {
            now.monotonic_seconds.saturating_sub(last) < self.budget.cooldown.as_secs()
        }) {
            return Err("cooldown active");
        }
        self.transition(RecoveryState::Acting)?;
        self.attempts += 1;
        self.last_attempt_mono = Some(now.monotonic_seconds);
        Ok(())
    }
    pub fn action_failed(
        &mut self,
        fingerprint: &str,
        wait: Duration,
        _now: ClockSnapshot,
    ) -> Result<(), &'static str> {
        if self.current.as_deref() != Some(fingerprint)
            || self.cumulative_wait.saturating_add(wait) > self.budget.max_cumulative_wait
        {
            return Err("wait budget exhausted");
        }
        self.cumulative_wait += wait;
        self.transition(RecoveryState::Waiting)?;
        self.transition(RecoveryState::Confirmed)?;
        Ok(())
    }
    pub fn action_succeeded(&mut self, fingerprint: &str) -> Result<(), &'static str> {
        if self.current.as_deref() != Some(fingerprint) {
            return Err("stale evidence");
        }
        self.transition(RecoveryState::Verifying)?;
        self.transition(RecoveryState::Recovered)?;
        self.completed.insert(fingerprint.into());
        Ok(())
    }
    pub fn reserve_planner_call(&mut self) -> Result<(), &'static str> {
        if self.planner_calls >= self.budget.planner_calls {
            return Err("planner budget exhausted");
        }
        self.planner_calls += 1;
        Ok(())
    }
    fn transition(&mut self, next: RecoveryState) -> Result<(), &'static str> {
        let valid = matches!(
            (self.state, next),
            (RecoveryState::NeedsRevalidation, RecoveryState::Observing)
                | (RecoveryState::Observing, RecoveryState::Confirmed)
                | (RecoveryState::Confirmed, RecoveryState::Acting)
                | (RecoveryState::Acting, RecoveryState::Waiting)
                | (RecoveryState::Acting, RecoveryState::Verifying)
                | (RecoveryState::Waiting, RecoveryState::Confirmed)
                | (RecoveryState::Verifying, RecoveryState::Recovered)
        );
        if valid {
            let from = self.state;
            self.state = next;
            self.audit.push(AuditTransition {
                from,
                to: next,
                reason: "validated transition".into(),
            });
            Ok(())
        } else {
            Err("invalid recovery transition")
        }
    }
}
