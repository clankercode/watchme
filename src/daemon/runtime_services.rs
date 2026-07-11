use std::time::Duration;

use super::{Registry, WatcherLifecycle, now_ms};

/// Concrete daemon-owned services for canonical, non-input actions. Each
/// success result follows a registry write, so a receipt never claims that a
/// wait, escalation, or stop was merely queued in memory.
pub(super) struct DaemonRuntimeServices {
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    watcher_id: String,
}

impl DaemonRuntimeServices {
    pub(super) fn new(
        registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
        watcher_id: String,
    ) -> Self {
        Self {
            registry,
            watcher_id,
        }
    }

    fn with_registry<T>(
        &self,
        action: impl FnOnce(&mut Registry) -> Result<T, String>,
    ) -> Result<T, String> {
        action(&mut self.registry.blocking_lock())
    }
}

impl crate::recovery::actuator::RuntimeServices for DaemonRuntimeServices {
    fn schedule(&self, deadline: &str) -> Result<(), String> {
        let now = now_ms();
        let until = parse_wait_deadline(deadline, now)?;
        self.with_registry(|registry| {
            let watcher = registry
                .get(&self.watcher_id)
                .ok_or_else(|| "unknown watcher for scheduled action".to_owned())?;
            let mut schedule = watcher.observation_schedule.clone();
            schedule.next_due_wall_ms = until;
            schedule.event_wake_pending = false;
            registry
                .persist_observation_schedule(&self.watcher_id, schedule, now)
                .map_err(|error| error.to_string())?;
            registry
                .transition(
                    &self.watcher_id,
                    WatcherLifecycle::Waiting {
                        until_unix_ms: until,
                        reason: "recovery wait scheduled".into(),
                    },
                    now,
                )
                .map_err(|error| error.to_string())
        })
    }

    fn capture(&self, _: &str, _: u16) -> Result<String, String> {
        Err("capture requires the target-bound multiplexer dispatcher".into())
    }

    fn check(&self, kind: &str, _: Option<&str>) -> Result<bool, String> {
        if kind != "PROCESS_ALIVE" {
            return Err("unsupported runtime status check".into());
        }
        let watcher = self.with_registry(|registry| {
            registry
                .get(&self.watcher_id)
                .cloned()
                .ok_or_else(|| "unknown watcher for status check".to_owned())
        })?;
        Ok(target_process_is_alive(&watcher.target))
    }

    fn notify(&self, _: &str, _: &str) -> Result<(), String> {
        Err("notification requires a target adapter".into())
    }

    fn escalate(&self, level: &str) -> Result<(), String> {
        if level != "human_required" {
            return Err("planner escalation is not available in the daemon runtime".into());
        }
        self.with_registry(|registry| {
            registry
                .transition(
                    &self.watcher_id,
                    WatcherLifecycle::HumanRequired {
                        reason: "recovery escalation requested".into(),
                    },
                    now_ms(),
                )
                .map_err(|error| error.to_string())
        })
    }

    fn stop_watching(&self) -> Result<(), String> {
        self.with_registry(|registry| {
            registry
                .transition(
                    &self.watcher_id,
                    WatcherLifecycle::Stopped {
                        reason: "recovery action stopped watcher".into(),
                    },
                    now_ms(),
                )
                .map_err(|error| error.to_string())
        })
    }
}

fn parse_wait_deadline(deadline: &str, now: u64) -> Result<u64, String> {
    if let Some(seconds) = deadline
        .strip_prefix("monotonic+")
        .and_then(|value| value.strip_suffix('s'))
    {
        let seconds = seconds
            .parse::<u64>()
            .map_err(|_| "invalid monotonic wait deadline")?;
        return Ok(now.saturating_add(seconds.saturating_mul(1_000)));
    }
    let date = chrono::DateTime::parse_from_rfc3339(deadline)
        .map_err(|_| "invalid wall-clock wait deadline")?;
    let milliseconds =
        u64::try_from(date.timestamp_millis()).map_err(|_| "wait deadline predates Unix epoch")?;
    if milliseconds < now {
        return Err("wait deadline is in the past".into());
    }
    Ok(milliseconds)
}

pub(super) fn target_process_is_alive(target: &crate::model::TargetIdentity) -> bool {
    let process = match target {
        crate::model::TargetIdentity::Process { process }
        | crate::model::TargetIdentity::Multiplexer { process, .. } => process,
    };
    #[cfg(target_os = "linux")]
    let inspector = crate::process::linux::LinuxProcessInspector::default();
    #[cfg(target_os = "macos")]
    let inspector = crate::process::macos::MacOsProcessInspector::default();
    crate::process::ProcessInspector::inspect(&inspector, process.pid)
        .ok()
        .is_some_and(|actual| actual.start_time == process.start_time)
}

pub(super) struct SystemRecoveryClock;
static RECOVERY_CLOCK_ORIGIN: std::sync::LazyLock<std::time::Instant> =
    std::sync::LazyLock::new(std::time::Instant::now);

impl SystemRecoveryClock {
    pub(super) const fn new() -> Self {
        Self
    }
}

impl crate::recovery::transaction::Clock for SystemRecoveryClock {
    fn monotonic_ms(&self) -> u64 {
        RECOVERY_CLOCK_ORIGIN.elapsed().as_millis() as u64
    }

    fn wall_time_rfc3339(&self) -> String {
        let now: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
        now.to_rfc3339()
    }

    fn sleep_ms(&self, duration: u64) {
        std::thread::sleep(Duration::from_millis(duration));
    }
}

struct NoEvidence;
impl crate::recovery::transaction::EvidenceReader for NoEvidence {
    fn read(&self) -> Result<crate::recovery::transaction::LiveEvidence, String> {
        Err("recovery scan has no live evidence".into())
    }
}

struct NoExecutor;
impl crate::recovery::actuator::ActionExecutor for NoExecutor {
    fn execute(
        &self,
        _: &crate::model::Action,
    ) -> Result<crate::recovery::actuator::ExecutionOutput, crate::recovery::actuator::ExecutionError>
    {
        Err(crate::recovery::actuator::ExecutionError::Unsafe(
            "recovery scan cannot execute actions",
        ))
    }
}

struct DaemonOwnerProbe;
impl crate::recovery::transaction::ProcessProbe for DaemonOwnerProbe {
    fn matches(&self, owner: &crate::recovery::transaction::OwnerIdentity) -> bool {
        #[cfg(target_os = "linux")]
        let inspector = crate::process::linux::LinuxProcessInspector::default();
        #[cfg(target_os = "macos")]
        let inspector = crate::process::macos::MacOsProcessInspector::default();
        crate::process::ProcessInspector::inspect(&inspector, owner.pid)
            .ok()
            .is_some_and(|actual| actual.start_time == owner.process_start_time)
    }
}

pub(super) fn recover_durable_actions_after_restart(
    engine: &crate::recovery::engine::RecoveryEngine<
        crate::recovery::action_store::JsonActionStore,
        crate::recovery::engine::BuiltinRecipes,
    >,
) {
    let evidence = NoEvidence;
    let executor = NoExecutor;
    let clock = SystemRecoveryClock::new();
    if let Ok(records) = engine.store().active_records() {
        for record in records {
            let _ = engine.recover_after_restart(&record.target, &evidence, &executor, &clock);
        }
    }
}

pub(super) fn recover_stale_durable_actions(
    engine: &crate::recovery::engine::RecoveryEngine<
        crate::recovery::action_store::JsonActionStore,
        crate::recovery::engine::BuiltinRecipes,
    >,
) {
    let evidence = NoEvidence;
    let executor = NoExecutor;
    let clock = SystemRecoveryClock::new();
    let probe = DaemonOwnerProbe;
    if let Ok(records) = engine.store().active_records() {
        for record in records {
            let _ = engine.recover_stale(&record.target, &probe, &evidence, &executor, &clock);
        }
    }
}
