use std::time::Duration;

use super::{Registry, WatcherLifecycle, now_ms, watcher_mux_identity};
use crate::config::{Config, NotificationsConfig};
use crate::model::{MultiplexerContext, TargetIdentity};
use crate::notify::{
    DesktopBackend, HerdrBackend, NotificationOutcome, NotifyRequest, NotifyTarget,
};
use crate::paths::WatchmePaths;

/// Concrete daemon-owned services for canonical, non-input actions. Each
/// success result follows a registry write, so a receipt never claims that a
/// wait, escalation, or stop was merely queued in memory.
pub(super) struct DaemonRuntimeServices {
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    watcher_id: String,
    paths: WatchmePaths,
}

impl DaemonRuntimeServices {
    pub(super) fn new(
        registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
        watcher_id: String,
        paths: WatchmePaths,
    ) -> Self {
        Self {
            registry,
            watcher_id,
            paths,
        }
    }

    fn with_registry<T>(
        &self,
        action: impl FnOnce(&mut Registry) -> Result<T, String>,
    ) -> Result<T, String> {
        action(&mut self.registry.blocking_lock())
    }

    fn load_notifications(&self) -> NotificationsConfig {
        let config_path = self.paths.config_dir().join("config.toml");
        Config::load_layers([config_path.as_path()])
            .unwrap_or_default()
            .notifications
    }

    fn notification_allowed(config: &NotificationsConfig, severity: &str) -> bool {
        let severity = severity.trim().to_ascii_lowercase();
        if severity.contains("human") || severity == "error" || severity == "critical" {
            return config.notify_on_human_required;
        }
        if severity.contains("exit") || severity.contains("terminat") {
            return config.notify_on_target_exit;
        }
        config.notify_on_recovery
    }

    fn herdr_backend_for_watcher(
        watcher: &crate::model::WatcherState,
    ) -> Option<(HerdrBackend, crate::mux::MuxIdentity)> {
        let identity = watcher_mux_identity(watcher).ok().flatten()?;
        let MultiplexerContext::Herdr {
            socket_path,
            workspace_id,
            tab_id,
            pane_id,
            ..
        } = watcher.target.observation_context()?
        else {
            return None;
        };
        let context = crate::mux::herdr::HerdrContext {
            socket_path: socket_path.clone(),
            workspace_id: workspace_id.clone(),
            tab_id: tab_id.clone(),
            pane_id: pane_id.clone(),
        };
        let identity_for_send = identity.clone();
        let backend = HerdrBackend::from_fn(move |title, body| {
            let herdr = crate::mux::herdr::Herdr::new(context.clone(), Duration::from_secs(2))
                .map_err(|error| error.to_string())?;
            herdr
                .notify(&identity_for_send, title, body)
                .map_err(|error| error.to_string())
        });
        Some((backend, identity))
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

    fn notify(&self, severity: &str, message: &str) -> Result<(), String> {
        let config = self.load_notifications();
        if !Self::notification_allowed(&config, severity) {
            return Ok(());
        }
        let watcher = self.with_registry(|registry| {
            registry
                .get(&self.watcher_id)
                .cloned()
                .ok_or_else(|| "unknown watcher for notify".to_owned())
        })?;
        let herdr = Self::herdr_backend_for_watcher(&watcher);
        let herdr_backend = herdr.as_ref().map(|(backend, _)| backend);
        let desktop = DesktopBackend::system_default();
        // Use the cleanup-safe path so notification failures never panic or
        // block recovery/shutdown work.
        let outcome = crate::notify::notify_during_cleanup(
            &config,
            &NotifyRequest {
                title: format!("watchme:{severity}"),
                body: message.to_owned(),
            },
            NotifyTarget {
                herdr: herdr_backend,
                desktop: Some(&desktop),
                stderr_write: Some(&|line: &str| {
                    eprint!("{line}");
                    Ok(())
                }),
            },
        );
        match outcome {
            NotificationOutcome::Delivered { .. } => Ok(()),
            NotificationOutcome::Suppressed { reason } => Err(reason),
        }
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

pub(super) fn target_process_is_alive(target: &TargetIdentity) -> bool {
    let process = match target {
        TargetIdentity::Process { process } | TargetIdentity::Multiplexer { process, .. } => {
            process
        }
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

pub(super) fn recover_durable_actions_after_restart(engine: &super::DaemonRecoveryEngine) {
    let evidence = NoEvidence;
    let executor = NoExecutor;
    let clock = SystemRecoveryClock::new();
    if let Ok(records) = engine.store().active_records() {
        for record in records {
            let _ = engine.recover_after_restart(&record.target, &evidence, &executor, &clock);
        }
    }
}

pub(super) fn recover_stale_durable_actions(engine: &super::DaemonRecoveryEngine) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProcessIdentity, WatcherLifecycle, WatcherState};
    use crate::recovery::actuator::RuntimeServices;
    use crate::store::JsonStore;
    use std::sync::Arc;

    #[test]
    fn notify_respects_notify_on_recovery_flag() {
        let temp = tempfile::tempdir().unwrap();
        let paths = WatchmePaths::resolve(
            temp.path(),
            Some(&temp.path().join("config")),
            Some(&temp.path().join("state")),
            Some(&temp.path().join("run")),
        )
        .unwrap();
        paths.create_owner_only().unwrap();
        fs_write_config(
            &paths,
            r#"
[notifications]
herdr = false
desktop = false
stderr = true
notify_on_recovery = false
notify_on_human_required = true
notify_on_target_exit = false
"#,
        );

        let mut registry =
            Registry::load(JsonStore::new(paths.state_dir().join("watchers.json"))).unwrap();
        registry
            .register(WatcherState::new(
                "watcher".into(),
                TargetIdentity::process(ProcessIdentity::new(7, 9)),
                WatcherLifecycle::Observing,
                0,
                1,
            ))
            .unwrap();
        let registry = Arc::new(tokio::sync::Mutex::new(registry));
        let services = DaemonRuntimeServices::new(registry, "watcher".into(), paths);
        // Disabled recovery notifications must succeed without delivery.
        assert!(services.notify("recovery", "wait scheduled").is_ok());
    }

    #[test]
    fn notify_attempts_herdr_when_target_has_herdr_context() {
        let temp = tempfile::tempdir().unwrap();
        let paths = WatchmePaths::resolve(
            temp.path(),
            Some(&temp.path().join("config")),
            Some(&temp.path().join("state")),
            Some(&temp.path().join("run")),
        )
        .unwrap();
        paths.create_owner_only().unwrap();
        fs_write_config(
            &paths,
            r#"
[notifications]
herdr = true
desktop = false
stderr = true
notify_on_recovery = true
"#,
        );

        let mut registry =
            Registry::load(JsonStore::new(paths.state_dir().join("watchers.json"))).unwrap();
        let target = TargetIdentity::herdr(
            "/tmp/watchme-herdr-test.sock".into(),
            "server".into(),
            "ws".into(),
            "tab".into(),
            "pane".into(),
            "/dev/pts/9".into(),
            ProcessIdentity::new(11, 22),
        );
        registry
            .register(WatcherState::new(
                "herdr-watcher".into(),
                target,
                WatcherLifecycle::Observing,
                0,
                1,
            ))
            .unwrap();
        let registry = Arc::new(tokio::sync::Mutex::new(registry));
        let services = DaemonRuntimeServices::new(registry, "herdr-watcher".into(), paths);
        // Socket is absent; Herdr fails closed and stderr fallback still delivers.
        let result = services.notify("recovery", "hello herdr");
        assert!(
            result.is_ok(),
            "herdr-backed notify must fall back without panicking: {result:?}"
        );
    }

    fn fs_write_config(paths: &WatchmePaths, body: &str) {
        std::fs::write(paths.config_dir().join("config.toml"), body).unwrap();
    }
}
