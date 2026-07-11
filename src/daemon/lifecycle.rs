//! Durable watcher scheduling and target-process lifecycle monitoring.

use std::collections::BTreeMap;
use std::io;
use std::time::Duration;

use crate::daemon::registry::Registry;
use crate::daemon::scheduler::{Scheduler, SchedulerEvent, SchedulerHandle};
use crate::model::WatcherLifecycle;
use crate::process::{LifecycleDecision, LifecycleMonitor, ProcessInspector};

const PROCESS_REEXEC_GRACE_MS: u64 = 2_000;

pub(super) async fn run_lifecycle_monitor(
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    scheduler: SchedulerHandle,
) {
    #[cfg(target_os = "linux")]
    let inspector = crate::process::linux::LinuxProcessInspector::default();
    #[cfg(target_os = "macos")]
    let inspector = crate::process::macos::MacOsProcessInspector::default();
    let mut monitors = BTreeMap::new();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        interval.tick().await;
        let mut registry_guard = registry.lock().await;
        monitor_process_lifecycles(&mut registry_guard, &scheduler, &inspector, &mut monitors);
    }
}

pub(crate) fn monitor_process_lifecycles(
    registry: &mut Registry,
    scheduler: &SchedulerHandle,
    inspector: &dyn ProcessInspector,
    monitors: &mut BTreeMap<String, LifecycleMonitor>,
) {
    let now = now_ms();
    for watcher in registry.list() {
        if matches!(
            watcher.lifecycle,
            WatcherLifecycle::Stopped { .. } | WatcherLifecycle::TargetTerminated
        ) {
            monitors.remove(&watcher.watcher_id);
            continue;
        }
        let identity = match &watcher.target {
            crate::model::TargetIdentity::Process { process }
            | crate::model::TargetIdentity::Multiplexer { process, .. } => process.clone(),
        };
        let monitor = monitors
            .entry(watcher.watcher_id.clone())
            .or_insert_with(|| {
                LifecycleMonitor::with_reexec_grace(identity, PROCESS_REEXEC_GRACE_MS)
            });
        match monitor.observe(inspector, now) {
            LifecycleDecision::Alive | LifecycleDecision::Grace => {}
            LifecycleDecision::ReexecAccepted(identity) => {
                if registry
                    .retarget_process(&watcher.watcher_id, identity.clone(), now)
                    .is_ok()
                {
                    monitor.commit_reexec(identity);
                }
            }
            LifecycleDecision::Terminate => {
                if registry
                    .transition(&watcher.watcher_id, WatcherLifecycle::TargetTerminated, now)
                    .is_ok()
                {
                    let _ = scheduler.send(SchedulerEvent::Stop(watcher.watcher_id.clone()));
                    monitors.remove(&watcher.watcher_id);
                }
            }
        }
    }
}

pub(super) fn scheduler_from_registry(
    registry: &Registry,
    idle_grace: Duration,
    stay_resident: bool,
) -> io::Result<(SchedulerHandle, Scheduler)> {
    let (scheduler, runner) = Scheduler::new(idle_grace, stay_resident);
    for watcher in registry.list() {
        if matches!(
            watcher.lifecycle,
            WatcherLifecycle::Stopped { .. } | WatcherLifecycle::TargetTerminated
        ) {
            continue;
        }
        scheduler
            .send(SchedulerEvent::Register(watcher.watcher_id.clone()))
            .map_err(io::Error::other)?;
        if matches!(
            watcher.lifecycle,
            WatcherLifecycle::Paused | WatcherLifecycle::HumanRequired { .. }
        ) {
            scheduler
                .send(SchedulerEvent::Pause(watcher.watcher_id))
                .map_err(io::Error::other)?;
        }
    }
    Ok((scheduler, runner))
}

pub(super) fn has_active_watchers(registry: &Registry) -> bool {
    registry.list().iter().any(|watcher| {
        !matches!(
            watcher.lifecycle,
            WatcherLifecycle::Stopped { .. } | WatcherLifecycle::TargetTerminated
        )
    })
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
