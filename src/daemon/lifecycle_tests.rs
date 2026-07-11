use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::Duration;

use crate::daemon::lifecycle::{monitor_process_lifecycles, now_ms};
use crate::daemon::registry::Registry;
use crate::daemon::scheduler::{Scheduler, SchedulerEvent};
use crate::model::{ProcessIdentity, TargetIdentity, WatcherLifecycle, WatcherState};
use crate::process::{
    LifecycleDecision, LifecycleMonitor, ProcessError, ProcessInspector, ProcessRecord,
};
use crate::store::JsonStore;

struct FakeInspector(HashMap<u32, ProcessRecord>);

impl ProcessInspector for FakeInspector {
    fn inspect(&self, pid: u32) -> Result<ProcessRecord, ProcessError> {
        self.0
            .get(&pid)
            .cloned()
            .ok_or(ProcessError::Disappeared(pid))
    }

    fn processes_on_tty(&self, tty: &str) -> Result<Vec<ProcessRecord>, ProcessError> {
        Ok(self
            .0
            .values()
            .filter(|process| process.tty.as_deref() == Some(tty))
            .cloned()
            .collect())
    }
}

fn process(pid: u32) -> ProcessRecord {
    ProcessRecord::synthetic(pid, 1, u64::from(pid) * 10, "claude")
        .with_uid(1000)
        .with_terminal("dev:136:4", 40, 30)
}

fn registry(path: &Path, identity: ProcessIdentity) -> Registry {
    let mut registry = Registry::load(JsonStore::new(path.to_path_buf())).unwrap();
    registry
        .register(WatcherState::new(
            "watcher".into(),
            TargetIdentity::process(identity),
            WatcherLifecycle::Observing,
            0,
            1,
        ))
        .unwrap();
    registry
}

#[tokio::test]
async fn accepted_reexec_is_persisted_before_monitor_commits() {
    let temp = tempfile::tempdir().unwrap();
    let old = process(40);
    let replacement = process(41);
    let state_path = temp.path().join("watchers.json");
    let mut registry = registry(&state_path, old.identity());
    let (scheduler, runner) = Scheduler::new(Duration::from_secs(60), true);
    let task = tokio::spawn(runner.run());
    let mut monitor = LifecycleMonitor::with_reexec_grace(old.identity(), 2_000);
    assert_eq!(
        monitor.observe(&FakeInspector(HashMap::new()), now_ms()),
        LifecycleDecision::Grace
    );
    let mut monitors = BTreeMap::from([("watcher".into(), monitor)]);
    monitor_process_lifecycles(
        &mut registry,
        &scheduler,
        &FakeInspector(HashMap::from([(41, replacement.clone())])),
        &mut monitors,
    );
    let TargetIdentity::Process { process } = &registry.get("watcher").unwrap().target else {
        panic!("process target")
    };
    assert_eq!(process.pid, 41);
    assert_eq!(
        monitors
            .get_mut("watcher")
            .unwrap()
            .observe(&FakeInspector(HashMap::from([(41, replacement)])), now_ms()),
        LifecycleDecision::Alive
    );
    scheduler.send(SchedulerEvent::Shutdown).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn retarget_persistence_failure_stops_without_adopting_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    std::fs::create_dir(&state_dir).unwrap();
    let state_path = state_dir.join("watchers.json");
    let old = process(40);
    let replacement = process(41);
    let mut registry = registry(&state_path, old.identity());
    let mut monitor = LifecycleMonitor::with_reexec_grace(old.identity(), 2_000);
    assert_eq!(
        monitor.observe(&FakeInspector(HashMap::new()), now_ms()),
        LifecycleDecision::Grace
    );
    let mut monitors = BTreeMap::from([("watcher".into(), monitor)]);
    std::fs::remove_file(&state_path).unwrap();
    std::fs::remove_dir(&state_dir).unwrap();
    let (scheduler, runner) = Scheduler::new(Duration::from_secs(60), true);
    scheduler
        .send(SchedulerEvent::Register("watcher".into()))
        .unwrap();
    let task = tokio::spawn(runner.run());
    monitor_process_lifecycles(
        &mut registry,
        &scheduler,
        &FakeInspector(HashMap::from([(41, replacement)])),
        &mut monitors,
    );
    let TargetIdentity::Process {
        process: target_process,
    } = &registry.get("watcher").unwrap().target
    else {
        panic!("process target")
    };
    assert_eq!(target_process.pid, 40);
    assert!(monitors.contains_key("watcher"));
    assert_eq!(scheduler.snapshot().await.unwrap().len(), 1);
    monitor_process_lifecycles(
        &mut registry,
        &scheduler,
        &FakeInspector(HashMap::from([(41, process(41))])),
        &mut monitors,
    );
    assert!(monitors.contains_key("watcher"));
    assert_eq!(scheduler.snapshot().await.unwrap().len(), 1);
    scheduler.send(SchedulerEvent::Shutdown).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn exited_target_is_cleaned_up_without_relaunch() {
    let temp = tempfile::tempdir().unwrap();
    let old = process(40);
    let mut registry = registry(&temp.path().join("watchers.json"), old.identity());
    let mut monitor = LifecycleMonitor::with_reexec_grace(old.identity(), 2_000);
    assert_eq!(
        monitor.observe(
            &FakeInspector(HashMap::new()),
            now_ms().saturating_sub(3_000)
        ),
        LifecycleDecision::Grace
    );
    let mut monitors = BTreeMap::from([("watcher".into(), monitor)]);
    let (scheduler, runner) = Scheduler::new(Duration::from_secs(60), true);
    scheduler
        .send(SchedulerEvent::Register("watcher".into()))
        .unwrap();
    let task = tokio::spawn(runner.run());
    monitor_process_lifecycles(
        &mut registry,
        &scheduler,
        &FakeInspector(HashMap::new()),
        &mut monitors,
    );
    assert!(matches!(
        registry.get("watcher").unwrap().lifecycle,
        WatcherLifecycle::TargetTerminated
    ));
    assert!(scheduler.snapshot().await.unwrap().is_empty());
    assert!(monitors.is_empty());
    scheduler.send(SchedulerEvent::Shutdown).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn aged_termination_latches_across_store_failure_and_beats_late_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("state");
    std::fs::create_dir(&state_dir).unwrap();
    let state_path = state_dir.join("watchers.json");
    let old = process(40);
    let mut registry = registry(&state_path, old.identity());
    let mut monitor = LifecycleMonitor::with_reexec_grace(old.identity(), 2_000);
    assert_eq!(
        monitor.observe(
            &FakeInspector(HashMap::new()),
            now_ms().saturating_sub(3_000)
        ),
        LifecycleDecision::Grace
    );
    let mut monitors = BTreeMap::from([("watcher".into(), monitor)]);
    std::fs::remove_file(&state_path).unwrap();
    std::fs::remove_dir(&state_dir).unwrap();
    let (scheduler, runner) = Scheduler::new(Duration::from_secs(60), true);
    scheduler
        .send(SchedulerEvent::Register("watcher".into()))
        .unwrap();
    let task = tokio::spawn(runner.run());
    monitor_process_lifecycles(
        &mut registry,
        &scheduler,
        &FakeInspector(HashMap::new()),
        &mut monitors,
    );
    assert!(monitors.contains_key("watcher"));
    assert_eq!(scheduler.snapshot().await.unwrap().len(), 1);
    std::fs::create_dir(&state_dir).unwrap();
    monitor_process_lifecycles(
        &mut registry,
        &scheduler,
        &FakeInspector(HashMap::from([(41, process(41))])),
        &mut monitors,
    );
    assert!(matches!(
        registry.get("watcher").unwrap().lifecycle,
        WatcherLifecycle::TargetTerminated
    ));
    assert!(monitors.is_empty());
    assert!(scheduler.snapshot().await.unwrap().is_empty());
    scheduler.send(SchedulerEvent::Shutdown).unwrap();
    task.await.unwrap();
}
