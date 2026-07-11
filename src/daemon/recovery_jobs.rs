//! Observation scheduling and durable recovery job coordination.
//!
//! This module keeps recovery workers owned by the daemon until their ledger
//! entries have reached a terminal state.  It deliberately contains no IPC or
//! process-lifecycle code: callers provide committed watcher state and this
//! module turns it into bounded observation and recovery work.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::recovery_runtime::execute_recovery_action_with_cancellation;
use super::{
    ObservationClock, ObservationResult, Observer, Registry, SystemObservationClock,
    WatcherLifecycle, now_ms,
};
use crate::daemon::runtime_services::recover_stale_durable_actions;

const RECOVERY_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

pub(super) type DaemonRecoveryEngine = crate::recovery::engine::RecoveryEngine<
    crate::recovery::action_store::JsonActionStore,
    Arc<dyn crate::recovery::engine::RecipeProvider>,
>;

/// Owns every blocking recovery transaction until it reaches a terminal ledger
/// state. Cancellation is cooperative because a mux request can be in a kernel
/// read when shutdown begins; the daemon therefore waits for the worker to
/// observe cancellation and finish fail-closed.
pub(super) struct RecoverySupervisor {
    accepting: AtomicBool,
    cancellation: Arc<AtomicBool>,
    jobs: std::sync::Mutex<Vec<(String, tokio::task::JoinHandle<()>)>>,
}

impl RecoverySupervisor {
    pub(super) fn new() -> Self {
        Self {
            accepting: AtomicBool::new(true),
            cancellation: Arc::new(AtomicBool::new(false)),
            jobs: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(super) fn schedule(
        &self,
        watcher_id: String,
        job: impl FnOnce(Arc<AtomicBool>) + Send + 'static,
    ) {
        let mut jobs = self.jobs.lock().expect("recovery job registry poisoned");
        if !self.accepting.load(Ordering::Acquire) {
            return;
        }
        jobs.retain(|(_, handle)| !handle.is_finished());
        let cancellation = self.cancellation.clone();
        jobs.push((
            watcher_id,
            tokio::task::spawn_blocking(move || job(cancellation)),
        ));
    }

    pub(super) fn begin_shutdown(&self) {
        self.accepting.store(false, Ordering::Release);
        self.cancellation.store(true, Ordering::Release);
    }

    pub(super) async fn wait_for_terminal_jobs(&self, registry: Arc<tokio::sync::Mutex<Registry>>) {
        self.begin_shutdown();
        let jobs = std::mem::take(&mut *self.jobs.lock().expect("recovery job registry poisoned"));
        for (watcher_id, mut job) in jobs {
            if tokio::time::timeout(RECOVERY_SHUTDOWN_GRACE, &mut job)
                .await
                .is_err()
            {
                // The worker cannot be safely killed after a possible mux side
                // effect. Persist the human hand-off, then retain this daemon
                // until the cooperative worker reaches its terminal state.
                let _ = registry.lock().await.transition(
                    &watcher_id,
                    WatcherLifecycle::HumanRequired {
                        reason: "recovery cancellation exceeded shutdown grace".into(),
                    },
                    now_ms(),
                );
                let _ = job.await;
            }
        }
    }
}

pub(super) async fn run_observation_monitor_with_recovery(
    registry: Arc<tokio::sync::Mutex<Registry>>,
    observer: Arc<dyn Observer>,
    recovery: Arc<DaemonRecoveryEngine>,
    owner: crate::recovery::transaction::OwnerIdentity,
    recovery_supervisor: Arc<RecoverySupervisor>,
) {
    run_observation_loop(
        registry,
        observer,
        Arc::new(SystemObservationClock::new()),
        0,
        Some(recovery),
        Some(owner),
        Some(recovery_supervisor),
    )
    .await
}

pub(super) async fn run_observation_loop(
    registry: Arc<tokio::sync::Mutex<Registry>>,
    observer: Arc<dyn Observer>,
    clock: Arc<dyn ObservationClock>,
    max_iterations: usize,
    recovery: Option<Arc<DaemonRecoveryEngine>>,
    owner: Option<crate::recovery::transaction::OwnerIdentity>,
    recovery_supervisor: Option<Arc<RecoverySupervisor>>,
) {
    let mut iterations = 0;
    let mut runtime_due = std::collections::BTreeMap::<String, u64>::new();
    loop {
        let now = clock.wall_now_ms();
        let mono = clock.mono_now_ms();
        let due = {
            let guard = registry.lock().await;
            let mut due = Vec::new();
            for watcher in guard.list() {
                if matches!(
                    watcher.lifecycle,
                    WatcherLifecycle::Paused
                        | WatcherLifecycle::Stopped { .. }
                        | WatcherLifecycle::TargetTerminated
                ) {
                    continue;
                }
                let schedule = &watcher.observation_schedule;
                let interval_ms = recovery_observation_interval_ms(&watcher);
                let due_mono = runtime_due
                    .entry(watcher.watcher_id.clone())
                    .or_insert_with(|| {
                        mono.saturating_add(
                            schedule.next_due_wall_ms.saturating_sub(now).min(65_000),
                        )
                    });
                *due_mono = (*due_mono).min(mono.saturating_add(interval_ms));
                if schedule.event_wake_pending || mono >= *due_mono {
                    let mut next = schedule.clone();
                    next.last_check_wall_ms = Some(now);
                    next.interval_sequence = next.interval_sequence.saturating_add(1);
                    let jitter =
                        observation_jitter_seconds(&watcher.watcher_id, next.interval_sequence);
                    let next_interval = if interval_ms < 60_000 {
                        interval_ms
                    } else {
                        (60_000i64 + jitter * 1_000).max(1) as u64
                    };
                    next.next_due_wall_ms = now.saturating_add(next_interval);
                    runtime_due.insert(
                        watcher.watcher_id.clone(),
                        mono.saturating_add(next_interval),
                    );
                    due.push((watcher, next))
                }
            }
            due
        };
        for (watcher, mut next_schedule) in due {
            let observed = match tokio::time::timeout(
                Duration::from_secs(5),
                observer.observe(watcher.clone()),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err("observation timed out".into()),
            };
            if let Ok(result) = observed {
                let coordinator = RecoveryDispatch {
                    registry: registry.clone(),
                    clock: clock.as_ref(),
                    recovery: recovery.as_ref(),
                    owner: owner.as_ref(),
                    supervisor: recovery_supervisor.as_ref(),
                };
                coordinator
                    .commit_and_schedule(watcher, &mut next_schedule, result)
                    .await;
            }
        }
        iterations += 1;
        if max_iterations > 0 && iterations >= max_iterations {
            return;
        }
        clock.sleep_until_mono(mono.saturating_add(1_000)).await;
    }
}

struct RecoveryDispatch<'a> {
    registry: Arc<tokio::sync::Mutex<Registry>>,
    clock: &'a dyn ObservationClock,
    recovery: Option<&'a Arc<DaemonRecoveryEngine>>,
    owner: Option<&'a crate::recovery::transaction::OwnerIdentity>,
    supervisor: Option<&'a Arc<RecoverySupervisor>>,
}

impl RecoveryDispatch<'_> {
    async fn commit_and_schedule(
        &self,
        watcher: crate::model::WatcherState,
        next_schedule: &mut crate::model::ObservationSchedule,
        result: ObservationResult,
    ) {
        if let Some(sequence) = result.herdr_after_sequence {
            next_schedule.herdr_after_sequence = sequence;
        }
        if let Some(event) = result.event.as_ref()
            && event.source.kind == crate::model::SourceKind::ScreenDetection
        {
            if event.category.is_actionable() {
                if next_schedule.screen_fingerprint.as_deref() == Some(&event.evidence_fingerprint)
                {
                    next_schedule.screen_stable_count =
                        next_schedule.screen_stable_count.saturating_add(1);
                } else {
                    next_schedule.screen_fingerprint = Some(event.evidence_fingerprint.clone());
                    next_schedule.screen_stable_count = 1;
                }
            } else {
                next_schedule.screen_fingerprint = None;
                next_schedule.screen_stable_count = 0;
            }
        }
        let mut guard = self.registry.lock().await;
        if guard
            .commit_observation(
                &watcher.watcher_id,
                next_schedule.clone(),
                result.event,
                self.clock.wall_now_ms(),
            )
            .is_err()
        {
            // A recovery decision may only consume a durably committed observation.
            // Retrying the next poll is safe; running against the old snapshot is not.
            return;
        }
        let current = self
            .recovery
            .and_then(|_| guard.get(&watcher.watcher_id).cloned());
        drop(guard);
        if let (Some(engine), Some(owner), Some(current), Some(supervisor)) =
            (self.recovery, self.owner, current, self.supervisor)
        {
            let engine = engine.clone();
            let registry = self.registry.clone();
            let owner = owner.clone();
            let watcher_id = current.watcher_id.clone();
            supervisor.schedule(watcher_id, move |cancellation| {
                // Herdr rejects synchronous protocol calls while Tokio is entered.
                // Keep the full transaction on a native worker rather than relaxing
                // that adapter guard or risking nested runtimes.
                let _ = std::thread::scope(|scope| {
                    scope
                        .spawn(|| {
                            recover_stale_durable_actions(&engine);
                            execute_recovery_action_with_cancellation(
                                registry,
                                engine,
                                current,
                                owner,
                                cancellation,
                            )
                        })
                        .join()
                });
            });
            // Verification intentionally runs alongside later observation ticks:
            // dispatched input only becomes trusted after a fresh committed observation.
        }
    }
}

fn recovery_observation_interval_ms(watcher: &crate::model::WatcherState) -> u64 {
    const NORMAL_INTERVAL_MS: u64 = 60_000;
    const VERIFY_INTERVAL_MS: u64 = 1_000;
    if watcher.recovery.as_ref().is_some_and(|machine| {
        machine.state() == crate::recovery::state_machine::RecoveryState::Acting
    }) {
        VERIFY_INTERVAL_MS
    } else {
        NORMAL_INTERVAL_MS
    }
}

pub fn observation_jitter_seconds(watcher_id: &str, interval_sequence: u64) -> i64 {
    let hash = watcher_id.bytes().fold(interval_sequence, |acc, byte| {
        acc.wrapping_mul(109).wrapping_add(u64::from(byte))
    });
    (hash % 11) as i64 - 5
}
