use std::sync::{Arc, Mutex};

use tempfile::tempdir;
use watchme::daemon::observation_jitter_seconds;
use watchme::daemon::registry::Registry;
use watchme::daemon::{ObservationClock, Observer, run_observation_monitor_with_clock};
use watchme::model::{ProcessIdentity, TargetIdentity, WatcherLifecycle, WatcherState};
use watchme::store::JsonStore;

#[derive(Default)]
struct FakeClock {
    wall: Mutex<u64>,
    mono: Mutex<u64>,
}
impl FakeClock {
    fn advance(&self, millis: u64) {
        *self.wall.lock().unwrap() += millis;
        *self.mono.lock().unwrap() += millis;
    }
}
impl ObservationClock for FakeClock {
    fn wall_now_ms(&self) -> u64 {
        *self.wall.lock().unwrap()
    }
    fn mono_now_ms(&self) -> u64 {
        *self.mono.lock().unwrap()
    }
    fn sleep_until_mono<'a>(
        &'a self,
        _: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}
struct CountingObserver(Mutex<Vec<String>>);
impl Observer for CountingObserver {
    fn observe<'a>(
        &'a self,
        watcher: WatcherState,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<watchme::daemon::ObservationResult, String>>
                + Send
                + 'a,
        >,
    > {
        self.0.lock().unwrap().push(watcher.watcher_id);
        Box::pin(async { Ok(watchme::daemon::ObservationResult::default()) })
    }
}

struct JumpingClock {
    wall: Mutex<i64>,
    mono: Mutex<u64>,
    sleeps: Mutex<u64>,
}
impl ObservationClock for JumpingClock {
    fn wall_now_ms(&self) -> u64 {
        (*self.wall.lock().unwrap()).max(0) as u64
    }
    fn mono_now_ms(&self) -> u64 {
        *self.mono.lock().unwrap()
    }
    fn sleep_until_mono<'a>(
        &'a self,
        deadline: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            *self.mono.lock().unwrap() = deadline;
            let mut sleeps = self.sleeps.lock().unwrap();
            *sleeps += 1;
            let delta = if *sleeps % 2 == 0 {
                3_601_000
            } else {
                -3_599_000
            };
            *self.wall.lock().unwrap() += delta;
        })
    }
}

#[tokio::test]
async fn injected_monotonic_clock_checks_once_and_persists_restart_deadline() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("watchers.json");
    let mut registry = Registry::load(JsonStore::new(path.clone())).unwrap();
    registry
        .register(WatcherState::new(
            "w".into(),
            TargetIdentity::process(ProcessIdentity::new(999_999, 1)),
            WatcherLifecycle::Observing,
            0,
            0,
        ))
        .unwrap();
    let registry = Arc::new(tokio::sync::Mutex::new(registry));
    let clock = Arc::new(FakeClock::default());
    let observer = Arc::new(CountingObserver(Mutex::new(Vec::new())));
    run_observation_monitor_with_clock(registry.clone(), observer.clone(), clock.clone(), 1).await;
    assert_eq!(observer.0.lock().unwrap().len(), 1);
    run_observation_monitor_with_clock(registry.clone(), observer.clone(), clock.clone(), 1).await;
    assert_eq!(observer.0.lock().unwrap().len(), 1);
    clock.advance(66_000);
    run_observation_monitor_with_clock(registry.clone(), observer.clone(), clock.clone(), 1).await;
    assert_eq!(observer.0.lock().unwrap().len(), 2);
    let restored = Registry::load(JsonStore::new(path)).unwrap();
    assert!(
        restored
            .get("w")
            .unwrap()
            .observation_schedule
            .next_due_wall_ms
            > 0
    );
}

#[test]
fn wake_fingerprint_dedupes_and_recurs_only_after_cooldown() {
    let dir = tempdir().unwrap();
    let mut registry = Registry::load(JsonStore::new(dir.path().join("w.json"))).unwrap();
    registry
        .register(WatcherState::new(
            "w".into(),
            TargetIdentity::process(ProcessIdentity::new(1, 1)),
            WatcherLifecycle::Observing,
            0,
            0,
        ))
        .unwrap();
    let fp = "0123456789abcdef";
    registry.wake_observation("w", fp, 1).unwrap();
    let revision = registry.get("w").unwrap().revision;
    registry.wake_observation("w", fp, 2).unwrap();
    assert_eq!(registry.get("w").unwrap().revision, revision);
    registry.complete_observation("w", None, 3).unwrap();
    registry.wake_observation("w", fp, 4).unwrap();
    assert!(
        !registry
            .get("w")
            .unwrap()
            .observation_schedule
            .event_wake_pending
    );
    registry.wake_observation("w", fp, 60_004).unwrap();
    assert!(
        registry
            .get("w")
            .unwrap()
            .observation_schedule
            .event_wake_pending
    );
}

struct FailingObserver;
impl Observer for FailingObserver {
    fn observe<'a>(
        &'a self,
        _: WatcherState,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<watchme::daemon::ObservationResult, String>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err("adapter unavailable".into()) })
    }
}

#[tokio::test]
async fn failed_wake_is_not_acknowledged_or_lost() {
    let dir = tempdir().unwrap();
    let mut registry = Registry::load(JsonStore::new(dir.path().join("w.json"))).unwrap();
    registry
        .register(WatcherState::new(
            "w".into(),
            TargetIdentity::process(ProcessIdentity::new(1, 1)),
            WatcherLifecycle::Observing,
            0,
            0,
        ))
        .unwrap();
    registry
        .wake_observation("w", "0123456789abcdef", 0)
        .unwrap();
    let registry = Arc::new(tokio::sync::Mutex::new(registry));
    run_observation_monitor_with_clock(
        registry.clone(),
        Arc::new(FailingObserver),
        Arc::new(FakeClock::default()),
        1,
    )
    .await;
    assert!(
        registry
            .lock()
            .await
            .get("w")
            .unwrap()
            .observation_schedule
            .event_wake_pending
    );
}

#[tokio::test]
async fn monotonic_cadence_ignores_repeated_forward_and_backward_wall_jumps() {
    let dir = tempdir().unwrap();
    let mut registry = Registry::load(JsonStore::new(dir.path().join("w.json"))).unwrap();
    registry
        .register(WatcherState::new(
            "w".into(),
            TargetIdentity::process(ProcessIdentity::new(1, 1)),
            WatcherLifecycle::Observing,
            0,
            0,
        ))
        .unwrap();
    let registry = Arc::new(tokio::sync::Mutex::new(registry));
    let clock = Arc::new(JumpingClock {
        wall: Mutex::new(10_000_000),
        mono: Mutex::new(0),
        sleeps: Mutex::new(0),
    });
    let observer = Arc::new(CountingObserver(Mutex::new(Vec::new())));
    run_observation_monitor_with_clock(registry, observer.clone(), clock.clone(), 130).await;
    let checks = observer.0.lock().unwrap().len();
    assert!((2..=3).contains(&checks), "unexpected checks: {checks}");
    assert_eq!(*clock.sleeps.lock().unwrap(), 129);
}

#[test]
fn deterministic_jitter_recomputes_each_interval_with_positive_and_negative_values() {
    let values: Vec<i64> = (1..=128)
        .map(|sequence| observation_jitter_seconds("watcher-seed", sequence))
        .collect();
    assert!(values.iter().all(|value| (-5..=5).contains(value)));
    assert!(values.iter().any(|value| *value < 0));
    assert!(values.iter().any(|value| *value > 0));
    assert!(values.windows(2).any(|pair| pair[0] != pair[1]));
    assert_eq!(
        values,
        (1..=128)
            .map(|sequence| observation_jitter_seconds("watcher-seed", sequence))
            .collect::<Vec<_>>()
    );
}
