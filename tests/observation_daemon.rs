use std::sync::{Arc, Mutex};

use tempfile::tempdir;
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
            dyn std::future::Future<Output = Result<Option<watchme::model::Event>, String>>
                + Send
                + 'a,
        >,
    > {
        self.0.lock().unwrap().push(watcher.watcher_id);
        Box::pin(async { Ok(None) })
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
fn wake_fingerprint_dedupes_pending_but_can_recur_after_completed_check() {
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
        registry
            .get("w")
            .unwrap()
            .observation_schedule
            .event_wake_pending
    );
}
