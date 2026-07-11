mod ipc_service;
pub(crate) mod lifecycle;
#[cfg(test)]
mod lifecycle_tests;
mod lock;
mod observation;
mod observer_runtime;
mod recovery_jobs;
mod recovery_runtime;
pub mod registry;
mod runtime_services;
pub mod scheduler;

use ipc_service::{acknowledge_shutdown_requests, service_connection};
pub(crate) use lifecycle::now_ms;
use lifecycle::{has_active_watchers, run_lifecycle_monitor, scheduler_from_registry};
pub use lock::{DaemonLock, ProcessProbe, SystemProcessProbe, current_process_start_time};
pub use observation::classify_herdr_state;
use observation::observation_event;
use observer_runtime::SystemObservationClock;
pub use observer_runtime::{GenericObserver, ObservationClock, ObservationResult, Observer};
pub use recovery_jobs::observation_jitter_seconds;
use recovery_jobs::{
    DaemonRecoveryEngine, RecoverySupervisor, run_observation_loop,
    run_observation_monitor_with_recovery,
};
use recovery_runtime::RuntimeComposerSafety;
use runtime_services::recover_durable_actions_after_restart;

use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use crate::daemon::registry::Registry;
use crate::daemon::scheduler::{SchedulerEvent, SchedulerHandle};
use crate::ipc::bind_owner_only;
use crate::model::WatcherLifecycle;
use crate::paths::WatchmePaths;
use crate::store::JsonStore;

pub const MAX_CONNECTIONS: usize = 32;
struct SocketCleanup(PathBuf);
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub async fn run(
    paths: &WatchmePaths,
    idle_grace: Duration,
    stay_resident: bool,
) -> io::Result<()> {
    run_with_peer_provider(
        paths,
        idle_grace,
        stay_resident,
        SystemPeerCredentialProvider,
    )
    .await
}

pub trait PeerCredentialProvider: Send + Sync + 'static {
    fn effective_uid(&self, stream: &tokio::net::UnixStream) -> io::Result<u32>;
}

pub struct SystemPeerCredentialProvider;

impl PeerCredentialProvider for SystemPeerCredentialProvider {
    fn effective_uid(&self, stream: &tokio::net::UnixStream) -> io::Result<u32> {
        Ok(stream.peer_cred()?.uid())
    }
}

pub async fn run_with_peer_provider(
    paths: &WatchmePaths,
    idle_grace: Duration,
    stay_resident: bool,
    peer_credentials: impl PeerCredentialProvider,
) -> io::Result<()> {
    run_with_components(
        paths,
        idle_grace,
        stay_resident,
        peer_credentials,
        std::sync::Arc::new(GenericObserver),
        std::sync::Arc::new(crate::agents::codex::CompositeRecipes::default()),
    )
    .await
}

pub async fn run_with_components(
    paths: &WatchmePaths,
    idle_grace: Duration,
    stay_resident: bool,
    peer_credentials: impl PeerCredentialProvider,
    observer: std::sync::Arc<dyn Observer>,
    recipes: std::sync::Arc<dyn crate::recovery::engine::RecipeProvider>,
) -> io::Result<()> {
    run_with_components_and_clock(
        paths,
        idle_grace,
        stay_resident,
        peer_credentials,
        observer,
        recipes,
        std::sync::Arc::new(SystemObservationClock::new()),
    )
    .await
}

/// Runs the daemon with an observation clock supplied by its host.
///
/// This is primarily useful to deterministic integration harnesses. Production
/// callers should use [`run`] or [`run_with_components`], both of which use a
/// monotonic system clock.
#[doc(hidden)]
pub async fn run_with_components_and_clock(
    paths: &WatchmePaths,
    idle_grace: Duration,
    stay_resident: bool,
    peer_credentials: impl PeerCredentialProvider,
    observer: std::sync::Arc<dyn Observer>,
    recipes: std::sync::Arc<dyn crate::recovery::engine::RecipeProvider>,
    observation_clock: std::sync::Arc<dyn ObservationClock>,
) -> io::Result<()> {
    paths.create_owner_only()?;
    let lock_path = paths.runtime_dir().join("daemon.lock");
    let _lock = DaemonLock::acquire(
        &lock_path,
        &SystemProcessProbe,
        std::process::id(),
        current_process_start_time()?,
    )?;
    let socket_path = paths.runtime_dir().join("daemon.sock");
    if socket_path.exists() {
        fs::remove_file(&socket_path)?;
    }
    let listener = bind_owner_only(&socket_path)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let _cleanup = SocketCleanup(socket_path);
    let state_path = paths.state_file("watchers.json")?;
    let registry = Registry::load(JsonStore::new(state_path)).map_err(io::Error::other)?;
    let (mut scheduler, runner) = scheduler_from_registry(&registry, idle_grace, stay_resident)?;
    let registry = std::sync::Arc::new(tokio::sync::Mutex::new(registry));
    let peer_credentials = std::sync::Arc::new(peer_credentials);
    let connections = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    let (shutdown_sender, mut shutdown_receiver) = tokio::sync::mpsc::unbounded_channel();
    let mut connection_tasks = tokio::task::JoinSet::new();
    let mut scheduler_task = tokio::spawn(runner.run());
    let lifecycle_task = tokio::spawn(run_lifecycle_monitor(registry.clone(), scheduler.clone()));
    let action_store =
        crate::recovery::action_store::JsonActionStore::load(paths.state_file("actions.json")?)
            .map_err(io::Error::other)?;
    let recovery_engine = std::sync::Arc::new(DaemonRecoveryEngine::new(action_store, recipes));
    let recovery_supervisor = std::sync::Arc::new(RecoverySupervisor::new());
    let recovery_owner = crate::recovery::transaction::OwnerIdentity {
        pid: _lock.identity().pid,
        process_start_time: _lock.identity().start_time,
        nonce: format!(
            "daemon:{}:{}",
            _lock.identity().pid,
            _lock.identity().start_time
        ),
    };
    recover_durable_actions_after_restart(&recovery_engine);
    let mut observation_task = Some(tokio::spawn(run_observation_monitor_with_recovery(
        registry.clone(),
        observer,
        observation_clock,
        recovery_engine,
        recovery_owner,
        recovery_supervisor.clone(),
        paths.clone(),
    )));
    let timeout = Duration::from_secs(2);
    let result = loop {
        let accepted = tokio::select! {
            result = &mut scheduler_task => {
                result.map_err(io::Error::other)?;
                while connection_tasks.try_join_next().is_some() {}
                if let Ok(signal) = shutdown_receiver.try_recv() {
                    recovery_supervisor.begin_shutdown();
                    if let Some(task) = observation_task.take() {
                        task.abort();
                        let _ = task.await;
                    }
                    recovery_supervisor.wait_for_terminal_jobs(registry.clone()).await;
                    acknowledge_shutdown_requests(signal, &mut shutdown_receiver, timeout).await;
                    break Ok(());
                }
                let registry_guard = registry.lock().await;
                if !has_active_watchers(&registry_guard) && connection_tasks.is_empty() {
                    break Ok(());
                }
                let (replacement, runner) =
                    scheduler_from_registry(&registry_guard, idle_grace, stay_resident)?;
                drop(registry_guard);
                scheduler = replacement;
                scheduler_task = tokio::spawn(runner.run());
                continue;
            }
            Some(signal) = shutdown_receiver.recv() => {
                let _ = scheduler.send(SchedulerEvent::Shutdown);
                recovery_supervisor.begin_shutdown();
                if let Some(task) = observation_task.take() {
                    task.abort();
                    let _ = task.await;
                }
                recovery_supervisor.wait_for_terminal_jobs(registry.clone()).await;
                acknowledge_shutdown_requests(signal, &mut shutdown_receiver, timeout).await;
                break Ok(());
            }
            result = listener.accept() => match result {
                Ok(accepted) => accepted,
                Err(error) => break Err(error),
            },
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let (stream, _) = accepted;
        let registry = registry.clone();
        let scheduler = scheduler.clone();
        let peer_credentials = peer_credentials.clone();
        let shutdown_sender = shutdown_sender.clone();
        connection_tasks.spawn(async move {
            let _permit = permit;
            service_connection(
                stream,
                registry,
                scheduler,
                peer_credentials,
                shutdown_sender,
                timeout,
            )
            .await;
        });
        while connection_tasks.try_join_next().is_some() {}
    };
    connection_tasks.abort_all();
    while connection_tasks.join_next().await.is_some() {}
    if !scheduler_task.is_finished() {
        scheduler_task.abort();
        let _ = scheduler_task.await;
    }
    lifecycle_task.abort();
    let _ = lifecycle_task.await;
    if let Some(task) = observation_task
        && !task.is_finished()
    {
        task.abort();
        let _ = task.await;
    }
    result
}

pub async fn run_observation_monitor(
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    observer: std::sync::Arc<dyn Observer>,
) {
    run_observation_monitor_with_clock(
        registry,
        observer,
        std::sync::Arc::new(SystemObservationClock::new()),
        0,
    )
    .await
}

pub async fn run_observation_monitor_with_clock(
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    observer: std::sync::Arc<dyn Observer>,
    clock: std::sync::Arc<dyn ObservationClock>,
    max_iterations: usize,
) {
    run_observation_loop(registry, observer, clock, max_iterations, None).await
}

/// A fresh, target-bound read used at every transaction revalidation point.
/// It intentionally does not reuse a previous boolean: identity, process,
/// mux state, composer state, and the persisted observation binding are all
/// recomputed for every call.
pub(super) fn target_identity_hash(target: &crate::model::TargetIdentity) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(target).unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn process_identity_key(target: &crate::model::TargetIdentity) -> String {
    match target {
        crate::model::TargetIdentity::Process { process }
        | crate::model::TargetIdentity::Multiplexer { process, .. } => {
            format!("process:{}:{}", process.pid, process.start_time)
        }
    }
}

pub(super) fn mux_identity_key(identity: &crate::mux::MuxIdentity) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}",
        identity.provider,
        identity.server,
        identity.server_instance,
        identity.session_id,
        identity.window_id,
        identity.pane_id,
        identity.process.pid,
        identity.process.start_time,
    )
}

pub(super) fn watcher_mux_identity(
    watcher: &crate::model::WatcherState,
) -> Result<Option<crate::mux::MuxIdentity>, crate::mux::MuxError> {
    let crate::model::TargetIdentity::Multiplexer {
        provider,
        server,
        pane,
        process,
        context: Some(context),
        needs_revalidation: false,
        ..
    } = &watcher.target
    else {
        return Ok(None);
    };
    let identity = match context.as_ref() {
        crate::model::MultiplexerContext::Tmux {
            socket_path,
            server_instance,
            session_id,
            window_id,
            pane_id,
            tty,
        } if provider == "tmux" && server == socket_path && pane == pane_id => {
            crate::mux::MuxIdentity {
                provider: provider.clone(),
                server_instance: server_instance.clone(),
                server: socket_path.clone(),
                session_id: session_id.clone(),
                window_id: window_id.clone(),
                pane_id: pane_id.clone(),
                tty: tty.clone(),
                process: process.clone(),
            }
        }
        crate::model::MultiplexerContext::Herdr {
            socket_path,
            server_instance,
            workspace_id,
            tab_id,
            pane_id,
            tty,
        } if provider == "herdr" && server == socket_path && pane == pane_id => {
            crate::mux::MuxIdentity {
                provider: provider.clone(),
                server_instance: server_instance.clone(),
                server: socket_path.clone(),
                session_id: workspace_id.clone(),
                window_id: tab_id.clone(),
                pane_id: pane_id.clone(),
                tty: tty.clone(),
                process: process.clone(),
            }
        }
        _ => {
            return Err(crate::mux::MuxError::IdentityChanged(
                "stored mux context contradicts target".into(),
            ));
        }
    };
    Ok(Some(identity))
}

pub(super) fn validate_mux_target(
    watcher: &crate::model::WatcherState,
    identity: &crate::mux::MuxIdentity,
) -> Result<(), crate::mux::MuxError> {
    use crate::mux::Multiplexer;
    match watcher.target.observation_context() {
        Some(crate::model::MultiplexerContext::Tmux { socket_path, .. }) => {
            crate::mux::tmux::Tmux::for_socket_path(socket_path.clone(), Duration::from_secs(2))
                .validate_identity(identity)
        }
        Some(crate::model::MultiplexerContext::Herdr {
            socket_path,
            workspace_id,
            tab_id,
            pane_id,
            ..
        }) => crate::mux::herdr::Herdr::new(
            crate::mux::herdr::HerdrContext {
                socket_path: socket_path.clone(),
                workspace_id: workspace_id.clone(),
                tab_id: tab_id.clone(),
                pane_id: pane_id.clone(),
            },
            Duration::from_secs(2),
        )?
        .validate_identity(identity),
        _ => Err(crate::mux::MuxError::IdentityChanged(
            "missing concrete multiplexer context".into(),
        )),
    }
}

pub(super) fn capture_mux_target(
    watcher: &crate::model::WatcherState,
    identity: &crate::mux::MuxIdentity,
    lines: usize,
    bytes: usize,
) -> Result<crate::mux::Capture, crate::mux::MuxError> {
    use crate::mux::Multiplexer;
    match watcher.target.observation_context() {
        Some(crate::model::MultiplexerContext::Tmux { socket_path, .. }) => {
            crate::mux::tmux::Tmux::for_socket_path(socket_path.clone(), Duration::from_secs(2))
                .capture_tail(identity, lines, bytes)
        }
        Some(crate::model::MultiplexerContext::Herdr {
            socket_path,
            workspace_id,
            tab_id,
            pane_id,
            ..
        }) => crate::mux::herdr::Herdr::new(
            crate::mux::herdr::HerdrContext {
                socket_path: socket_path.clone(),
                workspace_id: workspace_id.clone(),
                tab_id: tab_id.clone(),
                pane_id: pane_id.clone(),
            },
            Duration::from_secs(2),
        )?
        .capture_tail(identity, lines, bytes),
        _ => Err(crate::mux::MuxError::IdentityChanged(
            "missing concrete multiplexer context".into(),
        )),
    }
}

pub(super) fn execute_mux_action(
    watcher: &crate::model::WatcherState,
    action: &crate::model::Action,
) -> Result<crate::recovery::actuator::ExecutionOutput, crate::recovery::actuator::ExecutionError> {
    use crate::recovery::actuator::ActionExecutor;
    let source = watcher
        .last_observation
        .as_ref()
        .map(|event| &event.source)
        .ok_or(crate::recovery::actuator::ExecutionError::Unsafe(
            "mux action requires a current observation source",
        ))?;
    let identity = watcher_mux_identity(watcher)
        .map_err(|error| crate::recovery::actuator::ExecutionError::Integration(error.to_string()))?
        .ok_or(crate::recovery::actuator::ExecutionError::Unsafe(
            "input or capture requires a multiplexer target",
        ))?;
    let safety = RuntimeComposerSafety::new(watcher.clone());
    match watcher.target.observation_context() {
        Some(crate::model::MultiplexerContext::Tmux { socket_path, .. }) => {
            crate::recovery::actuator::MuxActuator::new(
                &crate::mux::tmux::Tmux::for_socket_path(
                    socket_path.clone(),
                    Duration::from_secs(2),
                ),
                &identity,
                &safety,
                source,
            )
            .execute(action)
        }
        Some(crate::model::MultiplexerContext::Herdr {
            socket_path,
            workspace_id,
            tab_id,
            pane_id,
            ..
        }) => {
            let herdr = crate::mux::herdr::Herdr::new(
                crate::mux::herdr::HerdrContext {
                    socket_path: socket_path.clone(),
                    workspace_id: workspace_id.clone(),
                    tab_id: tab_id.clone(),
                    pane_id: pane_id.clone(),
                },
                Duration::from_secs(2),
            )
            .map_err(|error| {
                crate::recovery::actuator::ExecutionError::Integration(error.to_string())
            })?;
            crate::recovery::actuator::MuxActuator::new(&herdr, &identity, &safety, source)
                .execute(action)
        }
        _ => Err(crate::recovery::actuator::ExecutionError::Unsafe(
            "missing concrete multiplexer context",
        )),
    }
}

#[cfg(test)]
mod recovery_runtime_tests {
    use std::future::Future;
    use std::pin::Pin;

    use super::runtime_services::DaemonRuntimeServices;
    use super::*;
    use crate::daemon::recovery_jobs::RecoveryLoopContext;
    use crate::model::{
        Event, EventCategory, EventSource, PolicyHint, ProcessIdentity, SourceKind, TargetIdentity,
        WatcherState,
    };
    use crate::process::ProcessInspector;
    use crate::recovery::actuator::RuntimeServices;
    use crate::recovery::state_machine::{Budget, RecoveryMachine};
    use crate::recovery::transaction::ActionStore;

    #[test]
    fn durable_wait_receipt_sets_the_next_observation_deadline() {
        let temp = tempfile::tempdir().unwrap();
        let mut registry =
            Registry::load(JsonStore::new(temp.path().join("watchers.json"))).unwrap();
        registry
            .register(WatcherState::new(
                "watcher".into(),
                TargetIdentity::process(ProcessIdentity::new(7, 9)),
                WatcherLifecycle::Observing,
                0,
                1,
            ))
            .unwrap();
        let registry = std::sync::Arc::new(tokio::sync::Mutex::new(registry));
        let services = DaemonRuntimeServices::new(
            registry.clone(),
            "watcher".into(),
            crate::paths::WatchmePaths::resolve(
                temp.path(),
                Some(&temp.path().join("config")),
                Some(&temp.path().join("state")),
                Some(&temp.path().join("run")),
            )
            .unwrap(),
        );

        services.schedule("monotonic+60s").unwrap();

        let watcher = registry.blocking_lock().get("watcher").cloned().unwrap();
        assert!(matches!(
            watcher.lifecycle,
            WatcherLifecycle::Waiting { ref reason, .. } if reason == "recovery wait scheduled"
        ));
        assert!(watcher.observation_schedule.next_due_wall_ms >= now_ms().saturating_add(59_000));
    }

    struct WaitObserver;
    impl Observer for WaitObserver {
        fn observe<'a>(
            &'a self,
            watcher: crate::model::WatcherState,
        ) -> Pin<Box<dyn Future<Output = Result<ObservationResult, String>> + Send + 'a>> {
            Box::pin(async move {
                Ok(ObservationResult {
                    event: Some(
                        Event::new(
                            "wait-event",
                            "2026-07-11T00:00:00Z",
                            watcher.watcher_id,
                            target_identity_hash(&watcher.target),
                            EventSource::new(SourceKind::StructuredLog, "test", "wait"),
                            EventCategory::WaitingForModel,
                            1.0,
                            false,
                            "a".repeat(64),
                            "wait allowed",
                            PolicyHint::WaitAllowed,
                        )
                        .unwrap(),
                    ),
                    herdr_after_sequence: None,
                })
            })
        }
    }

    #[tokio::test]
    async fn observed_wait_executes_once_and_persists_a_scheduler_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let process = {
            #[cfg(target_os = "linux")]
            let inspector = crate::process::linux::LinuxProcessInspector::default();
            #[cfg(target_os = "macos")]
            let inspector = crate::process::macos::MacOsProcessInspector::default();
            inspector.inspect(std::process::id()).unwrap().identity()
        };
        let mut watcher = WatcherState::new(
            "waiter".into(),
            TargetIdentity::process(process),
            WatcherLifecycle::Observing,
            0,
            now_ms(),
        );
        watcher.recovery = Some(RecoveryMachine::new(Budget {
            max_attempts: 3,
            max_cumulative_wait: Duration::from_secs(300),
            planner_calls: 0,
            cooldown: Duration::ZERO,
        }));
        let mut persisted =
            Registry::load(JsonStore::new(temp.path().join("watchers.json"))).unwrap();
        persisted.register(watcher).unwrap();
        let registry = std::sync::Arc::new(tokio::sync::Mutex::new(persisted));
        let engine = std::sync::Arc::new(crate::recovery::engine::RecoveryEngine::new(
            crate::recovery::action_store::JsonActionStore::load(temp.path().join("actions.json"))
                .unwrap(),
            std::sync::Arc::new(crate::recovery::engine::BuiltinRecipes)
                as std::sync::Arc<dyn crate::recovery::engine::RecipeProvider>,
        ));
        let owner = crate::recovery::transaction::OwnerIdentity {
            pid: std::process::id(),
            process_start_time: current_process_start_time().unwrap(),
            nonce: "test-owner".into(),
        };

        run_observation_loop(
            registry.clone(),
            std::sync::Arc::new(WaitObserver),
            std::sync::Arc::new(SystemObservationClock::new()),
            1,
            Some(RecoveryLoopContext {
                recovery: engine.clone(),
                owner,
                supervisor: std::sync::Arc::new(RecoverySupervisor::new()),
                paths: crate::paths::WatchmePaths::resolve(
                    temp.path(),
                    Some(&temp.path().join("config")),
                    Some(&temp.path().join("state")),
                    Some(&temp.path().join("run")),
                )
                .unwrap(),
            }),
        )
        .await;

        let mut audit = engine.store().audit("waiter").unwrap();
        for _ in 0..100 {
            if audit.last().is_some_and(|record| {
                record.phase == crate::recovery::transaction::ActionPhase::Succeeded
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            audit = engine.store().audit("waiter").unwrap();
        }
        assert_eq!(
            audit.last().unwrap().phase,
            crate::recovery::transaction::ActionPhase::Succeeded
        );
        assert!(matches!(
            registry.lock().await.get("waiter").unwrap().lifecycle,
            WatcherLifecycle::Waiting { .. }
        ));
    }

    #[tokio::test]
    async fn failed_observation_commit_never_begins_a_recovery_transaction() {
        let temp = tempfile::tempdir().unwrap();
        let process = {
            #[cfg(target_os = "linux")]
            let inspector = crate::process::linux::LinuxProcessInspector::default();
            #[cfg(target_os = "macos")]
            let inspector = crate::process::macos::MacOsProcessInspector::default();
            inspector.inspect(std::process::id()).unwrap().identity()
        };
        let mut watcher = WatcherState::new(
            "store-failure".into(),
            TargetIdentity::process(process),
            WatcherLifecycle::Observing,
            0,
            now_ms(),
        );
        let mut recovery = RecoveryMachine::new(Budget {
            max_attempts: 3,
            max_cumulative_wait: Duration::from_secs(300),
            planner_calls: 0,
            cooldown: Duration::ZERO,
        });
        recovery
            .apply(crate::recovery::state_machine::RecoveryCommand::Revalidated)
            .unwrap();
        recovery
            .apply(crate::recovery::state_machine::RecoveryCommand::Confirm {
                fingerprint: "a".repeat(64),
            })
            .unwrap();
        watcher.recovery = Some(recovery);
        watcher.last_observation = Some(
            Event::new(
                "stored-wait",
                "2026-07-11T00:00:00Z",
                "store-failure",
                target_identity_hash(&watcher.target),
                EventSource::new(SourceKind::StructuredLog, "test", "wait"),
                EventCategory::WaitingForModel,
                1.0,
                false,
                "a".repeat(64),
                "wait allowed",
                PolicyHint::WaitAllowed,
            )
            .unwrap(),
        );
        let mut persisted =
            Registry::load(JsonStore::new(temp.path().join("watchers.json"))).unwrap();
        persisted.register(watcher).unwrap();
        persisted.fail_next_persist();
        let registry = std::sync::Arc::new(tokio::sync::Mutex::new(persisted));
        let engine = std::sync::Arc::new(crate::recovery::engine::RecoveryEngine::new(
            crate::recovery::action_store::JsonActionStore::load(temp.path().join("actions.json"))
                .unwrap(),
            std::sync::Arc::new(crate::recovery::engine::BuiltinRecipes)
                as std::sync::Arc<dyn crate::recovery::engine::RecipeProvider>,
        ));
        let owner = crate::recovery::transaction::OwnerIdentity {
            pid: std::process::id(),
            process_start_time: current_process_start_time().unwrap(),
            nonce: "test-owner".into(),
        };

        run_observation_loop(
            registry,
            std::sync::Arc::new(WaitObserver),
            std::sync::Arc::new(SystemObservationClock::new()),
            1,
            Some(RecoveryLoopContext {
                recovery: engine.clone(),
                owner,
                supervisor: std::sync::Arc::new(RecoverySupervisor::new()),
                paths: crate::paths::WatchmePaths::resolve(
                    temp.path(),
                    Some(&temp.path().join("config")),
                    Some(&temp.path().join("state")),
                    Some(&temp.path().join("run")),
                )
                .unwrap(),
            }),
        )
        .await;

        assert!(engine.store().audit("store-failure").unwrap().is_empty());
    }
}
