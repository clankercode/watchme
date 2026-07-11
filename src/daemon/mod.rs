mod observation;
mod recovery_runtime;
pub mod registry;
mod runtime_services;
pub mod scheduler;

pub use observation::classify_herdr_state;
use observation::observation_event;
use recovery_runtime::{RuntimeComposerSafety, execute_recovery_action};
use runtime_services::{
    DaemonRuntimeServices, SystemRecoveryClock, recover_durable_actions_after_restart,
    recover_stale_durable_actions, target_process_is_alive,
};

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::daemon::registry::{RegistrationOutcome, Registry};
use crate::daemon::scheduler::{Scheduler, SchedulerEvent, SchedulerHandle};
use crate::ipc::protocol::{Request, Response};
use crate::ipc::{bind_owner_only, read_request, write_response};
use crate::model::WatcherLifecycle;
use crate::paths::WatchmePaths;
use crate::process::{LifecycleDecision, LifecycleMonitor, ProcessInspector};
use crate::store::JsonStore;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

type DaemonRecoveryEngine = crate::recovery::engine::RecoveryEngine<
    crate::recovery::action_store::JsonActionStore,
    std::sync::Arc<dyn crate::recovery::engine::RecipeProvider>,
>;

pub const MAX_CONNECTIONS: usize = 32;
const PROCESS_REEXEC_GRACE_MS: u64 = 2_000;
pub trait Observer: Send + Sync + 'static {
    fn observe<'a>(
        &'a self,
        watcher: crate::model::WatcherState,
    ) -> Pin<Box<dyn Future<Output = Result<ObservationResult, String>> + Send + 'a>>;
}
#[derive(Default)]
pub struct ObservationResult {
    pub event: Option<crate::model::Event>,
    pub herdr_after_sequence: Option<u64>,
}
pub trait ObservationClock: Send + Sync + 'static {
    fn wall_now_ms(&self) -> u64;
    fn mono_now_ms(&self) -> u64;
    fn sleep_until_mono<'a>(
        &'a self,
        deadline: u64,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}
struct SystemObservationClock {
    origin: std::time::Instant,
}
impl SystemObservationClock {
    fn new() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}
impl ObservationClock for SystemObservationClock {
    fn wall_now_ms(&self) -> u64 {
        now_ms()
    }
    fn mono_now_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }
    fn sleep_until_mono<'a>(
        &'a self,
        deadline: u64,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(tokio::time::sleep(Duration::from_millis(
            deadline.saturating_sub(self.mono_now_ms()),
        )))
    }
}
pub struct GenericObserver;
impl Observer for GenericObserver {
    fn observe<'a>(
        &'a self,
        watcher: crate::model::WatcherState,
    ) -> Pin<Box<dyn Future<Output = Result<ObservationResult, String>> + Send + 'a>> {
        Box::pin(async move {
            if let crate::model::TargetIdentity::Multiplexer {
                context: Some(context),
                process,
                ..
            } = &watcher.target
                && let crate::model::MultiplexerContext::Herdr {
                    socket_path,
                    workspace_id,
                    tab_id,
                    pane_id,
                    ..
                } = context.as_ref()
            {
                let context = crate::mux::herdr::HerdrContext {
                    socket_path: socket_path.clone(),
                    workspace_id: workspace_id.clone(),
                    tab_id: tab_id.clone(),
                    pane_id: pane_id.clone(),
                };
                let herdr = crate::mux::herdr::Herdr::new(context, Duration::from_secs(2))
                    .map_err(|error| error.to_string())?;
                let actual = herdr
                    .current_target_async()
                    .await
                    .map_err(|error| error.to_string())?;
                if actual.process.pid != process.pid
                    || actual.process.start_time != process.start_time
                {
                    return Err("target identity changed".into());
                }
                let state = herdr
                    .agent_state_events_async(
                        &actual,
                        watcher.observation_schedule.herdr_after_sequence,
                        64,
                    )
                    .await
                    .map_err(|error| error.to_string())?;
                let evidence = if state.events.is_empty() {
                    let capture = herdr
                        .capture_tail_async(&actual, 80, 32 * 1024)
                        .await
                        .map_err(|error| error.to_string())?;
                    crate::observe::screen::sanitize_terminal(
                        capture.text.as_bytes(),
                        32 * 1024,
                        80,
                    )
                    .into_bytes()
                } else {
                    serde_json::to_vec(&state).map_err(|error| error.to_string())?
                };
                let terminal_evidence = state.events.iter().any(|event| event.kind == "terminal");
                let classification = (!state.events.is_empty())
                    .then(|| classify_herdr_state(&state.state, terminal_evidence))
                    .flatten();
                let cursor = state.events.iter().map(|event| event.sequence).max();
                let Some((category, terminal)) = classification else {
                    return Ok(ObservationResult {
                        event: None,
                        herdr_after_sequence: cursor,
                    });
                };
                let mut event = observation_event(
                    &watcher,
                    crate::model::SourceKind::HerdrAgentState,
                    "herdr",
                    "typed_pane_state",
                    category,
                    0.8,
                    &evidence,
                )?;
                event.terminal = terminal;
                event.monotonic_sequence = state.events.iter().map(|event| event.sequence).max();
                return Ok(ObservationResult {
                    event: Some(event),
                    herdr_after_sequence: cursor,
                });
            }
            tokio::task::spawn_blocking(move || generic_observe(&watcher))
                .await
                .map_err(|error| error.to_string())?
        })
    }
}
fn generic_observe(watcher: &crate::model::WatcherState) -> Result<ObservationResult, String> {
    use crate::mux::Multiplexer;
    use sha2::{Digest, Sha256};
    if let crate::model::TargetIdentity::Process { process } = &watcher.target {
        use crate::process::ProcessInspector;
        #[cfg(target_os = "linux")]
        let inspector = crate::process::linux::LinuxProcessInspector::default();
        #[cfg(target_os = "macos")]
        let inspector = crate::process::macos::MacOsProcessInspector::default();
        let alive = inspector
            .inspect(process.pid)
            .ok()
            .is_some_and(|actual| actual.start_time == process.start_time);
        let category = if alive {
            crate::model::EventCategory::Working
        } else {
            crate::model::EventCategory::Terminated
        };
        return observation_event(
            watcher,
            crate::model::SourceKind::ProcessMetadata,
            "process",
            "liveness",
            category,
            1.0,
            if alive { b"alive" } else { b"dead" },
        )
        .map(|event| ObservationResult {
            event: Some(event),
            herdr_after_sequence: None,
        });
    }
    let crate::model::TargetIdentity::Multiplexer {
        provider,
        server,
        pane,
        process,
        session,
        context,
        chrome,
        ..
    } = &watcher.target
    else {
        return Ok(ObservationResult::default());
    };
    if provider != "tmux" || watcher.target.needs_revalidation() {
        return Ok(ObservationResult::default());
    }
    let Some(context) = context else {
        return Ok(ObservationResult::default());
    };
    let crate::model::MultiplexerContext::Tmux {
        socket_path,
        session_id,
        window_id,
        pane_id,
        tty,
        server_instance,
    } = context.as_ref()
    else {
        return Ok(ObservationResult::default());
    };
    let tmux = crate::mux::tmux::Tmux::for_socket_path(server.clone(), Duration::from_secs(2));
    let selector =
        crate::mux::tmux::TmuxSelector::parse(pane).map_err(|error| error.to_string())?;
    let identity = tmux
        .resolve_selector(&selector)
        .map_err(|error| error.to_string())?;
    if identity.process.pid != process.pid || identity.process.start_time != process.start_time {
        return Err("target identity changed".into());
    }
    if &identity.server != socket_path
        || &identity.server_instance != server_instance
        || &identity.session_id != session_id
        || &identity.window_id != window_id
        || &identity.pane_id != pane_id
        || &identity.tty != tty
    {
        return Err("target multiplexer identity changed".into());
    }
    let capture = tmux
        .capture_tail(&identity, 80, 32 * 1024)
        .map_err(|error| error.to_string())?;
    let clean = crate::observe::screen::sanitize_terminal(capture.text.as_bytes(), 32 * 1024, 80);
    let live = chrome.as_ref().map_or_else(
        || crate::observe::screen::LiveScreen::from_adapter(Vec::new(), None, false),
        |descriptor| crate::observe::screen::trusted_tmux_screen(&clean, descriptor),
    );
    let actionable = live.actionable_bottom(40);
    let fingerprint =
        crate::observe::evidence_fingerprint("screen_detection", "generic_tail", clean.as_bytes());
    let target_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&watcher.target).map_err(|error| error.to_string())?)
    );
    let observed: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    if !clean.trim().is_empty() {
        return Ok(ObservationResult::default());
    }
    let category = crate::model::EventCategory::Idle;
    let mut event = crate::model::Event::new(
        format!("obs-{}-{}", watcher.watcher_id, watcher.revision),
        observed.to_rfc3339(),
        watcher.watcher_id.clone(),
        target_hash,
        crate::model::EventSource::new(
            crate::model::SourceKind::ScreenDetection,
            "tmux",
            "generic_tail",
        ),
        category,
        if actionable.is_some() { 0.4 } else { 0.2 },
        false,
        fingerprint,
        "bounded generic observation",
        crate::model::PolicyHint::ObserveOnly,
    )
    .map_err(|error| error.to_string())?;
    event.session_id = session.clone();
    Ok(ObservationResult {
        event: Some(event),
        herdr_after_sequence: None,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonIdentity {
    pub version: u16,
    pub pid: u32,
    pub start_time: u64,
}

pub trait ProcessProbe {
    fn start_time(&self, pid: u32) -> io::Result<Option<u64>>;
}

pub struct DaemonLock {
    _file: File,
    identity: DaemonIdentity,
}

impl DaemonLock {
    pub fn acquire(
        path: &Path,
        probe: &impl ProcessProbe,
        pid: u32,
        start_time: u64,
    ) -> io::Result<Self> {
        let identity = DaemonIdentity {
            version: 1,
            pid,
            start_time,
        };
        match create_lock(path, identity) {
            Ok(file) => Ok(Self {
                _file: file,
                identity,
            }),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let existing = read_lock(path)?;
                if probe.start_time(existing.pid)? == Some(existing.start_time) {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "daemon already running",
                    ));
                }
                let mut file = open_existing_lock(path)?;
                rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                    .map_err(io::Error::from)?;
                file.set_len(0)?;
                file.rewind()?;
                write_identity(&mut file, identity)?;
                Ok(Self {
                    _file: file,
                    identity,
                })
            }
            Err(error) => Err(error),
        }
    }
    pub const fn identity(&self) -> DaemonIdentity {
        self.identity
    }
}

fn create_lock(path: &Path, identity: DaemonIdentity) -> io::Result<File> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(io::Error::from)?;
    write_identity(&mut file, identity)?;
    Ok(file)
}

fn write_identity(file: &mut File, identity: DaemonIdentity) -> io::Result<()> {
    file.write_all(&serde_json::to_vec(&identity).map_err(io::Error::other)?)?;
    file.sync_all()
}

fn open_existing_lock(path: &Path) -> io::Result<File> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(io::Error::from)?;
    Ok(File::from(fd))
}

fn read_lock(path: &Path) -> io::Result<DaemonIdentity> {
    let file = open_existing_lock(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "daemon lock is unsafe",
        ));
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "daemon lock is oversized",
        ));
    }
    let identity: DaemonIdentity = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if identity.version != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported daemon lock version",
        ));
    }
    Ok(identity)
}

pub struct SystemProcessProbe;

impl ProcessProbe for SystemProcessProbe {
    fn start_time(&self, pid: u32) -> io::Result<Option<u64>> {
        let system = sysinfo::System::new_all();
        Ok(system
            .process(sysinfo::Pid::from_u32(pid))
            .map(sysinfo::Process::start_time))
    }
}

pub fn current_process_start_time() -> io::Result<u64> {
    SystemProcessProbe
        .start_time(std::process::id())?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "current process identity unavailable",
            )
        })
}

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
        std::sync::Arc::new(crate::recovery::engine::BuiltinRecipes),
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
    let (shutdown_sender, mut shutdown_receiver) = tokio::sync::mpsc::channel(1);
    let mut connection_tasks = tokio::task::JoinSet::new();
    let mut scheduler_task = tokio::spawn(runner.run());
    let lifecycle_task = tokio::spawn(run_lifecycle_monitor(registry.clone(), scheduler.clone()));
    let action_store =
        crate::recovery::action_store::JsonActionStore::load(paths.state_file("actions.json")?)
            .map_err(io::Error::other)?;
    let recovery_engine = std::sync::Arc::new(DaemonRecoveryEngine::new(action_store, recipes));
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
    let observation_task = tokio::spawn(run_observation_monitor_with_recovery(
        registry.clone(),
        observer,
        recovery_engine,
        recovery_owner,
    ));
    let timeout = Duration::from_secs(2);
    let result = loop {
        let accepted = tokio::select! {
            result = &mut scheduler_task => {
                result.map_err(io::Error::other)?;
                while connection_tasks.join_next().await.is_some() {}
                if shutdown_receiver.try_recv().is_ok() {
                    break Ok(());
                }
                let registry_guard = registry.lock().await;
                if !has_active_watchers(&registry_guard) {
                    break Ok(());
                }
                let (replacement, runner) =
                    scheduler_from_registry(&registry_guard, idle_grace, stay_resident)?;
                drop(registry_guard);
                scheduler = replacement;
                scheduler_task = tokio::spawn(runner.run());
                continue;
            }
            Some(()) = shutdown_receiver.recv() => {
                let _ = scheduler.send(SchedulerEvent::Shutdown);
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
    observation_task.abort();
    let _ = observation_task.await;
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

async fn run_observation_monitor_with_recovery(
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    observer: std::sync::Arc<dyn Observer>,
    recovery: std::sync::Arc<DaemonRecoveryEngine>,
    owner: crate::recovery::transaction::OwnerIdentity,
) {
    run_observation_loop(
        registry,
        observer,
        std::sync::Arc::new(SystemObservationClock::new()),
        0,
        Some(recovery),
        Some(owner),
    )
    .await
}
pub async fn run_observation_monitor_with_clock(
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    observer: std::sync::Arc<dyn Observer>,
    clock: std::sync::Arc<dyn ObservationClock>,
    max_iterations: usize,
) {
    run_observation_loop(registry, observer, clock, max_iterations, None, None).await
}

async fn run_observation_loop(
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    observer: std::sync::Arc<dyn Observer>,
    clock: std::sync::Arc<dyn ObservationClock>,
    max_iterations: usize,
    recovery: Option<std::sync::Arc<DaemonRecoveryEngine>>,
    owner: Option<crate::recovery::transaction::OwnerIdentity>,
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
                let due_mono = *runtime_due
                    .entry(watcher.watcher_id.clone())
                    .or_insert_with(|| {
                        mono.saturating_add(
                            schedule.next_due_wall_ms.saturating_sub(now).min(65_000),
                        )
                    });
                if schedule.event_wake_pending || mono >= due_mono {
                    let mut next = schedule.clone();
                    next.last_check_wall_ms = Some(now);
                    next.interval_sequence = next.interval_sequence.saturating_add(1);
                    let jitter =
                        observation_jitter_seconds(&watcher.watcher_id, next.interval_sequence);
                    next.next_due_wall_ms =
                        now.saturating_add_signed((60_000i64 + jitter * 1_000).max(1));
                    runtime_due.insert(
                        watcher.watcher_id.clone(),
                        mono.saturating_add_signed((60_000i64 + jitter * 1_000).max(1)),
                    );
                    due.push((watcher, next))
                }
            }
            due
        };
        for (watcher, mut next_schedule) in due {
            let event = match tokio::time::timeout(
                Duration::from_secs(5),
                observer.observe(watcher.clone()),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err("observation timed out".into()),
            };
            if let Ok(result) = event {
                if let Some(sequence) = result.herdr_after_sequence {
                    next_schedule.herdr_after_sequence = sequence;
                }
                let event = result.event;
                if let Some(event) = event.as_ref()
                    && event.source.kind == crate::model::SourceKind::ScreenDetection
                {
                    if event.category.is_actionable() {
                        if next_schedule.screen_fingerprint.as_deref()
                            == Some(&event.evidence_fingerprint)
                        {
                            next_schedule.screen_stable_count =
                                next_schedule.screen_stable_count.saturating_add(1);
                        } else {
                            next_schedule.screen_fingerprint =
                                Some(event.evidence_fingerprint.clone());
                            next_schedule.screen_stable_count = 1;
                        }
                    } else {
                        next_schedule.screen_fingerprint = None;
                        next_schedule.screen_stable_count = 0;
                    }
                }
                let mut guard = registry.lock().await;
                if guard
                    .commit_observation(
                        &watcher.watcher_id,
                        next_schedule,
                        event,
                        clock.wall_now_ms(),
                    )
                    .is_err()
                {
                    // A recovery decision may only consume an observation that is
                    // durably committed. Retrying the next poll is safe; running
                    // against the old snapshot is not.
                    continue;
                }
                let current = recovery
                    .as_ref()
                    .and_then(|_| guard.get(&watcher.watcher_id).cloned());
                drop(guard);
                if let (Some(engine), Some(owner), Some(current)) =
                    (recovery.as_ref(), owner.as_ref(), current)
                {
                    let engine = engine.clone();
                    let registry = registry.clone();
                    let owner = owner.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        recover_stale_durable_actions(&engine);
                        execute_recovery_action(registry, engine, current, owner)
                    })
                    .await;
                }
            }
        }
        iterations += 1;
        if max_iterations > 0 && iterations >= max_iterations {
            return;
        }
        clock.sleep_until_mono(mono.saturating_add(1_000)).await;
    }
}

pub fn observation_jitter_seconds(watcher_id: &str, interval_sequence: u64) -> i64 {
    let hash = watcher_id.bytes().fold(interval_sequence, |acc, byte| {
        acc.wrapping_mul(109).wrapping_add(u64::from(byte))
    });
    (hash % 11) as i64 - 5
}

async fn run_lifecycle_monitor(
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    scheduler: SchedulerHandle,
) {
    #[cfg(target_os = "linux")]
    let inspector = crate::process::linux::LinuxProcessInspector::default();
    #[cfg(target_os = "macos")]
    let inspector = crate::process::macos::MacOsProcessInspector::default();
    let mut monitors = std::collections::BTreeMap::new();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        interval.tick().await;
        let mut registry_guard = registry.lock().await;
        monitor_process_lifecycles(&mut registry_guard, &scheduler, &inspector, &mut monitors);
    }
}

fn monitor_process_lifecycles(
    registry: &mut Registry,
    scheduler: &SchedulerHandle,
    inspector: &dyn ProcessInspector,
    monitors: &mut std::collections::BTreeMap<String, LifecycleMonitor>,
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
                } else {
                    // Preserve the coherent old identity, scheduler entry, and monitor;
                    // later ticks retry persistence while action revalidation stays closed.
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

fn scheduler_from_registry(
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

fn has_active_watchers(registry: &Registry) -> bool {
    registry.list().iter().any(|watcher| {
        !matches!(
            watcher.lifecycle,
            WatcherLifecycle::Stopped { .. } | WatcherLifecycle::TargetTerminated
        )
    })
}

async fn service_connection<P: PeerCredentialProvider>(
    mut stream: tokio::net::UnixStream,
    registry: std::sync::Arc<tokio::sync::Mutex<Registry>>,
    scheduler: SchedulerHandle,
    peer_credentials: std::sync::Arc<P>,
    shutdown_sender: tokio::sync::mpsc::Sender<()>,
    timeout: Duration,
) {
    match peer_credentials.effective_uid(&stream) {
        Ok(uid) if uid == rustix::process::geteuid().as_raw() => {}
        Ok(_) => {
            eprintln!("watchme daemon: denied IPC peer with mismatched effective UID");
            return;
        }
        Err(error) => {
            eprintln!("watchme daemon: could not validate IPC peer: {error}");
            return;
        }
    }
    let request = match read_request(&mut stream, timeout).await {
        Ok(request) => request,
        Err(error) => {
            eprintln!("watchme daemon: rejected IPC request: {error}");
            let _ = write_response(
                &mut stream,
                &Response::Error {
                    code: "invalid_request".into(),
                    message: error.to_string(),
                },
                timeout,
            )
            .await;
            return;
        }
    };
    if request_has_empty_target(&request) {
        let _ = write_response(
            &mut stream,
            &Response::Error {
                code: "invalid_target".into(),
                message: "target ID must not be empty".into(),
            },
            timeout,
        )
        .await;
        return;
    }
    if matches!(
        request,
        Request::Stop {
            id: None,
            all: false
        }
    ) {
        let _ = write_response(
            &mut stream,
            &Response::Error {
                code: "invalid_request".into(),
                message: "stop requires a watcher ID or --all".into(),
            },
            timeout,
        )
        .await;
        return;
    }
    let (response, shutdown) = {
        let mut registry = registry.lock().await;
        handle_request(&mut registry, &scheduler, request)
    };
    let response = response.unwrap_or_else(|error| Response::Error {
        code: "daemon_error".into(),
        message: error.to_string(),
    });
    if let Err(error) = write_response(&mut stream, &response, timeout).await {
        eprintln!("watchme daemon: IPC response failed: {error}");
        return;
    }
    if shutdown {
        match shutdown_sender.try_send(()) {
            Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(())) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {}
        }
    }
}

fn request_has_empty_target(request: &Request) -> bool {
    match request {
        Request::Status { id } | Request::Stop { id, .. } => {
            id.as_ref().is_some_and(String::is_empty)
        }
        Request::Pause { id } | Request::Resume { id } | Request::WakeObservation { id, .. } => {
            id.is_empty()
        }
        Request::List | Request::Register { .. } | Request::Shutdown => false,
    }
}

fn handle_request(
    registry: &mut Registry,
    scheduler: &SchedulerHandle,
    request: Request,
) -> (Result<Response, registry::RegistryError>, bool) {
    match request {
        Request::Status { id } => (
            Ok(Response::Status {
                running: true,
                watchers: id.map_or_else(
                    || registry.list(),
                    |id| registry.get(&id).cloned().into_iter().collect(),
                ),
            }),
            false,
        ),
        Request::List => (
            Ok(Response::Watchers {
                watchers: registry.list(),
            }),
            false,
        ),
        Request::WakeObservation {
            id,
            event_fingerprint,
        } => (
            registry
                .wake_observation(&id, &event_fingerprint, now_ms())
                .map(|()| Response::Acknowledged),
            false,
        ),
        Request::Register { watcher } => (
            registry.register(*watcher).map(|outcome| match outcome {
                RegistrationOutcome::Added(watcher_id) => {
                    let _ = scheduler.send(SchedulerEvent::Register(watcher_id.clone()));
                    Response::Registered {
                        watcher_id,
                        existing: false,
                    }
                }
                RegistrationOutcome::Existing(watcher_id) => Response::Registered {
                    watcher_id,
                    existing: true,
                },
            }),
            false,
        ),
        Request::Stop { id, all } => {
            let ids: Vec<String> = if all {
                registry
                    .list()
                    .into_iter()
                    .map(|watcher| watcher.watcher_id)
                    .collect()
            } else {
                id.into_iter().collect()
            };
            let result = ids
                .into_iter()
                .try_for_each(|id| {
                    registry.transition(
                        &id,
                        WatcherLifecycle::Stopped {
                            reason: "requested".into(),
                        },
                        now_ms(),
                    )
                })
                .map(|()| Response::Stopped);
            for id in registry
                .list()
                .into_iter()
                .filter(|watcher| matches!(watcher.lifecycle, WatcherLifecycle::Stopped { .. }))
                .map(|watcher| watcher.watcher_id)
            {
                let _ = scheduler.send(SchedulerEvent::Stop(id));
            }
            (result, false)
        }
        Request::Pause { id } => (
            registry
                .transition(&id, WatcherLifecycle::Paused, now_ms())
                .map(|()| {
                    let _ = scheduler.send(SchedulerEvent::Pause(id.clone()));
                    Response::Updated {
                        watcher: Box::new(
                            registry
                                .get(&id)
                                .expect("transitioned watcher exists")
                                .clone(),
                        ),
                    }
                }),
            false,
        ),
        Request::Resume { id } => (
            registry
                .transition(&id, WatcherLifecycle::Observing, now_ms())
                .map(|()| {
                    let _ = scheduler.send(SchedulerEvent::Resume(id.clone()));
                    Response::Updated {
                        watcher: Box::new(
                            registry
                                .get(&id)
                                .expect("transitioned watcher exists")
                                .clone(),
                        ),
                    }
                }),
            false,
        ),
        Request::Shutdown => (Ok(Response::Stopped), true),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
mod process_lifecycle_tests {
    use std::collections::{BTreeMap, HashMap};

    use super::*;
    use crate::model::{ProcessIdentity, TargetIdentity, WatcherState};
    use crate::process::{ProcessError, ProcessRecord};

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
}

#[cfg(test)]
mod recovery_runtime_tests {
    use super::*;
    use crate::model::{
        Event, EventCategory, EventSource, PolicyHint, ProcessIdentity, SourceKind, TargetIdentity,
        WatcherState,
    };
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
        let services = DaemonRuntimeServices::new(registry.clone(), "watcher".into());

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
            Some(engine.clone()),
            Some(owner),
        )
        .await;

        let audit = engine.store().audit("waiter").unwrap();
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
            Some(engine.clone()),
            Some(owner),
        )
        .await;

        assert!(engine.store().audit("store-failure").unwrap().is_empty());
    }
}
