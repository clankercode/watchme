pub mod registry;
pub mod scheduler;

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

pub const MAX_CONNECTIONS: usize = 32;
const PROCESS_REEXEC_GRACE_MS: u64 = 2_000;
pub trait Observer: Send + Sync + 'static {
    fn observe<'a>(
        &'a self,
        watcher: crate::model::WatcherState,
    ) -> Pin<Box<dyn Future<Output = Result<Option<crate::model::Event>, String>> + Send + 'a>>;
}
struct GenericObserver;
impl Observer for GenericObserver {
    fn observe<'a>(
        &'a self,
        watcher: crate::model::WatcherState,
    ) -> Pin<Box<dyn Future<Output = Result<Option<crate::model::Event>, String>> + Send + 'a>>
    {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || generic_observe(&watcher))
                .await
                .map_err(|error| error.to_string())?
        })
    }
}
fn generic_observe(
    watcher: &crate::model::WatcherState,
) -> Result<Option<crate::model::Event>, String> {
    use crate::mux::Multiplexer;
    use sha2::{Digest, Sha256};
    let crate::model::TargetIdentity::Multiplexer {
        provider,
        server,
        pane,
        process,
        session,
    } = &watcher.target
    else {
        return Ok(None);
    };
    if provider != "tmux" {
        return Ok(None);
    }
    let tmux = crate::mux::tmux::Tmux::for_socket_path(server.clone(), Duration::from_secs(2));
    let selector =
        crate::mux::tmux::TmuxSelector::parse(pane).map_err(|error| error.to_string())?;
    let identity = tmux
        .resolve_selector(&selector)
        .map_err(|error| error.to_string())?;
    if identity.process.pid != process.pid || identity.process.start_time != process.start_time {
        return Err("target identity changed".into());
    }
    let capture = tmux
        .capture_tail(&identity, 80, 32 * 1024)
        .map_err(|error| error.to_string())?;
    let clean = crate::observe::screen::sanitize_terminal(capture.text.as_bytes(), 32 * 1024, 80);
    let lines = clean
        .lines()
        .map(|text| crate::observe::screen::ScreenLine {
            text: text.into(),
            provenance: crate::observe::screen::LineProvenance::LiveOutput,
        })
        .collect();
    let live = crate::observe::screen::LiveScreen::from_adapter(lines, None, true);
    let actionable = live.actionable_bottom(40);
    let fingerprint =
        crate::observe::evidence_fingerprint("screen_detection", "generic_tail", clean.as_bytes());
    let target_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&watcher.target).map_err(|error| error.to_string())?)
    );
    let observed: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    let category = if clean.trim().is_empty() {
        crate::model::EventCategory::Idle
    } else if actionable.is_some() {
        crate::model::EventCategory::UnknownBlocked
    } else {
        crate::model::EventCategory::Working
    };
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
    Ok(Some(event))
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
    let observation_task = tokio::spawn(run_observation_monitor(
        registry.clone(),
        std::sync::Arc::new(GenericObserver),
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
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let now = now_ms();
        let due = {
            let mut guard = registry.lock().await;
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
                let clock_discontinuity = schedule.next_due_wall_ms > now.saturating_add(65_000);
                if schedule.event_wake_pending
                    || schedule.next_due_wall_ms <= now
                    || clock_discontinuity
                {
                    let mut next = schedule.clone();
                    next.last_check_wall_ms = Some(now);
                    next.event_wake_pending = false;
                    next.interval_sequence = next.interval_sequence.saturating_add(1);
                    let hash = watcher
                        .watcher_id
                        .bytes()
                        .fold(next.interval_sequence, |acc, byte| {
                            acc.wrapping_mul(109).wrapping_add(u64::from(byte))
                        });
                    let jitter = (hash % 11) as i64 - 5;
                    next.next_due_wall_ms =
                        now.saturating_add_signed((60_000i64 + jitter * 1_000).max(1));
                    if guard
                        .persist_observation_schedule(&watcher.watcher_id, next, now)
                        .is_ok()
                    {
                        due.push(watcher)
                    }
                }
            }
            due
        };
        for watcher in due {
            if let Ok(Ok(Some(event))) =
                tokio::time::timeout(Duration::from_secs(5), observer.observe(watcher.clone()))
                    .await
            {
                let _ = registry.lock().await.persist_observation_event(
                    &watcher.watcher_id,
                    event,
                    now_ms(),
                );
            }
        }
    }
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
