pub mod registry;
pub mod scheduler;

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::daemon::registry::{RegistrationOutcome, Registry};
use crate::ipc::protocol::{Request, Response};
use crate::ipc::{bind_owner_only, read_request, write_response};
use crate::model::WatcherLifecycle;
use crate::paths::WatchmePaths;
use crate::store::JsonStore;
use serde::{Deserialize, Serialize};

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
    let mut registry = Registry::load(JsonStore::new(state_path)).map_err(io::Error::other)?;
    let timeout = Duration::from_secs(2);
    loop {
        let accepted = if registry.list().iter().all(|watcher| {
            matches!(
                watcher.lifecycle,
                WatcherLifecycle::Stopped { .. } | WatcherLifecycle::TargetTerminated
            )
        }) && !stay_resident
        {
            match tokio::time::timeout(idle_grace, listener.accept()).await {
                Ok(result) => result?,
                Err(_) => return Ok(()),
            }
        } else {
            listener.accept().await?
        };
        let (mut stream, _) = accepted;
        let credentials = stream.peer_cred()?;
        if credentials.uid() != rustix::process::geteuid().as_raw() {
            continue;
        }
        let request = match read_request(&mut stream, timeout).await {
            Ok(request) => request,
            Err(error) => {
                let _ = write_response(
                    &mut stream,
                    &Response::Error {
                        code: "invalid_request".into(),
                        message: error.to_string(),
                    },
                    timeout,
                )
                .await;
                continue;
            }
        };
        let (response, shutdown) = handle_request(&mut registry, request);
        let response = response.unwrap_or_else(|error| Response::Error {
            code: "daemon_error".into(),
            message: error.to_string(),
        });
        write_response(&mut stream, &response, timeout)
            .await
            .map_err(io::Error::other)?;
        if shutdown {
            return Ok(());
        }
    }
}

fn handle_request(
    registry: &mut Registry,
    request: Request,
) -> (Result<Response, registry::RegistryError>, bool) {
    match request {
        Request::Status => (
            Ok(Response::Status {
                running: true,
                watchers: registry.list().len(),
            }),
            false,
        ),
        Request::List => (
            Ok(Response::Watchers {
                watchers: registry.list(),
            }),
            false,
        ),
        Request::Register { watcher } => (
            registry.register(*watcher).map(|outcome| match outcome {
                RegistrationOutcome::Added(watcher_id) => Response::Registered {
                    watcher_id,
                    existing: false,
                },
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
            (result, false)
        }
        Request::Shutdown => (Ok(Response::Stopped), true),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
