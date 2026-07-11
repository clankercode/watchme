//! Exclusive daemon-process ownership and lock-file validation.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

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
