use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024;
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("state path is unsafe: {0}")]
    UnsafePath(String),
    #[error("state changed while corrupt data was being quarantined")]
    ConcurrentReplacement,
    #[error("state I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("state serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

#[derive(Debug, Eq, PartialEq)]
pub enum LoadOutcome<T> {
    Missing,
    Present(T),
    Corrupt { quarantine: PathBuf },
}

pub struct JsonStore {
    path: PathBuf,
    max_bytes: u64,
}

impl JsonStore {
    pub fn new(path: PathBuf) -> Self {
        Self::with_max_bytes(path, DEFAULT_MAX_BYTES)
    }

    pub fn with_max_bytes(path: PathBuf, max_bytes: u64) -> Self {
        Self { path, max_bytes }
    }

    pub fn write<V: Serialize>(&self, value: &V) -> Result<(), StoreError> {
        self.write_impl(value, || {})
    }

    #[cfg(test)]
    fn write_with_before_rename<V: Serialize, F: FnOnce()>(
        &self,
        value: &V,
        before_rename: F,
    ) -> Result<(), StoreError> {
        self.write_impl(value, before_rename)
    }

    fn write_impl<V: Serialize, F: FnOnce()>(
        &self,
        value: &V,
        before_rename: F,
    ) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() as u64 > self.max_bytes {
            return Err(StoreError::UnsafePath(
                "serialized state exceeds size limit".into(),
            ));
        }
        let parent = TrustedParent::open(&self.path)?;
        match rustix::fs::statat(parent.fd(), parent.name(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode).is_symlink() => {
                return Err(StoreError::UnsafePath(self.path.display().to_string()));
            }
            Ok(_) | Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(errno(error).into()),
        }
        let temporary = temporary_name(parent.name());
        let fd = rx(rustix::fs::openat(
            parent.fd(),
            &temporary,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        ))?;
        let mut file = File::from(fd);
        let result = (|| {
            file.write_all(&bytes)?;
            file.flush()?;
            file.sync_all()?;
            before_rename();
            rx(rustix::fs::renameat(
                parent.fd(),
                &temporary,
                parent.fd(),
                parent.name(),
            ))?;
            sync_directory(parent.fd())
        })();
        if result.is_err() {
            let _ = rustix::fs::unlinkat(parent.fd(), &temporary, AtFlags::empty());
        }
        result.map_err(StoreError::Io)
    }

    pub fn load<V: DeserializeOwned>(&self) -> Result<LoadOutcome<V>, StoreError> {
        self.load_impl(|| {})
    }

    #[cfg(test)]
    fn load_with_before_quarantine<V: DeserializeOwned, F: FnOnce()>(
        &self,
        before_quarantine: F,
    ) -> Result<LoadOutcome<V>, StoreError> {
        self.load_impl(before_quarantine)
    }

    fn load_impl<V: DeserializeOwned, F: FnOnce()>(
        &self,
        before_quarantine: F,
    ) -> Result<LoadOutcome<V>, StoreError> {
        let parent = TrustedParent::open(&self.path)?;
        let fd = match rustix::fs::openat(
            parent.fd(),
            parent.name(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(LoadOutcome::Missing),
            Err(error) => return Err(rx::<OwnedFd>(Err(error)).unwrap_err().into()),
        };
        let identity = FileIdentity::from_fd(&fd)?;
        let file = File::from(fd);
        let mut bytes = Vec::with_capacity(identity.size.min(self.max_bytes) as usize);
        file.take(self.max_bytes + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 <= self.max_bytes {
            if let Ok(value) = serde_json::from_slice(&bytes) {
                return Ok(LoadOutcome::Present(value));
            }
        }
        before_quarantine();
        self.quarantine(&parent, identity)
    }

    fn quarantine<V>(
        &self,
        parent: &TrustedParent,
        identity: FileIdentity,
    ) -> Result<LoadOutcome<V>, StoreError> {
        let current = rx(rustix::fs::statat(
            parent.fd(),
            parent.name(),
            AtFlags::SYMLINK_NOFOLLOW,
        ))?;
        if current.st_dev as u64 != identity.device || current.st_ino as u64 != identity.inode {
            return Err(StoreError::ConcurrentReplacement);
        }
        let quarantine_name = quarantine_name(parent.name());
        rx(rustix::fs::renameat(
            parent.fd(),
            parent.name(),
            parent.fd(),
            &quarantine_name,
        ))?;
        sync_directory(parent.fd())?;
        Ok(LoadOutcome::Corrupt {
            quarantine: parent.path().join(quarantine_name),
        })
    }
}

struct TrustedParent {
    fd: OwnedFd,
    path: PathBuf,
    name: OsString,
}

impl TrustedParent {
    fn open(path: &Path) -> Result<Self, StoreError> {
        if !path.is_absolute() {
            return Err(StoreError::UnsafePath("state path must be absolute".into()));
        }
        let name = path
            .file_name()
            .ok_or_else(|| StoreError::UnsafePath("state path has no filename".into()))?
            .to_os_string();
        let parent_path = path
            .parent()
            .ok_or_else(|| StoreError::UnsafePath("state path has no parent".into()))?;
        let mut fd = rx(rustix::fs::open("/", DIRECTORY_FLAGS, Mode::empty()))?;
        for component in parent_path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    fd = rx(rustix::fs::openat(
                        &fd,
                        name,
                        DIRECTORY_FLAGS,
                        Mode::empty(),
                    ))?;
                }
                _ => return Err(StoreError::UnsafePath(parent_path.display().to_string())),
            }
        }
        verify_directory(&fd, parent_path)?;
        Ok(Self {
            fd,
            path: parent_path.to_path_buf(),
            name,
        })
    }

    fn fd(&self) -> &OwnedFd {
        &self.fd
    }
    fn name(&self) -> &OsStr {
        &self.name
    }
    fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Clone, Copy)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
}

impl FileIdentity {
    fn from_fd(fd: &OwnedFd) -> io::Result<Self> {
        let stat = rx(rustix::fs::fstat(fd))?;
        if stat.st_size < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "negative state size",
            ));
        }
        Ok(Self {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
            size: stat.st_size as u64,
        })
    }
}

fn verify_directory(fd: &OwnedFd, path: &Path) -> Result<(), StoreError> {
    let stat = rx(rustix::fs::fstat(fd))?;
    let expected_uid = rustix::process::geteuid().as_raw();
    if stat.st_uid as u32 != expected_uid || stat.st_mode as u32 & 0o022 != 0 {
        return Err(StoreError::UnsafePath(format!(
            "untrusted state directory {}",
            path.display()
        )));
    }
    Ok(())
}

fn temporary_name(name: &OsStr) -> OsString {
    generated_name(name, "tmp")
}
fn quarantine_name(name: &OsStr) -> OsString {
    generated_name(name, "corrupt")
}

fn generated_name(name: &OsStr, label: &str) -> OsString {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut generated = name.to_os_string();
    generated.push(format!(".{label}-{}-{nonce}", std::process::id()));
    generated
}

fn sync_directory(fd: &OwnedFd) -> io::Result<()> {
    match rustix::fs::fsync(fd) {
        Ok(()) => Ok(()),
        Err(error) => {
            let error = errno(error);
            if is_unsupported_directory_sync(&error) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }
}

fn is_unsupported_directory_sync(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::Unsupported {
        return true;
    }
    #[cfg(target_os = "linux")]
    const UNSUPPORTED_RAW_ERROR: i32 = 95;
    #[cfg(target_os = "macos")]
    const UNSUPPORTED_RAW_ERROR: i32 = 45;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    const UNSUPPORTED_RAW_ERROR: i32 = i32::MIN;
    matches!(error.raw_os_error(), Some(22) | Some(UNSUPPORTED_RAW_ERROR))
}

fn rx<T>(result: rustix::io::Result<T>) -> io::Result<T> {
    result.map_err(errno)
}
fn errno(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

#[cfg(test)]
mod tests {
    use super::{JsonStore, StoreError, is_unsupported_directory_sync};
    use std::io;
    use tempfile::TempDir;

    #[test]
    fn directory_sync_ignores_only_explicitly_unsupported_errors() {
        assert!(is_unsupported_directory_sync(&io::Error::from(
            io::ErrorKind::Unsupported
        )));
        assert!(is_unsupported_directory_sync(
            &io::Error::from_raw_os_error(22)
        ));
        #[cfg(target_os = "linux")]
        assert!(is_unsupported_directory_sync(
            &io::Error::from_raw_os_error(95)
        ));
        #[cfg(target_os = "macos")]
        assert!(is_unsupported_directory_sync(
            &io::Error::from_raw_os_error(45)
        ));
    }

    #[test]
    fn directory_sync_propagates_permission_and_io_failures() {
        assert!(!is_unsupported_directory_sync(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
        assert!(!is_unsupported_directory_sync(&io::Error::from(
            io::ErrorKind::Other
        )));
        assert!(!is_unsupported_directory_sync(
            &io::Error::from_raw_os_error(5)
        ));
    }

    #[test]
    fn quarantine_refuses_to_move_a_replacement_inode() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("state.json");
        std::fs::write(&path, b"broken").unwrap();
        let store = JsonStore::new(path.clone());
        let error = store
            .load_with_before_quarantine::<serde_json::Value, _>(|| {
                let replacement = temp.path().join("replacement");
                std::fs::write(&replacement, br#"{"valid":true}"#).unwrap();
                std::fs::rename(replacement, &path).unwrap();
            })
            .unwrap_err();
        assert!(matches!(error, StoreError::ConcurrentReplacement));
        assert_eq!(std::fs::read(path).unwrap(), br#"{"valid":true}"#);
    }

    #[test]
    fn write_remains_anchored_when_parent_path_is_swapped_for_symlink() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let parent = temp.path().join("state");
        let anchored = temp.path().join("anchored");
        let victim = temp.path().join("victim");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&victim).unwrap();
        let store = JsonStore::new(parent.join("state.json"));
        store
            .write_with_before_rename(&serde_json::json!({"safe": true}), || {
                std::fs::rename(&parent, &anchored).unwrap();
                symlink(&victim, &parent).unwrap();
            })
            .unwrap();
        assert!(anchored.join("state.json").is_file());
        assert!(!victim.join("state.json").exists());
    }
}
