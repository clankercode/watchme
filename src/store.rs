use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("state path is unsafe: {0}")]
    UnsafePath(String),
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
        reject_symlink_components(&self.path)?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| StoreError::UnsafePath("state path has no parent".into()))?;
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() as u64 > self.max_bytes {
            return Err(StoreError::UnsafePath(
                "serialized state exceeds size limit".into(),
            ));
        }
        let temporary = temporary_path(&self.path);
        let result = write_temporary(&temporary, &bytes)
            .and_then(|()| fs::rename(&temporary, &self.path))
            .and_then(|()| sync_directory(parent));
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(StoreError::Io)
    }

    pub fn load<V: DeserializeOwned>(&self) -> Result<LoadOutcome<V>, StoreError> {
        reject_symlink_components(&self.path)?;
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(LoadOutcome::Missing);
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(StoreError::UnsafePath(self.path.display().to_string()));
        }
        if metadata.len() > self.max_bytes {
            return self.quarantine();
        }
        let file = File::open(&self.path)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(self.max_bytes + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > self.max_bytes {
            return self.quarantine();
        }
        match serde_json::from_slice(&bytes) {
            Ok(value) => Ok(LoadOutcome::Present(value)),
            Err(_) => self.quarantine(),
        }
    }

    fn quarantine<V>(&self) -> Result<LoadOutcome<V>, StoreError> {
        let quarantine = quarantine_path(&self.path);
        fs::rename(&self.path, &quarantine)?;
        if let Some(parent) = self.path.parent() {
            sync_directory(parent)?;
        }
        Ok(LoadOutcome::Corrupt { quarantine })
    }
}

fn reject_symlink_components(path: &Path) -> Result<(), StoreError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(StoreError::UnsafePath(current.display().to_string()));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_extension(format!("tmp-{}-{nonce}", std::process::id()))
}

fn quarantine_path(path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.with_extension(format!("corrupt-{nonce}"))
}

fn write_temporary(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}
