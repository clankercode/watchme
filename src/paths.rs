use std::io;
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{AtFlags, FileType, Mode, OFlags};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchmePaths {
    config_dir: PathBuf,
    state_dir: PathBuf,
    runtime_dir: PathBuf,
}

impl WatchmePaths {
    pub fn resolve(
        home: &Path,
        config_home: Option<&Path>,
        state_home: Option<&Path>,
        runtime_dir: Option<&Path>,
    ) -> io::Result<Self> {
        for path in [
            home,
            config_home.unwrap_or(home),
            state_home.unwrap_or(home),
        ] {
            require_absolute_clean(path)?;
        }
        if let Some(path) = runtime_dir {
            require_absolute_clean(path)?;
        }
        let config_root = config_home.map_or_else(|| home.join(".config"), Path::to_path_buf);
        let state_root = state_home.map_or_else(|| home.join(".local/state"), Path::to_path_buf);
        Ok(Self {
            config_dir: config_root.join("watchme"),
            state_dir: state_root.join("watchme"),
            runtime_dir: runtime_dir.map_or_else(runtime_fallback, |path| path.join("watchme")),
        })
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    pub fn create_owner_only(&self) -> io::Result<()> {
        for path in [&self.config_dir, &self.state_dir, &self.runtime_dir] {
            let directory = open_directory_chain(path, true)?;
            rx(rustix::fs::fchmod(
                &directory,
                Mode::from_bits_truncate(0o700),
            ))?;
            verify_owned_private(&directory)?;
        }
        Ok(())
    }

    pub fn state_file(&self, name: &str) -> io::Result<PathBuf> {
        let path = Path::new(name);
        if path.components().count() != 1
            || !matches!(path.components().next(), Some(Component::Normal(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "state filename must be a single safe component",
            ));
        }
        Ok(self.state_dir.join(path))
    }

    pub fn validate_managed_path(&self, path: &Path) -> io::Result<()> {
        require_absolute_clean(path)?;
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "managed path has no parent")
        })?;
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "managed path has no leaf")
        })?;
        let directory = open_directory_chain(parent, false)?;
        match rustix::fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode).is_symlink() => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "managed path leaf is a symlink",
            )),
            Ok(_) | Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(error) => Err(errno(error)),
        }
    }
}

fn runtime_fallback() -> PathBuf {
    PathBuf::from(format!(
        "/tmp/watchme-{}",
        rustix::process::geteuid().as_raw()
    ))
}

fn require_absolute_clean(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must be absolute without traversal",
        ));
    }
    Ok(())
}

fn open_directory_chain(path: &Path, create: bool) -> io::Result<OwnedFd> {
    require_absolute_clean(path)?;
    let mut directory = rx(rustix::fs::open("/", DIRECTORY_FLAGS, Mode::empty()))?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                if create {
                    match rustix::fs::mkdirat(&directory, name, Mode::from_bits_truncate(0o700)) {
                        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                        Err(error) => return Err(errno(error)),
                    }
                }
                directory = rx(rustix::fs::openat(
                    &directory,
                    name,
                    DIRECTORY_FLAGS,
                    Mode::empty(),
                ))?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsafe path component",
                ));
            }
        }
    }
    Ok(directory)
}

fn verify_owned_private(directory: &OwnedFd) -> io::Result<()> {
    let stat = rx(rustix::fs::fstat(directory))?;
    if stat.st_uid as u32 != rustix::process::geteuid().as_raw() || stat.st_mode as u32 & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "managed directory is not owner-only",
        ));
    }
    Ok(())
}

fn rx<T>(result: rustix::io::Result<T>) -> io::Result<T> {
    result.map_err(errno)
}
fn errno(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}
