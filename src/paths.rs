use std::fs::{self, DirBuilder};
use std::io;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;

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
            reject_symlink_components(path)?;
            create_private_dir(path)?;
            reject_symlink_components(path)?;
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
        reject_symlink_components(path)
    }
}

fn runtime_fallback() -> PathBuf {
    PathBuf::from(format!(
        "/tmp/watchme-{}",
        rustix::process::geteuid().as_raw()
    ))
}

fn reject_symlink_components(path: &Path) -> io::Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("managed path contains symlink: {}", current.display()),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
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

fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
