use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read configuration {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid configuration: {0}")]
    Invalid(#[from] toml::de::Error),
    #[error("configuration layer must be a table")]
    NotATable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub observation: ObservationConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ObservationConfig {
    pub poll_interval_seconds: u64,
    pub poll_jitter_seconds: u64,
}

impl Default for ObservationConfig {
    fn default() -> Self {
        Self {
            poll_interval_seconds: 60,
            poll_jitter_seconds: 5,
        }
    }
}

impl Config {
    pub fn load_layers<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Result<Self, ConfigError> {
        let mut merged = toml::Value::Table(Default::default());
        for path in paths {
            match fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(ConfigError::Read {
                        path: path.display().to_string(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "configuration path must not be a symlink",
                        ),
                    });
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(ConfigError::Read {
                        path: path.display().to_string(),
                        source,
                    });
                }
            }
            let source = match fs::read_to_string(path) {
                Ok(source) => source,
                Err(source) => {
                    return Err(ConfigError::Read {
                        path: path.display().to_string(),
                        source,
                    });
                }
            };
            let layer: toml::Value = toml::from_str(&source)?;
            merge(&mut merged, layer)?;
        }
        Ok(merged.try_into()?)
    }
}

fn merge(base: &mut toml::Value, overlay: toml::Value) -> Result<(), ConfigError> {
    match (base, overlay) {
        (toml::Value::Table(base), toml::Value::Table(overlay)) => {
            for (key, value) in overlay {
                if let Some(existing) = base.get_mut(&key) {
                    merge(existing, value)?;
                } else {
                    base.insert(key, value);
                }
            }
            Ok(())
        }
        (base, overlay) => {
            *base = overlay;
            Ok(())
        }
    }
}
