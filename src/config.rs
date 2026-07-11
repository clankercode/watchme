use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const SUPPORTED_CONFIG_VERSION: u32 = 1;
const REDACTED: &str = "[redacted]";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read configuration {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid configuration: {0}")]
    Invalid(#[from] toml::de::Error),
    #[error("unsupported config_version {0}; only version {SUPPORTED_CONFIG_VERSION} is supported")]
    UnsupportedVersion(u32),
    #[error("configuration layer must be a table")]
    NotATable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub config_version: u32,
    pub daemon: DaemonConfig,
    pub observation: ObservationConfig,
    pub lifecycle: LifecycleConfig,
    pub recovery: RecoveryConfig,
    pub planning: PlanningConfig,
    pub security: SecurityConfig,
    pub retention: RetentionConfig,
    pub notifications: NotificationsConfig,
    pub manifests: ManifestsConfig,
    pub agents: BTreeMap<String, AgentConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_version: SUPPORTED_CONFIG_VERSION,
            daemon: DaemonConfig::default(),
            observation: ObservationConfig::default(),
            lifecycle: LifecycleConfig::default(),
            recovery: RecoveryConfig::default(),
            planning: PlanningConfig::default(),
            security: SecurityConfig::default(),
            retention: RetentionConfig::default(),
            notifications: NotificationsConfig::default(),
            manifests: ManifestsConfig::default(),
            agents: default_agents(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    pub idle_grace_seconds: u64,
    pub stay_resident: bool,
    pub max_watchers: u32,
    pub socket_request_timeout_seconds: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            idle_grace_seconds: 30,
            stay_resident: false,
            max_watchers: 128,
            socket_request_timeout_seconds: 5,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ObservationConfig {
    pub poll_interval_seconds: u64,
    pub poll_jitter_seconds: u64,
    pub screen_confirm_samples: u32,
    pub max_screen_lines: u32,
    pub max_screen_bytes: u32,
    pub max_structured_record_bytes: u32,
    pub max_json_depth: u32,
    pub adapter_error_backoff_seconds: Vec<u64>,
}

impl Default for ObservationConfig {
    fn default() -> Self {
        Self {
            poll_interval_seconds: 60,
            poll_jitter_seconds: 5,
            screen_confirm_samples: 2,
            max_screen_lines: 120,
            max_screen_bytes: 30_000,
            max_structured_record_bytes: 262_144,
            max_json_depth: 64,
            adapter_error_backoff_seconds: vec![5, 15, 60, 300],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LifecycleConfig {
    pub reexec_grace_seconds: u64,
    pub relaunch_dead_agent: bool,
    pub stop_on_ambiguous_identity: bool,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            reexec_grace_seconds: 3,
            relaunch_dead_agent: false,
            stop_on_ambiguous_identity: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecoveryConfig {
    pub enabled: bool,
    pub max_attempts_per_fingerprint: u32,
    pub max_attempts_per_session_per_day: u32,
    pub default_action_timeout_seconds: u64,
    pub require_empty_composer_for_text: bool,
    pub cancel_on_human_intervention: bool,
    pub verify_every_action: bool,
    pub rate_limits: RecoveryRateLimitsConfig,
    pub overload: RecoveryOverloadConfig,
    pub codex_goal: RecoveryCodexGoalConfig,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_attempts_per_fingerprint: 3,
            max_attempts_per_session_per_day: 8,
            default_action_timeout_seconds: 120,
            require_empty_composer_for_text: true,
            cancel_on_human_intervention: true,
            verify_every_action: true,
            rate_limits: RecoveryRateLimitsConfig::default(),
            overload: RecoveryOverloadConfig::default(),
            codex_goal: RecoveryCodexGoalConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecoveryRateLimitsConfig {
    pub enabled: bool,
    pub select_wait_option_by_label: bool,
    pub reset_margin_seconds: u64,
    pub allow_low_confidence_fallback_wait: bool,
    pub fallback_wait_seconds: u64,
    pub max_resume_attempts_per_limit: u32,
    pub resume_text: String,
}

impl Default for RecoveryRateLimitsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            select_wait_option_by_label: true,
            reset_margin_seconds: 75,
            allow_low_confidence_fallback_wait: false,
            fallback_wait_seconds: 18_000,
            max_resume_attempts_per_limit: 2,
            resume_text: "Continue exactly where you left off.".into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecoveryOverloadConfig {
    pub enabled: bool,
    pub backoff_seconds: Vec<u64>,
    pub jitter_mode: String,
    pub max_total_wait_seconds: u64,
    pub respect_native_retries: bool,
}

impl Default for RecoveryOverloadConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            backoff_seconds: vec![30, 60, 120, 240, 300],
            jitter_mode: "full".into(),
            max_total_wait_seconds: 7_200,
            respect_native_retries: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecoveryCodexGoalConfig {
    pub enabled: bool,
    pub resume_command: String,
    pub max_attempts_per_fingerprint: u32,
    pub cooldown_seconds: u64,
    pub require_structured_goal_when_available: bool,
}

impl Default for RecoveryCodexGoalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            resume_command: "/goal resume".into(),
            max_attempts_per_fingerprint: 3,
            cooldown_seconds: 300,
            require_structured_goal_when_available: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlanningConfig {
    pub enabled: bool,
    pub max_calls_per_event: u32,
    pub allow_independent_second_opinion: bool,
    pub max_calls_per_session_per_day: u32,
    pub max_concurrent_calls: u32,
    pub timeout_seconds: u64,
    pub max_output_bytes: u32,
    pub max_snapshot_bytes: u32,
    pub allow_unknown_provider_family: bool,
    pub allow_repository_context: bool,
    pub allow_network: bool,
    pub planner_priority: Vec<String>,
    pub planners: BTreeMap<String, PlannerConfig>,
}

impl Default for PlanningConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_calls_per_event: 1,
            allow_independent_second_opinion: false,
            max_calls_per_session_per_day: 4,
            max_concurrent_calls: 1,
            timeout_seconds: 90,
            max_output_bytes: 100_000,
            max_snapshot_bytes: 50_000,
            allow_unknown_provider_family: false,
            allow_repository_context: false,
            allow_network: false,
            planner_priority: vec![
                "codex".into(),
                "claude".into(),
                "hermes".into(),
                "opencode".into(),
                "pi".into(),
            ],
            planners: default_planners(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlannerConfig {
    pub enabled: bool,
    pub executable: String,
    pub provider_family: String,
    pub provider: String,
    pub model: String,
}

impl Default for PlannerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            executable: String::new(),
            provider_family: "unknown".into(),
            provider: String::new(),
            model: String::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    pub telemetry: bool,
    pub raw_evidence_persistence: bool,
    pub allow_remote_manifest_updates: bool,
    pub allow_project_config: bool,
    pub require_owner_only_paths: bool,
    pub reject_symlinks_for_state: bool,
    pub minimal_child_environment: bool,
    pub extra_secret_names: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            telemetry: false,
            raw_evidence_persistence: false,
            allow_remote_manifest_updates: false,
            allow_project_config: false,
            require_owner_only_paths: true,
            reject_symlinks_for_state: true,
            minimal_child_environment: true,
            extra_secret_names: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    pub events_days: u32,
    pub audit_days: u32,
    pub snapshots_days: u32,
    pub max_log_bytes: u64,
    pub max_snapshot_files: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            events_days: 14,
            audit_days: 30,
            snapshots_days: 3,
            max_log_bytes: 10_485_760,
            max_snapshot_files: 100,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationsConfig {
    pub herdr: bool,
    pub desktop: bool,
    pub stderr: bool,
    pub notify_on_recovery: bool,
    pub notify_on_human_required: bool,
    pub notify_on_target_exit: bool,
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            herdr: true,
            desktop: true,
            stderr: true,
            notify_on_recovery: true,
            notify_on_human_required: true,
            notify_on_target_exit: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManifestsConfig {
    pub bundled: bool,
    pub local_directory: String,
    pub remote_updates: bool,
    pub strict_unknown_versions: bool,
}

impl Default for ManifestsConfig {
    fn default() -> Self {
        Self {
            bundled: true,
            local_directory: "~/.config/watchme/manifests".into(),
            remote_updates: false,
            strict_unknown_versions: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    pub enabled: bool,
    pub deterministic_recovery: bool,
    pub ai_planning: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            deterministic_recovery: false,
            ai_planning: true,
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
        let config: Self = merged.try_into()?;
        config.validate()
    }

    fn validate(self) -> Result<Self, ConfigError> {
        if self.config_version != SUPPORTED_CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion(self.config_version));
        }
        Ok(self)
    }

    /// Returns a copy suitable for `watchme config show`.
    ///
    /// Secret-like keys are replaced with `[redacted]`. The list of names in
    /// `security.extra_secret_names` is preserved (names only, never env values).
    pub fn redacted_for_display(&self) -> Config {
        let mut value =
            toml::Value::try_from(self.clone()).expect("config serializes to toml value");
        let extra_names = self.security.extra_secret_names.clone();
        redact_value(&mut value, &extra_names);
        value.try_into().expect("redacted config remains typed")
    }

    pub fn render_redacted_toml(&self) -> String {
        let redacted = self.redacted_for_display();
        let body = toml::to_string_pretty(&redacted).expect("redacted config is serializable");
        format!("# redacted configuration\n{body}")
    }
}

fn default_planners() -> BTreeMap<String, PlannerConfig> {
    let mut planners = BTreeMap::new();
    planners.insert(
        "codex".into(),
        PlannerConfig {
            enabled: true,
            executable: "codex".into(),
            provider_family: "openai".into(),
            ..PlannerConfig::default()
        },
    );
    planners.insert(
        "claude".into(),
        PlannerConfig {
            enabled: true,
            executable: "claude".into(),
            provider_family: "anthropic".into(),
            ..PlannerConfig::default()
        },
    );
    planners.insert(
        "hermes".into(),
        PlannerConfig {
            enabled: true,
            executable: "hermes".into(),
            provider_family: "unknown".into(),
            ..PlannerConfig::default()
        },
    );
    planners.insert(
        "opencode".into(),
        PlannerConfig {
            enabled: true,
            executable: "opencode".into(),
            provider_family: "unknown".into(),
            ..PlannerConfig::default()
        },
    );
    planners.insert(
        "pi".into(),
        PlannerConfig {
            enabled: false,
            executable: "pi".into(),
            provider_family: "unknown".into(),
            ..PlannerConfig::default()
        },
    );
    planners.insert(
        "kimi".into(),
        PlannerConfig {
            enabled: false,
            executable: "kimi".into(),
            provider_family: "moonshot".into(),
            ..PlannerConfig::default()
        },
    );
    planners.insert(
        "openhands".into(),
        PlannerConfig {
            enabled: false,
            executable: "openhands".into(),
            provider_family: "unknown".into(),
            ..PlannerConfig::default()
        },
    );
    planners.insert(
        "grok".into(),
        PlannerConfig {
            enabled: false,
            executable: "grok-build".into(),
            provider_family: "xai".into(),
            ..PlannerConfig::default()
        },
    );
    planners
}

fn default_agents() -> BTreeMap<String, AgentConfig> {
    let mut agents = BTreeMap::new();
    agents.insert(
        "claude".into(),
        AgentConfig {
            enabled: true,
            deterministic_recovery: true,
            ai_planning: true,
        },
    );
    agents.insert(
        "codex".into(),
        AgentConfig {
            enabled: true,
            deterministic_recovery: true,
            ai_planning: true,
        },
    );
    agents.insert(
        "opencode".into(),
        AgentConfig {
            enabled: true,
            deterministic_recovery: false,
            ai_planning: true,
        },
    );
    agents.insert(
        "pi".into(),
        AgentConfig {
            enabled: true,
            deterministic_recovery: false,
            ai_planning: true,
        },
    );
    agents.insert(
        "hermes".into(),
        AgentConfig {
            enabled: true,
            deterministic_recovery: false,
            ai_planning: true,
        },
    );
    agents.insert(
        "kimi".into(),
        AgentConfig {
            enabled: true,
            deterministic_recovery: false,
            ai_planning: false,
        },
    );
    agents.insert(
        "grok".into(),
        AgentConfig {
            enabled: true,
            deterministic_recovery: false,
            ai_planning: false,
        },
    );
    agents.insert(
        "openhands".into(),
        AgentConfig {
            enabled: true,
            deterministic_recovery: false,
            ai_planning: false,
        },
    );
    agents
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

fn redact_value(value: &mut toml::Value, extra_secret_names: &[String]) {
    match value {
        toml::Value::Table(table) => {
            for (child_key, child) in table.iter_mut() {
                if child_key == "extra_secret_names" {
                    continue;
                }
                if is_secret_like_key(child_key, extra_secret_names) {
                    match child {
                        toml::Value::String(text) => *text = REDACTED.into(),
                        toml::Value::Array(items) => {
                            for item in items {
                                if let toml::Value::String(text) = item {
                                    *text = REDACTED.into();
                                }
                            }
                        }
                        _ => {}
                    }
                } else {
                    redact_value(child, extra_secret_names);
                }
            }
        }
        toml::Value::Array(items) => {
            for item in items {
                redact_value(item, extra_secret_names);
            }
        }
        _ => {}
    }
}

fn is_secret_like_key(key: &str, extra_secret_names: &[String]) -> bool {
    let lower = key.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "token",
        "secret",
        "password",
        "credential",
        "api_key",
        "apikey",
        "authorization",
        "auth_header",
    ];
    if MARKERS.iter().any(|marker| lower.contains(marker)) {
        return true;
    }
    extra_secret_names
        .iter()
        .any(|name| name.eq_ignore_ascii_case(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_value_masks_secret_like_keys_but_keeps_secret_name_list() {
        let mut value = toml::Value::Table(toml::map::Map::from_iter([
            (
                "api_token".into(),
                toml::Value::String("sk-live-secret".into()),
            ),
            ("password".into(), toml::Value::String("hunter2".into())),
            (
                "extra_secret_names".into(),
                toml::Value::Array(vec![toml::Value::String("MY_INTERNAL_TOKEN".into())]),
            ),
            (
                "nested".into(),
                toml::Value::Table(toml::map::Map::from_iter([(
                    "MY_INTERNAL_TOKEN".into(),
                    toml::Value::String("should-hide".into()),
                )])),
            ),
        ]));
        redact_value(&mut value, &["MY_INTERNAL_TOKEN".to_owned()]);
        let table = value.as_table().unwrap();
        assert_eq!(table["api_token"].as_str(), Some(REDACTED));
        assert_eq!(table["password"].as_str(), Some(REDACTED));
        assert_eq!(
            table["extra_secret_names"].as_array().unwrap()[0].as_str(),
            Some("MY_INTERNAL_TOKEN")
        );
        assert_eq!(
            table["nested"].as_table().unwrap()["MY_INTERNAL_TOKEN"].as_str(),
            Some(REDACTED)
        );
    }
}
