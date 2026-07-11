//! Actionable local diagnostics for WatchMe installation health.

use std::path::Path;
use std::process::Command;

use serde::Serialize;

use crate::agents::manifest::{
    ManifestRegistry, ProviderReadiness, SupportTier, load_manifests, provider_listing,
};
use crate::config::Config;
use crate::hooks::claude as claude_hooks;
use crate::paths::WatchmePaths;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DoctorOptions {
    pub strict: bool,
    pub json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DoctorReport {
    pub schema_version: String,
    pub ok: bool,
    pub checks: Vec<DoctorCheck>,
}

pub fn run_doctor(paths: &WatchmePaths, config: &Config, options: DoctorOptions) -> DoctorReport {
    let checks = vec![
        check_paths(paths),
        check_permissions(paths),
        check_config(paths, config),
        check_binary("tmux"),
        check_herdr(),
        check_hooks(paths),
        check_providers(paths, config),
    ];

    let has_fail = checks.iter().any(|check| check.status == CheckStatus::Fail);
    let has_warn = checks.iter().any(|check| check.status == CheckStatus::Warn);
    let ok = if options.strict {
        !has_fail && !has_warn
    } else {
        !has_fail
    };

    DoctorReport {
        schema_version: "1.0".into(),
        ok,
        checks,
    }
}

fn check_paths(paths: &WatchmePaths) -> DoctorCheck {
    let required = [paths.config_dir(), paths.state_dir(), paths.runtime_dir()];
    for path in required {
        if !path.exists() {
            return DoctorCheck {
                name: "paths".into(),
                status: CheckStatus::Warn,
                message: format!("{} does not exist yet", path.display()),
            };
        }
    }
    DoctorCheck {
        name: "paths".into(),
        status: CheckStatus::Ok,
        message: "config, state, and runtime paths resolve".into(),
    }
}

fn check_permissions(paths: &WatchmePaths) -> DoctorCheck {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [paths.config_dir(), paths.state_dir(), paths.runtime_dir()] {
            if !path.exists() {
                continue;
            }
            match std::fs::metadata(path) {
                Ok(meta) if meta.permissions().mode() & 0o077 != 0 => {
                    return DoctorCheck {
                        name: "permissions".into(),
                        status: CheckStatus::Fail,
                        message: format!("{} is not owner-only", path.display()),
                    };
                }
                Ok(_) => {}
                Err(error) => {
                    return DoctorCheck {
                        name: "permissions".into(),
                        status: CheckStatus::Fail,
                        message: format!("cannot stat {}: {error}", path.display()),
                    };
                }
            }
        }
    }
    DoctorCheck {
        name: "permissions".into(),
        status: CheckStatus::Ok,
        message: "managed directories are owner-only".into(),
    }
}

fn check_config(paths: &WatchmePaths, _config: &Config) -> DoctorCheck {
    let config_path = paths.config_dir().join("config.toml");
    if !config_path.exists() {
        return DoctorCheck {
            name: "config".into(),
            status: CheckStatus::Ok,
            message: "using built-in defaults (no config.toml)".into(),
        };
    }
    match Config::load_layers([config_path.as_path()]) {
        Ok(_) => DoctorCheck {
            name: "config".into(),
            status: CheckStatus::Ok,
            message: "configuration is valid".into(),
        },
        Err(error) => DoctorCheck {
            name: "config".into(),
            status: CheckStatus::Fail,
            message: format!("configuration invalid: {error}"),
        },
    }
}

fn check_binary(name: &str) -> DoctorCheck {
    if which(name) {
        DoctorCheck {
            name: name.into(),
            status: CheckStatus::Ok,
            message: format!("{name} is available"),
        }
    } else {
        DoctorCheck {
            name: name.into(),
            status: CheckStatus::Warn,
            message: format!("{name} not found on PATH"),
        }
    }
}

fn check_herdr() -> DoctorCheck {
    let socket = std::env::var_os("HERDR_SOCKET_PATH");
    if socket.is_some()
        || std::env::var_os("HERDR_WORKSPACE_ID").is_some()
            && std::env::var_os("HERDR_TAB_ID").is_some()
            && std::env::var_os("HERDR_PANE_ID").is_some()
    {
        DoctorCheck {
            name: "herdr".into(),
            status: CheckStatus::Ok,
            message: "Herdr environment is present".into(),
        }
    } else if which("herdr") {
        DoctorCheck {
            name: "herdr".into(),
            status: CheckStatus::Warn,
            message: "herdr binary found but session environment is not set".into(),
        }
    } else {
        DoctorCheck {
            name: "herdr".into(),
            status: CheckStatus::Warn,
            message: "Herdr unavailable (optional)".into(),
        }
    }
}

fn check_hooks(paths: &WatchmePaths) -> DoctorCheck {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let Some(home) = home else {
        return DoctorCheck {
            name: "hooks".into(),
            status: CheckStatus::Warn,
            message: "HOME unset; cannot inspect Claude hooks".into(),
        };
    };
    let settings = home.join(".claude/settings.json");
    let marker = paths
        .state_file("claude-stop-failure.jsonl")
        .unwrap_or_else(|_| paths.state_dir().join("claude-stop-failure.jsonl"));
    match claude_hooks::stop_failure_command(&marker) {
        Ok(command) => {
            if settings.exists() && settings_contain_watchme(&settings, &command) {
                DoctorCheck {
                    name: "hooks".into(),
                    status: CheckStatus::Ok,
                    message: "Claude StopFailure hook installed".into(),
                }
            } else {
                DoctorCheck {
                    name: "hooks".into(),
                    status: CheckStatus::Warn,
                    message: "Claude StopFailure hook not installed".into(),
                }
            }
        }
        Err(error) => DoctorCheck {
            name: "hooks".into(),
            status: CheckStatus::Warn,
            message: format!("cannot evaluate Claude hook: {error}"),
        },
    }
}

fn settings_contain_watchme(settings: &Path, command: &str) -> bool {
    let Ok(raw) = std::fs::read_to_string(settings) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return false;
    };
    value
        .pointer("/hooks/StopFailure")
        .and_then(|groups| groups.as_array())
        .is_some_and(|groups| {
            groups.iter().any(|group| {
                group
                    .get("hooks")
                    .and_then(|hooks| hooks.as_array())
                    .is_some_and(|hooks| {
                        hooks.iter().any(|hook| {
                            hook.get("command")
                                .and_then(|c| c.as_str())
                                .is_some_and(|c| c.contains("watchme-hook-stop-failure"))
                                || hook.get("command").and_then(|c| c.as_str()) == Some(command)
                        })
                    })
            })
        })
}

fn check_providers(paths: &WatchmePaths, config: &Config) -> DoctorCheck {
    let _ = paths;
    let local = expand_home(&config.manifests.local_directory);
    let local_ref = local.exists().then_some(local.as_path());
    match load_manifests(local_ref, config.manifests.bundled) {
        Ok(report) => {
            let listing = provider_listing(&report.registry, which);
            let ready = listing
                .iter()
                .filter(|row| {
                    matches!(
                        row.readiness,
                        ProviderReadiness::Tested
                            | ProviderReadiness::Probed
                            | ProviderReadiness::ObservationOnly
                    )
                })
                .count();
            DoctorCheck {
                name: "providers".into(),
                status: CheckStatus::Ok,
                message: format!(
                    "{} provider manifests loaded; {ready} ready or observation-capable",
                    listing.len()
                ),
            }
        }
        Err(error) => DoctorCheck {
            name: "providers".into(),
            status: CheckStatus::Fail,
            message: format!("provider manifests failed: {error}"),
        },
    }
}

fn expand_home(value: &str) -> std::path::PathBuf {
    if let Some(rest) = value.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return std::path::PathBuf::from(home).join(rest);
        }
    }
    std::path::PathBuf::from(value)
}

fn which(binary: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {binary} >/dev/null 2>&1")])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// First-class Claude/Codex rows plus manifest listing for `watchme providers`.
#[derive(Clone, Debug, Serialize)]
pub struct ProviderRow {
    pub id: String,
    pub support_tier: String,
    pub readiness: String,
    pub first_class: bool,
    pub executable_present: bool,
    pub local_override: bool,
    pub manifest_version: String,
}

pub fn list_providers(config: &Config) -> Result<Vec<ProviderRow>, String> {
    let mut rows = vec![
        ProviderRow {
            id: "claude".into(),
            support_tier: "structured".into(),
            readiness: if which("claude") {
                "tested".into()
            } else {
                "absent".into()
            },
            first_class: true,
            executable_present: which("claude"),
            local_override: false,
            manifest_version: "builtin".into(),
        },
        ProviderRow {
            id: "codex".into(),
            support_tier: "structured".into(),
            readiness: if which("codex") {
                "tested".into()
            } else {
                "absent".into()
            },
            first_class: true,
            executable_present: which("codex"),
            local_override: false,
            manifest_version: "builtin".into(),
        },
    ];

    let local = expand_home(&config.manifests.local_directory);
    let local_ref = local.exists().then_some(local.as_path());
    let report = load_manifests(local_ref, config.manifests.bundled).map_err(|e| e.to_string())?;
    for status in provider_listing(&report.registry, which) {
        if status.id == "claude" || status.id == "codex" {
            continue;
        }
        rows.push(ProviderRow {
            id: status.id,
            support_tier: support_tier_name(status.support_tier).into(),
            readiness: readiness_name(status.readiness).into(),
            first_class: false,
            executable_present: status.executable_present,
            local_override: status.local_override,
            manifest_version: status.manifest_version,
        });
    }
    Ok(rows)
}

fn support_tier_name(tier: SupportTier) -> &'static str {
    match tier {
        SupportTier::Structured => "structured",
        SupportTier::DeterministicTerminal => "deterministic_terminal",
        SupportTier::PlannerAssisted => "planner_assisted",
        SupportTier::ObservationOnly => "observation_only",
        SupportTier::Disabled => "disabled",
    }
}

fn readiness_name(readiness: ProviderReadiness) -> &'static str {
    match readiness {
        ProviderReadiness::Tested => "tested",
        ProviderReadiness::Probed => "probed",
        ProviderReadiness::ObservationOnly => "observation_only",
        ProviderReadiness::Absent => "absent",
        ProviderReadiness::Disabled => "disabled",
    }
}

#[allow(dead_code)]
pub fn bundled_registry() -> Result<ManifestRegistry, String> {
    ManifestRegistry::bundled().map_err(|error| error.to_string())
}
