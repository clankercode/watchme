use std::time::Duration;

use watchme::client::ResolvedRegistration;
use watchme::mux::herdr::{Herdr, HerdrContext};
use watchme::mux::tmux::Tmux;
use watchme::mux::{Multiplexer, MuxError};
use watchme::process::{CandidateHints, ProcessInspector, ProcessResolver, ResolvedProcess};

use crate::error::WatchmeError;

pub fn detect_current() -> Result<ResolvedRegistration, WatchmeError> {
    #[cfg(target_os = "linux")]
    let inspector = watchme::process::linux::LinuxProcessInspector::default();
    #[cfg(target_os = "macos")]
    let inspector = watchme::process::macos::MacOsProcessInspector::default();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(unsupported_context());

    let current_pid = std::process::id();
    let current = inspector
        .inspect(current_pid)
        .map_err(|_| unsupported_context())?;
    let has_controlling_tty = current.tty.is_some();
    let hints = CandidateHints {
        tty: current.tty,
        // TTY-less agent tool calls commonly run in an isolated process group
        // and session. Those child-local IDs cannot contradict the ancestor;
        // ancestry plus the same UID remain required correlated evidence.
        process_group_id: has_controlling_tty
            .then_some(current.process_group_id)
            .flatten(),
        session_leader_id: has_controlling_tty
            .then_some(current.session_leader_id)
            .flatten(),
        uid: current.uid,
        executable_hint: None,
    };
    let names = watchme::agents::manifest::ManifestRegistry::bundled()
        .map(|registry| registry.process_match_basenames())
        .unwrap_or_default();
    let resolved = ProcessResolver::with_manifest_names(names)
        .resolve(&inspector, current_pid, &hints)
        .map_err(|error| WatchmeError::UnsupportedContext(error.to_string()))?;

    if has_herdr_environment() {
        return match herdr_registration(resolved.clone()) {
            Ok(registration) => Ok(registration),
            Err(MuxError::IncompatibleProtocol(_)) => Ok(process_registration(resolved)),
            Err(error) => Err(WatchmeError::UnsupportedContext(error.to_string())),
        };
    }
    if std::env::var_os("TMUX").is_some() || std::env::var_os("TMUX_PANE").is_some() {
        return tmux_registration(resolved);
    }
    Ok(process_registration(resolved))
}

fn process_registration(resolved: ResolvedProcess) -> ResolvedRegistration {
    let watcher_id = format!(
        "process-{}-{}",
        resolved.identity.pid, resolved.identity.start_time
    );
    let mut watcher = watchme::model::WatcherState::new(
        watcher_id,
        watchme::model::TargetIdentity::process(resolved.identity),
        watchme::model::WatcherLifecycle::Registered,
        0,
        unix_time_ms(),
    );
    watchme::claude_attachment::attach_process_correlated_claude_session(&mut watcher);
    ResolvedRegistration { watcher }
}

fn has_herdr_environment() -> bool {
    [
        "HERDR_SOCKET_PATH",
        "HERDR_WORKSPACE_ID",
        "HERDR_TAB_ID",
        "HERDR_PANE_ID",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
}

fn herdr_registration(resolved: ResolvedProcess) -> Result<ResolvedRegistration, MuxError> {
    let herdr = Herdr::new(HerdrContext::from_environment()?, Duration::from_secs(2))?;
    let pane = herdr.current_target()?;
    if pane.process != resolved.identity
        || normalize_tty(pane.tty.as_str())
            != normalize_tty(resolved.identity.tty.as_deref().unwrap_or_default())
    {
        return Err(MuxError::IdentityChanged(
            "agent ancestor and Herdr pane process/TTY identities do not match".into(),
        ));
    }
    let watcher_id = format!(
        "herdr-{}-{}-{}",
        pane.pane_id, resolved.identity.pid, resolved.identity.start_time
    );
    let mut watcher = watchme::model::WatcherState::new(
        watcher_id,
        watchme::model::TargetIdentity::herdr(
            pane.server,
            pane.server_instance,
            pane.session_id,
            pane.window_id,
            pane.pane_id,
            pane.tty,
            resolved.identity,
        ),
        watchme::model::WatcherLifecycle::Registered,
        0,
        unix_time_ms(),
    );
    watchme::claude_attachment::attach_process_correlated_claude_session(&mut watcher);
    Ok(ResolvedRegistration { watcher })
}

fn tmux_registration(
    resolved: watchme::process::ResolvedProcess,
) -> Result<ResolvedRegistration, WatchmeError> {
    let tmux = Tmux::from_environment(Duration::from_secs(2))
        .map_err(|error| WatchmeError::UnsupportedContext(error.to_string()))?;
    let pane = tmux
        .current_target()
        .map_err(|error| WatchmeError::UnsupportedContext(error.to_string()))?;
    let resolved_tty = resolved.identity.tty.as_deref().unwrap_or_default();
    if normalize_tty(resolved_tty) != normalize_tty(pane.process.tty.as_deref().unwrap_or_default())
    {
        return Err(WatchmeError::UnsupportedContext(
            "agent process and tmux pane TTY identities do not match".into(),
        ));
    }
    let watcher_id = format!(
        "tmux-{}-{}-{}",
        pane.pane_id.trim_start_matches('%'),
        resolved.identity.pid,
        resolved.identity.start_time
    );
    let mut watcher = watchme::model::WatcherState::new(
        watcher_id,
        watchme::model::TargetIdentity::tmux(
            pane.server,
            pane.server_instance,
            pane.session_id,
            pane.window_id,
            pane.pane_id,
            pane.tty,
            resolved.identity,
            None,
        ),
        watchme::model::WatcherLifecycle::Registered,
        0,
        unix_time_ms(),
    );
    watchme::claude_attachment::attach_process_correlated_claude_session(&mut watcher);
    Ok(ResolvedRegistration { watcher })
}

fn unsupported_context() -> WatchmeError {
    WatchmeError::UnsupportedContext(
        "invoke WatchMe normally as !watchme from a supported coding-agent session; run `watchme doctor` for diagnostics"
            .to_owned(),
    )
}

fn normalize_tty(tty: &str) -> &str {
    tty.strip_prefix("/dev/").unwrap_or(tty)
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_context_message_explains_shell_escape_and_doctor() {
        let message = unsupported_context().to_string();
        assert!(message.contains("!watchme"));
        assert!(message.contains("watchme doctor"));
    }
}
