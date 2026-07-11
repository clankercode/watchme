//! Registration-time Claude session correlation.

use std::path::PathBuf;

/// Accept only explicit Claude session variables that correlate to the agent
/// identity already resolved for the current shell escape. There is no
/// newest-file fallback: absence or failed proof just disables hook recovery.
pub(crate) fn attach_process_correlated_claude_session(watcher: &mut watchme::model::WatcherState) {
    let (Some(session_id), Some(transcript), Some(marker)) = (
        std::env::var_os("CLAUDE_SESSION_ID"),
        std::env::var_os("CLAUDE_TRANSCRIPT_PATH"),
        std::env::var_os("WATCHME_CLAUDE_MARKER_PATH"),
    ) else {
        return;
    };
    let transcript = match std::fs::canonicalize(transcript) {
        Ok(path) if path.is_file() => path,
        _ => return,
    };
    let transcript_binding = match watchme::hooks::claude::bind_transcript(&transcript) {
        Ok(binding) => binding,
        Err(_) => return,
    };
    let marker = PathBuf::from(marker);
    if !marker.is_absolute() {
        return;
    }
    let process = match &watcher.target {
        watchme::model::TargetIdentity::Process { process }
        | watchme::model::TargetIdentity::Multiplexer { process, .. } => process,
    };
    #[cfg(target_os = "linux")]
    {
        let fd_dir = format!("/proc/{}/fd", process.pid);
        let opened = std::fs::read_dir(fd_dir).ok().is_some_and(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|entry| std::fs::read_link(entry.path()).ok().as_ref() == Some(&transcript))
        });
        let cwd = std::fs::read_link(format!("/proc/{}/cwd", process.pid)).ok();
        let (true, Some(cwd)) = (opened, cwd) else {
            return;
        };
        let _ = watcher.set_claude_session(watchme::model::ClaudeSessionReference {
            session_id: session_id.to_string_lossy().into(),
            transcript_path: transcript.to_string_lossy().into(),
            marker_path: marker.to_string_lossy().into(),
            process_start_time: process.start_time,
            process_cwd: cwd.to_string_lossy().into(),
            transcript_binding: Some(transcript_binding),
        });
    }
    #[cfg(target_os = "macos")]
    {
        let supplied_pid = std::env::var("WATCHME_CLAUDE_PROCESS_PID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok());
        let supplied_start = std::env::var("WATCHME_CLAUDE_PROCESS_START_TIME")
            .ok()
            .and_then(|value| value.parse::<u64>().ok());
        let cwd = std::env::var_os("WATCHME_CLAUDE_PROCESS_CWD")
            .and_then(|value| std::fs::canonicalize(value).ok());
        let (Some(supplied_pid), Some(supplied_start), Some(cwd)) =
            (supplied_pid, supplied_start, cwd)
        else {
            return;
        };
        if supplied_pid != process.pid
            || supplied_start != process.start_time
            || !cwd.is_dir()
            || !transcript.starts_with(&cwd)
            || !owner_private_regular(&transcript)
        {
            return;
        }
        let _ = watcher.set_claude_session(watchme::model::ClaudeSessionReference {
            session_id: session_id.to_string_lossy().into(),
            transcript_path: transcript.to_string_lossy().into(),
            marker_path: marker.to_string_lossy().into(),
            process_start_time: process.start_time,
            process_cwd: cwd.to_string_lossy().into(),
            transcript_binding: Some(transcript_binding),
        });
    }
}

#[cfg(target_os = "macos")]
fn owner_private_regular(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .ok()
        .is_some_and(|metadata| {
            metadata.file_type().is_file()
                && metadata.uid() == rustix::process::getuid().as_raw()
                && metadata.mode() & 0o077 == 0
        })
}
