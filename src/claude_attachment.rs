//! Registration-time Claude session correlation.

#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;

/// Correlate a Claude session already open by the resolved agent process. On
/// Linux this uses only process file descriptors, never a newest-file scan.
/// macOS requires the explicit supported correlation variables below.
pub fn attach_process_correlated_claude_session(watcher: &mut crate::model::WatcherState) {
    let process = match &watcher.target {
        crate::model::TargetIdentity::Process { process }
        | crate::model::TargetIdentity::Multiplexer { process, .. } => process,
    };
    let marker = marker_path();
    let supplied = std::env::var_os("CLAUDE_SESSION_ID")
        .zip(std::env::var_os("CLAUDE_TRANSCRIPT_PATH"))
        .map(|(session, transcript)| {
            (
                session.to_string_lossy().into_owned(),
                PathBuf::from(transcript),
            )
        });
    let (session_id, transcript) = match supplied {
        Some((session, transcript)) => {
            #[cfg(target_os = "linux")]
            if !linux_open_transcript_matches(process.pid, &transcript) {
                return;
            }
            (session, transcript)
        }
        None => match discover_linux_open_transcript(process.pid) {
            Some(candidate) => candidate,
            None => return,
        },
    };
    let transcript = match std::fs::canonicalize(transcript) {
        Ok(path) if path.is_file() => path,
        _ => return,
    };
    let transcript_binding = match crate::hooks::claude::bind_transcript(&transcript) {
        Ok(binding) => binding,
        Err(_) => return,
    };
    if !marker.is_absolute() {
        return;
    }
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
        let _ = watcher.set_claude_session(crate::model::ClaudeSessionReference {
            session_id,
            transcript_path: transcript.to_string_lossy().into(),
            marker_path: marker.to_string_lossy().into(),
            process_start_time: process.start_time,
            process_cwd: cwd.to_string_lossy().into(),
            target_session: target_session(&watcher.target),
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
        let _ = watcher.set_claude_session(crate::model::ClaudeSessionReference {
            session_id,
            transcript_path: transcript.to_string_lossy().into(),
            marker_path: marker.to_string_lossy().into(),
            process_start_time: process.start_time,
            process_cwd: cwd.to_string_lossy().into(),
            target_session: target_session(&watcher.target),
            transcript_binding: Some(transcript_binding),
        });
    }
}

fn marker_path() -> PathBuf {
    if let Some(path) = std::env::var_os("WATCHME_CLAUDE_MARKER_PATH") {
        return PathBuf::from(path);
    }
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")));
    state
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
        .join("watchme/claude-stop-failure.jsonl")
}

fn target_session(target: &crate::model::TargetIdentity) -> Option<String> {
    match target {
        crate::model::TargetIdentity::Process { .. } => None,
        crate::model::TargetIdentity::Multiplexer { session, .. } => session.clone(),
    }
}

#[cfg(target_os = "linux")]
fn linux_open_transcript_matches(pid: u32, transcript: &Path) -> bool {
    let Ok(expected) = std::fs::canonicalize(transcript) else {
        return false;
    };
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()
        .is_some_and(|entries| {
            entries
                .filter_map(Result::ok)
                .any(|entry| std::fs::canonicalize(entry.path()).ok().as_ref() == Some(&expected))
        })
}

#[cfg(target_os = "linux")]
fn discover_linux_open_transcript(pid: u32) -> Option<(String, PathBuf)> {
    discover_linux_open_transcript_at(
        Path::new("/proc"),
        Path::new(&std::env::var_os("HOME")?),
        pid,
    )
}

#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn discover_linux_open_transcript_at(
    proc_root: &Path,
    home: &Path,
    pid: u32,
) -> Option<(String, PathBuf)> {
    let root = std::fs::canonicalize(home.join(".claude/projects")).ok()?;
    let mut candidates = std::fs::read_dir(proc_root.join(pid.to_string()).join("fd"))
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::canonicalize(entry.path()).ok())
        .filter(|path| valid_claude_transcript(path, &root))
        .filter_map(|path| transcript_session_id(&path).map(|session| (session, path)))
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    (candidates.len() == 1).then(|| candidates.remove(0))
}

#[cfg(not(target_os = "linux"))]
fn discover_linux_open_transcript(_pid: u32) -> Option<(String, PathBuf)> {
    None
}

#[cfg(target_os = "linux")]
fn valid_claude_transcript(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
        && path
            .extension()
            .is_some_and(|extension| extension == "jsonl")
        && owner_private_regular(path)
}

#[cfg(target_os = "linux")]
fn transcript_session_id(path: &Path) -> Option<String> {
    use std::io::{BufRead as _, BufReader};
    let file = std::fs::File::open(path).ok()?;
    for line in BufReader::new(file).lines().take(64) {
        let Ok(line) = line else { continue };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let Some(session) = value
            .get("sessionId")
            .or_else(|| value.get("session_id"))
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        if session.is_empty() || session.len() > 256 || session.chars().any(char::is_control) {
            continue;
        }
        return Some(session.into());
    }
    None
}

#[cfg(target_os = "linux")]
fn owner_private_regular(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .ok()
        .is_some_and(|metadata| {
            metadata.file_type().is_file()
                && metadata.uid() == rustix::process::getuid().as_raw()
                && metadata.mode() & 0o077 == 0
        })
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
