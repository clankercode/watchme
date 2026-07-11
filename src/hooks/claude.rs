//! Owner-only StopFailure hook lifecycle and bounded marker ingestion.
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

const OWNER_ONLY: u32 = 0o077;
const WATCHME_MARKER: &str = "watchme_stop_failure_v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookMarker {
    pub session_id: String,
    pub transcript_path: String,
    pub error_type: String,
    pub detail: String,
}

/// Builds the only shell command WatchMe writes into Claude's hook settings.
/// The executable is a fixed token; the user-controlled path is strictly
/// POSIX single-quoted so whitespace and shell metacharacters remain data.
pub fn stop_failure_command(marker: &Path) -> Result<String, String> {
    validate_marker_path(marker)?;
    Ok(format!(
        "watchme watchme-hook-stop-failure --marker {}",
        posix_single_quote(&marker.to_string_lossy())
    ))
}

pub fn install_stop_failure_hook(settings: &Path, marker: &Path) -> Result<bool, String> {
    check_parent(settings)?;
    let command = stop_failure_command(marker)?;
    let mut root = read_settings(settings)?;
    let hooks = root
        .as_object_mut()
        .ok_or("Claude settings root must be object")?
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}));
    let object = hooks.as_object_mut().ok_or("Claude hooks must be object")?;
    let entries = object
        .entry("StopFailure")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or("StopFailure hook must be array")?;
    if entries.iter().any(|item| {
        item.get("watchme_marker")
            .and_then(serde_json::Value::as_str)
            == Some(WATCHME_MARKER)
    }) {
        return Ok(false);
    }
    entries.push(serde_json::json!({"watchme_marker":WATCHME_MARKER,"command":command}));
    atomic_json(settings, &root)?;
    Ok(true)
}

pub fn remove_stop_failure_hook(settings: &Path, _marker: &Path) -> Result<bool, String> {
    let mut root = read_settings(settings)?;
    let Some(entries) = root
        .get_mut("hooks")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|hooks| hooks.get_mut("StopFailure"))
        .and_then(serde_json::Value::as_array_mut)
    else {
        return Ok(false);
    };
    let old = entries.len();
    entries.retain(|item| {
        item.get("watchme_marker")
            .and_then(serde_json::Value::as_str)
            != Some(WATCHME_MARKER)
    });
    if entries.len() == old {
        return Ok(false);
    }
    atomic_json(settings, &root)?;
    Ok(true)
}

/// Marker files are accepted only if regular and owner-only. The caller binds
/// returned markers to the current process-correlated session/transcript; this
/// function deliberately does not search for any "newest" transcript.
pub fn read_markers(path: &Path) -> Result<Vec<HookMarker>, String> {
    let meta = checked_file(path, "hook marker", true)?;
    if meta.len() > 1_048_576 {
        return Err("hook marker exceeds size limit".into());
    }
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata().map_err(|e| e.to_string())?;
        if opened.dev() != meta.dev() || opened.ino() != meta.ino() {
            return Err("hook marker changed while opening".into());
        }
    }
    // Keep only the newest bounded records. A long-lived marker file must not
    // starve a current StopFailure behind an old 256-line prefix.
    let mut lines = std::collections::VecDeque::with_capacity(256);
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.len() > 8192 {
            continue;
        }
        if let Ok(marker) = serde_json::from_str::<HookMarker>(&line) {
            if valid_marker(&marker) {
                if lines.len() == 256 {
                    lines.pop_front();
                }
                lines.push_back(marker);
            }
        }
    }
    Ok(lines.into_iter().collect())
}

/// Revalidates the transcript immediately before accepting a marker. It is
/// intentionally a strict canonical-path and owner-only check; replacing the
/// path, following a link, or relaxing its permissions invalidates the
/// reference rather than letting a hook event steer recovery.
pub fn transcript_matches_reference(path: &Path, expected: &Path) -> bool {
    std::fs::canonicalize(path)
        .ok()
        .as_deref()
        .filter(|actual| *actual == expected)
        .is_some_and(|actual| checked_file(actual, "Claude transcript", true).is_ok())
}

pub fn bind_transcript(path: &Path) -> Result<crate::model::TranscriptBinding, String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = checked_file(path, "Claude transcript", true)?;
    let mut file = fs::File::open(path).map_err(|error| error.to_string())?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err("Claude transcript changed while opening".into());
    }
    let mut prefix = vec![0_u8; usize::try_from(metadata.len().min(4096)).unwrap_or(4096)];
    use std::io::Read as _;
    file.read_exact(&mut prefix)
        .map_err(|error| error.to_string())?;
    Ok(crate::model::TranscriptBinding {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        changed_at_ns: i128::from(metadata.ctime()) * 1_000_000_000
            + i128::from(metadata.ctime_nsec()),
        head_digest: sha256_hex(&prefix),
    })
}

pub fn transcript_matches_binding(
    path: &Path,
    expected: &Path,
    binding: &crate::model::TranscriptBinding,
) -> bool {
    if !transcript_matches_reference(path, expected) {
        return false;
    }
    bind_transcript(path).is_ok_and(|current| current == *binding)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// Append one bounded, strict marker without shell interpolation. O_APPEND
/// makes each small JSONL record a single append operation; readers ignore an
/// interrupted final line rather than guessing about a partial event.
pub fn write_marker(path: &Path, marker: &HookMarker) -> Result<(), String> {
    if !valid_marker(marker) {
        return Err("invalid hook marker".into());
    }
    check_parent(path)?;
    if path.exists() {
        checked_file(path, "hook marker", true)?;
    }
    let encoded = serde_json::to_vec(marker).map_err(|error| error.to_string())?;
    if encoded.len() > 8192 {
        return Err("hook marker exceeds size limit".into());
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    // Recheck after open so a pre-existing symlink is never silently followed.
    checked_file(path, "hook marker", true)?;
    file.write_all(&encoded)
        .map_err(|error| error.to_string())?;
    file.write_all(b"\n").map_err(|error| error.to_string())?;
    file.sync_data().map_err(|error| error.to_string())
}
pub fn correlate_marker<'a>(
    markers: &'a [HookMarker],
    session_id: &str,
    transcript: &Path,
) -> Option<&'a HookMarker> {
    markers.iter().rev().find(|marker| {
        marker.session_id == session_id && Path::new(&marker.transcript_path) == transcript
    })
}

fn validate_marker_path(marker: &Path) -> Result<(), String> {
    if !marker.is_absolute()
        || marker.as_os_str().is_empty()
        || marker
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .any(|byte| matches!(byte, b'\0' | b'\n' | b'\r'))
    {
        return Err("hook marker path must be an absolute single-line path".into());
    }
    Ok(())
}

fn posix_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn valid_marker(marker: &HookMarker) -> bool {
    !marker.session_id.is_empty()
        && marker.session_id.len() <= 256
        && Path::new(&marker.transcript_path).is_absolute()
        && marker.transcript_path.len() <= 4096
        && marker.error_type.len() <= 128
        && marker.detail.len() <= 4096
}
fn read_settings(settings: &Path) -> Result<serde_json::Value, String> {
    if !settings.exists() {
        return Ok(serde_json::json!({}));
    }
    checked_file(settings, "Claude settings", true)?;
    serde_json::from_slice(&fs::read(settings).map_err(|e| e.to_string())?)
        .map_err(|e| format!("invalid Claude settings JSON: {e}"))
}
fn check_parent(settings: &Path) -> Result<(), String> {
    let parent = settings.parent().ok_or("settings lacks parent")?;
    let meta = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !meta.file_type().is_dir() {
        return Err("configuration parent is not a directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o022 != 0 || meta.uid() != rustix::process::getuid().as_raw() {
            return Err(
                "Claude configuration directory must be owned and not group/world writable".into(),
            );
        }
    }
    Ok(())
}
fn checked_file(path: &Path, label: &str, private: bool) -> Result<fs::Metadata, String> {
    let meta = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !meta.file_type().is_file() {
        return Err(format!("{label} is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let bad_mode = if private {
            meta.mode() & OWNER_ONLY != 0
        } else {
            meta.mode() & 0o022 != 0
        };
        if bad_mode || meta.uid() != rustix::process::getuid().as_raw() {
            return Err(format!("{label} must be owner-only"));
        }
    }
    Ok(meta)
}
fn atomic_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let parent = path.parent().ok_or("settings lacks parent")?;
    check_parent(path)?;
    let body = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    let temp = (0_u32..64)
        .map(|attempt| {
            parent.join(format!(
                ".watchme-settings-{}-{attempt}.tmp",
                std::process::id()
            ))
        })
        .find(|candidate| !candidate.exists())
        .ok_or("unable to allocate private settings temporary file")?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp).map_err(|error| error.to_string())?;
    file.write_all(&body).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    fs::rename(temp, path).map_err(|e| e.to_string())
}
