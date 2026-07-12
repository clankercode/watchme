//! Owner-only StopFailure hook lifecycle and bounded marker ingestion.
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};

const OWNER_ONLY: u32 = 0o077;
const WATCHME_MARKER: &str = "watchme_stop_failure_v1";
const STOP_FAILURE_MATCHER: &str = "rate_limit|overloaded|server_error";

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
    let groups = object
        .entry("StopFailure")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or("StopFailure hook must be array")?;
    if groups
        .iter()
        .any(|group| group_owns_watchme(group, &command))
    {
        return Ok(false);
    }
    groups.push(serde_json::json!({
        "matcher": STOP_FAILURE_MATCHER,
        "hooks": [{"type":"command", "command": command}],
    }));
    atomic_json(settings, &root)?;
    Ok(true)
}

pub fn remove_stop_failure_hook(settings: &Path, marker: &Path) -> Result<bool, String> {
    let command = stop_failure_command(marker)?;
    let mut root = read_settings(settings)?;
    let Some(groups) = root
        .get_mut("hooks")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|hooks| hooks.get_mut("StopFailure"))
        .and_then(serde_json::Value::as_array_mut)
    else {
        return Ok(false);
    };
    let mut changed = false;
    groups.retain_mut(|group| {
        if group
            .get("watchme_marker")
            .and_then(serde_json::Value::as_str)
            == Some(WATCHME_MARKER)
        {
            changed = true;
            return false;
        }
        let Some(handlers) = group
            .get_mut("hooks")
            .and_then(serde_json::Value::as_array_mut)
        else {
            return true;
        };
        let before = handlers.len();
        handlers.retain(|handler| !handler_owns_watchme(handler, &command));
        changed |= handlers.len() != before;
        !handlers.is_empty()
    });
    if !changed {
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
    let file = fs::File::open(path).map_err(|error| error.to_string())?;
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err("Claude transcript changed while opening".into());
    }
    Ok(crate::model::TranscriptBinding {
        canonical_path: fs::canonicalize(path)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .into(),
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub fn transcript_matches_binding(
    path: &Path,
    expected: &Path,
    binding: &crate::model::TranscriptBinding,
) -> bool {
    let Ok(canonical) = fs::canonicalize(path) else {
        return false;
    };
    // macOS tempdirs often live under /var -> /private/var. Callers may pass
    // either form; compare after resolving both sides to the same physical path.
    let Ok(expected_canonical) = fs::canonicalize(expected) else {
        return false;
    };
    if canonical != expected_canonical || canonical.to_string_lossy() != binding.canonical_path {
        return false;
    }
    bind_transcript(&canonical).is_ok_and(|current| {
        current.device == binding.device
            && current.inode == binding.inode
            && current.canonical_path == binding.canonical_path
    })
}

/// Parse the documented Claude Code StopFailure payload. Unknown fields are
/// deliberately ignored for forward compatibility; only bounded, non-secret
/// fields that WatchMe persists become a local marker.
pub fn parse_stop_failure_payload(payload: &[u8]) -> Result<HookMarker, String> {
    let value: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|_| "Claude hook payload is not valid JSON".to_owned())?;
    let object = value
        .as_object()
        .ok_or_else(|| "Claude hook payload must be an object".to_owned())?;
    let session_id = required_string(object, "session_id", 256)?;
    let transcript_path = required_string(object, "transcript_path", 4096)?;
    let error_type = required_string(object, "error", 128)?;
    if object
        .get("hook_event_name")
        .and_then(serde_json::Value::as_str)
        != Some("StopFailure")
    {
        return Err("Claude hook payload is not StopFailure".into());
    }
    if let Some(cwd) = optional_string(object, "cwd", 4096)? {
        if !Path::new(cwd).is_absolute() {
            return Err("Claude hook cwd must be absolute".into());
        }
    }
    let _ = optional_string(object, "permission_mode", 128)?;
    if !Path::new(transcript_path).is_absolute()
        || contains_line_control(session_id)
        || contains_line_control(transcript_path)
        || !error_type
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("Claude hook payload contains invalid identity fields".into());
    }
    let detail = optional_string(object, "error_details", 4096)?
        .or(optional_string(object, "last_assistant_message", 4096)?)
        .unwrap_or("StopFailure");
    if contains_secret_like(detail) || contains_line_control(detail) {
        return Err("Claude hook payload detail is unsafe to persist".into());
    }
    Ok(HookMarker {
        session_id: session_id.into(),
        transcript_path: transcript_path.into(),
        error_type: error_type.into(),
        detail: detail.into(),
    })
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
    max: usize,
) -> Result<&'a str, String> {
    optional_string(object, field, max)?.ok_or_else(|| format!("Claude hook payload lacks {field}"))
}

fn optional_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
    max: usize,
) -> Result<Option<&'a str>, String> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| format!("Claude hook payload field {field} must be a string"))?;
    if text.is_empty() || text.len() > max {
        return Err(format!(
            "Claude hook payload field {field} is out of bounds"
        ));
    }
    Ok(Some(text))
}

fn contains_line_control(text: &str) -> bool {
    text.chars().any(|character| character.is_control())
}

fn contains_secret_like(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "bearer ",
        "api_key",
        "api key",
        "authorization:",
        "password",
        "secret",
        "sk-",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn group_owns_watchme(group: &serde_json::Value, command: &str) -> bool {
    group
        .get("hooks")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|handlers| {
            handlers
                .iter()
                .any(|handler| handler_owns_watchme(handler, command))
        })
}

fn handler_owns_watchme(handler: &serde_json::Value, command: &str) -> bool {
    handler.get("type").and_then(serde_json::Value::as_str) == Some("command")
        && handler.get("command").and_then(serde_json::Value::as_str) == Some(command)
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
    // Claude settings are configuration, not secrets, and Claude Code creates the
    // file 0644 by default. Require only that it is not group/world *writable*
    // (matching the parent-directory rule) rather than fully owner-only.
    checked_file(settings, "Claude settings", false)?;
    serde_json::from_slice(&fs::read(settings).map_err(|e| e.to_string())?)
        .map_err(|e| format!("invalid Claude settings JSON: {e}"))
}
fn check_parent(settings: &Path) -> Result<(), String> {
    let parent = settings.parent().ok_or("settings lacks parent")?;
    // Resolve a symlinked configuration directory (e.g. ~/.claude -> ~/.claude-p)
    // to its physical location before validating. A symlinked *leaf* settings file
    // is still refused by checked_file / the open-time recheck; only the directory
    // prefix is permitted to be a symlink, matching the state-store security model.
    let parent = crate::paths::physicalize_existing_prefix(parent).map_err(|e| e.to_string())?;
    let meta = fs::symlink_metadata(&parent).map_err(|e| e.to_string())?;
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
            let rule = if private {
                "owner-only"
            } else {
                "owned and not group/world writable"
            };
            return Err(format!("{label} must be {rule}"));
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
