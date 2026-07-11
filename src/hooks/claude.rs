//! Owner-only StopFailure hook lifecycle and bounded marker ingestion.
use std::fs;
use std::io::{BufRead, BufReader};
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

pub fn install_stop_failure_hook(settings: &Path, marker: &Path) -> Result<bool, String> {
    check_parent(settings)?;
    let mut root = read_settings(settings)?;
    let command = format!("watchme-hook-stop-failure --marker {}", marker.display());
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
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() {
        return Err("hook marker is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & OWNER_ONLY != 0 || meta.uid() != rustix::process::getuid().as_raw() {
            return Err("hook marker must be owner-only".into());
        }
    }
    if meta.len() > 1_048_576 {
        return Err("hook marker exceeds size limit".into());
    }
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut markers = Vec::new();
    for line in BufReader::new(file).lines().take(256) {
        let line = line.map_err(|e| e.to_string())?;
        if line.len() > 8192 {
            continue;
        }
        if let Ok(marker) = serde_json::from_str::<HookMarker>(&line) {
            if valid_marker(&marker) {
                markers.push(marker);
            }
        }
    }
    Ok(markers)
}
pub fn correlate_marker<'a>(
    markers: &'a [HookMarker],
    session_id: &str,
    transcript: &Path,
) -> Option<&'a HookMarker> {
    markers.iter().find(|marker| {
        marker.session_id == session_id && Path::new(&marker.transcript_path) == transcript
    })
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
    let meta = fs::symlink_metadata(settings).map_err(|e| e.to_string())?;
    if !meta.file_type().is_file() {
        return Err("Claude settings must be a regular file".into());
    }
    serde_json::from_slice(&fs::read(settings).map_err(|e| e.to_string())?)
        .map_err(|e| format!("invalid Claude settings JSON: {e}"))
}
fn check_parent(settings: &Path) -> Result<(), String> {
    let parent = settings.parent().ok_or("settings lacks parent")?;
    let meta = fs::metadata(parent).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & OWNER_ONLY != 0 || meta.uid() != rustix::process::getuid().as_raw() {
            return Err("Claude configuration directory must be owner-only".into());
        }
    }
    Ok(())
}
fn atomic_json(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let parent = path.parent().ok_or("settings lacks parent")?;
    let temp = parent.join(format!(".watchme-settings-{}.tmp", std::process::id()));
    fs::write(
        &temp,
        serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    }
    fs::rename(temp, path).map_err(|e| e.to_string())
}
