use std::collections::BTreeMap;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

use crate::model::{
    CodexBoundFile, CodexSessionReference, CodexStructuredStateReference, MultiplexerContext,
    TargetIdentity, WatcherState,
};

const MAX_CMDLINE_BYTES: u64 = 64 * 1024;

pub fn attach_process_correlated_codex_session(
    watcher: &mut WatcherState,
    herdr_session: Option<&str>,
) {
    #[cfg(target_os = "linux")]
    attach_process_correlated_codex_session_at(watcher, Path::new("/proc"), herdr_session);
    #[cfg(target_os = "macos")]
    {
        let values = EXPLICIT_VALUE_NAMES
            .iter()
            .filter_map(|name| {
                std::env::var(name)
                    .ok()
                    .map(|value| ((*name).into(), value))
            })
            .collect::<BTreeMap<_, _>>();
        if herdr_session.is_none_or(|session| {
            values
                .get("WATCHME_CODEX_THREAD_ID")
                .is_some_and(|thread| thread == session)
        }) {
            attach_explicit_codex_session_from_values(watcher, &values);
        }
    }
}

const EXPLICIT_VALUE_NAMES: [&str; 7] = [
    "WATCHME_CODEX_THREAD_ID",
    "WATCHME_CODEX_PROCESS_PID",
    "WATCHME_CODEX_PROCESS_START_TIME",
    "WATCHME_CODEX_PROCESS_CWD",
    "WATCHME_CODEX_ROLLOUT_PATH",
    "WATCHME_CODEX_THREAD_DB_PATH",
    "WATCHME_CODEX_GOALS_DB_PATH",
];

pub fn attach_explicit_codex_session_from_values(
    watcher: &mut WatcherState,
    values: &BTreeMap<String, String>,
) {
    if !EXPLICIT_VALUE_NAMES
        .iter()
        .all(|name| values.get(*name).is_some_and(|value| !value.is_empty()))
    {
        return;
    }
    let process = match &watcher.target {
        TargetIdentity::Process { process } | TargetIdentity::Multiplexer { process, .. } => {
            process
        }
    };
    let Some(pid) = values["WATCHME_CODEX_PROCESS_PID"].parse::<u32>().ok() else {
        return;
    };
    let Some(start_time) = values["WATCHME_CODEX_PROCESS_START_TIME"]
        .parse::<u64>()
        .ok()
    else {
        return;
    };
    if pid != process.pid || start_time != process.start_time {
        return;
    }
    let thread_id = &values["WATCHME_CODEX_THREAD_ID"];
    if !valid_thread_id(thread_id) {
        return;
    }
    let Some(process_cwd) = canonical_directory(&values["WATCHME_CODEX_PROCESS_CWD"]) else {
        return;
    };
    let Some(rollout) = bind_safe_file(Path::new(&values["WATCHME_CODEX_ROLLOUT_PATH"])) else {
        return;
    };
    let Some(thread_db) = bind_safe_file(Path::new(&values["WATCHME_CODEX_THREAD_DB_PATH"])) else {
        return;
    };
    let Some(goals_db) = bind_safe_file(Path::new(&values["WATCHME_CODEX_GOALS_DB_PATH"])) else {
        return;
    };
    let rollout_path = Path::new(&rollout.canonical_path);
    let rollout_name = rollout_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !rollout_matches_thread(rollout_path, rollout_name, thread_id)
        || !thread_db_matches(Path::new(&thread_db.canonical_path), thread_id)
        || !goals_db_matches(Path::new(&goals_db.canonical_path))
    {
        return;
    }
    let structured_state = CodexStructuredStateReference {
        rollout,
        thread_db,
        goals_db,
    };
    let reference = CodexSessionReference {
        thread_id: thread_id.clone(),
        rollout_path: structured_state.rollout.canonical_path.clone(),
        process_start_time: process.start_time,
        process_cwd: process_cwd.to_string_lossy().into_owned(),
        target_session: target_session(&watcher.target),
        rollout_binding: None,
        app_server_state_path: None,
        structured_state: Some(structured_state),
    };
    let _ = watcher.set_codex_session(reference);
}

fn canonical_directory(value: &str) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(value).ok()?;
    std::fs::metadata(&canonical)
        .ok()?
        .is_dir()
        .then_some(canonical)
}

#[cfg(target_os = "linux")]
pub fn attach_process_correlated_codex_session_at(
    watcher: &mut WatcherState,
    proc_root: &Path,
    herdr_session: Option<&str>,
) {
    let process = match &watcher.target {
        TargetIdentity::Process { process } | TargetIdentity::Multiplexer { process, .. } => {
            process.clone()
        }
    };
    let Some(thread_id) = resume_thread_id(proc_root, process.pid) else {
        return;
    };
    if herdr_session.is_some_and(|session| session != thread_id) {
        return;
    }
    let Some(structured_state) = discover_exact_open_state(proc_root, process.pid, &thread_id)
    else {
        return;
    };
    let Some(process_cwd) = process_cwd(proc_root, process.pid) else {
        return;
    };
    let reference = CodexSessionReference {
        thread_id,
        rollout_path: structured_state.rollout.canonical_path.clone(),
        process_start_time: process.start_time,
        process_cwd: process_cwd.to_string_lossy().into_owned(),
        target_session: target_session(&watcher.target),
        rollout_binding: None,
        app_server_state_path: None,
        structured_state: Some(structured_state),
    };
    let _ = watcher.set_codex_session(reference);
}

#[cfg(target_os = "linux")]
fn resume_thread_id(proc_root: &Path, pid: u32) -> Option<String> {
    let path = proc_root.join(pid.to_string()).join("cmdline");
    let metadata = std::fs::metadata(&path).ok()?;
    if metadata.len() == 0 || metadata.len() > MAX_CMDLINE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if !bytes.ends_with(&[0]) {
        return None;
    }
    let arguments = bytes[..bytes.len() - 1]
        .split(|byte| *byte == 0)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let mut matches = arguments
        .windows(2)
        .filter(|pair| pair[0] == "resume")
        .map(|pair| pair[1])
        .filter(|thread| valid_thread_id(thread));
    let thread = matches.next()?.to_owned();
    matches.next().is_none().then_some(thread)
}

fn valid_thread_id(thread: &str) -> bool {
    !thread.is_empty()
        && thread.len() <= 256
        && thread
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}

#[cfg(target_os = "linux")]
fn discover_exact_open_state(
    proc_root: &Path,
    pid: u32,
    thread_id: &str,
) -> Option<CodexStructuredStateReference> {
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let mut rollouts = Vec::new();
    let mut thread_dbs = Vec::new();
    let mut goals_dbs = Vec::new();
    for entry in std::fs::read_dir(fd_dir).ok()?.take(4096) {
        let path = std::fs::canonicalize(entry.ok()?.path()).ok()?;
        let Some(bound) = bind_safe_file(&path) else {
            continue;
        };
        let name = path.file_name()?.to_str()?;
        if name.contains("rollout") && rollout_matches_thread(&path, name, thread_id) {
            push_unique(&mut rollouts, bound);
        } else if name.starts_with("state_")
            && name.ends_with(".sqlite")
            && thread_db_matches(&path, thread_id)
        {
            push_unique(&mut thread_dbs, bound);
        } else if name.starts_with("goals_") && name.ends_with(".sqlite") && goals_db_matches(&path)
        {
            push_unique(&mut goals_dbs, bound);
        }
    }
    if rollouts.len() != 1 || thread_dbs.len() != 1 || goals_dbs.len() != 1 {
        return None;
    }
    Some(CodexStructuredStateReference {
        rollout: rollouts.pop()?,
        thread_db: thread_dbs.pop()?,
        goals_db: goals_dbs.pop()?,
    })
}

fn push_unique(files: &mut Vec<CodexBoundFile>, candidate: CodexBoundFile) {
    if !files
        .iter()
        .any(|file| file.device == candidate.device && file.inode == candidate.inode)
    {
        files.push(candidate);
    }
}

#[cfg(unix)]
fn bind_safe_file(path: &Path) -> Option<CodexBoundFile> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let canonical = std::fs::canonicalize(path).ok()?;
    let metadata = std::fs::metadata(&canonical).ok()?;
    if !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o002 != 0
    {
        return None;
    }
    Some(CodexBoundFile {
        canonical_path: canonical.to_string_lossy().into_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
        owner_uid: metadata.uid(),
    })
}

fn rollout_matches_thread(path: &Path, name: &str, thread_id: &str) -> bool {
    if name.contains(thread_id) {
        return true;
    }
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut line = String::new();
    let mut reader = std::io::BufReader::new(file).take(64 * 1024);
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(&line)
        .ok()
        .is_some_and(|value| {
            value.get("type").and_then(serde_json::Value::as_str) == Some("session_meta")
                && value
                    .pointer("/payload/id")
                    .and_then(serde_json::Value::as_str)
                    == Some(thread_id)
        })
}

fn thread_db_matches(path: &Path, thread_id: &str) -> bool {
    let Some(connection) = read_only_database(path) else {
        return false;
    };
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM threads WHERE id = ?1)",
            [thread_id],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false)
}

fn goals_db_matches(path: &Path) -> bool {
    let Some(connection) = read_only_database(path) else {
        return false;
    };
    let mut statement = match connection.prepare("PRAGMA table_info(thread_goals)") {
        Ok(statement) => statement,
        Err(_) => return false,
    };
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .collect::<std::collections::BTreeSet<_>>();
    ["thread_id", "status", "updated_at_ms"]
        .iter()
        .all(|column| columns.contains(*column))
}

fn read_only_database(path: &Path) -> Option<rusqlite::Connection> {
    use rusqlite::OpenFlags;

    let connection = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    connection.pragma_update(None, "query_only", true).ok()?;
    Some(connection)
}

#[cfg(target_os = "linux")]
fn process_cwd(proc_root: &Path, pid: u32) -> Option<PathBuf> {
    std::fs::canonicalize(proc_root.join(pid.to_string()).join("cwd")).ok()
}

fn target_session(target: &TargetIdentity) -> Option<String> {
    match target.observation_context() {
        Some(MultiplexerContext::Tmux { session_id, .. }) => Some(session_id.clone()),
        Some(MultiplexerContext::Herdr { workspace_id, .. }) => Some(workspace_id.clone()),
        None => None,
    }
}
