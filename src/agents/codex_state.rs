use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use super::codex::CodexGoalSnapshot;
use crate::model::{CodexBoundFile, CodexSessionReference, TargetIdentity, WatcherState};
use crate::process::ProcessInspector;

pub const MAX_ROLLOUT_TAIL_BYTES: u64 = 1024 * 1024;
pub const MAX_ROLLOUT_RECORD_BYTES: usize = 256 * 1024;
const CAPACITY_MESSAGE: &str = "Selected model is at capacity. Please try a different model.";

pub fn observe_bound_codex_state(watcher: &WatcherState) -> Option<CodexGoalSnapshot> {
    let reference = watcher.codex_session.as_ref()?;
    let state = reference.structured_state.as_ref()?;
    revalidate_target(watcher, reference)?;
    for file in [&state.rollout, &state.thread_db, &state.goals_db] {
        revalidate_file(file)?;
    }
    if !thread_exists(&state.thread_db, &reference.thread_id) {
        return None;
    }
    let (goal_status, _updated_at) = read_goal(&state.goals_db, &reference.thread_id)?;
    let capacity = latest_terminal_turn_has_capacity(&state.rollout)?;
    Some(CodexGoalSnapshot {
        thread_id: reference.thread_id.clone(),
        goal_status: Some(goal_status.clone()),
        goal_text: None,
        runtime_type: None,
        active_flags: Vec::new(),
        last_error_category: (normalize(&goal_status) == "blocked" && capacity)
            .then(|| "capacity_block".into()),
        last_error_terminal: normalize(&goal_status) == "blocked" && capacity,
        screen_tail: None,
    })
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn revalidate_target(watcher: &WatcherState, reference: &CodexSessionReference) -> Option<()> {
    let process = match &watcher.target {
        TargetIdentity::Process { process } | TargetIdentity::Multiplexer { process, .. } => {
            process
        }
    };
    if process.start_time != reference.process_start_time
        || target_session(&watcher.target) != reference.target_session
    {
        return None;
    }
    #[cfg(target_os = "linux")]
    let inspector = crate::process::linux::LinuxProcessInspector::default();
    #[cfg(target_os = "macos")]
    let inspector = crate::process::macos::MacOsProcessInspector::default();
    let observed = inspector.inspect(process.pid).ok()?;
    if observed.start_time != process.start_time || observed.pid != process.pid {
        return None;
    }
    process_cwd_matches(process.pid, &reference.process_cwd).then_some(())
}

fn target_session(target: &TargetIdentity) -> Option<String> {
    match target {
        TargetIdentity::Process { .. } => None,
        TargetIdentity::Multiplexer { session, .. } => session.clone(),
    }
}

fn process_cwd_matches(pid: u32, expected: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::fs::canonicalize(format!("/proc/{pid}/cwd"))
            .ok()
            .zip(std::fs::canonicalize(expected).ok())
            .is_some_and(|(actual, expected)| actual == expected)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = pid;
        std::fs::canonicalize(expected)
            .ok()
            .is_some_and(|path| path.is_dir())
    }
}

fn revalidate_file(binding: &CodexBoundFile) -> Option<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let path = Path::new(&binding.canonical_path);
    let canonical = std::fs::canonicalize(path).ok()?;
    let metadata = std::fs::metadata(&canonical).ok()?;
    (canonical == path
        && metadata.is_file()
        && metadata.dev() == binding.device
        && metadata.ino() == binding.inode
        && metadata.uid() == binding.owner_uid
        && binding.owner_uid == rustix::process::geteuid().as_raw()
        && metadata.permissions().mode() & 0o002 == 0)
        .then_some(())
}

fn open_database(binding: &CodexBoundFile) -> Option<Connection> {
    revalidate_file(binding)?;
    let connection = Connection::open_with_flags(
        &binding.canonical_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    connection.pragma_update(None, "query_only", true).ok()?;
    revalidate_file(binding)?;
    Some(connection)
}

fn table_columns(
    connection: &Connection,
    table: &str,
) -> Option<std::collections::BTreeSet<String>> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .ok()?;
    Some(
        statement
            .query_map([], |row| row.get::<_, String>(1))
            .ok()?
            .filter_map(Result::ok)
            .collect(),
    )
}

fn thread_exists(binding: &CodexBoundFile, thread_id: &str) -> bool {
    let Some(connection) = open_database(binding) else {
        return false;
    };
    let Some(columns) = table_columns(&connection, "threads") else {
        return false;
    };
    if !columns.contains("id") {
        return false;
    }
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM threads WHERE id = ?1)",
            [thread_id],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false)
}

fn read_goal(binding: &CodexBoundFile, thread_id: &str) -> Option<(String, i64)> {
    let connection = open_database(binding)?;
    let columns = table_columns(&connection, "thread_goals")?;
    if !["thread_id", "status", "updated_at_ms"]
        .iter()
        .all(|column| columns.contains(*column))
    {
        return None;
    }
    connection
        .query_row(
            "SELECT status, updated_at_ms FROM thread_goals WHERE thread_id = ?1",
            [thread_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok()
}

fn latest_terminal_turn_has_capacity(binding: &CodexBoundFile) -> Option<bool> {
    let bytes = read_rollout_tail(binding)?;
    let mut current_turn = None::<String>;
    let mut capacity_turn = None::<String>;
    let mut terminal_capacity = false;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > MAX_ROLLOUT_RECORD_BYTES {
            return None;
        }
        let value: serde_json::Value = serde_json::from_slice(line).ok()?;
        match value.get("type").and_then(serde_json::Value::as_str) {
            Some("event_msg") => {
                let kind = value
                    .pointer("/payload/type")
                    .and_then(serde_json::Value::as_str);
                let turn = value
                    .pointer("/payload/turn_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                match kind {
                    Some("task_started") => {
                        current_turn = turn;
                        capacity_turn = None;
                        terminal_capacity = false;
                    }
                    Some("task_complete") => {
                        terminal_capacity = turn.is_some() && turn == capacity_turn;
                        current_turn = None;
                    }
                    _ => {}
                }
            }
            Some("response_item") => {
                let role = value
                    .pointer("/payload/role")
                    .and_then(serde_json::Value::as_str);
                if role == Some("user") {
                    terminal_capacity = false;
                    capacity_turn = None;
                } else if role == Some("assistant") && assistant_has_exact_capacity_message(&value)
                {
                    capacity_turn = current_turn.clone();
                }
            }
            _ => {}
        }
    }
    Some(terminal_capacity)
}

fn assistant_has_exact_capacity_message(value: &serde_json::Value) -> bool {
    value
        .pointer("/payload/content")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .any(|part| {
            part.get("type").and_then(serde_json::Value::as_str) == Some("output_text")
                && part.get("text").and_then(serde_json::Value::as_str) == Some(CAPACITY_MESSAGE)
        })
}

fn read_rollout_tail(binding: &CodexBoundFile) -> Option<Vec<u8>> {
    use std::os::unix::fs::FileExt;

    revalidate_file(binding)?;
    let file = std::fs::File::open(&binding.canonical_path).ok()?;
    let length = file.metadata().ok()?.len();
    let offset = length.saturating_sub(MAX_ROLLOUT_TAIL_BYTES);
    let size = usize::try_from(length - offset).ok()?;
    let mut bytes = vec![0; size];
    let mut read = 0;
    while read < bytes.len() {
        let count = file
            .read_at(&mut bytes[read..], offset + read as u64)
            .ok()?;
        if count == 0 {
            return None;
        }
        read += count;
    }
    revalidate_file(binding)?;
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return None;
    }
    if offset > 0 {
        let newline = bytes.iter().position(|byte| *byte == b'\n')?;
        bytes.drain(..=newline);
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    fn binding(path: &Path) -> CodexBoundFile {
        let canonical = std::fs::canonicalize(path).unwrap();
        let metadata = std::fs::metadata(&canonical).unwrap();
        CodexBoundFile {
            canonical_path: canonical.to_string_lossy().into_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner_uid: metadata.uid(),
        }
    }

    fn record(kind: &str, turn_id: &str) -> serde_json::Value {
        serde_json::json!({"type":"event_msg", "payload":{"type":kind,"turn_id":turn_id}})
    }

    fn capacity() -> serde_json::Value {
        serde_json::json!({"type":"response_item","payload":{"type":"message",
            "role":"assistant","content":[{"type":"output_text","text":CAPACITY_MESSAGE}]}})
    }

    fn user() -> serde_json::Value {
        serde_json::json!({"type":"response_item","payload":{"type":"message",
            "role":"user","content":[{"type":"input_text","text":"continue"}]}})
    }

    fn write_records(path: &Path, records: &[serde_json::Value]) {
        let mut file = std::fs::File::create(path).unwrap();
        for value in records {
            writeln!(file, "{}", serde_json::to_string(value).unwrap()).unwrap();
        }
    }

    #[test]
    fn only_latest_completed_capacity_turn_is_actionable() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rollout.jsonl");
        write_records(
            &path,
            &[
                record("task_started", "one"),
                capacity(),
                record("task_complete", "one"),
            ],
        );
        assert_eq!(
            latest_terminal_turn_has_capacity(&binding(&path)),
            Some(true)
        );

        write_records(
            &path,
            &[
                record("task_started", "one"),
                capacity(),
                record("task_complete", "one"),
                user(),
            ],
        );
        assert_eq!(
            latest_terminal_turn_has_capacity(&binding(&path)),
            Some(false)
        );

        write_records(
            &path,
            &[
                record("task_started", "one"),
                capacity(),
                record("task_complete", "one"),
                record("task_started", "two"),
            ],
        );
        assert_eq!(
            latest_terminal_turn_has_capacity(&binding(&path)),
            Some(false)
        );
    }

    #[test]
    fn partial_and_oversized_rollout_records_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rollout.jsonl");
        std::fs::write(&path, b"{\"type\":\"event_msg\"").unwrap();
        assert_eq!(latest_terminal_turn_has_capacity(&binding(&path)), None);

        std::fs::write(
            &path,
            format!("{{\"padding\":\"{}\"}}\n", "x".repeat(300_000)),
        )
        .unwrap();
        assert_eq!(latest_terminal_turn_has_capacity(&binding(&path)), None);
    }
}
