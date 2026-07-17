#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use tempfile::TempDir;
use watchme::codex_attachment::{
    attach_explicit_codex_session_from_values, attach_process_correlated_codex_session_at,
};
use watchme::model::{ProcessIdentity, TargetIdentity, WatcherLifecycle, WatcherState};

struct CodexProcessFixture {
    _root: TempDir,
    proc_root: PathBuf,
    process_dir: PathBuf,
    fd_dir: PathBuf,
    rollout: PathBuf,
    state_db: PathBuf,
    goals_db: PathBuf,
    cwd: PathBuf,
    pid: u32,
}

impl CodexProcessFixture {
    fn new(thread_id: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let proc_root = root.path().join("proc");
        let pid = 4242;
        let process_dir = proc_root.join(pid.to_string());
        let fd_dir = process_dir.join("fd");
        let cwd = root.path().join("repo");
        let state_dir = root.path().join("codex");
        std::fs::create_dir_all(&fd_dir).unwrap();
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(
            process_dir.join("cmdline"),
            format!("codex\0resume\0{thread_id}\0"),
        )
        .unwrap();
        symlink(&cwd, process_dir.join("cwd")).unwrap();

        let rollout = state_dir.join(format!("rollout-{thread_id}.jsonl"));
        std::fs::write(
            &rollout,
            format!("{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"{thread_id}\"}}}}\n"),
        )
        .unwrap();
        let state_db = state_dir.join("state_5.sqlite");
        let connection = Connection::open(&state_db).unwrap();
        connection
            .execute("CREATE TABLE threads (id TEXT PRIMARY KEY)", [])
            .unwrap();
        connection
            .execute("INSERT INTO threads (id) VALUES (?1)", [thread_id])
            .unwrap();
        drop(connection);
        let goals_db = state_dir.join("goals_1.sqlite");
        let connection = Connection::open(&goals_db).unwrap();
        connection
            .execute(
                "CREATE TABLE thread_goals (thread_id TEXT PRIMARY KEY, status TEXT, updated_at_ms INTEGER)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO thread_goals (thread_id, status, updated_at_ms) VALUES (?1, 'active', 1)",
                [thread_id],
            )
            .unwrap();
        drop(connection);

        for path in [&rollout, &state_db, &goals_db] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o664)).unwrap();
        }
        symlink(&rollout, fd_dir.join("3")).unwrap();
        symlink(&state_db, fd_dir.join("4")).unwrap();
        symlink(&goals_db, fd_dir.join("5")).unwrap();
        symlink(&state_db, fd_dir.join("8")).unwrap();
        symlink(&goals_db, fd_dir.join("9")).unwrap();
        Self {
            _root: root,
            proc_root,
            process_dir,
            fd_dir,
            rollout,
            state_db,
            goals_db,
            cwd,
            pid,
        }
    }

    fn watcher(&self) -> WatcherState {
        WatcherState::new(
            "process-4242-77".into(),
            TargetIdentity::process(ProcessIdentity::new(self.pid, 77)),
            WatcherLifecycle::Registered,
            0,
            0,
        )
    }

    fn metadata(path: &Path) -> std::fs::Metadata {
        std::fs::metadata(path).unwrap()
    }

    fn explicit_values(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("WATCHME_CODEX_THREAD_ID".into(), "thr_demo".into()),
            ("WATCHME_CODEX_PROCESS_PID".into(), self.pid.to_string()),
            ("WATCHME_CODEX_PROCESS_START_TIME".into(), "77".into()),
            (
                "WATCHME_CODEX_PROCESS_CWD".into(),
                self.cwd.to_string_lossy().into_owned(),
            ),
            (
                "WATCHME_CODEX_ROLLOUT_PATH".into(),
                self.rollout.to_string_lossy().into_owned(),
            ),
            (
                "WATCHME_CODEX_THREAD_DB_PATH".into(),
                self.state_db.to_string_lossy().into_owned(),
            ),
            (
                "WATCHME_CODEX_GOALS_DB_PATH".into(),
                self.goals_db.to_string_lossy().into_owned(),
            ),
        ])
    }
}

fn attach(fixture: &CodexProcessFixture, herdr_session: Option<&str>) -> WatcherState {
    let mut watcher = fixture.watcher();
    attach_process_correlated_codex_session_at(&mut watcher, &fixture.proc_root, herdr_session);
    watcher
}

#[test]
fn linux_attachment_binds_resume_thread_and_open_codex_files() {
    let fixture = CodexProcessFixture::new("thr_demo");
    let mut watcher = fixture.watcher();

    attach_process_correlated_codex_session_at(&mut watcher, &fixture.proc_root, None);

    let reference = watcher.codex_session.as_ref().expect("Codex binding");
    assert_eq!(reference.thread_id, "thr_demo");
    assert_eq!(reference.process_cwd, fixture.cwd.to_string_lossy());
    let state = reference.structured_state.as_ref().expect("state files");
    assert_eq!(
        state.rollout.device,
        CodexProcessFixture::metadata(&fixture.rollout).dev()
    );
    assert_eq!(
        state.goals_db.inode,
        CodexProcessFixture::metadata(&fixture.goals_db).ino()
    );
    assert_eq!(
        state.thread_db.inode,
        CodexProcessFixture::metadata(&fixture.state_db).ino()
    );
}

#[test]
fn attachment_rejects_missing_resume_and_conflicting_herdr_session() {
    let fixture = CodexProcessFixture::new("thr_demo");
    assert!(
        attach(&fixture, Some("other-thread"))
            .codex_session
            .is_none()
    );

    std::fs::write(fixture.process_dir.join("cmdline"), b"codex\0").unwrap();
    assert!(attach(&fixture, None).codex_session.is_none());
}

#[test]
fn attachment_requires_exact_open_safe_unambiguous_files() {
    let fixture = CodexProcessFixture::new("thr_demo");
    std::fs::remove_file(fixture.fd_dir.join("3")).unwrap();
    assert!(attach(&fixture, None).codex_session.is_none());

    symlink(&fixture.rollout, fixture.fd_dir.join("3")).unwrap();
    std::fs::set_permissions(&fixture.rollout, std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(attach(&fixture, None).codex_session.is_none());
}

#[test]
fn attachment_rejects_ambiguous_matching_rollouts_but_ignores_unrelated_open_rollout() {
    let fixture = CodexProcessFixture::new("thr_demo");
    let unrelated = fixture
        .rollout
        .parent()
        .unwrap()
        .join("rollout-unrelated.jsonl");
    std::fs::write(
        &unrelated,
        "{\"type\":\"session_meta\",\"payload\":{\"id\":\"thr_other\"}}\n",
    )
    .unwrap();
    symlink(&unrelated, fixture.fd_dir.join("6")).unwrap();
    assert!(attach(&fixture, None).codex_session.is_some());

    let duplicate = fixture
        .rollout
        .parent()
        .unwrap()
        .join("rollout-thr_demo-copy.jsonl");
    std::fs::write(
        &duplicate,
        "{\"type\":\"session_meta\",\"payload\":{\"id\":\"thr_demo\"}}\n",
    )
    .unwrap();
    symlink(&duplicate, fixture.fd_dir.join("7")).unwrap();
    assert!(attach(&fixture, None).codex_session.is_none());
}

#[test]
fn attachment_ignores_proc_fds_without_filesystem_targets() {
    let fixture = CodexProcessFixture::new("thr_demo");
    symlink("socket:[12345]", fixture.fd_dir.join("10")).unwrap();

    assert!(
        attach(&fixture, None).codex_session.is_some(),
        "sockets, pipes, and raced-away descriptors must not abort state discovery"
    );
}

#[test]
fn attachment_rejects_malformed_or_ambiguous_resume_arguments() {
    let fixture = CodexProcessFixture::new("thr_demo");
    std::fs::write(
        fixture.process_dir.join("cmdline"),
        b"codex\0resume\0thr_demo\0resume\0thr_other\0",
    )
    .unwrap();
    assert!(attach(&fixture, None).codex_session.is_none());

    std::fs::write(
        fixture.process_dir.join("cmdline"),
        b"codex\0resume\0thr_demo",
    )
    .unwrap();
    assert!(attach(&fixture, None).codex_session.is_none());
}

#[test]
fn explicit_attachment_requires_complete_matching_values() {
    let fixture = CodexProcessFixture::new("thr_demo");
    let values = fixture.explicit_values();
    let mut watcher = fixture.watcher();
    attach_explicit_codex_session_from_values(&mut watcher, &values);
    assert!(watcher.codex_session.is_some());

    for name in values.keys() {
        let mut incomplete = values.clone();
        incomplete.remove(name);
        let mut watcher = fixture.watcher();
        attach_explicit_codex_session_from_values(&mut watcher, &incomplete);
        assert!(watcher.codex_session.is_none(), "missing {name}");
    }

    let mut wrong_process = values;
    wrong_process.insert("WATCHME_CODEX_PROCESS_START_TIME".into(), "78".into());
    let mut watcher = fixture.watcher();
    attach_explicit_codex_session_from_values(&mut watcher, &wrong_process);
    assert!(watcher.codex_session.is_none());
}
