#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use tempfile::TempDir;
use watchme::config::Config;
use watchme::model::{ProcessIdentity, TargetIdentity, WatcherLifecycle, WatcherState};
use watchme::paths::WatchmePaths;
use watchme::store::{JsonStore, LoadOutcome};

fn process() -> ProcessIdentity {
    ProcessIdentity {
        pid: 42,
        start_time: 1_234_567,
        executable: Some("/usr/bin/codex".into()),
        argv_digest: Some("sha256:abc".into()),
        uid: Some(1000),
        process_group_id: Some(40),
        session_leader_id: Some(40),
        tty: Some("/dev/pts/2".into()),
        parent_digest: Some("sha256:def".into()),
    }
}

fn state() -> WatcherState {
    WatcherState {
        schema_version: 1,
        watcher_id: "watcher-1".into(),
        target: TargetIdentity::Process {
            version: 1,
            process: process(),
        },
        lifecycle: WatcherLifecycle::Observing,
        revision: 3,
        updated_at_unix_ms: 9_876,
    }
}

#[test]
fn xdg_paths_use_safe_fallbacks_and_explicit_overrides() {
    let fallback = WatchmePaths::resolve(Path::new("/home/alice"), None, None, None).unwrap();
    assert_eq!(
        fallback.config_dir(),
        Path::new("/home/alice/.config/watchme")
    );
    assert_eq!(
        fallback.state_dir(),
        Path::new("/home/alice/.local/state/watchme")
    );
    assert_eq!(
        fallback.runtime_dir(),
        Path::new("/home/alice/.local/state/watchme/run")
    );

    let overridden = WatchmePaths::resolve(
        Path::new("/home/alice"),
        Some(Path::new("/cfg")),
        Some(Path::new("/state")),
        Some(Path::new("/run/user/1000")),
    )
    .unwrap();
    assert_eq!(overridden.config_dir(), Path::new("/cfg/watchme"));
    assert_eq!(overridden.state_dir(), Path::new("/state/watchme"));
    assert_eq!(
        overridden.runtime_dir(),
        Path::new("/run/user/1000/watchme")
    );
}

#[test]
fn managed_paths_reject_relative_traversal_and_symlinks() {
    let temp = TempDir::new().unwrap();
    let paths = WatchmePaths::resolve(temp.path(), None, None, None).unwrap();
    paths.create_owner_only().unwrap();
    assert!(paths.state_file("../escape.json").is_err());
    assert!(paths.state_file("nested/value.json").is_err());

    let target = temp.path().join("elsewhere");
    fs::create_dir(&target).unwrap();
    let link = paths.state_dir().join("linked");
    symlink(&target, &link).unwrap();
    assert!(paths.validate_managed_path(&link).is_err());
}

#[test]
fn created_directories_and_state_files_are_owner_only() {
    let temp = TempDir::new().unwrap();
    let paths = WatchmePaths::resolve(temp.path(), None, None, None).unwrap();
    paths.create_owner_only().unwrap();
    for directory in [paths.config_dir(), paths.state_dir(), paths.runtime_dir()] {
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    let file = paths.state_file("watchers.json").unwrap();
    JsonStore::new(file.clone()).write(&state()).unwrap();
    assert_eq!(
        fs::metadata(file).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn configuration_layers_over_conservative_defaults_and_rejects_unknown_keys() {
    let temp = TempDir::new().unwrap();
    let system = temp.path().join("system.toml");
    let user = temp.path().join("user.toml");
    fs::write(&system, "[observation]\npoll_interval_seconds = 90\n").unwrap();
    fs::write(&user, "[observation]\npoll_jitter_seconds = 2\n").unwrap();
    let config = Config::load_layers([system.as_path(), user.as_path()]).unwrap();
    assert_eq!(config.observation.poll_interval_seconds, 90);
    assert_eq!(config.observation.poll_jitter_seconds, 2);

    let defaults = Config::default();
    assert_eq!(defaults.observation.poll_interval_seconds, 60);
    assert_eq!(defaults.observation.poll_jitter_seconds, 5);

    fs::write(&user, "mystery = true\n").unwrap();
    assert!(Config::load_layers([user.as_path()]).is_err());
}

#[test]
fn state_round_trips_and_atomic_replacement_does_not_change_inode_contents_partway() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("state.json");
    let store = JsonStore::new(path.clone());
    store.write(&state()).unwrap();
    let first_inode = fs::metadata(&path).unwrap().ino();

    let mut replacement = state();
    replacement.revision = 4;
    store.write(&replacement).unwrap();
    let second_inode = fs::metadata(&path).unwrap().ino();
    assert_ne!(first_inode, second_inode);
    assert_eq!(
        store.load::<WatcherState>().unwrap(),
        LoadOutcome::Present(replacement)
    );
    assert!(fs::read_dir(temp.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp")
    }));
}

#[test]
fn corrupt_and_oversized_state_fails_closed_and_preserves_evidence() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("state.json");
    fs::write(&path, b"{not-json").unwrap();
    let store = JsonStore::with_max_bytes(path.clone(), 64);
    let quarantine = match store.load::<WatcherState>().unwrap() {
        LoadOutcome::Corrupt { quarantine } => quarantine,
        outcome => panic!("expected corrupt state, got {outcome:?}"),
    };
    assert!(!path.exists());
    assert_eq!(fs::read(quarantine).unwrap(), b"{not-json");

    fs::write(&path, vec![b'x'; 65]).unwrap();
    assert!(matches!(
        store.load::<WatcherState>().unwrap(),
        LoadOutcome::Corrupt { .. }
    ));
}

#[test]
fn store_refuses_to_read_or_replace_symlinks() {
    let temp = TempDir::new().unwrap();
    let victim = temp.path().join("victim");
    fs::write(&victim, b"untouched").unwrap();
    let link = temp.path().join("state.json");
    symlink(&victim, &link).unwrap();
    let store = JsonStore::new(link);
    assert!(store.write(&state()).is_err());
    assert!(store.load::<WatcherState>().is_err());
    assert_eq!(fs::read(victim).unwrap(), b"untouched");
}

#[test]
fn managed_paths_and_store_reject_symlinked_ancestors() {
    let temp = TempDir::new().unwrap();
    let real = temp.path().join("real");
    fs::create_dir(&real).unwrap();
    let linked = temp.path().join("linked");
    symlink(&real, &linked).unwrap();

    let paths = WatchmePaths::resolve(&linked, None, None, None).unwrap();
    assert!(paths.create_owner_only().is_err());

    let nested = linked.join("state.json");
    assert!(JsonStore::new(nested).write(&state()).is_err());
}
