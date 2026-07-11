#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use tempfile::TempDir;
use watchme::config::Config;
use watchme::model::{
    PROCESS_IDENTITY_SCHEMA_VERSION, ProcessIdentity, TargetIdentity, WatcherLifecycle,
    WatcherState,
};
use watchme::paths::WatchmePaths;
use watchme::store::{JsonStore, LoadOutcome};

fn process() -> ProcessIdentity {
    let mut identity = ProcessIdentity::new(42, 1_234_567);
    identity.executable = Some("/usr/bin/codex".into());
    identity.argv_digest = Some("sha256:abc".into());
    identity.uid = Some(1000);
    identity.process_group_id = Some(40);
    identity.session_leader_id = Some(40);
    identity.tty = Some("/dev/pts/2".into());
    identity.parent_digest = Some("sha256:def".into());
    identity
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
        Path::new(&format!(
            "/tmp/watchme-{}",
            rustix::process::geteuid().as_raw()
        ))
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
fn runtime_fallback_is_owner_only() {
    let temp = TempDir::new().unwrap();
    let paths = WatchmePaths::resolve(temp.path(), None, None, None).unwrap();
    paths.create_owner_only().unwrap();
    assert_eq!(
        fs::metadata(paths.runtime_dir())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[test]
fn process_identity_has_a_locked_current_schema_version() {
    let identity = ProcessIdentity::new(7, 99);
    assert_eq!(identity.schema_version(), PROCESS_IDENTITY_SCHEMA_VERSION);
    let encoded = serde_json::to_value(&identity).unwrap();
    assert_eq!(encoded["schema_version"], PROCESS_IDENTITY_SCHEMA_VERSION);

    let mut unsupported = encoded;
    unsupported["schema_version"] = serde_json::json!(999);
    assert!(serde_json::from_value::<ProcessIdentity>(unsupported).is_err());
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
fn every_lifecycle_and_multiplexer_identity_round_trips_through_atomic_store() {
    let temp = TempDir::new().unwrap();
    let store = JsonStore::new(temp.path().join("state.json"));
    let lifecycles = [
        WatcherLifecycle::Registered,
        WatcherLifecycle::Observing,
        WatcherLifecycle::Recovering {
            evidence_fingerprint: "sha256:evidence".into(),
        },
        WatcherLifecycle::Waiting {
            until_unix_ms: 123_456,
            reason: "native retry".into(),
        },
        WatcherLifecycle::HumanRequired {
            reason: "ambiguous target".into(),
        },
        WatcherLifecycle::TargetTerminated,
        WatcherLifecycle::Stopped {
            reason: "requested".into(),
        },
    ];

    for (revision, lifecycle) in lifecycles.into_iter().enumerate() {
        let expected = WatcherState {
            schema_version: 1,
            watcher_id: format!("watcher-{revision}"),
            target: TargetIdentity::Multiplexer {
                version: 1,
                provider: "tmux".into(),
                server: "/tmp/tmux-1000/default".into(),
                pane: "%3".into(),
                process: process(),
                session: Some("work:1.2".into()),
            },
            lifecycle,
            revision: revision as u64,
            updated_at_unix_ms: 555_000 + revision as u64,
        };
        store.write(&expected).unwrap();
        assert_eq!(
            store.load::<WatcherState>().unwrap(),
            LoadOutcome::Present(expected)
        );
    }
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
