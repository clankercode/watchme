#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use tempfile::TempDir;
use watchme::config::Config;
use watchme::model::{
    PROCESS_IDENTITY_SCHEMA_VERSION, ProcessIdentity, TARGET_IDENTITY_SCHEMA_VERSION,
    TargetIdentity, WATCHER_STATE_SCHEMA_VERSION, WatcherLifecycle, WatcherState,
};
use watchme::paths::WatchmePaths;
#[cfg(target_os = "linux")]
use watchme::store::StoreError;
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
    WatcherState::new(
        "watcher-1".into(),
        TargetIdentity::process(process()),
        WatcherLifecycle::Observing,
        3,
        9_876,
    )
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
    let expected_runtime = fs::canonicalize("/tmp")
        .unwrap_or_else(|_| Path::new("/tmp").to_path_buf())
        .join(format!("watchme-{}", rustix::process::geteuid().as_raw()));
    assert_eq!(fallback.runtime_dir(), expected_runtime);

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
fn resolve_physicalizes_symlink_prefixes_before_joining_watchme() {
    // Simulates macOS `/var` → `/private/var` prefixes under tempfile paths: resolve must
    // canonicalize existing ancestors so O_NOFOLLOW directory walks can succeed.
    let temp = TempDir::new().unwrap();
    let real = temp.path().join("real");
    fs::create_dir_all(real.join("run")).unwrap();
    let linked = temp.path().join("linked");
    symlink(&real, &linked).unwrap();

    let paths = WatchmePaths::resolve(
        &linked,
        Some(&linked.join("config")),
        Some(&linked.join("state")),
        Some(&linked.join("run")),
    )
    .unwrap();
    let physical = fs::canonicalize(&real).unwrap();
    assert_eq!(paths.config_dir(), physical.join("config/watchme"));
    assert_eq!(paths.state_dir(), physical.join("state/watchme"));
    assert_eq!(paths.runtime_dir(), physical.join("run/watchme"));
    paths.create_owner_only().unwrap();
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
fn target_and_watcher_state_reject_unknown_versions_and_fields() {
    let target = TargetIdentity::process(process());
    assert_eq!(target.schema_version(), TARGET_IDENTITY_SCHEMA_VERSION);
    let mut target_json = serde_json::to_value(&target).unwrap();
    let mut target_unknown = target_json.clone();
    target_unknown["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<TargetIdentity>(target_unknown).is_err());
    target_json["schema_version"] = serde_json::json!(999);
    assert!(serde_json::from_value::<TargetIdentity>(target_json).is_err());

    let watcher = state();
    assert_eq!(watcher.schema_version(), WATCHER_STATE_SCHEMA_VERSION);
    let mut watcher_json = serde_json::to_value(&watcher).unwrap();
    watcher_json["schema_version"] = serde_json::json!(999);
    assert!(serde_json::from_value::<WatcherState>(watcher_json).is_err());

    let mut unknown = serde_json::to_value(state()).unwrap();
    unknown["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<WatcherState>(unknown).is_err());
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

    let regular = paths.state_dir().join("regular.json");
    fs::write(&regular, b"{}").unwrap();
    paths.validate_managed_path(&regular).unwrap();
    paths
        .validate_managed_path(&paths.state_dir().join("not-created.json"))
        .unwrap();

    let leaf_link = paths.state_dir().join("leaf-link.json");
    symlink(&regular, &leaf_link).unwrap();
    assert!(paths.validate_managed_path(&leaf_link).is_err());
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
fn documented_example_config_loads_under_strict_typed_model() {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/config.example.toml");
    let config = Config::load_layers([example.as_path()]).expect("example config must load");
    assert_eq!(config.config_version, 1);
    assert_eq!(config.observation.screen_confirm_samples, 2);
    assert_eq!(config.observation.max_screen_lines, 120);
    assert_eq!(config.daemon.max_watchers, 128);
    assert!(config.recovery.enabled);
    assert_eq!(config.recovery.max_attempts_per_fingerprint, 3);
    assert_eq!(config.recovery.rate_limits.reset_margin_seconds, 75);
    assert_eq!(
        config.recovery.overload.backoff_seconds,
        vec![30, 60, 120, 240, 300]
    );
    assert_eq!(config.recovery.codex_goal.resume_command, "/goal resume");
    assert!(!config.security.telemetry);
    assert_eq!(
        config.security.extra_secret_names,
        vec!["MY_INTERNAL_TOKEN".to_owned(), "PRIVATE_API_KEY".to_owned()]
    );
    assert_eq!(config.planning.planner_priority.len(), 5);
    assert_eq!(
        config
            .planning
            .planners
            .get("codex")
            .unwrap()
            .provider_family,
        "openai"
    );
    assert!(config.agents.get("claude").unwrap().deterministic_recovery);
    assert!(
        !config
            .agents
            .get("opencode")
            .unwrap()
            .deterministic_recovery
    );
    assert_eq!(
        config.manifests.local_directory,
        "~/.config/watchme/manifests"
    );
    assert_eq!(config.retention.events_days, 14);
    assert!(config.notifications.herdr);
}

#[test]
fn configuration_defaults_match_conservative_example_semantics() {
    let defaults = Config::default();
    assert_eq!(defaults.config_version, 1);
    assert_eq!(defaults.daemon.idle_grace_seconds, 30);
    assert!(!defaults.daemon.stay_resident);
    assert_eq!(defaults.observation.poll_interval_seconds, 60);
    assert_eq!(defaults.observation.poll_jitter_seconds, 5);
    assert_eq!(defaults.observation.screen_confirm_samples, 2);
    assert_eq!(defaults.observation.max_screen_bytes, 30_000);
    assert_eq!(
        defaults.observation.adapter_error_backoff_seconds,
        vec![5, 15, 60, 300]
    );
    assert!(!defaults.lifecycle.relaunch_dead_agent);
    assert!(defaults.lifecycle.stop_on_ambiguous_identity);
    assert!(defaults.recovery.enabled);
    assert!(defaults.recovery.require_empty_composer_for_text);
    assert!(defaults.recovery.verify_every_action);
    assert!(
        !defaults
            .recovery
            .rate_limits
            .allow_low_confidence_fallback_wait
    );
    assert_eq!(defaults.recovery.rate_limits.fallback_wait_seconds, 18_000);
    assert_eq!(defaults.recovery.overload.jitter_mode, "full");
    assert!(defaults.planning.enabled);
    assert!(!defaults.planning.allow_network);
    assert!(!defaults.planning.allow_repository_context);
    assert!(!defaults.security.allow_project_config);
    assert!(defaults.security.require_owner_only_paths);
    assert!(defaults.security.reject_symlinks_for_state);
    assert_eq!(defaults.retention.snapshots_days, 3);
    assert!(defaults.notifications.notify_on_human_required);
    assert!(!defaults.notifications.notify_on_target_exit);
    assert!(defaults.manifests.bundled);
    assert!(!defaults.manifests.remote_updates);
}

#[test]
fn configuration_rejects_unknown_nested_fields_and_unsupported_versions() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("bad.toml");

    fs::write(&path, "[observation]\nunexpected_field = 1\n").unwrap();
    assert!(Config::load_layers([path.as_path()]).is_err());

    fs::write(&path, "[daemon]\nmystery = true\n").unwrap();
    assert!(Config::load_layers([path.as_path()]).is_err());

    fs::write(&path, "[recovery.rate_limits]\nextra = 1\n").unwrap();
    assert!(Config::load_layers([path.as_path()]).is_err());

    fs::write(&path, "[planning.planners.codex]\nweird = true\n").unwrap();
    assert!(Config::load_layers([path.as_path()]).is_err());

    fs::write(&path, "[agents.claude]\nbonus = false\n").unwrap();
    assert!(Config::load_layers([path.as_path()]).is_err());

    fs::write(&path, "config_version = 999\n").unwrap();
    assert!(Config::load_layers([path.as_path()]).is_err());
}

#[test]
fn configuration_show_includes_redacted_header_and_preserves_secret_names() {
    let mut config = Config::default();
    config.security.extra_secret_names = vec!["MY_INTERNAL_TOKEN".to_owned()];
    let show = config.render_redacted_toml();
    assert!(show.starts_with("# redacted configuration\n"));
    assert!(show.contains("config_version"));
    assert!(show.contains("MY_INTERNAL_TOKEN"));
}

#[test]
fn configuration_ignores_only_missing_files_and_reports_broken_symlinks() {
    let temp = TempDir::new().unwrap();
    let missing = temp.path().join("missing.toml");
    assert_eq!(
        Config::load_layers([missing.as_path()]).unwrap(),
        Config::default()
    );

    let broken = temp.path().join("broken.toml");
    symlink(temp.path().join("absent-target"), &broken).unwrap();
    let error = Config::load_layers([broken.as_path()]).unwrap_err();
    assert!(error.to_string().contains(&broken.display().to_string()));

    let target = temp.path().join("target.toml");
    fs::write(&target, "[observation]\npoll_interval_seconds = 10\n").unwrap();
    let linked = temp.path().join("linked.toml");
    symlink(&target, &linked).unwrap();
    let error = Config::load_layers([linked.as_path()]).unwrap_err();
    assert!(error.to_string().contains(&linked.display().to_string()));
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
        let expected = WatcherState::new(
            format!("watcher-{revision}"),
            TargetIdentity::multiplexer(
                "tmux".into(),
                "/tmp/tmux-1000/default".into(),
                "%3".into(),
                process(),
                Some("work:1.2".into()),
            ),
            lifecycle,
            revision as u64,
            555_000 + revision as u64,
        );
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
    assert!(path.exists());
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
#[cfg(target_os = "linux")]
fn store_rejects_directory_and_fifo_leaves_without_blocking() {
    use std::sync::mpsc;
    use std::time::Duration;

    let temp = TempDir::new().unwrap();
    let directory_store = JsonStore::new(temp.path().join("directory"));
    fs::create_dir(temp.path().join("directory")).unwrap();
    assert!(matches!(
        directory_store.load::<WatcherState>(),
        Err(StoreError::UnsafePath(_))
    ));

    let fifo = temp.path().join("state.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .unwrap();
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let result = JsonStore::new(fifo).load::<WatcherState>();
        sender
            .send(matches!(result, Err(StoreError::UnsafePath(_))))
            .unwrap();
    });
    assert!(receiver.recv_timeout(Duration::from_millis(500)).unwrap());
}

#[test]
fn managed_paths_and_store_reject_symlinked_ancestors() {
    let temp = TempDir::new().unwrap();
    let real = temp.path().join("real");
    fs::create_dir(&real).unwrap();
    let linked = temp.path().join("linked");
    symlink(&real, &linked).unwrap();

    // resolve() physicalizes symlink prefixes, so create_owner_only succeeds on the
    // canonical path. JsonStore still refuses unresolved symlink ancestors.
    let paths = WatchmePaths::resolve(&linked, None, None, None).unwrap();
    paths.create_owner_only().unwrap();
    assert!(
        paths
            .config_dir()
            .starts_with(fs::canonicalize(&real).unwrap())
    );

    let nested = linked.join("state.json");
    assert!(JsonStore::new(nested).write(&state()).is_err());
}
