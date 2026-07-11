//! Isolated-prefix install/uninstall smoke for packaging scripts.
#![cfg(unix)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn install_script() -> PathBuf {
    repo_root().join("scripts/install.sh")
}

fn uninstall_script() -> PathBuf {
    repo_root().join("scripts/uninstall.sh")
}

fn watchme_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_watchme"))
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn wait_until(timeout: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pred() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    pred()
}

#[test]
fn isolated_prefix_install_smoke_and_uninstall_preserves_unrelated() {
    assert!(
        install_script().is_file(),
        "missing install script at {}",
        install_script().display()
    );
    assert!(
        uninstall_script().is_file(),
        "missing uninstall script at {}",
        uninstall_script().display()
    );

    let temp = tempdir().unwrap();
    let prefix = temp.path().join("prefix");
    let home = temp.path().join("home");
    let config = home.join(".config");
    let state = home.join(".local/state");
    let runtime = temp.path().join("run");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();

    // Unrelated user content that uninstall must leave alone.
    let keep_dir = prefix.join("share/unrelated");
    fs::create_dir_all(&keep_dir).unwrap();
    let keep_file = keep_dir.join("keep-me.txt");
    fs::write(&keep_file, "do not delete").unwrap();
    let keep_config = config.join("other-app/settings.toml");
    fs::create_dir_all(keep_config.parent().unwrap()).unwrap();
    fs::write(&keep_config, "keep=true\n").unwrap();

    let status = StdCommand::new("bash")
        .arg(install_script())
        .arg("--prefix")
        .arg(&prefix)
        .arg("--from")
        .arg(watchme_bin())
        .arg("--with-systemd")
        .arg("--with-completions")
        .status()
        .expect("install.sh runs");
    assert!(status.success(), "install.sh failed: {status}");

    let bin = prefix.join("bin/watchme");
    let alias = prefix.join("bin/WatchMe");
    assert!(bin.is_file(), "watchme binary missing");
    assert!(alias.exists(), "WatchMe alias missing");
    let alias_meta = fs::symlink_metadata(&alias).unwrap();
    if alias_meta.file_type().is_symlink() {
        assert_eq!(fs::read_link(&alias).unwrap(), Path::new("watchme"));
    } else {
        // Case-insensitive FS (e.g. macOS APFS): WatchMe collapses onto watchme.
        assert!(
            cfg!(target_os = "macos"),
            "non-symlink WatchMe alias is only expected on Darwin case-insensitive volumes"
        );
        assert!(alias.is_file(), "collapsed WatchMe must still be the binary");
        assert_eq!(
            fs::canonicalize(&alias).unwrap(),
            fs::canonicalize(&bin).unwrap()
        );
    }

    // Bare-command behavior for both spellings.
    for exe in [&bin, &alias] {
        Command::new(exe)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_STATE_HOME", &state)
            .env("XDG_RUNTIME_DIR", &runtime)
            .env_remove("TMUX")
            .env_remove("HERDR_SOCKET_PATH")
            .assert()
            .failure()
            .stderr(predicate::str::contains("!watchme"))
            .stderr(predicate::str::contains("watchme doctor"));
    }

    // Doctor creates owner-only managed directories.
    Command::new(&bin)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["doctor", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"schema_version\":\"1.0\""));

    let watchme_config = config.join("watchme");
    let watchme_state = state.join("watchme");
    let watchme_runtime = runtime.join("watchme");
    for dir in [&watchme_config, &watchme_state, &watchme_runtime] {
        assert!(dir.is_dir(), "missing managed dir {}", dir.display());
        assert_eq!(mode(dir), 0o700, "{} must be 0700", dir.display());
    }

    // Optional packaging artifacts from install helpers.
    let unit = prefix.join("lib/systemd/user/watchme.service");
    assert!(unit.is_file(), "systemd user unit not installed");
    let completion = prefix.join("share/bash-completion/completions/watchme");
    assert!(completion.is_file(), "bash completion not installed");

    // Daemon/status/stop smoke with a short-lived daemon.
    let mut daemon = StdCommand::new(&bin)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["daemon", "run"])
        .spawn()
        .expect("daemon run");
    let sock = watchme_runtime.join("daemon.sock");
    assert!(
        wait_until(Duration::from_secs(3), || sock.exists()),
        "daemon socket did not appear"
    );
    assert_eq!(mode(&sock), 0o600, "daemon socket must be 0600");

    Command::new(&bin)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["daemon", "status"])
        .assert()
        .success();

    Command::new(&bin)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["status", "--json"])
        .assert()
        .success();

    Command::new(&bin)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["stop", "--all", "--json"])
        .assert()
        .success();

    Command::new(&bin)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["daemon", "stop"])
        .assert()
        .success();

    let _ = daemon.wait();

    // Uninstall removes WatchMe-owned install files only.
    let status = StdCommand::new("bash")
        .arg(uninstall_script())
        .arg("--prefix")
        .arg(&prefix)
        .status()
        .expect("uninstall.sh runs");
    assert!(status.success(), "uninstall.sh failed: {status}");

    assert!(!bin.exists(), "watchme should be removed");
    assert!(!alias.exists(), "WatchMe should be removed");
    assert!(!unit.exists(), "systemd unit should be removed");
    assert!(!completion.exists(), "completion should be removed");
    assert!(
        keep_file.is_file(),
        "unrelated prefix file must be preserved"
    );
    assert_eq!(fs::read_to_string(&keep_file).unwrap(), "do not delete");
    assert!(keep_config.is_file(), "unrelated config must be preserved");
    assert!(
        watchme_config.is_dir() || !watchme_config.exists(),
        "uninstall must not delete user config unless asked"
    );
    // Default uninstall leaves XDG config/state alone.
    assert!(watchme_config.is_dir());
    assert!(watchme_state.is_dir());
}

#[test]
fn install_and_uninstall_dry_run_report_without_writing() {
    assert!(install_script().is_file());
    assert!(uninstall_script().is_file());

    let temp = tempdir().unwrap();
    let prefix = temp.path().join("prefix");
    fs::create_dir_all(prefix.join("bin")).unwrap();

    let output = StdCommand::new("bash")
        .arg(install_script())
        .arg("--prefix")
        .arg(&prefix)
        .arg("--from")
        .arg(watchme_bin())
        .arg("--dry-run")
        .output()
        .expect("dry-run install");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("would install") || stdout.contains("DRY-RUN"),
        "dry-run should report planned changes: {stdout}"
    );
    assert!(
        !prefix.join("bin/watchme").exists(),
        "dry-run must not write binary"
    );

    // Seed files then dry-run uninstall.
    fs::copy(watchme_bin(), prefix.join("bin/watchme")).unwrap();
    if let Err(error) = std::os::unix::fs::symlink("watchme", prefix.join("bin/WatchMe")) {
        assert!(
            cfg!(target_os = "macos") && prefix.join("bin/WatchMe").exists(),
            "WatchMe alias seed failed: {error}"
        );
    }

    let output = StdCommand::new("bash")
        .arg(uninstall_script())
        .arg("--prefix")
        .arg(&prefix)
        .arg("--dry-run")
        .output()
        .expect("dry-run uninstall");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("would remove") || stdout.contains("DRY-RUN"),
        "dry-run uninstall should report planned removals: {stdout}"
    );
    assert!(prefix.join("bin/watchme").is_file());
    assert!(prefix.join("bin/WatchMe").exists());
}
