use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn bare_codex_registration(herdr_socket: Option<&Path>) -> Value {
    use std::process::{Command as StdCommand, Stdio};
    use std::time::{Duration, Instant};

    let temp = tempdir().unwrap();
    let codex = temp.path().join("codex");
    assert!(
        StdCommand::new("rustc")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(["--edition=2024", "tests/fixtures/fake_codex.rs", "-o"])
            .arg(&codex)
            .status()
            .unwrap()
            .success()
    );
    let runtime = temp.path().join("runtime");
    let state = temp.path().join("state");
    let home = temp.path().join("home");
    for directory in [&runtime, &state, &home] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let mut command = StdCommand::new(&codex);
    command
        .env("WATCHME_BIN", env!("CARGO_BIN_EXE_watchme"))
        .env("HOME", &home)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("XDG_STATE_HOME", &state)
        .env("WATCHME_ISOLATE_PROCESS_GROUP", "1")
        .env_remove("TMUX")
        .env_remove("TMUX_PANE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for name in [
        "HERDR_SOCKET_PATH",
        "HERDR_WORKSPACE_ID",
        "HERDR_TAB_ID",
        "HERDR_PANE_ID",
    ] {
        command.env_remove(name);
    }
    if let Some(socket) = herdr_socket {
        command
            .env("HERDR_SOCKET_PATH", socket)
            .env("HERDR_WORKSPACE_ID", "w6")
            .env("HERDR_TAB_ID", "w6:t1")
            .env("HERDR_PANE_ID", "w6:pD");
    }
    let child = command.spawn().unwrap();
    let mut child = ChildGuard(child);
    let state_file = state.join("watchme/watchers.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    let persisted = loop {
        if let Ok(bytes) = fs::read(&state_file)
            && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
            && value["watchers"]
                .as_array()
                .is_some_and(|watchers| !watchers.is_empty())
        {
            break value;
        }
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!("fake Codex exited before registration: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "bare registration did not persist"
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    let watcher = &persisted["watchers"][0];
    assert_eq!(watcher["target"]["kind"], "process");
    assert_eq!(
        watcher["target"]["process"]["executable"],
        codex.to_str().unwrap()
    );

    let _ = StdCommand::new(env!("CARGO_BIN_EXE_watchme"))
        .env("HOME", &home)
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("XDG_STATE_HOME", &state)
        .args(["daemon", "stop"])
        .status();

    persisted
}

#[test]
fn bare_watchme_registers_from_ttyless_codex_ancestor() {
    let persisted = bare_codex_registration(None);
    let watcher = &persisted["watchers"][0];
    assert_eq!(watcher["target"]["kind"], "process");
}

#[test]
fn bare_watchme_falls_back_for_unsupported_native_herdr_protocol() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};

    let herdr = tempdir().unwrap();
    let socket = herdr.path().join("herdr.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    let server = std::thread::spawn(move || {
        for index in 0..2 {
            let (mut connection, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(connection.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request = serde_json::from_str::<Value>(&line).unwrap();
            recorded.lock().unwrap().push(request.clone());
            let response = if index == 0 {
                serde_json::json!({"id":"", "error":{"code":"invalid_request",
                    "message":"invalid request: missing field id"}})
            } else {
                serde_json::json!({"id":request["id"], "result":{"type":"pong",
                    "version":"0.8.0", "protocol":17}})
            };
            connection
                .write_all(&serde_json::to_vec(&response).unwrap())
                .unwrap();
            connection.write_all(b"\n").unwrap();
        }
    });

    let persisted = bare_codex_registration(Some(&socket));
    server.join().unwrap();

    assert_eq!(persisted["watchers"][0]["target"]["kind"], "process");
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["protocol"], "watchme.herdr");
    assert_eq!(requests[1]["method"], "ping");
}

#[test]
fn start_is_not_a_command() {
    Command::cargo_bin("watchme")
        .expect("binary exists")
        .arg("start")
        .assert()
        .failure()
        .stderr(predicate::str::contains("unrecognized subcommand 'start'"));
}

#[test]
fn administrative_commands_parse() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let configure = |command: &mut Command| {
        command
            .env("HOME", temp.path())
            .env("XDG_CONFIG_HOME", temp.path().join("config"))
            .env("XDG_STATE_HOME", temp.path().join("state"))
            .env("XDG_RUNTIME_DIR", &runtime);
    };
    // Operability commands must not fall through to the generic unimplemented
    // stub: they succeed, or return a specific actionable error.
    for arguments in [
        &["explain", "watcher-1"][..],
        &["snapshot", "watcher-1", "--redacted"],
        &["logs", "watcher-1"],
        &["doctor", "--strict"],
        &["providers"],
    ] {
        let mut command = Command::cargo_bin("watchme").expect("binary exists");
        configure(&mut command);
        let output = command.args(arguments).output().expect("command runs");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("not implemented yet"),
            "{} still unimplemented: {stderr}",
            arguments[0]
        );
    }

    for arguments in [
        &["status", "watcher-1"][..],
        &["list"],
        &["stop", "--all"],
        &["pause", "watcher-1"],
        &["resume", "watcher-1"],
        &["daemon", "status"],
        &["daemon", "stop"],
    ] {
        let mut command = Command::cargo_bin("watchme").expect("binary exists");
        configure(&mut command);
        command
            .args(arguments)
            .assert()
            .failure()
            .stderr(predicate::str::contains("daemon unavailable"));
    }
}

#[test]
fn daemon_completion_includes_detached_start() {
    let completion = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/completions/watchme.bash"),
    )
    .unwrap();
    assert!(completion.contains("daemon) COMPREPLY=( $(compgen -W \"start run status stop\""));
}

#[test]
fn config_path_prints_xdg_resolved_config_file() {
    let temp = tempdir().unwrap();
    let config_home = temp.path().join("config");
    std::fs::create_dir_all(&config_home).unwrap();
    // macOS tempdirs sit under /var -> /private/var; WatchMe physicalizes the
    // existing prefix before joining watchme/config.toml.
    let expected = std::fs::canonicalize(&config_home)
        .unwrap()
        .join("watchme")
        .join("config.toml");
    Command::cargo_bin("watchme")
        .unwrap()
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", temp.path().join("state"))
        .env("XDG_RUNTIME_DIR", temp.path().join("run"))
        .args(["config", "path"])
        .assert()
        .success()
        .stdout(predicate::eq(format!("{}\n", expected.display())))
        .stderr(predicate::str::is_empty());
}

#[test]
fn config_check_accepts_defaults_and_valid_file_and_rejects_unknown_fields() {
    let temp = tempdir().unwrap();
    let config_home = temp.path().join("config");
    let state = temp.path().join("state");
    let runtime = temp.path().join("run");
    let watchme_config = config_home.join("watchme");
    fs::create_dir_all(&watchme_config).unwrap();

    Command::cargo_bin("watchme")
        .unwrap()
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["config", "check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("configuration ok"))
        .stderr(predicate::str::is_empty());

    let config_file = watchme_config.join("config.toml");
    fs::write(
        &config_file,
        fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("config/config.example.toml"),
        )
        .unwrap(),
    )
    .unwrap();
    Command::cargo_bin("watchme")
        .unwrap()
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["config", "check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("configuration ok"));

    fs::write(&config_file, "mystery = true\n").unwrap();
    Command::cargo_bin("watchme")
        .unwrap()
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state)
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["config", "check"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("configuration"));
}

#[test]
fn config_show_prints_redacted_configuration() {
    let temp = tempdir().unwrap();
    let config_home = temp.path().join("config");
    fs::create_dir_all(config_home.join("watchme")).unwrap();
    fs::write(
        config_home.join("watchme/config.toml"),
        concat!(
            "config_version = 1\n",
            "[security]\n",
            "extra_secret_names = [\"MY_INTERNAL_TOKEN\"]\n",
        ),
    )
    .unwrap();

    Command::cargo_bin("watchme")
        .unwrap()
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", temp.path().join("state"))
        .env("XDG_RUNTIME_DIR", temp.path().join("run"))
        .args(["config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("# redacted configuration"))
        .stdout(predicate::str::contains("config_version"))
        .stdout(predicate::str::contains("MY_INTERNAL_TOKEN"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn stop_requires_a_target() {
    Command::cargo_bin("watchme")
        .unwrap()
        .arg("stop")
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires"));
}

#[test]
fn administrative_target_ids_must_not_be_empty() {
    for arguments in [
        &["status", ""][..],
        &["stop", ""],
        &["pause", ""],
        &["resume", ""],
    ] {
        Command::cargo_bin("watchme")
            .unwrap()
            .args(arguments)
            .assert()
            .failure()
            .stderr(predicate::str::contains("target ID must not be empty"));
    }
}

#[test]
fn json_errors_are_versioned_envelopes() {
    let temp = tempdir().unwrap();
    let runtime = temp.path().join("runtime");
    fs::create_dir(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::cargo_bin("watchme")
        .expect("binary exists")
        .env("HOME", temp.path())
        .env("XDG_STATE_HOME", temp.path().join("state"))
        .env("XDG_RUNTIME_DIR", &runtime)
        .args(["list", "--json"])
        .output()
        .expect("command runs");

    assert!(!output.status.success());
    let envelope: Value = serde_json::from_slice(&output.stdout).expect("valid JSON response");
    assert_eq!(envelope["schema_version"], "1.0");
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["error"]["code"], "retryable_integration");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains("daemon unavailable")
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn stop_failure_hook_mode_writes_only_a_valid_marker() {
    let temp = tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let marker = temp.path().join("markers.jsonl");
    Command::cargo_bin("watchme")
        .unwrap()
        .args(["watchme-hook-stop-failure", "--marker", marker.to_str().unwrap()])
        .write_stdin(r#"{"session_id":"s","transcript_path":"/tmp/t.jsonl","cwd":"/tmp","permission_mode":"default","hook_event_name":"StopFailure","error":"rate_limit","error_details":"429 Too Many Requests","last_assistant_message":"API Error: Rate limit reached","future_claude_field":{"ok":true}}"#)
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());
    assert!(fs::read_to_string(marker).unwrap().contains("rate_limit"));
}

#[test]
fn stop_failure_hook_rejects_malformed_or_secret_bearing_payloads() {
    let temp = tempdir().unwrap();
    #[cfg(unix)]
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let marker = temp.path().join("markers.jsonl");
    for payload in [
        r#"{"session_id":"s","transcript_path":"/tmp/t.jsonl","hook_event_name":"Stop","error":"rate_limit"}"#,
        r#"{"session_id":"s","transcript_path":"relative.jsonl","hook_event_name":"StopFailure","error":"rate_limit"}"#,
        r#"{"session_id":"s","transcript_path":"/tmp/t.jsonl","hook_event_name":"StopFailure","error":"rate_limit","error_details":"Bearer secret-token"}"#,
    ] {
        Command::cargo_bin("watchme")
            .unwrap()
            .args([
                "watchme-hook-stop-failure",
                "--marker",
                marker.to_str().unwrap(),
            ])
            .write_stdin(payload)
            .assert()
            .failure();
    }
    assert!(!marker.exists());
}

#[test]
fn public_claude_hook_lifecycle_is_dry_run_safe_and_has_no_registration_alias() {
    let temp = tempdir().unwrap();
    let settings = temp.path().join("settings.json");
    let marker = temp.path().join("watch me.jsonl");
    Command::cargo_bin("watchme")
        .unwrap()
        .args([
            "hooks",
            "install-claude",
            "--settings",
            settings.to_str().unwrap(),
            "--marker",
            marker.to_str().unwrap(),
            "--dry-run",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("would install Claude hook"))
        .stdout(predicate::str::contains("--marker '"));
    assert!(!settings.exists());
}

#[test]
fn daemon_start_detaches_waits_and_is_idempotent() {
    use std::process::Command as StdCommand;

    struct DaemonGuard {
        home: PathBuf,
        config: PathBuf,
        state: PathBuf,
        runtime: PathBuf,
    }

    impl Drop for DaemonGuard {
        fn drop(&mut self) {
            let _ = StdCommand::new(env!("CARGO_BIN_EXE_watchme"))
                .env("HOME", &self.home)
                .env("XDG_CONFIG_HOME", &self.config)
                .env("XDG_STATE_HOME", &self.state)
                .env("XDG_RUNTIME_DIR", &self.runtime)
                .args(["daemon", "stop"])
                .status();
        }
    }

    let temp = tempdir().unwrap();
    let home = temp.path().join("home");
    let config = temp.path().join("config");
    let state = temp.path().join("state");
    let runtime = temp.path().join("runtime");
    for directory in [&home, &config, &state, &runtime] {
        fs::create_dir(directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::create_dir(config.join("watchme")).unwrap();
    fs::write(
        config.join("watchme/config.toml"),
        "config_version = 1\n\n[daemon]\nidle_grace_seconds = 1\nstay_resident = true\n",
    )
    .unwrap();
    let _guard = DaemonGuard {
        home: home.clone(),
        config: config.clone(),
        state: state.clone(),
        runtime: runtime.clone(),
    };
    let configure = |command: &mut Command| {
        command
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_STATE_HOME", &state)
            .env("XDG_RUNTIME_DIR", &runtime);
    };

    let mut first = Command::cargo_bin("watchme").unwrap();
    configure(&mut first);
    first
        .args(["daemon", "start"])
        .assert()
        .success()
        .stdout(predicate::eq("daemon started\n"))
        .stderr(predicate::str::is_empty());

    let mut second = Command::cargo_bin("watchme").unwrap();
    configure(&mut second);
    second
        .args(["daemon", "start"])
        .assert()
        .success()
        .stdout(predicate::eq("daemon already running\n"))
        .stderr(predicate::str::is_empty());

    let mut status = Command::cargo_bin("watchme").unwrap();
    configure(&mut status);
    status
        .args(["daemon", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("daemon: running"))
        .stderr(predicate::str::is_empty());
}

#[test]
fn daemon_run_honors_config_stay_resident_and_idle_grace() {
    use std::process::{Command as StdCommand, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    fn spawn_daemon(
        temp: &tempfile::TempDir,
        stay_resident: bool,
    ) -> (std::process::Child, PathBuf) {
        let config = temp.path().join(format!("config-{stay_resident}"));
        let state = temp.path().join(format!("state-{stay_resident}"));
        let runtime = temp.path().join(format!("run-{stay_resident}"));
        fs::create_dir_all(config.join("watchme")).unwrap();
        fs::create_dir_all(state.join("watchme")).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        #[cfg(unix)]
        {
            fs::set_permissions(config.join("watchme"), fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(state.join("watchme"), fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(
            config.join("watchme/config.toml"),
            format!(
                "config_version = 1\n\n[daemon]\nidle_grace_seconds = 1\nstay_resident = {stay_resident}\n"
            ),
        )
        .unwrap();

        let child = StdCommand::new(env!("CARGO_BIN_EXE_watchme"))
            .env("HOME", temp.path())
            .env("XDG_CONFIG_HOME", &config)
            .env("XDG_STATE_HOME", &state)
            .env("XDG_RUNTIME_DIR", &runtime)
            .args(["daemon", "run"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let sock = runtime.join("watchme/daemon.sock");
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && !sock.exists() {
            thread::sleep(Duration::from_millis(25));
        }
        assert!(
            sock.exists(),
            "daemon socket missing for stay_resident={stay_resident}"
        );
        (child, runtime)
    }

    let temp = tempdir().unwrap();

    // Without stay_resident, idle_grace=1 must stop an empty daemon promptly.
    let (mut ephemeral, runtime_ephemeral) = spawn_daemon(&temp, false);
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline && ephemeral.try_wait().unwrap().is_none() {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        ephemeral.try_wait().unwrap().is_some(),
        "empty daemon should exit after configured idle_grace when stay_resident=false"
    );
    drop(runtime_ephemeral);

    // With stay_resident=true the daemon must survive past idle_grace.
    let (mut resident, runtime_resident) = spawn_daemon(&temp, true);
    thread::sleep(Duration::from_millis(1500));
    assert!(
        resident.try_wait().unwrap().is_none(),
        "daemon exited despite stay_resident=true in config"
    );
    let _ = StdCommand::new(env!("CARGO_BIN_EXE_watchme"))
        .env("HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("config-true"))
        .env("XDG_STATE_HOME", temp.path().join("state-true"))
        .env("XDG_RUNTIME_DIR", &runtime_resident)
        .args(["daemon", "stop"])
        .status();
    let _ = resident.wait();
}
