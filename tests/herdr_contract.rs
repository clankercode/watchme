use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use watchme::mux::herdr::{
    ConnectedSocketEvidence, ConnectedSocketEvidenceProvider, Herdr, HerdrContext, SocketMetadata,
};
use watchme::mux::{
    ComposerSafety, ComposerState, Multiplexer, MuxError, MuxIdentity, SymbolicKey,
};

const PROTOCOL: &str = "watchme.herdr";

struct Safe;
impl ComposerSafety for Safe {
    fn observe(&self, _: &MuxIdentity) -> Result<ComposerState, MuxError> {
        Ok(ComposerState::Safe)
    }
}

struct Unsafe;
impl ComposerSafety for Unsafe {
    fn observe(&self, _: &MuxIdentity) -> Result<ComposerState, MuxError> {
        Ok(ComposerState::Unsafe)
    }
}

struct CountingSafety(std::sync::atomic::AtomicUsize);
impl ComposerSafety for CountingSafety {
    fn observe(&self, _: &MuxIdentity) -> Result<ComposerState, MuxError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(ComposerState::Safe)
    }
}

struct UnsafeAfterCommit(std::sync::atomic::AtomicUsize);
impl ComposerSafety for UnsafeAfterCommit {
    fn observe(&self, _: &MuxIdentity) -> Result<ComposerState, MuxError> {
        let call = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(if call < 2 {
            ComposerState::Safe
        } else {
            ComposerState::Unsafe
        })
    }
}

fn response(request: &Value, result: Value) -> Value {
    json!({
        "schema_version": 1,
        "protocol": PROTOCOL,
        "request_id": request["request_id"],
        "method": request["method"],
        "ok": true,
        "result": result
    })
}

fn pane_result(pid: u32, start_time: u64) -> Value {
    json!({
        "server_id": "server-a", "workspace_id": "ws-1", "workspace_name": "work",
        "tab_id": "tab-2", "tab_title": "agents", "tab_index": 2,
        "pane_id": "pane-3", "pane_title": "codex", "pane_index": 3,
        "tty": "/dev/pts/8", "current_command": "codex", "current_path": "/repo",
        "process": {"pid": pid, "start_time": start_time, "executable": "/bin/codex",
            "argv_digest": "argv", "uid": 1000, "process_group_id": pid,
            "session_leader_id": pid, "tty": "/dev/pts/8", "parent_digest": "parent"}
    })
}

struct FakeServer {
    _directory: tempfile::TempDir,
    path: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::os::unix::net::UnixStream::connect(&self.path);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn spawn_fake<F>(handler: F) -> (FakeServer, String, Arc<Mutex<Vec<Value>>>)
where
    F: Fn(Value, usize) -> Option<Value> + Send + 'static,
{
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("herdr.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let should_stop = Arc::clone(&stop);
    let server_thread = thread::spawn(move || {
        for (index, connection) in listener.incoming().enumerate() {
            let mut connection = connection.unwrap();
            if should_stop.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            let mut line = String::new();
            BufReader::new(connection.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            recorded.lock().unwrap().push(request.clone());
            if let Some(reply) = handler(request, index) {
                let encoded = serde_json::to_vec(&reply).unwrap();
                let midpoint = encoded.len() / 2;
                connection.write_all(&encoded[..midpoint]).unwrap();
                connection.write_all(&encoded[midpoint..]).unwrap();
                connection.write_all(b"\n").unwrap();
            }
        }
    });
    let path = path.to_string_lossy().into_owned();
    (
        FakeServer {
            _directory: directory,
            path: path.clone(),
            stop,
            thread: Some(server_thread),
        },
        path,
        requests,
    )
}

fn context(socket_path: String) -> HerdrContext {
    HerdrContext {
        socket_path,
        workspace_id: "ws-1".into(),
        tab_id: "tab-2".into(),
        pane_id: "pane-3".into(),
    }
}

#[test]
fn inherited_context_metadata_reads_and_auxiliary_contract_are_schema_faithful() {
    let pid = std::process::id();
    let (_directory, socket, requests) = spawn_fake(move |request, _| {
        let result = match request["method"].as_str().unwrap() {
            "pane_info" | "process_info" => pane_result(pid, 77),
            "pane_read" => json!({"text":"one\ntwo", "bytes":7, "truncated":false}),
            "agent_session" => json!({"session_id":"session-9", "agent":"codex", "process_id":pid}),
            "agent_state_events" => {
                json!({"state":"working", "events":[{"sequence":4,"kind":"turn"}]})
            }
            "notification" => json!({"delivered":true}),
            other => panic!("unexpected method {other}"),
        };
        Some(response(&request, result))
    });
    let herdr = Herdr::new(context(socket.clone()), Duration::from_millis(300)).unwrap();
    let identity = herdr.current_target().unwrap();
    let physical_socket = std::fs::canonicalize(&socket)
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        (
            identity.server.as_str(),
            identity.session_id.as_str(),
            identity.window_id.as_str(),
            identity.pane_id.as_str()
        ),
        (physical_socket.as_str(), "ws-1", "tab-2", "pane-3")
    );
    assert_eq!(identity.server_instance, "server-a");
    let info = herdr.pane_info(&identity).unwrap();
    assert_eq!(
        (
            info.session_name.as_str(),
            info.window_name.as_str(),
            info.window_index,
            info.pane_index
        ),
        ("work", "agents", 2, 3)
    );
    let capture = herdr.capture_tail(&identity, 12, 64).unwrap();
    assert_eq!(capture.text, "one\ntwo");
    assert_eq!(
        herdr.agent_session(&identity).unwrap().session_id,
        "session-9"
    );
    assert_eq!(
        herdr
            .agent_state_events(&identity, 3, 10)
            .unwrap()
            .events
            .len(),
        1
    );
    assert!(herdr.notify(&identity, "watchme", "waiting").unwrap());
    let requests = requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .all(|request| request["schema_version"] == 1 && request["protocol"] == PROTOCOL)
    );
    let request_ids: std::collections::HashSet<_> = requests
        .iter()
        .map(|request| request["request_id"].as_str().unwrap())
        .collect();
    assert_eq!(request_ids.len(), requests.len());
    let read = requests
        .iter()
        .find(|request| request["method"] == "pane_read")
        .unwrap();
    assert_eq!(
        read["params"],
        json!({"workspace_id":"ws-1","tab_id":"tab-2","pane_id":"pane-3","max_lines":12,"max_bytes":64,"recent_unwrapped":true,"detect_state":true})
    );
}

#[test]
fn request_ids_do_not_reset_across_adapter_instances() {
    let pid = std::process::id();
    let (_first_server, first_socket, first_requests) =
        spawn_fake(move |request, _| Some(response(&request, pane_result(pid, 77))));
    let (_second_server, second_socket, second_requests) =
        spawn_fake(move |request, _| Some(response(&request, pane_result(pid, 77))));
    Herdr::new(context(first_socket), Duration::from_millis(200))
        .unwrap()
        .current_target()
        .unwrap();
    Herdr::new(context(second_socket), Duration::from_millis(200))
        .unwrap()
        .current_target()
        .unwrap();
    assert_ne!(
        first_requests.lock().unwrap()[0]["request_id"],
        second_requests.lock().unwrap()[0]["request_id"]
    );
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_adapter_instances_use_distinct_request_ids() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("concurrent.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pid = std::process::id();
    let server = tokio::spawn(async move {
        let mut ids = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let byte = tokio::io::AsyncReadExt::read_u8(&mut stream).await.unwrap();
                bytes.push(byte);
                if byte == b'\n' {
                    break;
                }
            }
            let request: Value = serde_json::from_slice(&bytes).unwrap();
            ids.push(request["request_id"].as_str().unwrap().to_owned());
            let mut reply = serde_json::to_vec(&response(&request, pane_result(pid, 77))).unwrap();
            reply.push(b'\n');
            tokio::io::AsyncWriteExt::write_all(&mut stream, &reply)
                .await
                .unwrap();
        }
        ids
    });
    let socket = socket.to_string_lossy().into_owned();
    let first = Herdr::new(context(socket.clone()), Duration::from_millis(200)).unwrap();
    let second = Herdr::new(context(socket), Duration::from_millis(200)).unwrap();
    let (first_result, second_result) =
        tokio::join!(first.current_target_async(), second.current_target_async());
    first_result.unwrap();
    second_result.unwrap();
    let ids = server.await.unwrap();
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn safe_input_is_literal_or_symbolic_and_revalidates_before_and_after() {
    let pid = std::process::id();
    let (_directory, socket, requests) = spawn_fake(move |request, _| {
        let result = match request["method"].as_str().unwrap() {
            "pane_info" => pane_result(pid, 77),
            "send_text" | "send_keys" => json!({"accepted":true}),
            other => panic!("unexpected {other}"),
        };
        Some(response(&request, result))
    });
    let herdr = Herdr::new(context(socket), Duration::from_millis(300)).unwrap();
    let identity = herdr.current_target().unwrap();
    herdr
        .send_literal(&identity, "-n; literal λ", &Safe)
        .unwrap();
    herdr
        .send_key(&identity, SymbolicKey::Enter, &Safe)
        .unwrap();
    assert!(matches!(
        herdr.send_literal(&identity, "bad\ntext", &Safe),
        Err(MuxError::InvalidSelector(_))
    ));
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["method"] == "pane_info")
            .count(),
        7
    );
    assert_eq!(
        requests
            .iter()
            .find(|r| r["method"] == "send_text")
            .unwrap()["params"]["text"],
        "-n; literal λ"
    );
    assert_eq!(
        requests
            .iter()
            .find(|r| r["method"] == "send_keys")
            .unwrap()["params"]["keys"],
        json!(["Enter"])
    );
}

#[test]
fn successful_send_has_precommit_and_postaction_composer_evidence() {
    let pid = std::process::id();
    let (_server, socket, _) = spawn_fake(move |request, _| {
        Some(response(
            &request,
            match request["method"].as_str().unwrap() {
                "pane_info" => pane_result(pid, 77),
                "send_text" => json!({"accepted":true}),
                other => panic!("unexpected {other}"),
            },
        ))
    });
    let herdr = Herdr::new(context(socket), Duration::from_millis(200)).unwrap();
    let identity = herdr.current_target().unwrap();
    let safety = CountingSafety(std::sync::atomic::AtomicUsize::new(0));
    herdr.send_literal(&identity, "hello", &safety).unwrap();
    assert_eq!(safety.0.load(std::sync::atomic::Ordering::SeqCst), 3);
}

#[test]
fn postaction_composer_refusal_is_not_claimed_as_success() {
    let pid = std::process::id();
    let (_server, socket, requests) = spawn_fake(move |request, _| {
        Some(response(
            &request,
            match request["method"].as_str().unwrap() {
                "pane_info" => pane_result(pid, 77),
                "send_keys" => json!({"accepted":true}),
                other => panic!("unexpected {other}"),
            },
        ))
    });
    let herdr = Herdr::new(context(socket), Duration::from_millis(200)).unwrap();
    let identity = herdr.current_target().unwrap();
    let safety = UnsafeAfterCommit(std::sync::atomic::AtomicUsize::new(0));
    assert!(matches!(
        herdr.send_key(&identity, SymbolicKey::Enter, &safety),
        Err(MuxError::IdentityChanged(_))
    ));
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["method"] == "send_keys")
    );
    assert_eq!(safety.0.load(std::sync::atomic::Ordering::SeqCst), 3);
}

#[test]
fn malformed_mismatched_timeout_oversize_and_replaced_identity_fail_closed() {
    let pid = std::process::id();
    let cases: Vec<Box<dyn Fn(Value) -> Option<Value> + Send>> = vec![
        Box::new(|_| Some(json!({"not":"a response"}))),
        Box::new(move |request| {
            let mut reply = response(&request, pane_result(pid, 77));
            reply["request_id"] = json!("wrong");
            Some(reply)
        }),
        Box::new(|_| {
            thread::sleep(Duration::from_millis(160));
            None
        }),
        Box::new(|request| Some(response(&request, json!({"blob":"x".repeat(300_000)})))),
    ];
    for handler in cases {
        let (_directory, socket, _) = spawn_fake(move |request, _| handler(request));
        let herdr = Herdr::new(context(socket), Duration::from_millis(40)).unwrap();
        let started = std::time::Instant::now();
        let error = herdr.current_target().unwrap_err();
        if matches!(error, MuxError::Timeout) {
            assert!(started.elapsed() >= Duration::from_millis(35));
            assert!(started.elapsed() < Duration::from_millis(120));
        }
    }
    let (_directory, socket, _) = spawn_fake(move |request, index| {
        Some(response(
            &request,
            pane_result(pid, if index == 0 { 77 } else { 78 }),
        ))
    });
    let herdr = Herdr::new(context(socket), Duration::from_millis(300)).unwrap();
    let identity = herdr.current_target().unwrap();
    assert!(matches!(
        herdr.send_key(&identity, SymbolicKey::Enter, &Safe),
        Err(MuxError::IdentityChanged(_))
    ));

    let (_directory, socket, requests) =
        spawn_fake(move |request, _| Some(response(&request, pane_result(pid, 77))));
    let herdr = Herdr::new(context(socket), Duration::from_millis(300)).unwrap();
    let identity = herdr.current_target().unwrap();
    assert!(matches!(
        herdr.send_key(&identity, SymbolicKey::Enter, &Unsafe),
        Err(MuxError::IdentityChanged(_))
    ));
    assert!(
        !requests
            .lock()
            .unwrap()
            .iter()
            .any(|request| request["method"] == "send_keys")
    );
}

#[test]
fn context_rejects_partial_or_unsafe_environment() {
    let values = [
        ("HERDR_SOCKET_PATH", "/tmp/h.sock"),
        ("HERDR_WORKSPACE_ID", "ws"),
        ("HERDR_TAB_ID", "tab"),
        ("HERDR_PANE_ID", "pane"),
    ];
    let complete = HerdrContext::from_values(|name| {
        values
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| (*value).into())
    })
    .unwrap();
    assert_eq!(complete.pane_id, "pane");
    assert!(
        HerdrContext::from_values(
            |name| (name == "HERDR_SOCKET_PATH").then(|| "/tmp/h.sock".into())
        )
        .is_err()
    );
    assert!(
        HerdrContext::from_values(|name| values.iter().find(|(key, _)| *key == name).map(
            |(_, value)| if name == "HERDR_PANE_ID" {
                "bad\n".into()
            } else {
                (*value).into()
            }
        ))
        .is_err()
    );
}

#[test]
fn response_envelope_rejects_wrong_schema_protocol_and_method() {
    let pid = std::process::id();
    for field in ["schema_version", "protocol", "method"] {
        let (_directory, socket, _) = spawn_fake(move |request, _| {
            let mut reply = response(&request, pane_result(pid, 77));
            reply[field] = match field {
                "schema_version" => json!(2),
                "protocol" => json!("other"),
                _ => json!("process_info"),
            };
            Some(reply)
        });
        let herdr = Herdr::new(context(socket), Duration::from_millis(200)).unwrap();
        assert!(matches!(herdr.current_target(), Err(MuxError::Protocol(_))));
    }
}

#[test]
fn drip_feed_cannot_extend_the_end_to_end_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("drip.sock");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        let mut request = String::new();
        BufReader::new(connection.try_clone().unwrap())
            .read_line(&mut request)
            .unwrap();
        for byte in b"{\"schema_version\":" {
            if connection.write_all(&[*byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(15));
        }
    });
    let herdr = Herdr::new(
        context(path.to_string_lossy().into_owned()),
        Duration::from_millis(55),
    )
    .unwrap();
    let started = std::time::Instant::now();
    assert!(matches!(herdr.current_target(), Err(MuxError::Timeout)));
    assert!(started.elapsed() >= Duration::from_millis(50));
    assert!(started.elapsed() < Duration::from_millis(140));
}

#[test]
fn socket_policy_rejects_aliases_types_owners_and_writable_modes() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("real.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    assert!(
        Herdr::new(
            context(socket.to_string_lossy().into_owned()),
            Duration::from_millis(50)
        )
        .is_ok()
    );
    let file = directory.path().join("file");
    std::fs::write(&file, b"not socket").unwrap();
    assert!(matches!(
        Herdr::new(
            context(file.to_string_lossy().into_owned()),
            Duration::from_millis(50)
        ),
        Err(MuxError::UnsafeSocket(_))
    ));
    let alias = directory.path().join("alias.sock");
    symlink(&socket, &alias).unwrap();
    assert!(matches!(
        Herdr::new(
            context(alias.to_string_lossy().into_owned()),
            Duration::from_millis(50)
        ),
        Err(MuxError::UnsafeSocket(_))
    ));
    let real_parent = directory.path().join("real-parent");
    std::fs::create_dir(&real_parent).unwrap();
    let nested = real_parent.join("nested.sock");
    let _nested_listener = UnixListener::bind(&nested).unwrap();
    let parent_alias = directory.path().join("parent-alias");
    symlink(&real_parent, &parent_alias).unwrap();
    // Directory aliases are resolved and then bound by device/inode; only a
    // leaf socket symlink is refused as an unsafe alias.
    assert!(
        Herdr::new(
            context(
                parent_alias
                    .join("nested.sock")
                    .to_string_lossy()
                    .into_owned()
            ),
            Duration::from_millis(50)
        )
        .is_ok()
    );
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o622)).unwrap();
    assert!(matches!(
        Herdr::new(
            context(socket.to_string_lossy().into_owned()),
            Duration::from_millis(50)
        ),
        Err(MuxError::UnsafeSocket(_))
    ));
    assert!(
        SocketMetadata {
            uid: u32::MAX,
            mode: 0o600,
            is_socket: true
        }
        .validate_for_uid(1000)
        .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn synchronous_adapter_is_safe_inside_daemon_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("async.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pid = std::process::id();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request_bytes = Vec::new();
        loop {
            let byte = tokio::io::AsyncReadExt::read_u8(&mut stream).await.unwrap();
            request_bytes.push(byte);
            if byte == b'\n' {
                break;
            }
        }
        let request: Value = serde_json::from_slice(&request_bytes).unwrap();
        let mut encoded = serde_json::to_vec(&response(&request, pane_result(pid, 77))).unwrap();
        encoded.push(b'\n');
        tokio::io::AsyncWriteExt::write_all(&mut stream, &encoded)
            .await
            .unwrap();
    });
    let herdr = Herdr::new(
        context(socket.to_string_lossy().into_owned()),
        Duration::from_millis(200),
    )
    .unwrap();
    assert!(matches!(herdr.current_target(), Err(MuxError::Command(_))));
    let timer_progressed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let progressed = Arc::clone(&timer_progressed);
    let timer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(5)).await;
        progressed.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    assert_eq!(herdr.current_target_async().await.unwrap().process.pid, pid);
    timer.await.unwrap();
    peer.await.unwrap();
    assert!(timer_progressed.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn connected_socket_evidence_fails_closed_on_replacement_credentials_and_query_errors() {
    let accepted = ConnectedSocketEvidence {
        path_device: 10,
        path_inode: 20,
        peer_uid: Ok(1000),
    };
    assert!(accepted.validate(10, 20, 1000).is_ok());
    for evidence in [
        ConnectedSocketEvidence {
            path_device: 10,
            path_inode: 21,
            peer_uid: Ok(1000),
        },
        ConnectedSocketEvidence {
            path_device: 10,
            path_inode: 20,
            peer_uid: Ok(1001),
        },
        ConnectedSocketEvidence {
            path_device: 10,
            path_inode: 20,
            peer_uid: Err("unsupported".into()),
        },
    ] {
        assert!(matches!(
            evidence.validate(10, 20, 1000),
            Err(MuxError::UnsafeSocket(_))
        ));
    }
}

#[derive(Debug)]
struct FixedEvidence(ConnectedSocketEvidence);

impl ConnectedSocketEvidenceProvider for FixedEvidence {
    fn evidence(&self, _: &tokio::net::UnixStream, _: &std::path::Path) -> ConnectedSocketEvidence {
        ConnectedSocketEvidence {
            path_device: self.0.path_device,
            path_inode: self.0.path_inode,
            peer_uid: self.0.peer_uid.clone(),
        }
    }
}

#[test]
fn adapter_rejects_injected_connected_replacement_peer_mismatch_and_query_failure() {
    let pid = std::process::id();
    for kind in ["inode", "uid", "query"] {
        let (_directory, socket, _) =
            spawn_fake(move |request, _| Some(response(&request, pane_result(pid, 77))));
        let metadata = std::fs::metadata(&socket).unwrap();
        let evidence = ConnectedSocketEvidence {
            path_device: metadata.dev(),
            path_inode: if kind == "inode" {
                metadata.ino() + 1
            } else {
                metadata.ino()
            },
            peer_uid: match kind {
                "uid" => Ok(u32::MAX),
                "query" => Err("credential API unavailable".into()),
                _ => Ok(rustix::process::geteuid().as_raw()),
            },
        };
        let herdr = Herdr::new_with_evidence_provider(
            context(socket),
            Duration::from_millis(200),
            Arc::new(FixedEvidence(evidence)),
        )
        .unwrap();
        assert!(matches!(
            herdr.current_target(),
            Err(MuxError::UnsafeSocket(_))
        ));
    }
}

#[test]
fn response_success_and_error_are_an_exact_non_null_union() {
    let pid = std::process::id();
    type ResponseMutation = Box<dyn Fn(&mut Value) + Send>;
    let mutations: Vec<ResponseMutation> = vec![
        Box::new(|reply| reply["error"] = json!("must not coexist")),
        Box::new(|reply| {
            reply["ok"] = json!(false);
            reply["error"] = json!("denied");
        }),
        Box::new(|reply| {
            reply.as_object_mut().unwrap().remove("result");
        }),
        Box::new(|reply| reply["result"] = Value::Null),
        Box::new(|reply| {
            reply["ok"] = json!(false);
            reply.as_object_mut().unwrap().remove("result");
        }),
        Box::new(|reply| {
            reply["ok"] = json!(false);
            reply.as_object_mut().unwrap().remove("result");
            reply["error"] = Value::Null;
        }),
    ];
    for mutate in mutations {
        let (_directory, socket, _) = spawn_fake(move |request, _| {
            let mut reply = response(&request, pane_result(pid, 77));
            mutate(&mut reply);
            Some(reply)
        });
        let herdr = Herdr::new(context(socket), Duration::from_millis(200)).unwrap();
        assert!(matches!(herdr.current_target(), Err(MuxError::Protocol(_))));
    }
    let (_directory, socket, _) = spawn_fake(move |request, _| {
        let mut reply = response(&request, pane_result(pid, 77));
        reply["ok"] = json!(false);
        reply.as_object_mut().unwrap().remove("result");
        reply["error"] = json!("denied");
        Some(reply)
    });
    let herdr = Herdr::new(context(socket), Duration::from_millis(200)).unwrap();
    assert!(
        matches!(herdr.current_target(), Err(MuxError::Protocol(message)) if message == "denied")
    );
}
