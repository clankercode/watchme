use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use watchme::model::{HerdrWireProtocol, ProcessIdentity};
use watchme::mux::herdr::{
    ConnectedSocketEvidence, ConnectedSocketEvidenceProvider, Herdr, HerdrContext, SocketMetadata,
};
use watchme::mux::{
    ComposerSafety, ComposerState, Multiplexer, MuxError, MuxIdentity, SymbolicKey,
};
use watchme::process::ProcessInspector;

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
        wire_protocol: HerdrWireProtocol::Auto,
    }
}

fn native_response(request: &Value, result: Value) -> Value {
    json!({"id": request["id"], "result": result})
}

#[derive(Clone, Copy)]
struct NativeIdentityFixture {
    protocol: u32,
    workspace_id: &'static str,
    tab_id: &'static str,
    pane_id: &'static str,
    process_pid: u32,
    tty: Option<&'static str>,
    response_id: Option<&'static str>,
}

impl NativeIdentityFixture {
    fn valid(process_pid: u32) -> Self {
        Self {
            protocol: 16,
            workspace_id: "ws-1",
            tab_id: "tab-2",
            pane_id: "pane-3",
            process_pid,
            tty: Some("/dev/pts/8"),
            response_id: None,
        }
    }
}

fn spawn_native_identity_fake(
    fixture: NativeIdentityFixture,
) -> (FakeServer, String, Arc<Mutex<Vec<Value>>>) {
    spawn_fake(move |request, _| {
        if request.get("protocol").is_some() {
            return Some(json!({
                "id": "",
                "error": {
                    "code": "invalid_request",
                    "message": "missing field id"
                }
            }));
        }
        let result = match request["method"].as_str().unwrap() {
            "ping" => json!({
                "type": "pong",
                "version": "0.7.4",
                "protocol": fixture.protocol
            }),
            "pane.current" => json!({
                "type": "pane_current",
                "pane": {
                    "pane_id": fixture.pane_id,
                    "terminal_id": "term-1",
                    "workspace_id": fixture.workspace_id,
                    "tab_id": fixture.tab_id,
                    "focused": true,
                    "agent_status": "working",
                    "revision": 7,
                    "cwd": "/repo",
                    "foreground_cwd": "/repo"
                }
            }),
            "pane.process_info" => json!({
                "type": "pane_process_info",
                "process_info": {
                    "pane_id": fixture.pane_id,
                    "tty": fixture.tty,
                    "foreground_processes": [{
                        "pid": fixture.process_pid,
                        "name": "codex",
                        "argv": ["codex"]
                    }]
                }
            }),
            method => panic!("unexpected native request {method}"),
        };
        let mut response = native_response(&request, result);
        if let Some(response_id) = fixture.response_id {
            response["id"] = Value::String(response_id.into());
        }
        Some(response)
    })
}

fn spawn_native_io_fake(process_pid: u32) -> (FakeServer, String, Arc<Mutex<Vec<Value>>>) {
    spawn_fake(move |request, _| {
        let result = match request["method"].as_str().unwrap() {
            "ping" => json!({"type":"pong", "version":"0.7.4", "protocol":16}),
            "pane.current" => json!({
                "type":"pane_current",
                "pane": {"pane_id":"pane-3", "workspace_id":"ws-1", "tab_id":"tab-2",
                    "revision":7}
            }),
            "pane.process_info" => json!({
                "type":"pane_process_info",
                "process_info": {"pane_id":"pane-3", "tty":"/dev/pts/8",
                    "foreground_processes":[{"pid":process_pid}]}
            }),
            "pane.read" => json!({
                "type":"pane_read",
                "read": {"pane_id":"pane-3", "workspace_id":"ws-1", "tab_id":"tab-2",
                    "source":"recent_unwrapped", "format":"plain",
                    "text":"Selected model is at capacity. Please try a different model.",
                    "revision":7, "truncated":false}
            }),
            "pane.send_input" => json!({"type":"ok"}),
            method => panic!("unexpected native request {method}"),
        };
        Some(native_response(&request, result))
    })
}

fn spawn_native_revision_change_fake(
    process_pid: u32,
) -> (FakeServer, String, Arc<Mutex<Vec<Value>>>) {
    let pane_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    spawn_fake(move |request, _| {
        let result = match request["method"].as_str().unwrap() {
            "ping" => json!({"type":"pong", "version":"0.7.4", "protocol":16}),
            "pane.current" => {
                let read = pane_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                json!({"type":"pane_current", "pane": {"pane_id":"pane-3",
                    "workspace_id":"ws-1", "tab_id":"tab-2",
                    "revision": if read < 2 { 7 } else { 8 }}})
            }
            "pane.process_info" => json!({"type":"pane_process_info", "process_info": {
                "pane_id":"pane-3", "tty":"/dev/pts/8",
                "foreground_processes":[{"pid":process_pid}]}}),
            "pane.send_input" => json!({"type":"ok"}),
            method => panic!("unexpected native request {method}"),
        };
        Some(native_response(&request, result))
    })
}

fn spawn_native_send_without_ack_fake(
    process_pid: u32,
) -> (FakeServer, String, Arc<Mutex<Vec<Value>>>) {
    spawn_fake(move |request, _| {
        let result = match request["method"].as_str().unwrap() {
            "ping" => json!({"type":"pong", "version":"0.7.4", "protocol":16}),
            "pane.current" => json!({"type":"pane_current", "pane": {"pane_id":"pane-3",
                "workspace_id":"ws-1", "tab_id":"tab-2", "revision":7}}),
            "pane.process_info" => json!({"type":"pane_process_info", "process_info": {
                "pane_id":"pane-3", "tty":"/dev/pts/8",
                "foreground_processes":[{"pid":process_pid}]}}),
            "pane.send_input" => return None,
            method => panic!("unexpected native request {method}"),
        };
        Some(native_response(&request, result))
    })
}

fn current_process_start_time() -> u64 {
    #[cfg(target_os = "linux")]
    let inspector = watchme::process::linux::LinuxProcessInspector::default();
    #[cfg(target_os = "macos")]
    let inspector = watchme::process::macos::MacOsProcessInspector::default();
    inspector.inspect(std::process::id()).unwrap().start_time
}

#[test]
fn native_protocol_16_correlates_exact_pane_and_process() {
    let pid = std::process::id();
    let (_server, socket, requests) = spawn_native_identity_fake(NativeIdentityFixture::valid(pid));
    let mut process = ProcessIdentity::new(pid, current_process_start_time());
    process.tty = Some("/dev/pts/8".into());
    let herdr = Herdr::new(context(socket), Duration::from_millis(300)).unwrap();

    let identity = herdr.current_target_for_process(&process).unwrap();

    assert_eq!(identity.provider, "herdr");
    assert_eq!(identity.pane_id, "pane-3");
    assert_eq!(identity.process, process);
    assert!(identity.server_instance.contains("protocol-16"));
    let requests = requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .any(|request| request["method"] == "pane.current")
    );
    assert!(
        requests
            .iter()
            .any(|request| request["method"] == "pane.process_info")
    );
}

#[test]
fn native_protocol_other_than_16_is_incompatible() {
    let pid = std::process::id();
    let fixture = NativeIdentityFixture {
        protocol: 17,
        ..NativeIdentityFixture::valid(pid)
    };
    let (_server, socket, _) = spawn_native_identity_fake(fixture);
    let mut process = ProcessIdentity::new(pid, current_process_start_time());
    process.tty = Some("/dev/pts/8".into());
    let herdr = Herdr::new(context(socket), Duration::from_millis(300)).unwrap();

    let error = herdr.current_target_for_process(&process).unwrap_err();

    assert!(matches!(error, MuxError::IncompatibleProtocol(_)));
}

#[test]
fn native_response_id_must_match_request() {
    let pid = std::process::id();
    let fixture = NativeIdentityFixture {
        response_id: Some("wrong-request"),
        ..NativeIdentityFixture::valid(pid)
    };
    let (_server, socket, _) = spawn_native_identity_fake(fixture);
    let mut process = ProcessIdentity::new(pid, current_process_start_time());
    process.tty = Some("/dev/pts/8".into());
    let herdr = Herdr::new(context(socket), Duration::from_millis(300)).unwrap();

    let error = herdr.current_target_for_process(&process).unwrap_err();

    assert!(matches!(error, MuxError::Protocol(message) if message.contains("ID mismatch")));
}

#[test]
fn native_pane_must_match_registration_context() {
    let pid = std::process::id();
    let fixture = NativeIdentityFixture {
        workspace_id: "other-workspace",
        ..NativeIdentityFixture::valid(pid)
    };
    let (_server, socket, _) = spawn_native_identity_fake(fixture);
    let mut process = ProcessIdentity::new(pid, current_process_start_time());
    process.tty = Some("/dev/pts/8".into());
    let herdr = Herdr::new(context(socket), Duration::from_millis(300)).unwrap();

    let error = herdr.current_target_for_process(&process).unwrap_err();

    assert!(matches!(
        error,
        MuxError::IdentityChanged(message) if message.contains("pane context")
    ));
}

#[test]
fn native_pane_must_contain_registered_process() {
    let pid = std::process::id();
    let fixture = NativeIdentityFixture {
        process_pid: pid.saturating_add(10_000),
        ..NativeIdentityFixture::valid(pid)
    };
    let (_server, socket, _) = spawn_native_identity_fake(fixture);
    let mut process = ProcessIdentity::new(pid, current_process_start_time());
    process.tty = Some("/dev/pts/8".into());
    let herdr = Herdr::new(context(socket), Duration::from_millis(300)).unwrap();

    let error = herdr.current_target_for_process(&process).unwrap_err();

    assert!(matches!(
        error,
        MuxError::IdentityChanged(message) if message.contains("registered process")
    ));
}

#[test]
fn native_pane_tty_must_match_registered_process() {
    let pid = std::process::id();
    let fixture = NativeIdentityFixture {
        tty: Some("/dev/pts/99"),
        ..NativeIdentityFixture::valid(pid)
    };
    let (_server, socket, _) = spawn_native_identity_fake(fixture);
    let mut process = ProcessIdentity::new(pid, current_process_start_time());
    process.tty = Some("/dev/pts/8".into());
    let herdr = Herdr::new(context(socket), Duration::from_millis(300)).unwrap();

    let error = herdr.current_target_for_process(&process).unwrap_err();

    assert!(matches!(
        error,
        MuxError::IdentityChanged(message) if message.contains("TTY")
    ));
}

#[test]
fn native_optional_tty_may_be_absent_when_exact_pane_pid_matches() {
    let pid = std::process::id();
    let fixture = NativeIdentityFixture {
        tty: None,
        ..NativeIdentityFixture::valid(pid)
    };
    let (_server, socket, _) = spawn_native_identity_fake(fixture);
    let mut process = ProcessIdentity::new(pid, current_process_start_time());
    process.tty = Some("dev:136:1".into());
    let herdr = Herdr::new(context(socket), Duration::from_millis(300)).unwrap();

    let identity = herdr.current_target_for_process(&process).unwrap();

    assert_eq!(identity.process, process);
    assert_eq!(identity.tty, "dev:136:1");
}

#[test]
fn native_target_revalidates_process_start_time() {
    let pid = std::process::id();
    let (_server, socket, _) = spawn_native_identity_fake(NativeIdentityFixture::valid(pid));
    let mut process = ProcessIdentity::new(pid, current_process_start_time().saturating_add(1));
    process.tty = Some("/dev/pts/8".into());
    let herdr = Herdr::new(context(socket), Duration::from_millis(300)).unwrap();

    let error = herdr.current_target_for_process(&process).unwrap_err();

    assert!(matches!(
        error,
        MuxError::IdentityChanged(message) if message.contains("process identity")
    ));
}

#[test]
fn persisted_native_dialect_skips_bridge_probe() {
    let pid = std::process::id();
    let (_server, socket, requests) = spawn_native_identity_fake(NativeIdentityFixture::valid(pid));
    let mut process = ProcessIdentity::new(pid, current_process_start_time());
    process.tty = Some("/dev/pts/8".into());
    let mut native_context = context(socket);
    native_context.wire_protocol = HerdrWireProtocol::Native16;
    let herdr = Herdr::new(native_context, Duration::from_millis(300)).unwrap();

    herdr.current_target_for_process(&process).unwrap();

    let requests = requests.lock().unwrap();
    assert_eq!(requests[0]["method"], "ping");
    assert!(
        requests
            .iter()
            .all(|request| request.get("protocol").is_none())
    );
}

#[test]
fn native_capture_and_submit_are_bounded_and_atomic() {
    let pid = std::process::id();
    let (_server, socket, requests) = spawn_native_io_fake(pid);
    let mut process = ProcessIdentity::new(pid, current_process_start_time());
    process.tty = Some("/dev/pts/8".into());
    let mut native_context = context(socket);
    native_context.wire_protocol = HerdrWireProtocol::Native16;
    let herdr = Herdr::new(native_context, Duration::from_millis(300)).unwrap();
    let identity = herdr.current_target_for_process(&process).unwrap();

    let capture = herdr.capture_tail(&identity, 20, 4096).unwrap();
    assert_eq!(
        capture.text,
        "Selected model is at capacity. Please try a different model."
    );
    herdr
        .submit_literal(&identity, "/goal resume", &Safe)
        .unwrap();

    let requests = requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .any(|request| request["method"] == "pane.read"
                && request["params"]["source"] == "recent_unwrapped"
                && request["params"]["lines"] == 20
                && request["params"]["strip_ansi"] == true)
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request["method"] == "pane.send_input")
            .count(),
        1
    );
    let send = requests
        .iter()
        .find(|request| request["method"] == "pane.send_input")
        .unwrap();
    assert_eq!(
        send["params"],
        json!({"pane_id":"pane-3", "text":"/goal resume", "keys":["Enter"]})
    );
}

#[test]
fn native_submit_refuses_revision_change_before_dispatch() {
    let pid = std::process::id();
    let (_server, socket, requests) = spawn_native_revision_change_fake(pid);
    let mut process = ProcessIdentity::new(pid, current_process_start_time());
    process.tty = Some("/dev/pts/8".into());
    let mut native_context = context(socket);
    native_context.wire_protocol = HerdrWireProtocol::Native16;
    let herdr = Herdr::new(native_context, Duration::from_millis(300)).unwrap();
    let identity = herdr.current_target_for_process(&process).unwrap();

    let error = herdr
        .submit_literal(&identity, "/goal resume", &Safe)
        .unwrap_err();

    assert!(matches!(
        error,
        MuxError::IdentityChanged(message) if message.contains("revision")
    ));
    assert!(
        requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| request["method"] != "pane.send_input")
    );
}

#[test]
fn native_submit_without_ack_has_unknown_outcome() {
    let pid = std::process::id();
    let (_server, socket, requests) = spawn_native_send_without_ack_fake(pid);
    let mut process = ProcessIdentity::new(pid, current_process_start_time());
    process.tty = Some("/dev/pts/8".into());
    let mut native_context = context(socket);
    native_context.wire_protocol = HerdrWireProtocol::Native16;
    let herdr = Herdr::new(native_context, Duration::from_millis(100)).unwrap();
    let identity = herdr.current_target_for_process(&process).unwrap();

    let error = herdr
        .submit_literal(&identity, "/goal resume", &Safe)
        .unwrap_err();

    assert!(matches!(error, MuxError::CommandOutcomeUnknown(_)));
    assert_eq!(
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["method"] == "pane.send_input")
            .count(),
        1
    );
}

#[test]
fn native_input_safety_and_read_bounds_fail_before_dispatch() {
    let pid = std::process::id();
    let (_server, socket, requests) = spawn_native_io_fake(pid);
    let mut process = ProcessIdentity::new(pid, current_process_start_time());
    process.tty = Some("/dev/pts/8".into());
    let mut native_context = context(socket);
    native_context.wire_protocol = HerdrWireProtocol::Native16;
    let herdr = Herdr::new(native_context, Duration::from_millis(300)).unwrap();
    let identity = herdr.current_target_for_process(&process).unwrap();

    assert!(
        herdr
            .submit_literal(&identity, "/goal resume", &Unsafe)
            .is_err()
    );
    let requests_after_unsafe = requests.lock().unwrap().len();
    assert!(herdr.capture_tail(&identity, 10_001, 4096).is_err());

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), requests_after_unsafe);
    assert!(
        requests
            .iter()
            .all(|request| request["method"] != "pane.send_input")
    );
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
fn native_herdr_response_is_a_typed_protocol_incompatibility() {
    let (_server, socket, _) = spawn_fake(|_, _| {
        Some(json!({
            "id": "",
            "error": {
                "code": "invalid_request",
                "message": "invalid request: missing field `id`"
            }
        }))
    });
    let herdr = Herdr::new(context(socket), Duration::from_millis(200)).unwrap();
    assert!(matches!(
        herdr.current_target(),
        Err(MuxError::IncompatibleProtocol(_))
    ));
}

#[test]
fn native_herdr_classifier_rejects_ambiguous_envelopes() {
    for reply in [
        json!({"id": "only-id"}),
        json!({"id": "bad-error", "error": {"code": "invalid_request"}}),
        json!({
            "id": "ambiguous",
            "result": {"type": "pong"},
            "error": {"code": "invalid_request", "message": "bad"}
        }),
    ] {
        let (_server, socket, _) = spawn_fake(move |_, _| Some(reply.clone()));
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
