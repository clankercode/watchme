use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;
use watchme::mux::herdr::{Herdr, HerdrContext};
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

fn response(request: &Value, result: Value) -> Value {
    json!({
        "schema_version": 1,
        "protocol": PROTOCOL,
        "request_id": request["request_id"],
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

fn spawn_fake<F>(handler: F) -> (TempDir, String, Arc<Mutex<Vec<Value>>>)
where
    F: Fn(Value, usize) -> Option<Value> + Send + 'static,
{
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("herdr.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&requests);
    thread::spawn(move || {
        for (index, connection) in listener.incoming().enumerate() {
            let mut connection = connection.unwrap();
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
    (directory, path.to_string_lossy().into_owned(), requests)
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
    assert_eq!(
        (
            identity.server.as_str(),
            identity.session_id.as_str(),
            identity.window_id.as_str(),
            identity.pane_id.as_str()
        ),
        (socket.as_str(), "ws-1", "tab-2", "pane-3")
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
fn malformed_mismatched_timeout_oversize_and_replaced_identity_fail_closed() {
    let pid = std::process::id();
    let cases: Vec<Box<dyn Fn(Value) -> Option<Value> + Send>> = vec![
        Box::new(|_| Some(json!({"not":"a response"}))),
        Box::new(move |request| {
            let mut reply = response(&request, pane_result(pid, 77));
            reply["request_id"] = json!("wrong");
            Some(reply)
        }),
        Box::new(|_| None),
        Box::new(|request| Some(response(&request, json!({"blob":"x".repeat(300_000)})))),
    ];
    for handler in cases {
        let (_directory, socket, _) = spawn_fake(move |request, _| handler(request));
        let herdr = Herdr::new(context(socket), Duration::from_millis(40)).unwrap();
        assert!(herdr.current_target().is_err());
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
