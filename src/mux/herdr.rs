use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    Capture, ComposerSafety, ComposerState, Multiplexer, MuxError, MuxIdentity, PaneInfo,
    SymbolicKey,
};
use crate::model::ProcessIdentity;

pub const HERDR_PROTOCOL: &str = "watchme.herdr";
pub const HERDR_SCHEMA_VERSION: u16 = 1;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_REQUEST_BYTES: usize = 256 * 1024;
const MAX_CAPTURE_LINES: usize = 10_000;
const MAX_CAPTURE_BYTES: usize = 128 * 1024;
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
static REQUEST_NONCE: std::sync::LazyLock<u128> = std::sync::LazyLock::new(|| {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
});

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HerdrContext {
    pub socket_path: String,
    pub workspace_id: String,
    pub tab_id: String,
    pub pane_id: String,
}

impl HerdrContext {
    pub fn from_environment() -> Result<Self, MuxError> {
        Self::from_values(|name| std::env::var(name).ok())
    }

    pub fn from_values(mut value: impl FnMut(&str) -> Option<String>) -> Result<Self, MuxError> {
        let required = |name: &str, value: Option<String>| {
            let value = value.ok_or_else(|| MuxError::Command(format!("{name} is not set")))?;
            validate_context(name, &value)?;
            Ok(value)
        };
        Ok(Self {
            socket_path: required("HERDR_SOCKET_PATH", value("HERDR_SOCKET_PATH"))?,
            workspace_id: required("HERDR_WORKSPACE_ID", value("HERDR_WORKSPACE_ID"))?,
            tab_id: required("HERDR_TAB_ID", value("HERDR_TAB_ID"))?,
            pane_id: required("HERDR_PANE_ID", value("HERDR_PANE_ID"))?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Herdr {
    context: HerdrContext,
    timeout: Duration,
    evidence_provider: std::sync::Arc<dyn ConnectedSocketEvidenceProvider>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketMetadata {
    pub uid: u32,
    pub mode: u32,
    pub is_socket: bool,
}

impl SocketMetadata {
    pub fn validate_for_uid(self, expected_uid: u32) -> Result<(), MuxError> {
        if !self.is_socket {
            return Err(MuxError::UnsafeSocket("path is not a Unix socket".into()));
        }
        if self.uid != expected_uid {
            return Err(MuxError::UnsafeSocket(
                "socket is not owned by the current user".into(),
            ));
        }
        if self.mode & 0o022 != 0 {
            return Err(MuxError::UnsafeSocket(
                "socket is writable by group or others".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentSession {
    pub session_id: String,
    pub agent: String,
    pub process_id: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentEvent {
    pub sequence: u64,
    pub kind: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AgentStateEvents {
    pub state: String,
    pub events: Vec<AgentEvent>,
}

#[derive(Serialize)]
struct Request<'a, P> {
    schema_version: u16,
    protocol: &'static str,
    request_id: &'a str,
    method: &'a str,
    params: P,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response<T> {
    schema_version: u16,
    protocol: String,
    request_id: String,
    method: String,
    ok: bool,
    result: Option<T>,
    error: Option<String>,
}

#[derive(Serialize)]
struct TargetParams<'a> {
    workspace_id: &'a str,
    tab_id: &'a str,
    pane_id: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProcess {
    pid: u32,
    start_time: u64,
    executable: Option<String>,
    argv_digest: Option<String>,
    uid: Option<u32>,
    process_group_id: Option<u32>,
    session_leader_id: Option<u32>,
    tty: Option<String>,
    parent_digest: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePane {
    server_id: String,
    workspace_id: String,
    workspace_name: String,
    tab_id: String,
    tab_title: String,
    tab_index: u32,
    pane_id: String,
    pane_title: String,
    pane_index: u32,
    tty: String,
    current_command: String,
    current_path: String,
    process: WireProcess,
}

impl Herdr {
    pub fn new(context: HerdrContext, timeout: Duration) -> Result<Self, MuxError> {
        Self::new_with_evidence_provider(context, timeout, std::sync::Arc::new(SystemEvidence))
    }

    pub fn new_with_evidence_provider(
        mut context: HerdrContext,
        timeout: Duration,
        evidence_provider: std::sync::Arc<dyn ConnectedSocketEvidenceProvider>,
    ) -> Result<Self, MuxError> {
        if timeout.is_zero() {
            return Err(MuxError::Protocol("timeout must be non-zero".into()));
        }
        let identity = validate_socket(Path::new(&context.socket_path))?;
        // Persist the physical path so later connects do not re-traverse macOS
        // `/var` → `/private/var` aliases that fail a strict path equality check.
        context.socket_path = identity.canonical_path;
        Ok(Self {
            context,
            timeout,
            evidence_provider,
        })
    }

    pub fn agent_session(&self, identity: &MuxIdentity) -> Result<AgentSession, MuxError> {
        self.validate_identity(identity)?;
        self.call("agent_session", self.target_params())
    }

    pub fn agent_state_events(
        &self,
        identity: &MuxIdentity,
        after: u64,
        max_events: usize,
    ) -> Result<AgentStateEvents, MuxError> {
        self.validate_identity(identity)?;
        if max_events == 0 || max_events > 1_000 {
            return Err(MuxError::Protocol("max_events is out of bounds".into()));
        }
        #[derive(Serialize)]
        struct Params<'a> {
            workspace_id: &'a str,
            tab_id: &'a str,
            pane_id: &'a str,
            after: u64,
            max_events: usize,
        }
        self.call(
            "agent_state_events",
            Params {
                workspace_id: &self.context.workspace_id,
                tab_id: &self.context.tab_id,
                pane_id: &self.context.pane_id,
                after,
                max_events,
            },
        )
    }

    pub async fn agent_state_events_async(
        &self,
        expected: &MuxIdentity,
        after: u64,
        max_events: usize,
    ) -> Result<AgentStateEvents, MuxError> {
        if max_events == 0 || max_events > 1_000 {
            return Err(MuxError::Protocol("max_events is out of bounds".into()));
        }
        if &self.current_target_async().await? != expected {
            return Err(MuxError::IdentityChanged("Herdr target changed".into()));
        }
        #[derive(Serialize)]
        struct Params<'a> {
            workspace_id: &'a str,
            tab_id: &'a str,
            pane_id: &'a str,
            after: u64,
            max_events: usize,
        }
        self.call_async(
            "agent_state_events",
            Params {
                workspace_id: &self.context.workspace_id,
                tab_id: &self.context.tab_id,
                pane_id: &self.context.pane_id,
                after,
                max_events,
            },
        )
        .await
    }

    pub async fn capture_tail_async(
        &self,
        expected: &MuxIdentity,
        lines: usize,
        max_bytes: usize,
    ) -> Result<Capture, MuxError> {
        if lines == 0
            || lines > MAX_CAPTURE_LINES
            || max_bytes == 0
            || max_bytes > MAX_CAPTURE_BYTES
        {
            return Err(MuxError::Protocol("pane read bounds exceeded".into()));
        }
        if &self.current_target_async().await? != expected {
            return Err(MuxError::IdentityChanged("Herdr target changed".into()));
        }
        #[derive(Serialize)]
        struct Params<'a> {
            workspace_id: &'a str,
            tab_id: &'a str,
            pane_id: &'a str,
            max_lines: usize,
            max_bytes: usize,
            recent_unwrapped: bool,
            detect_state: bool,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ReadResult {
            text: String,
            bytes: usize,
            truncated: bool,
        }
        let started = Instant::now();
        let result: ReadResult = self
            .call_async(
                "pane_read",
                Params {
                    workspace_id: &self.context.workspace_id,
                    tab_id: &self.context.tab_id,
                    pane_id: &self.context.pane_id,
                    max_lines: lines,
                    max_bytes,
                    recent_unwrapped: true,
                    detect_state: true,
                },
            )
            .await?;
        if result.bytes > max_bytes || result.text.len() != result.bytes {
            return Err(MuxError::Protocol(
                "pane read violated byte contract".into(),
            ));
        }
        if &self.current_target_async().await? != expected {
            return Err(MuxError::IdentityChanged("Herdr target changed".into()));
        }
        Ok(Capture {
            text: result.text,
            bytes: result.bytes,
            truncated: result.truncated,
            elapsed: started.elapsed(),
        })
    }

    pub fn notify(
        &self,
        identity: &MuxIdentity,
        title: &str,
        body: &str,
    ) -> Result<bool, MuxError> {
        self.validate_identity(identity)?;
        validate_literal(title)?;
        validate_literal(body)?;
        #[derive(Serialize)]
        struct Params<'a> {
            workspace_id: &'a str,
            tab_id: &'a str,
            pane_id: &'a str,
            title: &'a str,
            body: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ResultValue {
            delivered: bool,
        }
        Ok(self
            .call::<_, ResultValue>(
                "notification",
                Params {
                    workspace_id: &self.context.workspace_id,
                    tab_id: &self.context.tab_id,
                    pane_id: &self.context.pane_id,
                    title,
                    body,
                },
            )?
            .delivered)
    }

    fn target_params(&self) -> TargetParams<'_> {
        TargetParams {
            workspace_id: &self.context.workspace_id,
            tab_id: &self.context.tab_id,
            pane_id: &self.context.pane_id,
        }
    }

    fn pane(&self, method: &str) -> Result<PaneInfo, MuxError> {
        self.call::<_, WirePane>(method, self.target_params())
            .map(|pane| self.map_pane(pane))
    }

    async fn pane_async(&self, method: &str) -> Result<PaneInfo, MuxError> {
        self.call_async::<_, WirePane>(method, self.target_params())
            .await
            .map(|pane| self.map_pane(pane))
    }

    pub async fn current_target_async(&self) -> Result<MuxIdentity, MuxError> {
        Ok(self.pane_async("pane_info").await?.identity)
    }

    fn map_pane(&self, pane: WirePane) -> PaneInfo {
        let mut process = ProcessIdentity::new(pane.process.pid, pane.process.start_time);
        process.executable = pane.process.executable;
        process.argv_digest = pane.process.argv_digest;
        process.uid = pane.process.uid;
        process.process_group_id = pane.process.process_group_id;
        process.session_leader_id = pane.process.session_leader_id;
        process.tty = pane.process.tty;
        process.parent_digest = pane.process.parent_digest;
        PaneInfo {
            identity: MuxIdentity {
                provider: "herdr".into(),
                server_instance: pane.server_id.clone(),
                server: self.context.socket_path.clone(),
                session_id: pane.workspace_id,
                window_id: pane.tab_id,
                pane_id: pane.pane_id,
                tty: pane.tty,
                process,
            },
            server_id: pane.server_id,
            session_name: pane.workspace_name,
            window_name: pane.tab_title,
            window_index: pane.tab_index,
            pane_index: pane.pane_index,
            pane_title: pane.pane_title,
            current_command: pane.current_command,
            current_path: pane.current_path,
            dead: false,
            dead_status: None,
            started_at: None,
            dead_at: None,
        }
    }

    fn call<P: Serialize, T: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<T, MuxError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(MuxError::Command(
                "synchronous Herdr request cannot run inside a Tokio runtime; use the async API"
                    .into(),
            ));
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|error| MuxError::Command(error.to_string()))?
            .block_on(self.call_async(method, params))
    }

    async fn call_async<P: Serialize, T: DeserializeOwned>(
        &self,
        method: &str,
        params: P,
    ) -> Result<T, MuxError> {
        let started = Instant::now();
        let socket_identity = validate_socket(Path::new(&self.context.socket_path))?;
        let sequence = NEXT_REQUEST_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| MuxError::Protocol("request ID space exhausted".into()))?;
        let request_id = format!(
            "watchme-{}-{}-{sequence}",
            std::process::id(),
            *REQUEST_NONCE
        );
        let request = Request {
            schema_version: HERDR_SCHEMA_VERSION,
            protocol: HERDR_PROTOCOL,
            request_id: &request_id,
            method,
            params,
        };
        let mut encoded =
            serde_json::to_vec(&request).map_err(|error| MuxError::Protocol(error.to_string()))?;
        if encoded.len() >= MAX_REQUEST_BYTES {
            return Err(MuxError::Protocol("request exceeds byte limit".into()));
        }
        encoded.push(b'\n');
        let deadline = started.checked_add(self.timeout).ok_or(MuxError::Timeout)?;
        let socket_path = self.context.socket_path.clone();
        let evidence_provider = std::sync::Arc::clone(&self.evidence_provider);
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(MuxError::Timeout)?;
        let bytes = tokio::time::timeout(remaining, async move {
            let mut stream = tokio::net::UnixStream::connect(&socket_path)
                .await
                .map_err(map_io)?;
            verify_connected_socket(
                &stream,
                Path::new(&socket_path),
                socket_identity,
                evidence_provider.as_ref(),
            )?;
            stream.write_all(&encoded).await.map_err(map_io)?;
            let mut bytes = Vec::new();
            loop {
                let byte = stream.read_u8().await.map_err(map_io)?;
                bytes.push(byte);
                if bytes.len() > MAX_RESPONSE_BYTES || byte == b'\n' {
                    break;
                }
            }
            Ok::<_, MuxError>(bytes)
        })
        .await
        .map_err(|_| MuxError::Timeout)??;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(MuxError::Protocol("response exceeds byte limit".into()));
        }
        if !bytes.ends_with(b"\n") {
            return Err(MuxError::Protocol(
                "response is not newline terminated".into(),
            ));
        }
        let response: Response<T> = match serde_json::from_slice(&bytes) {
            Ok(response) => response,
            Err(_) if is_native_response(&bytes) => {
                return Err(MuxError::IncompatibleProtocol(
                    "native Herdr socket API does not implement the watchme.herdr bridge".into(),
                ));
            }
            Err(error) => {
                return Err(MuxError::Protocol(format!("malformed response: {error}")));
            }
        };
        if started.elapsed() >= self.timeout {
            return Err(MuxError::Timeout);
        }
        if response.schema_version != HERDR_SCHEMA_VERSION
            || response.protocol != HERDR_PROTOCOL
            || response.request_id != request_id
            || response.method != method
        {
            return Err(MuxError::Protocol(
                "response contract or request ID mismatch".into(),
            ));
        }
        if response.ok {
            if response.error.is_some() {
                return Err(MuxError::Protocol(
                    "successful response must omit error".into(),
                ));
            }
            return response.result.ok_or_else(|| {
                MuxError::Protocol("successful response must contain non-null result".into())
            });
        }
        if response.result.is_some() {
            return Err(MuxError::Protocol(
                "failed response must omit result".into(),
            ));
        }
        let error = response.error.ok_or_else(|| {
            MuxError::Protocol("failed response must contain non-null error".into())
        })?;
        Err(MuxError::Protocol(error))
    }
}

fn is_native_response(bytes: &[u8]) -> bool {
    let Ok(serde_json::Value::Object(response)) = serde_json::from_slice(bytes) else {
        return false;
    };
    if !matches!(response.get("id"), Some(serde_json::Value::String(_))) {
        return false;
    }
    match (response.get("result"), response.get("error")) {
        (Some(result), None) => !result.is_null(),
        (None, Some(serde_json::Value::Object(error))) => {
            matches!(error.get("code"), Some(serde_json::Value::String(_)))
                && matches!(error.get("message"), Some(serde_json::Value::String(_)))
        }
        _ => false,
    }
}

impl Multiplexer for Herdr {
    type Selector = HerdrContext;
    fn current_target(&self) -> Result<MuxIdentity, MuxError> {
        Ok(self.pane("pane_info")?.identity)
    }
    fn resolve_selector(&self, selector: &Self::Selector) -> Result<MuxIdentity, MuxError> {
        if selector != &self.context {
            return Err(MuxError::IdentityChanged(
                "selector differs from inherited Herdr context".into(),
            ));
        }
        self.current_target()
    }
    fn pane_info(&self, identity: &MuxIdentity) -> Result<PaneInfo, MuxError> {
        self.validate_identity(identity)?;
        self.pane("process_info")
    }
    fn validate_identity(&self, expected: &MuxIdentity) -> Result<(), MuxError> {
        let actual = self.pane("pane_info")?.identity;
        if &actual == expected {
            Ok(())
        } else {
            Err(MuxError::IdentityChanged(format!(
                "expected {expected:?}, found {actual:?}"
            )))
        }
    }
    fn capture_tail(
        &self,
        identity: &MuxIdentity,
        lines: usize,
        max_bytes: usize,
    ) -> Result<Capture, MuxError> {
        if lines == 0 || max_bytes == 0 {
            return Ok(Capture {
                text: String::new(),
                bytes: 0,
                truncated: false,
                elapsed: Duration::ZERO,
            });
        }
        if lines > MAX_CAPTURE_LINES || max_bytes > MAX_CAPTURE_BYTES {
            return Err(MuxError::Protocol("pane read bounds exceeded".into()));
        }
        self.validate_identity(identity)?;
        #[derive(Serialize)]
        struct Params<'a> {
            workspace_id: &'a str,
            tab_id: &'a str,
            pane_id: &'a str,
            max_lines: usize,
            max_bytes: usize,
            recent_unwrapped: bool,
            detect_state: bool,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ReadResult {
            text: String,
            bytes: usize,
            truncated: bool,
        }
        let started = Instant::now();
        let result: ReadResult = self.call(
            "pane_read",
            Params {
                workspace_id: &self.context.workspace_id,
                tab_id: &self.context.tab_id,
                pane_id: &self.context.pane_id,
                max_lines: lines,
                max_bytes,
                recent_unwrapped: true,
                detect_state: true,
            },
        )?;
        if result.bytes > max_bytes || result.text.len() != result.bytes {
            return Err(MuxError::Protocol(
                "pane read violated byte contract".into(),
            ));
        }
        self.validate_identity(identity)?;
        Ok(Capture {
            text: result.text,
            bytes: result.bytes,
            truncated: result.truncated,
            elapsed: started.elapsed(),
        })
    }
    fn send_literal(
        &self,
        identity: &MuxIdentity,
        text: &str,
        safety: &dyn ComposerSafety,
    ) -> Result<(), MuxError> {
        validate_literal(text)?;
        self.validate_identity(identity)?;
        require_safe(safety, identity)?;
        self.validate_identity(identity)?;
        require_safe(safety, identity)?;
        #[derive(Serialize)]
        struct Params<'a> {
            workspace_id: &'a str,
            tab_id: &'a str,
            pane_id: &'a str,
            text: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Accepted {
            accepted: bool,
        }
        let accepted: Accepted = self.call(
            "send_text",
            Params {
                workspace_id: &self.context.workspace_id,
                tab_id: &self.context.tab_id,
                pane_id: &self.context.pane_id,
                text,
            },
        )?;
        if !accepted.accepted {
            return Err(MuxError::Protocol("Herdr refused literal input".into()));
        }
        self.validate_identity(identity)?;
        require_safe(safety, identity)
    }
    fn send_key(
        &self,
        identity: &MuxIdentity,
        key: SymbolicKey,
        safety: &dyn ComposerSafety,
    ) -> Result<(), MuxError> {
        self.validate_identity(identity)?;
        require_safe(safety, identity)?;
        self.validate_identity(identity)?;
        require_safe(safety, identity)?;
        #[derive(Serialize)]
        struct Params<'a> {
            workspace_id: &'a str,
            tab_id: &'a str,
            pane_id: &'a str,
            keys: [&'a str; 1],
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Accepted {
            accepted: bool,
        }
        let accepted: Accepted = self.call(
            "send_keys",
            Params {
                workspace_id: &self.context.workspace_id,
                tab_id: &self.context.tab_id,
                pane_id: &self.context.pane_id,
                keys: [key_name(key)],
            },
        )?;
        if !accepted.accepted {
            return Err(MuxError::Protocol("Herdr refused symbolic input".into()));
        }
        self.validate_identity(identity)?;
        require_safe(safety, identity)
    }
}

fn key_name(key: SymbolicKey) -> &'static str {
    match key {
        SymbolicKey::Enter => "Enter",
        SymbolicKey::Escape => "Escape",
        SymbolicKey::Up => "Up",
        SymbolicKey::Down => "Down",
        SymbolicKey::Left => "Left",
        SymbolicKey::Right => "Right",
        SymbolicKey::Tab => "Tab",
        SymbolicKey::Backspace => "Backspace",
    }
}
fn require_safe(safety: &dyn ComposerSafety, identity: &MuxIdentity) -> Result<(), MuxError> {
    match safety.observe(identity)? {
        ComposerState::Safe => Ok(()),
        state => Err(MuxError::IdentityChanged(format!(
            "composer safety is {state:?}"
        ))),
    }
}
fn validate_literal(value: &str) -> Result<(), MuxError> {
    if value.chars().any(char::is_control) {
        Err(MuxError::InvalidSelector(
            "literal contains a control character".into(),
        ))
    } else {
        Ok(())
    }
}
fn validate_context(name: &str, value: &str) -> Result<(), MuxError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        Err(MuxError::Protocol(format!("invalid {name}")))
    } else {
        Ok(())
    }
}
fn map_io(error: std::io::Error) -> MuxError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        MuxError::Timeout
    } else {
        MuxError::Command(error.to_string())
    }
}

#[derive(Clone)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    canonical_path: String,
}

#[derive(Debug)]
pub struct ConnectedSocketEvidence {
    pub path_device: u64,
    pub path_inode: u64,
    pub peer_uid: Result<u32, String>,
}

pub trait ConnectedSocketEvidenceProvider: std::fmt::Debug + Send + Sync {
    fn evidence(&self, stream: &tokio::net::UnixStream, path: &Path) -> ConnectedSocketEvidence;
}

#[derive(Debug)]
struct SystemEvidence;

impl ConnectedSocketEvidenceProvider for SystemEvidence {
    fn evidence(&self, stream: &tokio::net::UnixStream, path: &Path) -> ConnectedSocketEvidence {
        match fs::symlink_metadata(path) {
            Ok(metadata) => ConnectedSocketEvidence {
                path_device: metadata.dev(),
                path_inode: metadata.ino(),
                peer_uid: stream
                    .peer_cred()
                    .map(|credentials| credentials.uid())
                    .map_err(|error| error.to_string()),
            },
            Err(error) => ConnectedSocketEvidence {
                path_device: 0,
                path_inode: 0,
                peer_uid: Err(format!("socket metadata query failed: {error}")),
            },
        }
    }
}

impl ConnectedSocketEvidence {
    pub fn validate(
        &self,
        expected_device: u64,
        expected_inode: u64,
        expected_uid: u32,
    ) -> Result<(), MuxError> {
        if self.path_device != expected_device || self.path_inode != expected_inode {
            return Err(MuxError::UnsafeSocket(
                "socket identity changed while connecting".into(),
            ));
        }
        let peer_uid = self.peer_uid.as_ref().map_err(|error| {
            MuxError::UnsafeSocket(format!("peer credential query failed: {error}"))
        })?;
        if *peer_uid != expected_uid {
            return Err(MuxError::UnsafeSocket(
                "connected Herdr peer has a different UID".into(),
            ));
        }
        Ok(())
    }
}

fn validate_socket(path: &Path) -> Result<SocketIdentity, MuxError> {
    if !path.is_absolute() {
        return Err(MuxError::UnsafeSocket("path is not absolute".into()));
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|error| MuxError::UnsafeSocket(error.to_string()))?;
    // Reject only a leaf alias. Intermediate directory symlinks (macOS `/var`,
    // or a parent dir link) are resolved and then bound by device/inode so a
    // later replacement still fails closed.
    if metadata.file_type().is_symlink() {
        return Err(MuxError::UnsafeSocket(
            "socket path contains a symlink or alias".into(),
        ));
    }
    let canonical =
        fs::canonicalize(path).map_err(|error| MuxError::UnsafeSocket(error.to_string()))?;
    SocketMetadata {
        uid: metadata.uid(),
        mode: metadata.mode(),
        is_socket: metadata.file_type().is_socket(),
    }
    .validate_for_uid(rustix::process::geteuid().as_raw())?;
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        canonical_path: canonical.to_string_lossy().into_owned(),
    })
}

fn verify_connected_socket(
    stream: &tokio::net::UnixStream,
    path: &Path,
    expected: SocketIdentity,
    evidence_provider: &dyn ConnectedSocketEvidenceProvider,
) -> Result<(), MuxError> {
    evidence_provider.evidence(stream, path).validate(
        expected.device,
        expected.inode,
        rustix::process::geteuid().as_raw(),
    )
}
