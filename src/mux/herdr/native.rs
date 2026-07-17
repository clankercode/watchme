use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{
    Herdr, MAX_REQUEST_BYTES, next_request_id, require_safe, validate_literal, validate_socket,
};
use crate::model::{HerdrWireProtocol, ProcessIdentity};
use crate::mux::{Capture, ComposerSafety, Multiplexer, MuxError, MuxIdentity};
use crate::process::ProcessInspector;

pub const PROTOCOL: u32 = 16;

#[derive(Serialize)]
pub(super) struct Request<'a, P> {
    pub id: &'a str,
    pub method: &'a str,
    pub params: P,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Success<T> {
    id: String,
    result: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    id: String,
    error: ErrorBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorBody {
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum ResultValue {
    Pong { version: String, protocol: u32 },
    PaneCurrent { pane: Pane },
    PaneProcessInfo { process_info: ProcessInfo },
    PaneRead { read: ReadResult },
    Ok,
}

#[derive(Debug, Deserialize)]
pub(super) struct Pane {
    pub pane_id: String,
    pub workspace_id: String,
    pub tab_id: String,
    pub revision: u64,
}

#[derive(Debug, Deserialize)]
pub(super) struct ProcessInfo {
    pub pane_id: String,
    pub tty: Option<String>,
    #[serde(default)]
    pub foreground_processes: Vec<ForegroundProcess>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ForegroundProcess {
    pub pid: u32,
}

#[derive(Debug, Deserialize)]
pub(super) struct ReadResult {
    pub pane_id: String,
    pub workspace_id: String,
    pub tab_id: String,
    pub source: String,
    pub format: String,
    pub text: String,
    pub revision: u64,
    pub truncated: bool,
}

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8], id: &str) -> Result<T, String> {
    if let Ok(success) = serde_json::from_slice::<Success<T>>(bytes) {
        if success.id != id {
            return Err(format!(
                "native response ID mismatch: expected {id:?}, got {:?}",
                success.id
            ));
        }
        return Ok(success.result);
    }
    let failure: Failure = serde_json::from_slice(bytes)
        .map_err(|error| format!("malformed native response: {error}"))?;
    if failure.id != id {
        return Err(format!(
            "native error response ID mismatch: expected {id:?}, got {:?}",
            failure.id
        ));
    }
    Err(format!("{}: {}", failure.error.code, failure.error.message))
}

impl Herdr {
    /// Resolve a native Herdr pane only when it contains the exact process that
    /// registration already established independently.
    pub fn current_target_for_process(
        &self,
        expected: &ProcessIdentity,
    ) -> Result<MuxIdentity, MuxError> {
        if self.context.wire_protocol == HerdrWireProtocol::Native16 {
            return self.native_target(expected);
        }
        match self.current_target() {
            Ok(identity) => {
                if identity.process.pid == expected.pid
                    && identity.process.start_time == expected.start_time
                {
                    Ok(identity)
                } else {
                    Err(MuxError::IdentityChanged(
                        "bridge pane process differs from resolved process".into(),
                    ))
                }
            }
            Err(MuxError::IncompatibleProtocol(_))
                if self.context.wire_protocol == HerdrWireProtocol::Auto =>
            {
                self.native_target(expected)
            }
            Err(error) => Err(error),
        }
    }

    pub async fn current_target_for_process_async(
        &self,
        expected: &ProcessIdentity,
    ) -> Result<MuxIdentity, MuxError> {
        if self.context.wire_protocol == HerdrWireProtocol::Native16 {
            return self
                .native_target_snapshot_async(expected)
                .await
                .map(|(identity, _)| identity);
        }
        match self.current_target_async().await {
            Ok(identity) => {
                if identity.process.pid == expected.pid
                    && identity.process.start_time == expected.start_time
                {
                    Ok(identity)
                } else {
                    Err(MuxError::IdentityChanged(
                        "bridge pane process differs from resolved process".into(),
                    ))
                }
            }
            Err(MuxError::IncompatibleProtocol(_))
                if self.context.wire_protocol == HerdrWireProtocol::Auto =>
            {
                self.native_target_snapshot_async(expected)
                    .await
                    .map(|(identity, _)| identity)
            }
            Err(error) => Err(error),
        }
    }

    fn native_target(&self, expected: &ProcessIdentity) -> Result<MuxIdentity, MuxError> {
        self.native_target_snapshot(expected)
            .map(|(identity, _)| identity)
    }

    fn native_target_snapshot(
        &self,
        expected: &ProcessIdentity,
    ) -> Result<(MuxIdentity, u64), MuxError> {
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
            .block_on(self.native_target_snapshot_async(expected))
    }

    async fn native_target_snapshot_async(
        &self,
        expected: &ProcessIdentity,
    ) -> Result<(MuxIdentity, u64), MuxError> {
        let socket = validate_socket(Path::new(&self.context.socket_path))?;
        let (version, protocol) = match self
            .call_native_async("ping", serde_json::json!({}))
            .await?
        {
            ResultValue::Pong { version, protocol } => (version, protocol),
            _ => {
                return Err(MuxError::Protocol(
                    "native ping returned wrong result type".into(),
                ));
            }
        };
        if protocol != PROTOCOL {
            return Err(MuxError::IncompatibleProtocol(format!(
                "native Herdr protocol {protocol} is unsupported"
            )));
        }
        let pane = match self
            .call_native_async(
                "pane.current",
                serde_json::json!({"caller_pane_id": self.context.pane_id}),
            )
            .await?
        {
            ResultValue::PaneCurrent { pane } => pane,
            _ => {
                return Err(MuxError::Protocol(
                    "native pane.current returned wrong result type".into(),
                ));
            }
        };
        if pane.workspace_id != self.context.workspace_id
            || pane.tab_id != self.context.tab_id
            || pane.pane_id != self.context.pane_id
        {
            return Err(MuxError::IdentityChanged(
                "native Herdr pane context differs from registration context".into(),
            ));
        }
        let process_info = match self
            .call_native_async(
                "pane.process_info",
                serde_json::json!({"pane_id": self.context.pane_id}),
            )
            .await?
        {
            ResultValue::PaneProcessInfo { process_info } => process_info,
            _ => {
                return Err(MuxError::Protocol(
                    "native pane.process_info returned wrong result type".into(),
                ));
            }
        };
        if process_info.pane_id != self.context.pane_id
            || !process_info
                .foreground_processes
                .iter()
                .any(|process| process.pid == expected.pid)
        {
            return Err(MuxError::IdentityChanged(
                "native Herdr pane does not contain the registered process".into(),
            ));
        }
        let expected_tty = expected.tty.as_deref().ok_or_else(|| {
            MuxError::IdentityChanged("resolved process has no controlling TTY".into())
        })?;
        if process_info
            .tty
            .as_deref()
            .is_some_and(|observed_tty| !native_tty_matches(expected_tty, observed_tty))
        {
            return Err(MuxError::IdentityChanged(
                "native Herdr pane TTY differs from the registered process".into(),
            ));
        }
        revalidate_process_identity(expected)?;
        let revision = pane.revision;
        Ok((
            MuxIdentity {
                provider: "herdr".into(),
                server_instance: format!(
                    "native-{version}-protocol-{protocol}-{}-{}",
                    socket.device, socket.inode
                ),
                server: self.context.socket_path.clone(),
                session_id: pane.workspace_id,
                window_id: pane.tab_id,
                pane_id: pane.pane_id,
                tty: expected_tty.into(),
                process: expected.clone(),
            },
            revision,
        ))
    }

    pub(super) fn capture_native(
        &self,
        identity: &MuxIdentity,
        lines: usize,
        max_bytes: usize,
    ) -> Result<Capture, MuxError> {
        let started = Instant::now();
        let actual = self.current_target_for_process(&identity.process)?;
        if &actual != identity {
            return Err(MuxError::IdentityChanged(
                "native Herdr target changed before pane read".into(),
            ));
        }
        let read = match self.call_native(
            "pane.read",
            serde_json::json!({
                "pane_id": self.context.pane_id,
                "source": "recent_unwrapped",
                "lines": lines,
                "strip_ansi": true
            }),
        )? {
            ResultValue::PaneRead { read } => read,
            _ => {
                return Err(MuxError::Protocol(
                    "native pane.read returned wrong result type".into(),
                ));
            }
        };
        if read.pane_id != self.context.pane_id
            || read.workspace_id != self.context.workspace_id
            || read.tab_id != self.context.tab_id
            || read.source != "recent_unwrapped"
            || read.format != "plain"
            || read.text.len() > max_bytes
        {
            return Err(MuxError::Protocol(
                "native pane.read violated response contract".into(),
            ));
        }
        let _ = read.revision;
        Ok(Capture {
            bytes: read.text.len(),
            text: read.text,
            truncated: read.truncated,
            elapsed: started.elapsed(),
        })
    }

    pub(super) fn submit_native(
        &self,
        identity: &MuxIdentity,
        text: &str,
        safety: &dyn ComposerSafety,
    ) -> Result<(), MuxError> {
        validate_literal(text)?;
        let revision = self.validate_native_identity_at_revision(identity)?;
        require_safe(safety, identity)?;
        let confirmed_revision = self.validate_native_identity_at_revision(identity)?;
        if confirmed_revision != revision {
            return Err(MuxError::IdentityChanged(
                "native Herdr pane revision changed before input dispatch".into(),
            ));
        }
        require_safe(safety, identity)?;
        match self.call_native_committing(
            "pane.send_input",
            serde_json::json!({
                "pane_id": self.context.pane_id,
                "text": text,
                "keys": ["Enter"]
            }),
        )? {
            ResultValue::Ok => Ok(()),
            _ => Err(MuxError::CommandOutcomeUnknown(
                "native pane.send_input returned an unexpected acknowledgement".into(),
            )),
        }
    }

    pub(super) fn validate_native_identity(&self, expected: &MuxIdentity) -> Result<(), MuxError> {
        self.validate_native_identity_at_revision(expected)
            .map(drop)
    }

    fn validate_native_identity_at_revision(
        &self,
        expected: &MuxIdentity,
    ) -> Result<u64, MuxError> {
        let (actual, revision) = self.native_target_snapshot(&expected.process)?;
        if &actual == expected {
            Ok(revision)
        } else {
            Err(MuxError::IdentityChanged(
                "native Herdr target identity changed".into(),
            ))
        }
    }

    fn call_native<P: Serialize>(&self, method: &str, params: P) -> Result<ResultValue, MuxError> {
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
            .block_on(self.call_native_async(method, params))
    }

    fn call_native_committing<P: Serialize>(
        &self,
        method: &str,
        params: P,
    ) -> Result<ResultValue, MuxError> {
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
            .block_on(self.call_native_committing_async(method, params))
    }

    async fn call_native_async<P: Serialize>(
        &self,
        method: &str,
        params: P,
    ) -> Result<ResultValue, MuxError> {
        let started = Instant::now();
        let request_id = next_request_id()?;
        let request = Request {
            id: &request_id,
            method,
            params,
        };
        let mut encoded =
            serde_json::to_vec(&request).map_err(|error| MuxError::Protocol(error.to_string()))?;
        if encoded.len() >= MAX_REQUEST_BYTES {
            return Err(MuxError::Protocol("request exceeds byte limit".into()));
        }
        encoded.push(b'\n');
        let bytes = self.exchange_async(encoded, started).await?;
        decode(&bytes, &request_id).map_err(MuxError::Protocol)
    }

    async fn call_native_committing_async<P: Serialize>(
        &self,
        method: &str,
        params: P,
    ) -> Result<ResultValue, MuxError> {
        let started = Instant::now();
        let request_id = next_request_id()?;
        let request = Request {
            id: &request_id,
            method,
            params,
        };
        let mut encoded =
            serde_json::to_vec(&request).map_err(|error| MuxError::Protocol(error.to_string()))?;
        if encoded.len() >= MAX_REQUEST_BYTES {
            return Err(MuxError::Protocol("request exceeds byte limit".into()));
        }
        encoded.push(b'\n');
        let bytes = self.exchange_committing_async(encoded, started).await?;
        decode(&bytes, &request_id).map_err(MuxError::CommandOutcomeUnknown)
    }
}

fn native_tty_matches(expected: &str, observed: &str) -> bool {
    if normalized_tty(expected) == normalized_tty(observed) {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        let canonical = |tty: &str| {
            tty.starts_with("/dev/")
                .then(|| crate::process::linux::canonical_tty_path(Path::new(tty)).ok())
                .flatten()
        };
        canonical(expected).as_deref() == Some(observed)
            || canonical(observed).as_deref() == Some(expected)
    }
    #[cfg(not(target_os = "linux"))]
    false
}

fn normalized_tty(tty: &str) -> &str {
    tty.strip_prefix("/dev/").unwrap_or(tty)
}

fn revalidate_process_identity(expected: &ProcessIdentity) -> Result<(), MuxError> {
    #[cfg(target_os = "linux")]
    let inspector = crate::process::linux::LinuxProcessInspector::default();
    #[cfg(target_os = "macos")]
    let inspector = crate::process::macos::MacOsProcessInspector::default();
    let observed = inspector.inspect(expected.pid).map_err(|error| {
        MuxError::IdentityChanged(format!("could not revalidate process identity: {error}"))
    })?;
    if observed.pid != expected.pid || observed.start_time != expected.start_time {
        return Err(MuxError::IdentityChanged(
            "registered process identity changed during native Herdr resolution".into(),
        ));
    }
    Ok(())
}
