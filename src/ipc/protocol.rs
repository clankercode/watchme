use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status {
        id: Option<String>,
    },
    List,
    Stop {
        id: Option<String>,
        all: bool,
    },
    Pause {
        id: String,
    },
    Resume {
        id: String,
    },
    WakeObservation {
        id: String,
        event_fingerprint: String,
    },
    Register {
        watcher: Box<crate::model::WatcherState>,
    },
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Status {
        running: bool,
        watchers: Vec<crate::model::WatcherState>,
    },
    Watchers {
        watchers: Vec<crate::model::WatcherState>,
    },
    Registered {
        watcher_id: String,
        existing: bool,
    },
    Updated {
        watcher: Box<crate::model::WatcherState>,
    },
    Stopped,
    Acknowledged,
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("IPC frame exceeds {MAX_FRAME_BYTES} bytes")]
    Oversized,
    #[error("malformed IPC frame: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("unsupported IPC protocol version {0}")]
    Version(u16),
}

#[derive(Serialize)]
struct EncodeEnvelope<'a, T> {
    version: u16,
    #[serde(flatten)]
    payload: &'a T,
}

#[derive(Deserialize)]
struct DecodeEnvelope<T> {
    version: u16,
    #[serde(flatten)]
    payload: T,
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let bytes = serde_json::to_vec(&EncodeEnvelope {
        version: PROTOCOL_VERSION,
        payload: value,
    })?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::Oversized);
    }
    Ok(bytes)
}

pub fn decode_frame<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::Oversized);
    }
    let envelope: DecodeEnvelope<T> = serde_json::from_slice(bytes)?;
    if envelope.version != PROTOCOL_VERSION {
        return Err(ProtocolError::Version(envelope.version));
    }
    Ok(envelope.payload)
}
