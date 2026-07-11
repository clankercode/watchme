pub mod protocol;

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use protocol::{MAX_FRAME_BYTES, ProtocolError, Request, Response, decode_frame, encode_frame};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("IPC operation timed out")]
    Timeout,
}

pub fn bind_owner_only(path: &Path) -> io::Result<UnixListener> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket has no parent"))?;
    let metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socket parent is not owner-only",
        ));
    }
    if fs::symlink_metadata(path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "socket path already exists",
        ));
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub fn validate_peer_uid(peer_uid: u32, owner_uid: u32) -> io::Result<()> {
    if peer_uid == owner_uid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "IPC peer is not the daemon owner",
        ))
    }
}

pub fn validate_stream_owner(stream: &UnixStream, owner_uid: u32) -> io::Result<()> {
    let credentials = rustix::net::sockopt::socket_peercred(stream).map_err(io::Error::from)?;
    validate_peer_uid(credentials.uid.as_raw(), owner_uid)
}

pub async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
    timeout: Duration,
) -> Result<Request, IpcError> {
    tokio::time::timeout(timeout, read_frame(reader))
        .await
        .map_err(|_| IpcError::Timeout)?
}

pub async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &Response,
    timeout: Duration,
) -> Result<(), IpcError> {
    tokio::time::timeout(timeout, write_frame(writer, response))
        .await
        .map_err(|_| IpcError::Timeout)?
}

pub async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request: &Request,
    timeout: Duration,
) -> Result<(), IpcError> {
    tokio::time::timeout(timeout, write_frame(writer, request))
        .await
        .map_err(|_| IpcError::Timeout)?
}

pub async fn read_response<R: AsyncRead + Unpin>(
    reader: &mut R,
    timeout: Duration,
) -> Result<Response, IpcError> {
    tokio::time::timeout(timeout, read_frame(reader))
        .await
        .map_err(|_| IpcError::Timeout)?
}

async fn read_frame<T: serde::de::DeserializeOwned, R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<T, IpcError> {
    let length = reader.read_u32().await? as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::Oversized.into());
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    Ok(decode_frame(&bytes)?)
}

async fn write_frame<T: serde::Serialize, W: AsyncWrite + Unpin>(
    writer: &mut W,
    value: &T,
) -> Result<(), IpcError> {
    let bytes = encode_frame(value)?;
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}
