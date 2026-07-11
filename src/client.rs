use std::io;
use std::time::Duration;

use crate::ipc::protocol::{Request, Response};
use crate::ipc::{read_response, write_request};
use crate::model::WatcherState;
use crate::paths::WatchmePaths;

#[derive(Clone, Debug)]
pub struct ResolvedRegistration {
    pub watcher: WatcherState,
}

pub async fn register_resolved(
    paths: &WatchmePaths,
    registration: ResolvedRegistration,
) -> io::Result<Response> {
    let mut stream =
        tokio::net::UnixStream::connect(paths.runtime_dir().join("daemon.sock")).await?;
    write_request(
        &mut stream,
        &Request::Register {
            watcher: Box::new(registration.watcher),
        },
        Duration::from_secs(2),
    )
    .await
    .map_err(io::Error::other)?;
    read_response(&mut stream, Duration::from_secs(2))
        .await
        .map_err(io::Error::other)
}
