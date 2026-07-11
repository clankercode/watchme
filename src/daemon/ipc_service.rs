//! Owner-authenticated daemon IPC request handling.
//!
//! The daemon loop owns listener lifetime and shutdown sequencing. This module
//! owns individual peer authentication, framing, validation, and registry
//! mutations so those concerns do not leak into recovery orchestration.

use std::sync::Arc;
use std::time::Duration;

use super::{PeerCredentialProvider, Registry, SchedulerHandle, WatcherLifecycle, now_ms};
use crate::daemon::registry::{RegistrationOutcome, RegistryError};
use crate::daemon::scheduler::SchedulerEvent;
use crate::ipc::protocol::{Request, Response};
use crate::ipc::{read_request, write_response};

pub(super) struct ShutdownSignal {
    pub(super) acknowledged: tokio::sync::oneshot::Sender<()>,
    pub(super) response_written: tokio::sync::oneshot::Receiver<()>,
}

pub(super) async fn acknowledge_shutdown_requests(
    first: ShutdownSignal,
    receiver: &mut tokio::sync::mpsc::UnboundedReceiver<ShutdownSignal>,
    timeout: Duration,
) {
    // Let concurrently accepted IPC tasks enqueue their already-requested
    // shutdown before acknowledging any of them. This keeps repeated requests
    // idempotent without leaving a second client blocked.
    tokio::task::yield_now().await;
    let mut signals = vec![first];
    while let Ok(signal) = receiver.try_recv() {
        signals.push(signal);
    }
    let responses = signals
        .into_iter()
        .map(|signal| {
            let _ = signal.acknowledged.send(());
            signal.response_written
        })
        .collect::<Vec<_>>();
    for response_written in responses {
        let _ = tokio::time::timeout(timeout, response_written).await;
    }
}

pub(super) async fn service_connection<P: PeerCredentialProvider>(
    mut stream: tokio::net::UnixStream,
    registry: Arc<tokio::sync::Mutex<Registry>>,
    scheduler: SchedulerHandle,
    peer_credentials: Arc<P>,
    shutdown_sender: tokio::sync::mpsc::UnboundedSender<ShutdownSignal>,
    timeout: Duration,
) {
    match peer_credentials.effective_uid(&stream) {
        Ok(uid) if uid == rustix::process::geteuid().as_raw() => {}
        Ok(_) => {
            eprintln!("watchme daemon: denied IPC peer with mismatched effective UID");
            return;
        }
        Err(error) => {
            eprintln!("watchme daemon: could not validate IPC peer: {error}");
            return;
        }
    }
    let request = match read_request(&mut stream, timeout).await {
        Ok(request) => request,
        Err(error) => {
            eprintln!("watchme daemon: rejected IPC request: {error}");
            let _ = write_response(
                &mut stream,
                &Response::Error {
                    code: "invalid_request".into(),
                    message: error.to_string(),
                },
                timeout,
            )
            .await;
            return;
        }
    };
    if let Some(response) = validation_error(&request) {
        let _ = write_response(&mut stream, &response, timeout).await;
        return;
    }
    if matches!(request, Request::Shutdown) {
        return request_shutdown(&mut stream, shutdown_sender, timeout).await;
    }
    let response = {
        let mut registry = registry.lock().await;
        handle_request(&mut registry, &scheduler, request).unwrap_or_else(|error| Response::Error {
            code: "daemon_error".into(),
            message: error.to_string(),
        })
    };
    if let Err(error) = write_response(&mut stream, &response, timeout).await {
        eprintln!("watchme daemon: IPC response failed: {error}");
    }
}

async fn request_shutdown(
    stream: &mut tokio::net::UnixStream,
    shutdown_sender: tokio::sync::mpsc::UnboundedSender<ShutdownSignal>,
    timeout: Duration,
) {
    let (acknowledged, acknowledgement) = tokio::sync::oneshot::channel();
    let (written, response_written) = tokio::sync::oneshot::channel();
    if shutdown_sender
        .send(ShutdownSignal {
            acknowledged,
            response_written,
        })
        .is_err()
    {
        let _ = write_response(
            stream,
            &Response::Error {
                code: "daemon_stopping".into(),
                message: "daemon shutdown coordinator is unavailable".into(),
            },
            timeout,
        )
        .await;
        return;
    }
    if acknowledgement.await.is_err() {
        return;
    }
    let _ = write_response(stream, &Response::Stopped, timeout).await;
    let _ = written.send(());
}

fn validation_error(request: &Request) -> Option<Response> {
    if request_has_empty_target(request) {
        return Some(Response::Error {
            code: "invalid_target".into(),
            message: "target ID must not be empty".into(),
        });
    }
    if matches!(
        request,
        Request::Stop {
            id: None,
            all: false
        }
    ) {
        return Some(Response::Error {
            code: "invalid_request".into(),
            message: "stop requires a watcher ID or --all".into(),
        });
    }
    None
}

fn request_has_empty_target(request: &Request) -> bool {
    match request {
        Request::Status { id } | Request::Stop { id, .. } => {
            id.as_ref().is_some_and(String::is_empty)
        }
        Request::Pause { id } | Request::Resume { id } | Request::WakeObservation { id, .. } => {
            id.is_empty()
        }
        Request::List | Request::Register { .. } | Request::Shutdown => false,
    }
}

fn handle_request(
    registry: &mut Registry,
    scheduler: &SchedulerHandle,
    request: Request,
) -> Result<Response, RegistryError> {
    match request {
        Request::Status { id } => Ok(Response::Status {
            running: true,
            watchers: id.map_or_else(
                || registry.list(),
                |id| registry.get(&id).cloned().into_iter().collect(),
            ),
        }),
        Request::List => Ok(Response::Watchers {
            watchers: registry.list(),
        }),
        Request::WakeObservation {
            id,
            event_fingerprint,
        } => registry
            .wake_observation(&id, &event_fingerprint, now_ms())
            .map(|()| Response::Acknowledged),
        Request::Register { watcher } => registry.register(*watcher).map(|outcome| match outcome {
            RegistrationOutcome::Added(watcher_id) => {
                let _ = scheduler.send(SchedulerEvent::Register(watcher_id.clone()));
                Response::Registered {
                    watcher_id,
                    existing: false,
                }
            }
            RegistrationOutcome::Existing(watcher_id) => Response::Registered {
                watcher_id,
                existing: true,
            },
        }),
        Request::Stop { id, all } => {
            let ids: Vec<String> = if all {
                registry
                    .list()
                    .into_iter()
                    .map(|watcher| watcher.watcher_id)
                    .collect()
            } else {
                id.into_iter().collect()
            };
            let result = ids
                .into_iter()
                .try_for_each(|id| {
                    registry.transition(
                        &id,
                        WatcherLifecycle::Stopped {
                            reason: "requested".into(),
                        },
                        now_ms(),
                    )
                })
                .map(|()| Response::Stopped);
            for id in registry
                .list()
                .into_iter()
                .filter(|watcher| matches!(watcher.lifecycle, WatcherLifecycle::Stopped { .. }))
                .map(|watcher| watcher.watcher_id)
            {
                let _ = scheduler.send(SchedulerEvent::Stop(id));
            }
            result
        }
        Request::Pause { id } => registry
            .transition(&id, WatcherLifecycle::Paused, now_ms())
            .map(|()| {
                let _ = scheduler.send(SchedulerEvent::Pause(id.clone()));
                Response::Updated {
                    watcher: Box::new(
                        registry
                            .get(&id)
                            .expect("transitioned watcher exists")
                            .clone(),
                    ),
                }
            }),
        Request::Resume { id } => registry
            .transition(&id, WatcherLifecycle::Observing, now_ms())
            .map(|()| {
                let _ = scheduler.send(SchedulerEvent::Resume(id.clone()));
                Response::Updated {
                    watcher: Box::new(
                        registry
                            .get(&id)
                            .expect("transitioned watcher exists")
                            .clone(),
                    ),
                }
            }),
        Request::Shutdown => Ok(Response::Stopped),
    }
}
