use std::collections::BTreeMap;
use std::time::Duration;

use crate::ipc::protocol::Response;
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatcherSchedule {
    pub id: String,
    pub paused: bool,
}

#[derive(Debug)]
pub enum SchedulerEvent {
    Register(String),
    Pause(String),
    Resume(String),
    Stop(String),
    Shutdown,
    Snapshot(oneshot::Sender<Vec<WatcherSchedule>>),
}

#[derive(Clone)]
pub struct SchedulerHandle {
    sender: mpsc::UnboundedSender<SchedulerEvent>,
}
pub struct Scheduler {
    receiver: mpsc::UnboundedReceiver<SchedulerEvent>,
    idle_grace: Duration,
    stay_resident: bool,
}

impl Scheduler {
    pub fn new(idle_grace: Duration, stay_resident: bool) -> (SchedulerHandle, Self) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (
            SchedulerHandle { sender },
            Self {
                receiver,
                idle_grace,
                stay_resident,
            },
        )
    }

    pub async fn run(mut self) -> Response {
        let mut watchers = BTreeMap::new();
        loop {
            let event = if watchers.is_empty() && !self.stay_resident {
                match tokio::time::timeout(self.idle_grace, self.receiver.recv()).await {
                    Ok(event) => event,
                    Err(_) => return Response::Stopped,
                }
            } else {
                self.receiver.recv().await
            };
            match event {
                Some(SchedulerEvent::Register(id)) => {
                    watchers.insert(id, false);
                }
                Some(SchedulerEvent::Pause(id)) => {
                    if let Some(paused) = watchers.get_mut(&id) {
                        *paused = true;
                    }
                }
                Some(SchedulerEvent::Resume(id)) => {
                    if let Some(paused) = watchers.get_mut(&id) {
                        *paused = false;
                    }
                }
                Some(SchedulerEvent::Stop(id)) => {
                    watchers.remove(&id);
                }
                Some(SchedulerEvent::Snapshot(reply)) => {
                    let _ = reply.send(
                        watchers
                            .iter()
                            .map(|(id, paused)| WatcherSchedule {
                                id: id.clone(),
                                paused: *paused,
                            })
                            .collect(),
                    );
                }
                Some(SchedulerEvent::Shutdown) | None => return Response::Stopped,
            }
        }
    }
}

impl SchedulerHandle {
    pub fn send(
        &self,
        event: SchedulerEvent,
    ) -> Result<(), mpsc::error::SendError<SchedulerEvent>> {
        self.sender.send(event)
    }
    pub async fn snapshot(&self) -> Result<Vec<WatcherSchedule>, &'static str> {
        let (sender, receiver) = oneshot::channel();
        self.send(SchedulerEvent::Snapshot(sender))
            .map_err(|_| "scheduler stopped")?;
        receiver.await.map_err(|_| "scheduler stopped")
    }
}
