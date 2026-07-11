//! Notification delivery with Herdr → desktop → stderr fallback.

use crate::config::NotificationsConfig;

type HerdrSend = Box<dyn Fn(&str, &str) -> Result<bool, String> + Send + Sync>;
type DesktopSend = Box<dyn Fn(&str, &str) -> Result<(), String> + Send + Sync>;
type StderrWriteFn<'a> = dyn Fn(&str) -> Result<(), String> + 'a;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyRequest {
    pub title: String,
    pub body: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotificationOutcome {
    Delivered { channel: &'static str },
    Suppressed { reason: String },
}

pub struct HerdrBackend {
    send: HerdrSend,
}

impl HerdrBackend {
    pub fn from_fn(
        send: impl Fn(&str, &str) -> Result<bool, String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            send: Box::new(send),
        }
    }

    pub fn try_send(&self, title: &str, body: &str) -> Result<bool, String> {
        (self.send)(title, body)
    }
}

pub struct DesktopBackend {
    send: DesktopSend,
}

impl DesktopBackend {
    pub fn from_fn(
        send: impl Fn(&str, &str) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            send: Box::new(send),
        }
    }

    pub fn system_default() -> Self {
        Self::from_fn(system_desktop_notify)
    }

    pub fn try_send(&self, title: &str, body: &str) -> Result<(), String> {
        (self.send)(title, body)
    }
}

pub struct NotifyTarget<'a> {
    pub herdr: Option<&'a HerdrBackend>,
    pub desktop: Option<&'a DesktopBackend>,
    pub stderr_write: Option<&'a StderrWriteFn<'a>>,
}

pub fn notify(
    config: &NotificationsConfig,
    request: &NotifyRequest,
    target: NotifyTarget<'_>,
) -> NotificationOutcome {
    deliver(config, request, target, false)
}

/// Best-effort notification for shutdown/cleanup paths. Never panics; failures
/// are swallowed into [`NotificationOutcome::Suppressed`].
pub fn notify_during_cleanup(
    config: &NotificationsConfig,
    request: &NotifyRequest,
    target: NotifyTarget<'_>,
) -> NotificationOutcome {
    deliver(config, request, target, true)
}

fn deliver(
    config: &NotificationsConfig,
    request: &NotifyRequest,
    target: NotifyTarget<'_>,
    cleanup: bool,
) -> NotificationOutcome {
    if config.herdr
        && let Some(herdr) = target.herdr
        && let Ok(true) = herdr.try_send(&request.title, &request.body)
    {
        return NotificationOutcome::Delivered { channel: "herdr" };
    }

    if config.desktop
        && let Some(desktop) = target.desktop
        && desktop.try_send(&request.title, &request.body).is_ok()
    {
        return NotificationOutcome::Delivered { channel: "desktop" };
    }

    if config.stderr
        && let Some(write) = target.stderr_write
    {
        let line = format!("watchme notify: {}: {}\n", request.title, request.body);
        match write(&line) {
            Ok(()) => return NotificationOutcome::Delivered { channel: "stderr" },
            Err(reason) if cleanup => {
                return NotificationOutcome::Suppressed { reason };
            }
            Err(_) => {}
        }
    }

    if cleanup {
        NotificationOutcome::Suppressed {
            reason: "all notification channels failed during cleanup".into(),
        }
    } else {
        NotificationOutcome::Suppressed {
            reason: "all notification channels failed".into(),
        }
    }
}

fn system_desktop_notify(title: &str, body: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if which("notify-send") {
            let status = std::process::Command::new("notify-send")
                .args([title, body])
                .status()
                .map_err(|error| error.to_string())?;
            if status.success() {
                return Ok(());
            }
            return Err("notify-send failed".into());
        }
        Err("notify-send unavailable".into())
    }
    #[cfg(target_os = "macos")]
    {
        if which("osascript") {
            let script = format!(
                "display notification \"{}\" with title \"{}\"",
                escape_applescript(body),
                escape_applescript(title)
            );
            let status = std::process::Command::new("osascript")
                .args(["-e", &script])
                .status()
                .map_err(|error| error.to_string())?;
            if status.success() {
                return Ok(());
            }
            return Err("osascript notification failed".into());
        }
        Err("osascript unavailable".into())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (title, body);
        Err("desktop notifications unsupported on this platform".into())
    }
}

fn which(binary: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                let candidate = dir.join(binary);
                candidate.is_file()
            })
        })
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn escape_applescript(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
