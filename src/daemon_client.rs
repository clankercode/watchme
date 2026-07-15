use std::io::Read as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use watchme::ipc::protocol::{Request, Response};
use watchme::ipc::{read_response, write_request};
use watchme::paths::WatchmePaths;

use crate::error::WatchmeError;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(3);
const INITIAL_STARTUP_BACKOFF: Duration = Duration::from_millis(20);
const MAX_STARTUP_BACKOFF: Duration = Duration::from_millis(200);
const MAX_DIAGNOSTIC_BYTES: usize = 512;

pub fn request(paths: &WatchmePaths, request: &Request) -> std::io::Result<Response> {
    request_with_timeout(paths, request, Duration::from_secs(2))
}

pub fn start_and_request(
    paths: &WatchmePaths,
    request: &Request,
) -> Result<Response, WatchmeError> {
    let executable = std::env::current_exe()
        .map_err(|error| WatchmeError::RetryableIntegration(error.to_string()))?;
    paths
        .create_owner_only()
        .map_err(|error| WatchmeError::RetryableIntegration(error.to_string()))?;
    let (diagnostic_file, diagnostic_path) = open_startup_diagnostic(paths)
        .map_err(|error| WatchmeError::RetryableIntegration(error.to_string()))?;
    let mut command = Command::new(executable);
    command
        .args(["daemon", "run"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(diagnostic_file))
        .process_group(0);
    let mut child = command
        .spawn()
        .map_err(|error| WatchmeError::RetryableIntegration(error.to_string()))?;
    let readiness = wait_for_readiness(&SystemWaitClock, STARTUP_TIMEOUT, |remaining| {
        request_with_timeout(paths, request, remaining)
    });
    match readiness {
        Ok(response) => Ok(response),
        Err(error) => {
            let diagnostic = child_failure_diagnostic(&mut child, &diagnostic_path);
            Err(WatchmeError::RetryableIntegration(format!(
                "daemon did not become ready: {error}{diagnostic}"
            )))
        }
    }
}

fn request_with_timeout(
    paths: &WatchmePaths,
    request: &Request,
    timeout: Duration,
) -> std::io::Result<Response> {
    let socket = paths.runtime_dir().join("daemon.sock");
    local_runtime()?.block_on(within_attempt_deadline(timeout, async {
        let mut stream = tokio::net::UnixStream::connect(socket).await?;
        write_request(&mut stream, request, timeout)
            .await
            .map_err(std::io::Error::other)?;
        read_response(&mut stream, timeout)
            .await
            .map_err(std::io::Error::other)
    }))
}

fn local_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(std::io::Error::other)
}

async fn within_attempt_deadline<T>(
    timeout: Duration,
    future: impl std::future::Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    tokio::time::timeout(timeout, future).await.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "daemon readiness deadline elapsed",
        )
    })?
}

fn open_startup_diagnostic(paths: &WatchmePaths) -> std::io::Result<(std::fs::File, PathBuf)> {
    let path = paths.runtime_dir().join("daemon-startup.log");
    let file = rustix::fs::open(
        &path,
        rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::TRUNC
            | rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .map(std::fs::File::from)
    .map_err(std::io::Error::from)?;
    rustix::fs::fchmod(&file, rustix::fs::Mode::from_bits_truncate(0o600))
        .map_err(std::io::Error::from)?;
    Ok((file, path))
}

trait WaitClock {
    fn now(&self) -> std::time::Instant;
    fn sleep(&self, duration: Duration);
}

struct SystemWaitClock;

impl WaitClock for SystemWaitClock {
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

fn wait_for_readiness<T, E>(
    clock: &impl WaitClock,
    timeout: Duration,
    mut attempt: impl FnMut(Duration) -> Result<T, E>,
) -> Result<T, E> {
    let deadline = clock.now() + timeout;
    let mut backoff = INITIAL_STARTUP_BACKOFF;
    loop {
        let remaining = deadline.saturating_duration_since(clock.now());
        match attempt(remaining) {
            Ok(value) => return Ok(value),
            Err(error) => {
                let now = clock.now();
                if now >= deadline {
                    return Err(error);
                }
                clock.sleep(backoff.min(deadline.duration_since(now)));
                backoff = (backoff * 2).min(MAX_STARTUP_BACKOFF);
            }
        }
    }
}

fn child_failure_diagnostic(child: &mut std::process::Child, path: &Path) -> String {
    let status = match child.try_wait() {
        Ok(Some(status)) => Some(status),
        Ok(None) | Err(_) => {
            let _ = child.kill();
            child.wait().ok()
        }
    };
    let mut stderr = Vec::new();
    if let Ok(mut file) = std::fs::File::open(path) {
        let _ = file
            .by_ref()
            .take((MAX_DIAGNOSTIC_BYTES + 1) as u64)
            .read_to_end(&mut stderr);
    }
    let diagnostic = sanitize_daemon_stderr(&stderr);
    match (status, diagnostic.is_empty()) {
        (Some(status), false) => format!("; child {status}: {diagnostic}"),
        (Some(status), true) => format!("; child {status}"),
        (None, false) => format!("; child diagnostic: {diagnostic}"),
        (None, true) => String::new(),
    }
}

fn sanitize_daemon_stderr(stderr: &[u8]) -> String {
    let source = String::from_utf8_lossy(&stderr[..stderr.len().min(MAX_DIAGNOSTIC_BYTES)]);
    let mut sanitized = String::new();
    for line in source.lines() {
        if !sanitized.is_empty() {
            sanitized.push('\n');
        }
        let lower = line.to_ascii_lowercase();
        if ["token", "secret", "password", "credential", "api_key"]
            .iter()
            .any(|marker| lower.contains(marker))
        {
            sanitized.push_str("[redacted]");
        } else {
            sanitized.extend(line.chars().filter(|character| !character.is_control()));
        }
        if sanitized.len() >= MAX_DIAGNOSTIC_BYTES {
            sanitized.truncate(MAX_DIAGNOSTIC_BYTES);
            break;
        }
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    struct FakeWaitClock {
        now: Cell<std::time::Instant>,
        sleeps: RefCell<Vec<Duration>>,
    }

    impl WaitClock for FakeWaitClock {
        fn now(&self) -> std::time::Instant {
            self.now.get()
        }

        fn sleep(&self, duration: Duration) {
            self.sleeps.borrow_mut().push(duration);
            self.now.set(self.now.get() + duration);
        }
    }

    #[test]
    fn startup_readiness_uses_bounded_deadline_and_backoff() {
        let clock = FakeWaitClock {
            now: Cell::new(std::time::Instant::now()),
            sleeps: RefCell::new(Vec::new()),
        };
        let started = clock.now();
        let mut attempts = 0;
        let mut budgets = Vec::new();
        let result = wait_for_readiness(&clock, Duration::from_secs(2), |remaining| {
            budgets.push(remaining);
            attempts += 1;
            Err::<(), _>(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not ready",
            ))
        });

        assert!(result.is_err());
        assert!(attempts > 5);
        assert_eq!(budgets[0], Duration::from_secs(2));
        assert!(budgets.windows(2).all(|pair| pair[0] >= pair[1]));
        assert_eq!(clock.now().duration_since(started), Duration::from_secs(2));
        let sleeps = clock.sleeps.borrow();
        assert!(
            sleeps[..sleeps.len() - 1]
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
        );
        assert!(
            sleeps
                .iter()
                .all(|delay| *delay <= Duration::from_millis(200))
        );
    }

    #[test]
    fn readiness_attempt_future_is_bounded_by_remaining_deadline() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let started = std::time::Instant::now();
        let error = runtime
            .block_on(within_attempt_deadline(
                Duration::from_millis(25),
                std::future::pending::<std::io::Result<()>>(),
            ))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(150));
    }

    #[test]
    fn daemon_stderr_diagnostics_are_bounded_and_redact_secret_lines() {
        let diagnostic = sanitize_daemon_stderr(
            b"failed to bind runtime socket\nAPI_TOKEN=super-secret\npassword=hunter2\n",
        );
        assert_eq!(
            diagnostic,
            "failed to bind runtime socket\n[redacted]\n[redacted]"
        );
        assert!(diagnostic.len() <= MAX_DIAGNOSTIC_BYTES);
    }

    #[test]
    fn daemon_startup_diagnostic_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::TempDir::new().unwrap();
        let paths =
            WatchmePaths::resolve(temp.path(), None, None, Some(&temp.path().join("run"))).unwrap();
        paths.create_owner_only().unwrap();
        let (_file, path) = open_startup_diagnostic(&paths).unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
