use std::ffi::OsString;
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::{Capture, Multiplexer, MuxError, MuxIdentity, PaneInfo, SymbolicKey};
use crate::process::ProcessInspector;

const FIELD_SEPARATOR: char = '\u{1f}';
const OUTPUT_LIMIT: usize = 256 * 1024;
const METADATA_FORMAT: &str = "#{socket_path}\u{1f}#{session_id}\u{1f}#{session_name}\u{1f}#{window_id}\u{1f}#{window_name}\u{1f}#{window_index}\u{1f}#{pane_id}\u{1f}#{pane_index}\u{1f}#{pane_tty}\u{1f}#{pane_pid}\u{1f}#{pane_current_command}\u{1f}#{pane_current_path}\u{1f}#{pane_dead}\u{1f}#{pane_dead_status}\u{1f}#{pane_start_time}\u{1f}#{pane_dead_time}";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TmuxSelector(String);

impl TmuxSelector {
    pub fn parse(value: &str) -> Result<Self, MuxError> {
        if value.is_empty() || value.starts_with('-') || value.chars().any(char::is_control) {
            return Err(MuxError::InvalidSelector(
                value.escape_default().to_string(),
            ));
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug)]
enum Server {
    Default,
    SocketName(String),
    SocketPath(String),
}

#[derive(Clone, Debug)]
pub struct Tmux {
    server: Server,
    timeout: Duration,
}

impl Tmux {
    pub fn from_environment(timeout: Duration) -> Result<Self, MuxError> {
        let tmux =
            std::env::var("TMUX").map_err(|_| MuxError::Command("TMUX is not set".into()))?;
        let socket = tmux
            .split(',')
            .next()
            .filter(|part| !part.is_empty())
            .ok_or_else(|| MuxError::Malformed("TMUX has no socket path".into()))?;
        validate_argument(socket)?;
        Ok(Self {
            server: Server::SocketPath(socket.into()),
            timeout,
        })
    }
    pub fn for_socket_name(name: String, timeout: Duration) -> Self {
        Self {
            server: Server::SocketName(name),
            timeout,
        }
    }
    pub fn default_server(timeout: Duration) -> Self {
        Self {
            server: Server::Default,
            timeout,
        }
    }

    fn args(&self) -> Vec<OsString> {
        match &self.server {
            Server::Default => Vec::new(),
            Server::SocketName(name) => vec!["-L".into(), name.into()],
            Server::SocketPath(path) => vec!["-S".into(), path.into()],
        }
    }
    fn run(&self, args: &[&str], limit: usize) -> Result<Vec<u8>, MuxError> {
        let mut command_args = self.args();
        command_args.extend(args.iter().map(OsString::from));
        run_bounded("tmux", &command_args, self.timeout, limit)
    }
    fn query(&self, target: &str) -> Result<PaneInfo, MuxError> {
        validate_argument(target)?;
        let output = self.run(
            &["display-message", "-p", "-t", target, METADATA_FORMAT],
            OUTPUT_LIMIT,
        )?;
        parse_metadata(
            std::str::from_utf8(&output)
                .map_err(|_| MuxError::InvalidUtf8)?
                .trim_end(),
        )
    }
}

impl Multiplexer for Tmux {
    type Selector = TmuxSelector;
    fn current_target(&self) -> Result<MuxIdentity, MuxError> {
        let pane = std::env::var("TMUX_PANE")
            .map_err(|_| MuxError::Command("TMUX_PANE is not set".into()))?;
        Ok(self.query(&pane)?.identity)
    }
    fn resolve_selector(&self, selector: &Self::Selector) -> Result<MuxIdentity, MuxError> {
        Ok(self.query(selector.as_str())?.identity)
    }
    fn pane_info(&self, identity: &MuxIdentity) -> Result<PaneInfo, MuxError> {
        self.query(&identity.pane_id)
    }
    fn validate_identity(&self, expected: &MuxIdentity) -> Result<(), MuxError> {
        let actual = self.query(&expected.pane_id)?.identity;
        if actual.provider == expected.provider
            && actual.server == expected.server
            && actual.session_id == expected.session_id
            && actual.window_id == expected.window_id
            && actual.pane_id == expected.pane_id
            && actual.tty == expected.tty
            && actual.process.pid == expected.process.pid
            && actual.process.start_time == expected.process.start_time
        {
            Ok(())
        } else {
            Err(MuxError::IdentityChanged(format!(
                "expected pane {} PID {}, found pane {} PID {}",
                expected.pane_id, expected.process.pid, actual.pane_id, actual.process.pid
            )))
        }
    }
    fn capture_tail(
        &self,
        identity: &MuxIdentity,
        lines: usize,
        max_bytes: usize,
    ) -> Result<Capture, MuxError> {
        self.validate_identity(identity)?;
        if lines == 0 || max_bytes == 0 {
            return Ok(Capture {
                text: String::new(),
                bytes: 0,
                truncated: false,
                elapsed: Duration::ZERO,
            });
        }
        let start = Instant::now();
        let start_line = format!("-{lines}");
        let output = self.run(
            &[
                "capture-pane",
                "-p",
                "-J",
                "-S",
                &start_line,
                "-t",
                &identity.pane_id,
            ],
            max_bytes.saturating_add(1),
        )?;
        let truncated = output.len() > max_bytes;
        let selected = &output[..output.len().min(max_bytes)];
        let text = std::str::from_utf8(selected)
            .map_err(|_| MuxError::InvalidUtf8)?
            .to_owned();
        Ok(Capture {
            text,
            bytes: selected.len(),
            truncated,
            elapsed: start.elapsed(),
        })
    }
    fn send_literal(&self, identity: &MuxIdentity, text: &str) -> Result<(), MuxError> {
        validate_argument(text)?;
        self.validate_identity(identity)?;
        self.run(
            &["send-keys", "-t", &identity.pane_id, "-l", "--", text],
            OUTPUT_LIMIT,
        )?;
        Ok(())
    }
    fn send_key(&self, identity: &MuxIdentity, key: SymbolicKey) -> Result<(), MuxError> {
        self.validate_identity(identity)?;
        self.run(
            &["send-keys", "-t", &identity.pane_id, key.tmux_name()],
            OUTPUT_LIMIT,
        )?;
        Ok(())
    }
}

fn parse_metadata(value: &str) -> Result<PaneInfo, MuxError> {
    let fields: Vec<_> = value.split(FIELD_SEPARATOR).collect();
    if fields.len() != 16 {
        return Err(MuxError::Malformed(format!(
            "expected 16 fields, got {}",
            fields.len()
        )));
    }
    let number = |index: usize, name: &str| {
        fields[index]
            .parse::<u32>()
            .map_err(|_| MuxError::Malformed(format!("invalid {name}")))
    };
    let optional_i32 = |index: usize| {
        if fields[index].is_empty() {
            None
        } else {
            fields[index].parse().ok()
        }
    };
    let optional_u64 = |index: usize| {
        if fields[index].is_empty() {
            None
        } else {
            fields[index].parse().ok()
        }
    };
    let pid = number(9, "pane PID")?;
    #[cfg(target_os = "linux")]
    let process = crate::process::linux::LinuxProcessInspector::default()
        .inspect(pid)
        .map_err(|error| MuxError::IdentityChanged(error.to_string()))?
        .identity();
    #[cfg(target_os = "macos")]
    let process = crate::process::macos::MacOsProcessInspector::default()
        .inspect(pid)
        .map_err(|error| MuxError::IdentityChanged(error.to_string()))?
        .identity();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let process = crate::model::ProcessIdentity::new(pid, 0);
    let identity = MuxIdentity {
        provider: "tmux".into(),
        server: fields[0].into(),
        session_id: fields[1].into(),
        window_id: fields[3].into(),
        pane_id: fields[6].into(),
        tty: fields[8].into(),
        process,
    };
    Ok(PaneInfo {
        identity,
        session_name: fields[2].into(),
        window_name: fields[4].into(),
        window_index: number(5, "window index")?,
        pane_index: number(7, "pane index")?,
        current_command: fields[10].into(),
        current_path: fields[11].into(),
        dead: fields[12] == "1",
        dead_status: optional_i32(13),
        started_at: optional_u64(14),
        dead_at: optional_u64(15),
    })
}

fn validate_argument(value: &str) -> Result<(), MuxError> {
    if value.contains('\0')
        || value
            .chars()
            .any(|character| matches!(character, '\n' | '\r'))
    {
        return Err(MuxError::InvalidSelector(
            value.escape_default().to_string(),
        ));
    }
    Ok(())
}

fn run_bounded(
    executable: &str,
    args: &[OsString],
    timeout: Duration,
    limit: usize,
) -> Result<Vec<u8>, MuxError> {
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| MuxError::Command(error.to_string()))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let reader = |mut stream: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut result = Vec::new();
            let mut buffer = [0; 8192];
            loop {
                let read = stream.read(&mut buffer).unwrap_or(0);
                if read == 0 {
                    break;
                }
                if result.len() <= limit {
                    let remaining = limit.saturating_add(1).saturating_sub(result.len());
                    result.extend_from_slice(&buffer[..read.min(remaining)]);
                }
            }
            result
        })
    };
    let out_thread = reader(Box::new(stdout));
    let err_thread = reader(Box::new(stderr));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| MuxError::Command(error.to_string()))?
        {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_thread.join();
            let _ = err_thread.join();
            return Err(MuxError::Timeout);
        }
        thread::sleep(Duration::from_millis(5));
    };
    let output = out_thread
        .join()
        .map_err(|_| MuxError::Command("stdout reader panicked".into()))?;
    let error = err_thread
        .join()
        .map_err(|_| MuxError::Command("stderr reader panicked".into()))?;
    if !status.success() {
        return Err(MuxError::Command(
            String::from_utf8_lossy(&error).trim().to_owned(),
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_rejects_malformed_records() {
        assert!(parse_metadata("short").is_err());
    }
    #[test]
    fn argument_validation_rejects_control_boundaries() {
        assert!(validate_argument("a\nb").is_err());
        assert!(validate_argument("unicode-λ").is_ok());
    }
}
