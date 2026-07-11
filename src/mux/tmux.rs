use std::ffi::OsString;
use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use super::{
    Capture, ComposerSafety, ComposerState, Multiplexer, MuxError, MuxIdentity, PaneInfo,
    SymbolicKey,
};
use crate::process::ProcessInspector;

const FIELD_SEPARATOR: char = '\u{1f}';
const OUTPUT_LIMIT: usize = 256 * 1024;
/// Bytes needed after the requested boundary to complete any UTF-8 scalar.
const UTF8_BOUNDARY_LOOKAHEAD: usize = 3;
/// One extra byte records that the command produced more than its logical cap.
const OUTPUT_OVERFLOW_SENTINEL: usize = 1;
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
    pub fn for_socket_path(path: String, timeout: Duration) -> Self {
        Self {
            server: Server::SocketPath(path),
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
        let actual = self
            .query(&expected.pane_id)
            .map_err(|error| {
                MuxError::IdentityChanged(format!(
                    "pane {} is no longer the recorded target: {error}",
                    expected.pane_id
                ))
            })?
            .identity;
        if actual.provider == expected.provider
            && actual.server == expected.server
            && actual.session_id == expected.session_id
            && actual.window_id == expected.window_id
            && actual.pane_id == expected.pane_id
            && actual.tty == expected.tty
            && process_matches(&expected.process, &actual.process)
        {
            Ok(())
        } else {
            Err(MuxError::IdentityChanged(format!(
                "expected pane {} process {:?}, found pane {} process {:?}",
                expected.pane_id, expected.process, actual.pane_id, actual.process
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
            &capture_arguments(&identity.pane_id, &start_line),
            max_bytes.saturating_add(UTF8_BOUNDARY_LOOKAHEAD),
        )?;
        self.validate_identity(identity)?;
        let (text, bytes, truncated) = truncate_capture(&output, max_bytes)?;
        Ok(Capture {
            text,
            bytes,
            truncated,
            elapsed: start.elapsed(),
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
        self.run(&literal_arguments(&identity.pane_id, text), OUTPUT_LIMIT)?;
        Ok(())
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
        self.run(&symbolic_arguments(&identity.pane_id, key), OUTPUT_LIMIT)?;
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
    let optional_i32 = |index: usize| -> Result<Option<i32>, MuxError> {
        if fields[index].is_empty() {
            Ok(None)
        } else {
            fields[index]
                .parse()
                .map(Some)
                .map_err(|_| MuxError::Malformed(format!("invalid optional numeric field {index}")))
        }
    };
    let optional_u64 = |index: usize| -> Result<Option<u64>, MuxError> {
        if fields[index].is_empty() {
            Ok(None)
        } else {
            fields[index]
                .parse()
                .map(Some)
                .map_err(|_| MuxError::Malformed(format!("invalid optional numeric field {index}")))
        }
    };
    for index in [0, 1, 3, 6, 8] {
        if fields[index].is_empty() {
            return Err(MuxError::Malformed(format!(
                "required field {index} is empty"
            )));
        }
    }
    let dead = match fields[12] {
        "0" => false,
        "1" => true,
        _ => {
            return Err(MuxError::Malformed(
                "pane dead marker must be 0 or 1".into(),
            ));
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
        server_instance: fields[0].into(),
        server: fields[0].into(),
        session_id: fields[1].into(),
        window_id: fields[3].into(),
        pane_id: fields[6].into(),
        tty: fields[8].into(),
        process,
    };
    Ok(PaneInfo {
        identity,
        server_id: fields[0].into(),
        session_name: fields[2].into(),
        window_name: fields[4].into(),
        window_index: number(5, "window index")?,
        pane_index: number(7, "pane index")?,
        pane_title: fields[4].into(),
        current_command: fields[10].into(),
        current_path: fields[11].into(),
        dead,
        dead_status: optional_i32(13)?,
        started_at: optional_u64(14)?,
        dead_at: optional_u64(15)?,
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

fn validate_literal(value: &str) -> Result<(), MuxError> {
    if value.chars().any(|character| character.is_control()) {
        return Err(MuxError::InvalidSelector(
            "literal text contains a control character".into(),
        ));
    }
    Ok(())
}

fn truncate_capture(output: &[u8], max_bytes: usize) -> Result<(String, usize, bool), MuxError> {
    let valid_bytes = match std::str::from_utf8(output) {
        Ok(_) => output,
        Err(error)
            if error.error_len().is_none()
                && error.valid_up_to() >= max_bytes
                && output.len() > max_bytes =>
        {
            &output[..error.valid_up_to()]
        }
        Err(_) => return Err(MuxError::InvalidUtf8),
    };
    let complete = std::str::from_utf8(valid_bytes).map_err(|_| MuxError::InvalidUtf8)?;
    let mut boundary = valid_bytes.len().min(max_bytes);
    while !complete.is_char_boundary(boundary) {
        boundary -= 1;
    }
    Ok((
        complete[..boundary].to_owned(),
        boundary,
        output.len() > max_bytes,
    ))
}

fn capture_arguments<'a>(pane: &'a str, start_line: &'a str) -> [&'a str; 7] {
    ["capture-pane", "-p", "-J", "-S", start_line, "-t", pane]
}

fn literal_arguments<'a>(pane: &'a str, text: &'a str) -> [&'a str; 6] {
    ["send-keys", "-t", pane, "-l", "--", text]
}

fn symbolic_arguments(pane: &str, key: SymbolicKey) -> [&str; 4] {
    ["send-keys", "-t", pane, key.tmux_name()]
}

fn require_safe(safety: &dyn ComposerSafety, identity: &MuxIdentity) -> Result<(), MuxError> {
    match safety.observe(identity)? {
        ComposerState::Safe => Ok(()),
        state => Err(MuxError::IdentityChanged(format!(
            "composer safety is {state:?}"
        ))),
    }
}

fn process_matches(
    expected: &crate::model::ProcessIdentity,
    actual: &crate::model::ProcessIdentity,
) -> bool {
    expected == actual
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
                let read = stream.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                if result.len() <= limit {
                    let remaining = limit
                        .saturating_add(OUTPUT_OVERFLOW_SENTINEL)
                        .saturating_sub(result.len());
                    result.extend_from_slice(&buffer[..read.min(remaining)]);
                }
            }
            Ok::<_, std::io::Error>(result)
        })
    };
    let out_thread = reader(Box::new(stdout));
    let err_thread = reader(Box::new(stderr));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_thread.join();
                let _ = err_thread.join();
                return Err(MuxError::Command(error.to_string()));
            }
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
        .map_err(|_| MuxError::Command("stdout reader panicked".into()))?
        .map_err(|error| MuxError::Command(format!("stdout read failed: {error}")))?;
    let error = err_thread
        .join()
        .map_err(|_| MuxError::Command("stderr reader panicked".into()))?
        .map_err(|error| MuxError::Command(format!("stderr read failed: {error}")))?;
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

    #[test]
    fn capture_arguments_are_exact_and_do_not_use_pipe_pane() {
        assert_eq!(
            capture_arguments("%7", "-40"),
            ["capture-pane", "-p", "-J", "-S", "-40", "-t", "%7"]
        );
    }

    #[test]
    fn literal_and_symbolic_argument_paths_are_distinct() {
        assert_eq!(
            literal_arguments("%2", "-n;λ"),
            ["send-keys", "-t", "%2", "-l", "--", "-n;λ"]
        );
        assert_eq!(
            symbolic_arguments("%2", SymbolicKey::Enter),
            ["send-keys", "-t", "%2", "Enter"]
        );
        for key in [
            SymbolicKey::Enter,
            SymbolicKey::Escape,
            SymbolicKey::Up,
            SymbolicKey::Down,
            SymbolicKey::Left,
            SymbolicKey::Right,
            SymbolicKey::Tab,
            SymbolicKey::Backspace,
        ] {
            assert!(!key.tmux_name().is_empty());
        }
    }

    #[test]
    fn server_targeting_arguments_are_fixed() {
        assert!(
            Tmux::default_server(Duration::from_secs(1))
                .args()
                .is_empty()
        );
        assert_eq!(
            Tmux::for_socket_name("private".into(), Duration::from_secs(1)).args(),
            vec![OsString::from("-L"), OsString::from("private")]
        );
        assert_eq!(
            Tmux {
                server: Server::SocketPath("/tmp/socket".into()),
                timeout: Duration::from_secs(1)
            }
            .args(),
            vec![OsString::from("-S"), OsString::from("/tmp/socket")]
        );
    }

    fn metadata(dead: &str, status: &str, started: &str, ended: &str) -> String {
        let pid = std::process::id().to_string();
        [
            "/tmp/socket",
            "$1",
            "sλ",
            "@2",
            "wλ",
            "3",
            "%4",
            "5",
            "/dev/pts/1",
            &pid,
            "bash",
            "/tmp/λ",
            dead,
            status,
            started,
            ended,
        ]
        .join(&FIELD_SEPARATOR.to_string())
    }

    #[test]
    fn metadata_parses_exact_fields_and_rejects_bad_optional_numbers_and_markers() {
        let info = parse_metadata(&metadata("1", "7", "8", "9")).unwrap();
        assert_eq!(
            (
                info.identity.server.as_str(),
                info.identity.session_id.as_str(),
                info.identity.window_id.as_str(),
                info.identity.pane_id.as_str()
            ),
            ("/tmp/socket", "$1", "@2", "%4")
        );
        assert_eq!(
            (
                info.session_name.as_str(),
                info.window_name.as_str(),
                info.window_index,
                info.pane_index
            ),
            ("sλ", "wλ", 3, 5)
        );
        assert_eq!(
            (info.dead, info.dead_status, info.started_at, info.dead_at),
            (true, Some(7), Some(8), Some(9))
        );
        for malformed in [
            metadata("2", "", "", ""),
            metadata("0", "x", "", ""),
            metadata("0", "", "x", ""),
            metadata("0", "", "", "x"),
        ] {
            assert!(parse_metadata(&malformed).is_err());
        }
        let extra_delimiter =
            metadata("0", "", "", "").replace("sλ", &format!("s{FIELD_SEPARATOR}λ"));
        assert!(parse_metadata(&extra_delimiter).is_err());
    }

    #[test]
    fn literal_validation_rejects_all_control_ranges() {
        for code in (0..=0x1f).chain(0x7f..=0x9f) {
            assert!(validate_literal(&char::from_u32(code).unwrap().to_string()).is_err());
        }
        assert!(validate_literal("printable λ text").is_ok());
    }

    #[test]
    fn strong_process_fields_reject_every_contradiction() {
        let mut expected = crate::model::ProcessIdentity::new(1, 2);
        expected.executable = Some("agent".into());
        expected.argv_digest = Some("argv".into());
        expected.uid = Some(3);
        expected.process_group_id = Some(4);
        expected.session_leader_id = Some(5);
        expected.tty = Some("tty".into());
        expected.parent_digest = Some("parent".into());
        assert!(process_matches(&expected, &expected));
        let mut variants = Vec::new();
        let mut value = expected.clone();
        value.pid = 9;
        variants.push(value);
        let mut value = expected.clone();
        value.start_time = 9;
        variants.push(value);
        let mut value = expected.clone();
        value.executable = Some("other".into());
        variants.push(value);
        let mut value = expected.clone();
        value.argv_digest = Some("other".into());
        variants.push(value);
        let mut value = expected.clone();
        value.uid = Some(9);
        variants.push(value);
        let mut value = expected.clone();
        value.process_group_id = Some(9);
        variants.push(value);
        let mut value = expected.clone();
        value.session_leader_id = Some(9);
        variants.push(value);
        let mut value = expected.clone();
        value.tty = Some("other".into());
        variants.push(value);
        let mut value = expected.clone();
        value.parent_digest = Some("other".into());
        variants.push(value);
        assert!(
            variants
                .iter()
                .all(|actual| !process_matches(&expected, actual))
        );
        let absent = crate::model::ProcessIdentity::new(1, 2);
        let mut present = absent.clone();
        present.executable = Some("appeared".into());
        assert!(!process_matches(&absent, &present));
        assert!(!process_matches(&present, &absent));
    }

    #[test]
    fn unicode_truncation_uses_previous_scalar_boundary() {
        assert_eq!(
            truncate_capture("aλz".as_bytes(), 2).unwrap(),
            ("a".into(), 1, true)
        );
        assert_eq!(
            truncate_capture("aλz".as_bytes(), 3).unwrap(),
            ("aλ".into(), 3, true)
        );
        assert!(matches!(
            truncate_capture(&[0xff], 1),
            Err(MuxError::InvalidUtf8)
        ));
        let emoji = "😀".as_bytes();
        assert_eq!(
            truncate_capture(emoji, 1).unwrap(),
            (String::new(), 0, true)
        );
        assert!(matches!(
            truncate_capture(&emoji[..2], 1),
            Err(MuxError::InvalidUtf8)
        ));
        assert!(matches!(
            truncate_capture(&emoji[..2], 10),
            Err(MuxError::InvalidUtf8)
        ));
        assert!(matches!(
            truncate_capture(&[b'a', 0xf0, 0x9f, 0x98], 3),
            Err(MuxError::InvalidUtf8)
        ));
        assert_eq!(
            truncate_capture("a😀".as_bytes(), 3).unwrap(),
            ("a".into(), 1, true)
        );
    }

    #[test]
    fn bounded_runner_timeout_returns_after_killing_child() {
        let started = Instant::now();
        let result = run_bounded(
            "sh",
            &["-c".into(), "exec sleep 10".into()],
            Duration::from_millis(20),
            16,
        );
        assert!(matches!(result, Err(MuxError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
