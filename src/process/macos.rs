//! macOS process collection verifies every `ps` record between two matching
//! libproc start-time reads. Bulk enumeration supplies PID numbers only; rows
//! that disappear or recycle during per-PID verification are omitted.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::{ProcessError, ProcessInspector, ProcessRecord};

const MAX_PS_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

pub trait MacProcessSource {
    fn start_time(&self, pid: u32) -> Result<u64, ProcessError>;
    fn ps_record(&self, pid: u32) -> Result<Vec<u8>, ProcessError>;
    fn list_pids(&self) -> Result<Vec<u32>, ProcessError>;
}

pub struct VerifiedMacInspector<S> {
    source: S,
}

impl<S> VerifiedMacInspector<S> {
    pub const fn new(source: S) -> Self {
        Self { source }
    }

    pub const fn source(&self) -> &S {
        &self.source
    }
}

impl<S: MacProcessSource> VerifiedMacInspector<S> {
    fn verified_record(&self, pid: u32) -> Result<ProcessRecord, ProcessError> {
        let before = self.source.start_time(pid)?;
        let bytes = match self.source.ps_record(pid) {
            Ok(bytes) => bytes,
            Err(_) => {
                return match self.source.start_time(pid) {
                    Err(ProcessError::Disappeared(_)) => Err(ProcessError::Disappeared(pid)),
                    Ok(after) if after != before => Err(ProcessError::Disappeared(pid)),
                    Ok(_) => Err(ProcessError::Inspection(format!(
                        "ps metadata command failed for PID {pid} while identity remained stable"
                    ))),
                    Err(error) => Err(error),
                };
            }
        };
        if bytes.len() > MAX_PS_OUTPUT_BYTES {
            return Err(ProcessError::Inspection(
                "ps output exceeds size limit".into(),
            ));
        }
        let record = parse_ps_record(&bytes, before)?;
        if record.pid != pid || self.source.start_time(pid)? != before {
            return Err(ProcessError::Disappeared(pid));
        }
        Ok(record)
    }
}

impl<S: MacProcessSource> ProcessInspector for VerifiedMacInspector<S> {
    fn inspect(&self, pid: u32) -> Result<ProcessRecord, ProcessError> {
        self.verified_record(pid)
    }

    fn processes_on_tty(&self, tty: &str) -> Result<Vec<ProcessRecord>, ProcessError> {
        let mut records = Vec::new();
        for pid in self.source.list_pids()? {
            match self.verified_record(pid) {
                Ok(record) if record.tty.as_deref() == Some(tty) => records.push(record),
                Ok(_) | Err(ProcessError::Disappeared(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(records)
    }
}

#[cfg(target_os = "macos")]
pub struct SystemMacProcessSource;

#[cfg(target_os = "macos")]
impl MacProcessSource for SystemMacProcessSource {
    fn start_time(&self, pid: u32) -> Result<u64, ProcessError> {
        let info = match libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(pid as i32, 0) {
            Ok(info) => info,
            Err(_) => return classify_libproc_failure(pid),
        };
        info.pbi_start_tvsec
            .checked_mul(1_000_000)
            .and_then(|seconds| seconds.checked_add(info.pbi_start_tvusec))
            .ok_or_else(|| ProcessError::Malformed {
                pid,
                reason: "process start timestamp overflow".into(),
            })
    }

    fn ps_record(&self, pid: u32) -> Result<Vec<u8>, ProcessError> {
        let pid_argument = pid.to_string();
        let output = run_bounded_command(
            "/bin/ps",
            &[
                "-p",
                &pid_argument,
                "-o",
                "pid=,ppid=,pgid=,sess=,uid=,tty=,comm=",
            ],
            MAX_PS_OUTPUT_BYTES,
            Duration::from_secs(2),
        )?;
        (!output.is_empty())
            .then_some(output)
            .ok_or(ProcessError::Disappeared(pid))
    }

    fn list_pids(&self) -> Result<Vec<u32>, ProcessError> {
        let output = run_bounded_command(
            "/bin/ps",
            &["-axo", "pid="],
            MAX_PS_OUTPUT_BYTES,
            Duration::from_secs(2),
        )?;
        Ok(String::from_utf8_lossy(&output)
            .split_ascii_whitespace()
            .filter_map(|field| field.parse().ok())
            .collect())
    }
}

#[cfg(target_os = "macos")]
fn classify_libproc_failure(pid: u32) -> Result<u64, ProcessError> {
    let Some(pid_value) = rustix::process::Pid::from_raw(pid as i32) else {
        return Err(ProcessError::Disappeared(pid));
    };
    match rustix::process::test_kill_process(pid_value) {
        Err(rustix::io::Errno::SRCH) => Err(ProcessError::Disappeared(pid)),
        Ok(()) | Err(rustix::io::Errno::PERM) => Err(ProcessError::Inspection(format!(
            "libproc BSD info unavailable for existing PID {pid}"
        ))),
        Err(_) => Err(ProcessError::Inspection(format!(
            "libproc BSD info and PID existence checks failed for PID {pid}"
        ))),
    }
}

pub fn run_bounded_command(
    program: &str,
    arguments: &[&str],
    limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, ProcessError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| ProcessError::Inspection(error.to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ProcessError::Inspection("missing stdout pipe".into()))?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| ProcessError::Inspection(error.to_string()))?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            return Err(ProcessError::Inspection("process command timed out".into()));
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let bytes = reader
        .join()
        .map_err(|_| ProcessError::Inspection("pipe reader panicked".into()))?
        .map_err(|error| ProcessError::Inspection(error.to_string()))?;
    if !status.success() || bytes.len() > limit {
        return Err(ProcessError::Inspection(
            "process command failed or exceeded output limit".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(target_os = "macos")]
pub type MacOsProcessInspector = VerifiedMacInspector<SystemMacProcessSource>;

#[cfg(target_os = "macos")]
impl Default for VerifiedMacInspector<SystemMacProcessSource> {
    fn default() -> Self {
        Self::new(SystemMacProcessSource)
    }
}

pub fn parse_ps_record(bytes: &[u8], start_time: u64) -> Result<ProcessRecord, ProcessError> {
    if bytes.len() > MAX_PS_OUTPUT_BYTES {
        return Err(ProcessError::Inspection(
            "ps record exceeds size limit".into(),
        ));
    }
    let line = std::str::from_utf8(bytes)
        .map_err(|_| ProcessError::Inspection("ps returned non-UTF-8 metadata".into()))?;
    let mut fields = line.split_ascii_whitespace();
    let pid = parse(&mut fields, 0, "pid")?;
    let parent_pid = parse(&mut fields, pid, "parent pid")?;
    let process_group_id = parse(&mut fields, pid, "process group")?;
    let session_leader_id = parse(&mut fields, pid, "session")?;
    let uid = parse(&mut fields, pid, "uid")?;
    let tty = fields.next().filter(|tty| *tty != "??").map(normalize_tty);
    let executable = fields.next().map(str::to_owned);
    Ok(ProcessRecord {
        pid,
        parent_pid,
        start_time,
        executable,
        argv_digest: None,
        uid: Some(uid),
        process_group_id: Some(process_group_id),
        session_leader_id: Some(session_leader_id),
        tty,
    })
}

fn parse<T: std::str::FromStr>(
    fields: &mut std::str::SplitAsciiWhitespace<'_>,
    pid: u32,
    name: &str,
) -> Result<T, ProcessError> {
    fields
        .next()
        .and_then(|field| field.parse().ok())
        .ok_or_else(|| ProcessError::Malformed {
            pid,
            reason: format!("invalid {name}"),
        })
}

fn normalize_tty(tty: &str) -> String {
    if tty.starts_with('/') {
        tty.into()
    } else {
        format!("/dev/{tty}")
    }
}
