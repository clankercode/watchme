//! macOS process collection verifies every `ps` record between two matching
//! sysinfo start-time reads. Bulk enumeration supplies PID numbers only; rows
//! that disappear or recycle during per-PID verification are omitted.

#[cfg(target_os = "macos")]
use std::process::Command;

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
        let bytes = self.source.ps_record(pid)?;
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
        Ok(self
            .source
            .list_pids()?
            .into_iter()
            .filter_map(|pid| self.verified_record(pid).ok())
            .filter(|record| record.tty.as_deref() == Some(tty))
            .collect())
    }
}

#[cfg(target_os = "macos")]
pub struct SystemMacProcessSource;

#[cfg(target_os = "macos")]
impl MacProcessSource for SystemMacProcessSource {
    fn start_time(&self, pid: u32) -> Result<u64, ProcessError> {
        let system = sysinfo::System::new_all();
        system
            .process(sysinfo::Pid::from_u32(pid))
            .map(sysinfo::Process::start_time)
            .ok_or(ProcessError::Disappeared(pid))
    }

    fn ps_record(&self, pid: u32) -> Result<Vec<u8>, ProcessError> {
        let pid_argument = pid.to_string();
        let output = Command::new("/bin/ps")
            .args([
                "-p",
                &pid_argument,
                "-o",
                "pid=,ppid=,pgid=,sess=,uid=,tty=,comm=",
            ])
            .output()
            .map_err(|error| ProcessError::Inspection(error.to_string()))?;
        bounded_successful_output(pid, output)
    }

    fn list_pids(&self) -> Result<Vec<u32>, ProcessError> {
        let output = Command::new("/bin/ps")
            .args(["-axo", "pid="])
            .output()
            .map_err(|error| ProcessError::Inspection(error.to_string()))?;
        if !output.status.success() || output.stdout.len() > MAX_PS_OUTPUT_BYTES {
            return Err(ProcessError::Inspection(
                "bounded PID enumeration failed".into(),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .split_ascii_whitespace()
            .filter_map(|field| field.parse().ok())
            .collect())
    }
}

#[cfg(target_os = "macos")]
fn bounded_successful_output(
    pid: u32,
    output: std::process::Output,
) -> Result<Vec<u8>, ProcessError> {
    if !output.status.success() || output.stdout.is_empty() {
        return Err(ProcessError::Disappeared(pid));
    }
    if output.stdout.len() > MAX_PS_OUTPUT_BYTES {
        return Err(ProcessError::Inspection(
            "ps output exceeds size limit".into(),
        ));
    }
    Ok(output.stdout)
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
