use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{ProcessError, ProcessInspector, ProcessRecord};

const MAX_PROC_FILE_BYTES: u64 = 64 * 1024;
const MAX_PROC_ENTRIES: usize = 32 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedProcStat {
    pub parent_pid: u32,
    pub process_group_id: u32,
    pub session_leader_id: u32,
    pub start_time: u64,
}

pub struct LinuxProcessInspector {
    proc_root: PathBuf,
}

impl Default for LinuxProcessInspector {
    fn default() -> Self {
        Self::from_proc_root("/proc")
    }
}

impl LinuxProcessInspector {
    pub fn from_proc_root(root: impl AsRef<Path>) -> Self {
        Self {
            proc_root: root.as_ref().to_path_buf(),
        }
    }

    fn read_process(&self, pid: u32) -> Result<ProcessRecord, ProcessError> {
        let directory = self.proc_root.join(pid.to_string());
        let stat = read_bounded(&directory.join("stat"), pid)?;
        let parsed = parse_proc_stat(pid, &stat)?;
        let status = read_bounded(&directory.join("status"), pid)?;
        let uid = parse_status_uid(pid, &status)?;
        let executable = std::fs::read_link(directory.join("exe"))
            .ok()
            .map(|path| path.to_string_lossy().into_owned());
        let argv_digest = read_bounded(&directory.join("cmdline"), pid)
            .ok()
            .filter(|bytes| !bytes.is_empty())
            .map(|bytes| format!("{:x}", Sha256::digest(bytes)));
        let tty = std::fs::read_link(directory.join("fd/0"))
            .ok()
            .filter(|path| path.starts_with("/dev/"))
            .map(|path| path.to_string_lossy().into_owned());
        Ok(ProcessRecord {
            pid,
            parent_pid: parsed.parent_pid,
            start_time: parsed.start_time,
            executable,
            argv_digest,
            uid: Some(uid),
            process_group_id: Some(parsed.process_group_id),
            session_leader_id: Some(parsed.session_leader_id),
            tty,
        })
    }
}

impl ProcessInspector for LinuxProcessInspector {
    fn inspect(&self, pid: u32) -> Result<ProcessRecord, ProcessError> {
        self.read_process(pid)
    }

    fn processes_on_tty(&self, tty: &str) -> Result<Vec<ProcessRecord>, ProcessError> {
        let entries = std::fs::read_dir(&self.proc_root)
            .map_err(|error| ProcessError::Inspection(error.to_string()))?;
        let mut processes = Vec::new();
        for entry in entries.take(MAX_PROC_ENTRIES).flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse().ok())
            else {
                continue;
            };
            if let Ok(process) = self.read_process(pid)
                && process.tty.as_deref() == Some(tty)
            {
                processes.push(process);
            }
        }
        Ok(processes)
    }
}

pub fn parse_proc_stat(pid: u32, bytes: &[u8]) -> Result<ParsedProcStat, ProcessError> {
    let input = bounded_utf8(pid, bytes)?;
    let close = input
        .rfind(") ")
        .ok_or_else(|| malformed(pid, "missing command terminator"))?;
    let fields: Vec<&str> = input[close + 2..].split_ascii_whitespace().collect();
    if fields.len() <= 19 {
        return Err(malformed(pid, "truncated stat fields"));
    }
    Ok(ParsedProcStat {
        parent_pid: parse_field(pid, fields[1], "parent PID")?,
        process_group_id: parse_field(pid, fields[2], "process group")?,
        session_leader_id: parse_field(pid, fields[3], "session leader")?,
        start_time: parse_field(pid, fields[19], "start time")?,
    })
}

pub fn parse_status_uid(pid: u32, bytes: &[u8]) -> Result<u32, ProcessError> {
    let input = bounded_utf8(pid, bytes)?;
    let value = input
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|values| values.split_ascii_whitespace().next())
        .ok_or_else(|| malformed(pid, "missing real UID"))?;
    parse_field(pid, value, "real UID")
}

fn read_bounded(path: &Path, pid: u32) -> Result<Vec<u8>, ProcessError> {
    let file = File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ProcessError::Disappeared(pid)
        } else {
            ProcessError::Inspection(error.to_string())
        }
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_PROC_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ProcessError::Inspection(error.to_string()))?;
    if bytes.len() as u64 > MAX_PROC_FILE_BYTES {
        return Err(malformed(pid, "proc file exceeds size limit"));
    }
    Ok(bytes)
}

fn bounded_utf8(pid: u32, bytes: &[u8]) -> Result<&str, ProcessError> {
    if bytes.len() as u64 > MAX_PROC_FILE_BYTES {
        return Err(malformed(pid, "proc field exceeds size limit"));
    }
    std::str::from_utf8(bytes).map_err(|_| malformed(pid, "proc field is not UTF-8"))
}

fn parse_field<T: std::str::FromStr>(pid: u32, value: &str, name: &str) -> Result<T, ProcessError> {
    value
        .parse()
        .map_err(|_| malformed(pid, &format!("invalid {name}")))
}

fn malformed(pid: u32, reason: &str) -> ProcessError {
    ProcessError::Malformed {
        pid,
        reason: reason.into(),
    }
}
