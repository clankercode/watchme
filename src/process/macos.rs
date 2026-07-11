use std::process::Command;

use super::{ProcessError, ProcessInspector, ProcessRecord};

const MAX_PS_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// macOS inspector using fixed `ps` argument vectors and sysinfo start times.
/// No process-controlled value is interpreted by a shell.
pub struct MacOsProcessInspector;

impl ProcessInspector for MacOsProcessInspector {
    fn inspect(&self, pid: u32) -> Result<ProcessRecord, ProcessError> {
        let output = Command::new("/bin/ps")
            .args([
                "-p",
                &pid.to_string(),
                "-o",
                "pid=,ppid=,pgid=,sess=,uid=,tdev=,comm=",
            ])
            .output()
            .map_err(|error| ProcessError::Inspection(error.to_string()))?;
        if !output.status.success() || output.stdout.is_empty() {
            return Err(ProcessError::Disappeared(pid));
        }
        parse_ps_line(&output.stdout, process_start_time(pid)?)
    }

    fn processes_on_tty(&self, tty: &str) -> Result<Vec<ProcessRecord>, ProcessError> {
        let output = Command::new("/bin/ps")
            .args(["-axo", "pid=,ppid=,pgid=,sess=,uid=,tdev=,comm="])
            .output()
            .map_err(|error| ProcessError::Inspection(error.to_string()))?;
        if output.stdout.len() > MAX_PS_OUTPUT_BYTES {
            return Err(ProcessError::Inspection(
                "ps output exceeds size limit".into(),
            ));
        }
        Ok(output
            .stdout
            .split(|byte| *byte == b'\n')
            .filter_map(|line| {
                let pid = first_u32(line)?;
                parse_ps_line(line, process_start_time(pid).ok()?).ok()
            })
            .filter(|process| process.tty.as_deref() == Some(tty))
            .collect())
    }
}

fn process_start_time(pid: u32) -> Result<u64, ProcessError> {
    let system = sysinfo::System::new_all();
    system
        .process(sysinfo::Pid::from_u32(pid))
        .map(sysinfo::Process::start_time)
        .ok_or(ProcessError::Disappeared(pid))
}

fn parse_ps_line(bytes: &[u8], start_time: u64) -> Result<ProcessRecord, ProcessError> {
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

fn first_u32(line: &[u8]) -> Option<u32> {
    std::str::from_utf8(line)
        .ok()?
        .split_ascii_whitespace()
        .next()?
        .parse()
        .ok()
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
