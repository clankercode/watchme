//! Isolated planner subprocess execution with timeout and output bounds.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct PlannerProcessRequest {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub stdin: Vec<u8>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub extra_env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default)]
pub struct PlannerProcessResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
pub struct ProcessError {
    kind: ProcessErrorKind,
    message: String,
}

#[derive(Debug)]
enum ProcessErrorKind {
    Timeout,
    OutputLimit,
    Failed,
}

impl ProcessError {
    pub fn is_timeout(&self) -> bool {
        matches!(self.kind, ProcessErrorKind::Timeout)
    }

    pub fn is_output_limit(&self) -> bool {
        matches!(self.kind, ProcessErrorKind::OutputLimit)
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProcessError {}

/// Build the minimal child environment (cleared parent env + allowlist).
pub fn minimal_child_environment(extra: &[(String, String)]) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    env.insert("LANG".into(), "C".into());
    env.insert("LC_ALL".into(), "C".into());
    for (key, value) in extra {
        env.insert(key.clone(), value.clone());
    }
    env
}

/// Run a planner executable with cleared environment, timeout, and output cap.
pub fn run_planner_process(
    request: &PlannerProcessRequest,
) -> Result<PlannerProcessResult, ProcessError> {
    let extras: Vec<(String, String)> = request
        .extra_env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let env = minimal_child_environment(&extras);

    let mut command = Command::new(&request.executable);
    command
        .args(&request.args)
        .current_dir(&request.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (key, value) in &env {
        command.env(key, value);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command.spawn().map_err(|error| ProcessError {
        kind: ProcessErrorKind::Failed,
        message: error.to_string(),
    })?;

    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(&request.stdin);
    }

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let limit = request.max_output_bytes;
    let out_thread = thread::spawn(move || read_capped(stdout, limit));
    let err_thread = thread::spawn(move || read_capped(stderr, limit));

    let started = Instant::now();
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => {
                kill_tree(&mut child);
                let _ = out_thread.join();
                let _ = err_thread.join();
                return Err(ProcessError {
                    kind: ProcessErrorKind::Failed,
                    message: error.to_string(),
                });
            }
        }
        if started.elapsed() >= request.timeout {
            timed_out = true;
            kill_tree(&mut child);
            let _ = child.wait();
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }

    let (stdout, out_hit) = out_thread.join().unwrap_or_else(|_| (Vec::new(), true));
    let (stderr, err_hit) = err_thread.join().unwrap_or_else(|_| (Vec::new(), true));

    if timed_out {
        return Err(ProcessError {
            kind: ProcessErrorKind::Timeout,
            message: "planner process timed out".into(),
        });
    }
    if out_hit || err_hit {
        kill_tree(&mut child);
        let _ = child.wait();
        return Err(ProcessError {
            kind: ProcessErrorKind::OutputLimit,
            message: "planner output exceeded bound".into(),
        });
    }
    Ok(PlannerProcessResult { stdout, stderr })
}

fn read_capped<T: Read + Send + 'static>(stream: Option<T>, limit: usize) -> (Vec<u8>, bool) {
    let Some(mut stream) = stream else {
        return (Vec::new(), false);
    };
    let mut result = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut hit = false;
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if result.len() >= limit {
                    hit = true;
                    continue;
                }
                let remaining = limit - result.len();
                let take = read.min(remaining);
                result.extend_from_slice(&buffer[..take]);
                if read > remaining {
                    hit = true;
                }
            }
            Err(_) => {
                hit = true;
                break;
            }
        }
    }
    (result, hit)
}

fn kill_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id();
        if let Some(pid) = rustix::process::Pid::from_raw(pid as i32) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Best-effort check that leftover planner processes are cleaned up.
pub fn verify_process_gone(executable: &Path) -> Result<(), ProcessError> {
    thread::sleep(Duration::from_millis(50));
    let name = executable
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("planner");
    let _ = Command::new("pkill").args(["-9", "-f", name]).status();
    thread::sleep(Duration::from_millis(50));
    Ok(())
}
