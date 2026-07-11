mod scoring;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::ProcessIdentity;
use scoring::{MINIMUM_CONFIDENCE, identify_agent, score};

const MAX_ANCESTORS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentKind {
    Claude,
    Codex,
    Manifest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRecord {
    pub pid: u32,
    pub parent_pid: u32,
    pub start_time: u64,
    pub executable: Option<String>,
    pub argv_digest: Option<String>,
    pub uid: Option<u32>,
    pub process_group_id: Option<u32>,
    pub session_leader_id: Option<u32>,
    pub tty: Option<String>,
}

impl ProcessRecord {
    pub fn synthetic(pid: u32, parent_pid: u32, start_time: u64, executable: &str) -> Self {
        Self {
            pid,
            parent_pid,
            start_time,
            executable: Some(executable.into()),
            argv_digest: None,
            uid: None,
            process_group_id: None,
            session_leader_id: None,
            tty: None,
        }
    }

    pub const fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    pub fn with_terminal(
        mut self,
        tty: &str,
        process_group_id: u32,
        session_leader_id: u32,
    ) -> Self {
        self.tty = Some(tty.into());
        self.process_group_id = Some(process_group_id);
        self.session_leader_id = Some(session_leader_id);
        self
    }

    pub fn with_argv<I, S>(mut self, argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut hash = Sha256::new();
        for argument in argv {
            let bytes = argument.as_ref().as_bytes();
            hash.update(bytes.len().to_le_bytes());
            hash.update(bytes);
        }
        self.argv_digest = Some(format!("{:x}", hash.finalize()));
        self
    }

    pub fn identity(&self) -> ProcessIdentity {
        let mut identity = ProcessIdentity::new(self.pid, self.start_time);
        identity.executable = self.executable.clone();
        identity.argv_digest = self.argv_digest.clone();
        identity.uid = self.uid;
        identity.process_group_id = self.process_group_id;
        identity.session_leader_id = self.session_leader_id;
        identity.tty = self.tty.clone();
        identity
    }
}

pub trait ProcessInspector {
    fn inspect(&self, pid: u32) -> Result<ProcessRecord, ProcessError>;
    fn processes_on_tty(&self, tty: &str) -> Result<Vec<ProcessRecord>, ProcessError>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CandidateHints {
    pub tty: Option<String>,
    pub process_group_id: Option<u32>,
    pub session_leader_id: Option<u32>,
    pub uid: Option<u32>,
    pub executable_hint: Option<String>,
}

impl CandidateHints {
    pub fn for_tty(tty: &str) -> Self {
        Self {
            tty: Some(tty.into()),
            ..Self::default()
        }
    }
    pub const fn with_process_group(mut self, id: u32) -> Self {
        self.process_group_id = Some(id);
        self
    }
    pub const fn with_session(mut self, id: u32) -> Self {
        self.session_leader_id = Some(id);
        self
    }
    pub const fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }
    pub fn with_executable_hint(mut self, executable: &str) -> Self {
        self.executable_hint = Some(executable.into());
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedProcess {
    pub identity: ProcessIdentity,
    pub agent: AgentKind,
    pub score: i32,
    pub reasons: Vec<String>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProcessError {
    #[error("process {0} disappeared during inspection")]
    Disappeared(u32),
    #[error("malformed process metadata for PID {pid}: {reason}")]
    Malformed { pid: u32, reason: String },
    #[error("process inspection failed: {0}")]
    Inspection(String),
    #[error(
        "agent process discovery is ambiguous ({candidates:?}); run `watchme doctor` for pane and process evidence"
    )]
    Ambiguous { candidates: Vec<u32> },
    #[error(
        "no agent process has sufficient correlated evidence; invoke through `!watchme` and run `watchme doctor`"
    )]
    NoConfidentCandidate { examined: usize },
}

#[derive(Default)]
pub struct ProcessResolver {
    manifest_names: Vec<String>,
}

impl ProcessResolver {
    pub fn with_manifest_names(names: impl IntoIterator<Item = String>) -> Self {
        Self {
            manifest_names: names.into_iter().collect(),
        }
    }

    pub fn resolve(
        &self,
        inspector: &dyn ProcessInspector,
        child_pid: u32,
        hints: &CandidateHints,
    ) -> Result<ResolvedProcess, ProcessError> {
        let ancestry = self.ancestry(inspector, child_pid);
        let mut candidates = Vec::new();
        for (distance, process) in ancestry.iter().enumerate().skip(1) {
            if let Some(agent) = self.agent_for(process) {
                candidates.push(self.candidate(process, agent, hints, Some(distance)));
            }
        }
        if candidates.is_empty()
            && let Some(tty) = &hints.tty
        {
            for process in inspector.processes_on_tty(tty)? {
                if let Some(agent) = self.agent_for(&process) {
                    candidates.push(self.candidate(&process, agent, hints, None));
                }
            }
        }
        let mut selected = select_candidate(candidates)?;
        if !ancestry.is_empty() {
            let mut digest = Sha256::new();
            for process in &ancestry {
                digest.update(process.pid.to_le_bytes());
                digest.update(process.start_time.to_le_bytes());
            }
            selected.identity.parent_digest = Some(format!("{:x}", digest.finalize()));
        }
        Ok(selected)
    }

    fn ancestry(&self, inspector: &dyn ProcessInspector, child_pid: u32) -> Vec<ProcessRecord> {
        let mut result = Vec::new();
        let mut pid = child_pid;
        for _ in 0..MAX_ANCESTORS {
            let Ok(process) = inspector.inspect(pid) else {
                break;
            };
            pid = process.parent_pid;
            result.push(process);
            if pid <= 1 || result.iter().any(|seen| seen.pid == pid) {
                break;
            }
        }
        result
    }

    fn agent_for(&self, process: &ProcessRecord) -> Option<AgentKind> {
        let executable = process.executable.as_deref()?;
        identify_agent(executable).or_else(|| {
            let name = executable.rsplit('/').next().unwrap_or(executable);
            self.manifest_names
                .iter()
                .any(|known| known == name)
                .then_some(AgentKind::Manifest)
        })
    }

    fn candidate(
        &self,
        process: &ProcessRecord,
        agent: AgentKind,
        hints: &CandidateHints,
        distance: Option<usize>,
    ) -> ResolvedProcess {
        let (score, reasons) = score(process, hints, distance);
        ResolvedProcess {
            identity: process.identity(),
            agent,
            score,
            reasons,
        }
    }
}

fn select_candidate(mut candidates: Vec<ResolvedProcess>) -> Result<ResolvedProcess, ProcessError> {
    candidates.sort_by(|left, right| right.score.cmp(&left.score));
    let Some(best) = candidates.first() else {
        return Err(ProcessError::NoConfidentCandidate { examined: 0 });
    };
    if best.score < MINIMUM_CONFIDENCE {
        return Err(ProcessError::NoConfidentCandidate {
            examined: candidates.len(),
        });
    }
    if candidates
        .get(1)
        .is_some_and(|next| next.score == best.score)
    {
        let score = best.score;
        return Err(ProcessError::Ambiguous {
            candidates: candidates
                .into_iter()
                .take_while(|item| item.score == score)
                .map(|item| item.identity.pid)
                .collect(),
        });
    }
    Ok(candidates.remove(0))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LifecycleDecision {
    Alive,
    Grace,
    ReexecAccepted(ProcessIdentity),
    Terminate,
}

pub struct LifecycleMonitor {
    identity: ProcessIdentity,
    grace_ms: u64,
    missing_since: Option<u64>,
}

impl LifecycleMonitor {
    pub const fn new(identity: ProcessIdentity) -> Self {
        Self {
            identity,
            grace_ms: 0,
            missing_since: None,
        }
    }
    pub const fn with_reexec_grace(identity: ProcessIdentity, grace_ms: u64) -> Self {
        Self {
            identity,
            grace_ms,
            missing_since: None,
        }
    }
    pub fn observe(&mut self, inspector: &dyn ProcessInspector, now_ms: u64) -> LifecycleDecision {
        match inspector.inspect(self.identity.pid) {
            Ok(process) if same_process(&self.identity, &process) => LifecycleDecision::Alive,
            Ok(_) => LifecycleDecision::Terminate,
            Err(ProcessError::Disappeared(_)) if self.grace_ms > 0 => {
                self.observe_missing(inspector, now_ms)
            }
            Err(_) => LifecycleDecision::Terminate,
        }
    }

    fn observe_missing(
        &mut self,
        inspector: &dyn ProcessInspector,
        now_ms: u64,
    ) -> LifecycleDecision {
        let missing_since = *self.missing_since.get_or_insert(now_ms);
        if now_ms.saturating_sub(missing_since) > self.grace_ms {
            return LifecycleDecision::Terminate;
        }
        let Some(tty) = self.identity.tty.as_deref() else {
            return LifecycleDecision::Grace;
        };
        let Ok(processes) = inspector.processes_on_tty(tty) else {
            return LifecycleDecision::Grace;
        };
        let matches: Vec<_> = processes
            .into_iter()
            .filter(|process| strong_reexec_match(&self.identity, process))
            .collect();
        if matches.len() != 1 {
            return LifecycleDecision::Grace;
        }
        self.identity = matches[0].identity();
        self.missing_since = None;
        LifecycleDecision::ReexecAccepted(self.identity.clone())
    }
}

fn same_process(identity: &ProcessIdentity, process: &ProcessRecord) -> bool {
    identity.pid == process.pid
        && identity.start_time == process.start_time
        && identity.executable == process.executable
}

fn strong_reexec_match(identity: &ProcessIdentity, process: &ProcessRecord) -> bool {
    let original_agent = identity.executable.as_deref().and_then(identify_agent);
    let replacement_agent = process.executable.as_deref().and_then(identify_agent);
    identity.tty == process.tty
        && identity.process_group_id == process.process_group_id
        && identity.session_leader_id == process.session_leader_id
        && identity.uid == process.uid
        && original_agent.is_some()
        && original_agent == replacement_agent
}
