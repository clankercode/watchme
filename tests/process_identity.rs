use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
use watchme::process::linux::{LinuxProcessInspector, parse_proc_stat, parse_status_uid};
use watchme::process::{
    AgentKind, CandidateHints, LifecycleDecision, LifecycleMonitor, ProcessError, ProcessInspector,
    ProcessRecord, ProcessResolver,
};

#[derive(Default)]
struct FakeInspector {
    processes: BTreeMap<u32, ProcessRecord>,
}

impl FakeInspector {
    fn with(mut self, process: ProcessRecord) -> Self {
        self.processes.insert(process.pid, process);
        self
    }
}

impl ProcessInspector for FakeInspector {
    fn inspect(&self, pid: u32) -> Result<ProcessRecord, ProcessError> {
        self.processes
            .get(&pid)
            .cloned()
            .ok_or(ProcessError::Disappeared(pid))
    }

    fn processes_on_tty(&self, tty: &str) -> Result<Vec<ProcessRecord>, ProcessError> {
        Ok(self
            .processes
            .values()
            .filter(|process| process.tty.as_deref() == Some(tty))
            .cloned()
            .collect())
    }
}

fn process(pid: u32, parent_pid: u32, name: &str) -> ProcessRecord {
    ProcessRecord::synthetic(pid, parent_pid, pid as u64 * 10, name)
        .with_uid(1000)
        .with_terminal("/dev/pts/4", 40, 30)
}

#[test]
fn resolves_agent_through_watchme_and_shell_wrappers() {
    let inspector = FakeInspector::default()
        .with(process(70, 60, "watchme"))
        .with(process(60, 50, "bash"))
        .with(process(50, 40, "env"))
        .with(process(40, 1, "claude"));

    let resolved = ProcessResolver::default()
        .resolve(&inspector, 70, &CandidateHints::for_tty("/dev/pts/4"))
        .expect("unambiguous Claude ancestor");

    assert_eq!(resolved.agent, AgentKind::Claude);
    assert_eq!(resolved.identity.pid, 40);
    assert_eq!(
        resolved.identity.parent_digest.as_deref().map(str::len),
        Some(64)
    );
    assert!(
        resolved
            .reasons
            .iter()
            .any(|reason| reason.contains("ancestor"))
    );
}

#[test]
fn recognizes_codex_alias_and_correlates_pane_evidence() {
    let inspector = FakeInspector::default()
        .with(process(91, 80, "watchme"))
        .with(process(80, 1, "codex-linux-x64"));
    let hints = CandidateHints::for_tty("/dev/pts/4")
        .with_process_group(40)
        .with_session(30)
        .with_uid(1000)
        .with_executable_hint("codex-linux-x64");

    let resolved = ProcessResolver::default()
        .resolve(&inspector, 91, &hints)
        .unwrap();

    assert_eq!(resolved.agent, AgentKind::Codex);
    assert!(resolved.score >= 10);
    assert!(resolved.reasons.iter().any(|reason| reason.contains("tty")));
}

#[test]
fn rejects_ambiguous_tty_candidates_when_ancestry_is_broken() {
    let inspector = FakeInspector::default()
        .with(process(21, 999, "watchme"))
        .with(process(31, 1, "claude"))
        .with(process(32, 1, "codex"));

    let error = ProcessResolver::default()
        .resolve(&inspector, 21, &CandidateHints::for_tty("/dev/pts/4"))
        .unwrap_err();

    assert!(matches!(error, ProcessError::Ambiguous { .. }));
    assert!(error.to_string().contains("watchme doctor"));
}

#[test]
fn refuses_low_confidence_global_or_unrelated_processes() {
    let mut unrelated = process(42, 1, "claude");
    unrelated.tty = Some("/dev/pts/9".into());
    let inspector = FakeInspector::default()
        .with(process(21, 999, "watchme"))
        .with(unrelated);

    assert!(matches!(
        ProcessResolver::default().resolve(&inspector, 21, &CandidateHints::for_tty("/dev/pts/4")),
        Err(ProcessError::NoConfidentCandidate { .. })
    ));
}

#[test]
fn lifecycle_rejects_pid_reuse_and_executable_replacement() {
    let original = process(40, 1, "claude");
    let identity = original.identity();
    let mut monitor = LifecycleMonitor::new(identity.clone());
    let reused = ProcessRecord {
        start_time: 999,
        ..original.clone()
    };
    assert_eq!(
        monitor.observe(&FakeInspector::default().with(reused), 100),
        LifecycleDecision::Terminate
    );

    let replaced = ProcessRecord {
        executable: Some("/tmp/imposter".into()),
        ..original
    };
    assert_eq!(
        monitor.observe(&FakeInspector::default().with(replaced), 100),
        LifecycleDecision::Terminate
    );
}

#[test]
fn lifecycle_accepts_only_short_strongly_verified_reexec() {
    let original = process(40, 1, "claude");
    let mut monitor = LifecycleMonitor::with_reexec_grace(original.identity(), 50);
    assert_eq!(
        monitor.observe(&FakeInspector::default(), 100),
        LifecycleDecision::Grace
    );

    let replacement = process(41, 1, "claude");
    assert!(matches!(
        monitor.observe(&FakeInspector::default().with(replacement), 125),
        LifecycleDecision::ReexecAccepted(identity) if identity.pid == 41
    ));

    let original = process(50, 1, "codex");
    let mut monitor = LifecycleMonitor::with_reexec_grace(original.identity(), 10);
    assert_eq!(
        monitor.observe(&FakeInspector::default(), 100),
        LifecycleDecision::Grace
    );
    assert_eq!(
        monitor.observe(&FakeInspector::default().with(process(51, 1, "codex")), 111),
        LifecycleDecision::Terminate
    );
}

#[test]
fn lifecycle_refuses_reexec_with_weak_or_conflicting_evidence() {
    let original = process(40, 1, "agent-from-manifest");
    let mut monitor = LifecycleMonitor::with_reexec_grace(original.identity(), 50);
    assert_eq!(
        monitor.observe(&FakeInspector::default(), 100),
        LifecycleDecision::Grace
    );
    assert_eq!(
        monitor.observe(
            &FakeInspector::default().with(process(41, 1, "agent-from-manifest")),
            120
        ),
        LifecycleDecision::Grace
    );

    let original = process(50, 1, "claude");
    let mut monitor = LifecycleMonitor::with_reexec_grace(original.identity(), 50);
    assert_eq!(
        monitor.observe(&FakeInspector::default(), 100),
        LifecycleDecision::Grace
    );
    let conflicting = process(51, 1, "claude").with_terminal("/dev/pts/4", 99, 30);
    assert_eq!(
        monitor.observe(&FakeInspector::default().with(conflicting), 120),
        LifecycleDecision::Grace
    );
}

#[test]
fn argv_is_hashed_and_never_exposed_by_debug_or_serialization() {
    let secret = "sk-secret-never-persist";
    let record = process(40, 1, "claude").with_argv(["claude", "--token", secret]);
    let identity = record.identity();
    let debug = format!("{record:?} {identity:?}");
    let serialized = serde_json::to_string(&identity).unwrap();

    assert!(!debug.contains(secret));
    assert!(!serialized.contains(secret));
    assert!(
        identity
            .argv_digest
            .as_deref()
            .is_some_and(|digest| digest.len() == 64)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn proc_stat_parser_handles_spaces_parentheses_and_rejects_truncation() {
    let stat = "42 (agent (worker)) S 7 40 30 34817 0 0 0 0 0 0 0 0 0 0 0 0 0 0 987654 0";
    let parsed = parse_proc_stat(42, stat.as_bytes()).unwrap();
    assert_eq!(
        (
            parsed.parent_pid,
            parsed.process_group_id,
            parsed.session_leader_id
        ),
        (7, 40, 30)
    );
    assert_eq!(parsed.start_time, 987654);
    assert!(matches!(
        parse_proc_stat(42, b"42 (bad) S 1"),
        Err(ProcessError::Malformed { pid: 42, .. })
    ));
    assert!(parse_proc_stat(42, &vec![b'x'; 70_000]).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn proc_status_uid_is_strict_and_bounded() {
    assert_eq!(
        parse_status_uid(9, b"Name:\tx\nUid:\t1000\t1000\t1000\t1000\n").unwrap(),
        1000
    );
    assert!(parse_status_uid(9, b"Uid:\troot\n").is_err());
    assert!(parse_status_uid(9, &vec![b'x'; 70_000]).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn linux_inspector_reports_disappeared_proc_without_panicking() {
    let directory = tempfile::tempdir().unwrap();
    let inspector = LinuxProcessInspector::from_proc_root(directory.path());
    assert_eq!(
        inspector.inspect(1234),
        Err(ProcessError::Disappeared(1234))
    );
}
