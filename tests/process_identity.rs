use std::collections::BTreeMap;

#[cfg(target_os = "linux")]
use watchme::process::linux::{
    LinuxProcessInspector, MAX_PROC_ENTRIES, canonical_tty_path, collect_proc_pid_names,
    parse_proc_stat, parse_status_uid,
};
use watchme::process::macos::{
    MacProcessSource, VerifiedMacInspector, parse_ps_record, run_bounded_command,
};
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
fn rejects_known_ancestor_when_strong_pane_evidence_conflicts() {
    let mut agent = process(40, 1, "claude");
    agent.uid = Some(2000);
    let inspector = FakeInspector::default()
        .with(process(70, 40, "watchme"))
        .with(agent);
    let hints = CandidateHints::for_tty("/dev/pts/4")
        .with_uid(1000)
        .with_process_group(40)
        .with_session(30);
    assert!(matches!(
        ProcessResolver::default().resolve(&inspector, 70, &hints),
        Err(ProcessError::NoConfidentCandidate { .. })
    ));
}

#[test]
fn known_name_without_positive_cross_correlation_is_low_confidence() {
    let mut child = process(70, 40, "watchme");
    child.tty = None;
    child.uid = None;
    child.process_group_id = None;
    child.session_leader_id = None;
    let mut agent = process(40, 1, "claude");
    agent.tty = None;
    agent.uid = None;
    agent.process_group_id = None;
    agent.session_leader_id = None;
    let inspector = FakeInspector::default().with(child).with(agent);
    assert!(matches!(
        ProcessResolver::default().resolve(&inspector, 70, &CandidateHints::default()),
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
fn lifecycle_refuses_missing_uid_or_group_and_does_not_commit_proposal() {
    let original = process(40, 1, "claude");
    let mut monitor = LifecycleMonitor::with_reexec_grace(original.identity(), 50);
    assert_eq!(
        monitor.observe(&FakeInspector::default(), 100),
        LifecycleDecision::Grace
    );
    let mut missing_uid = process(41, 1, "claude");
    missing_uid.uid = None;
    assert_eq!(
        monitor.observe(&FakeInspector::default().with(missing_uid), 110),
        LifecycleDecision::Grace
    );
    let proposed = process(41, 1, "claude");
    assert!(matches!(
        monitor.observe(&FakeInspector::default().with(proposed.clone()), 120),
        LifecycleDecision::ReexecAccepted(_)
    ));
    assert!(
        matches!(
            monitor.observe(&FakeInspector::default().with(proposed), 121),
            LifecycleDecision::ReexecAccepted(_)
        ),
        "proposal must remain uncommitted until durable registry update succeeds"
    );
}

#[test]
fn macos_parser_uses_tty_name_and_is_runnable_cross_platform() {
    let parsed = parse_ps_record(b"42 7 40 30 1000 ttys004 /opt/claude", 123).unwrap();
    assert_eq!(parsed.tty.as_deref(), Some("/dev/ttys004"));
    assert_eq!(parsed.start_time, 123);
    assert!(parse_ps_record(b"42 malformed", 123).is_err());
}

#[derive(Default)]
struct FakeMacSource {
    calls: std::cell::RefCell<Vec<String>>,
    starts: std::cell::RefCell<Vec<u64>>,
}

struct PartiallyBrokenMacSource {
    broken: ProcessError,
}

impl MacProcessSource for PartiallyBrokenMacSource {
    fn start_time(&self, _pid: u32) -> Result<u64, ProcessError> {
        Ok(100)
    }
    fn ps_record(&self, pid: u32) -> Result<Vec<u8>, ProcessError> {
        if pid == 42 {
            Ok(b"42 7 40 30 1000 ttys004 /opt/claude".to_vec())
        } else {
            Err(match &self.broken {
                ProcessError::Malformed { pid, reason } => ProcessError::Malformed {
                    pid: *pid,
                    reason: reason.clone(),
                },
                ProcessError::Inspection(reason) => ProcessError::Inspection(reason.clone()),
                ProcessError::Disappeared(pid) => ProcessError::Disappeared(*pid),
                other => ProcessError::Inspection(other.to_string()),
            })
        }
    }
    fn list_pids(&self) -> Result<Vec<u32>, ProcessError> {
        Ok(vec![42, 43])
    }
}

impl MacProcessSource for FakeMacSource {
    fn start_time(&self, pid: u32) -> Result<u64, ProcessError> {
        self.calls.borrow_mut().push(format!("start:{pid}"));
        Ok(self.starts.borrow_mut().remove(0))
    }
    fn ps_record(&self, pid: u32) -> Result<Vec<u8>, ProcessError> {
        self.calls.borrow_mut().push(format!("ps:{pid}"));
        Ok(format!("{pid} 7 40 30 1000 ttys004 /opt/claude").into_bytes())
    }
    fn list_pids(&self) -> Result<Vec<u32>, ProcessError> {
        self.calls.borrow_mut().push("list".into());
        Ok(vec![42])
    }
}

#[test]
fn macos_inspection_rejects_recycle_with_before_ps_after_order() {
    let source = FakeMacSource {
        starts: std::cell::RefCell::new(vec![1_000_001, 1_000_002]),
        ..FakeMacSource::default()
    };
    let inspector = VerifiedMacInspector::new(source);
    assert_eq!(inspector.inspect(42), Err(ProcessError::Disappeared(42)));
    assert_eq!(
        inspector.source().calls.borrow().as_slice(),
        ["start:42", "ps:42", "start:42"]
    );
}

#[test]
fn macos_tty_enumeration_verifies_each_pid_before_reading_its_row() {
    let source = FakeMacSource {
        starts: std::cell::RefCell::new(vec![100, 101]),
        ..FakeMacSource::default()
    };
    let inspector = VerifiedMacInspector::new(source);
    assert!(
        inspector
            .processes_on_tty("/dev/ttys004")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        inspector.source().calls.borrow().as_slice(),
        ["list", "start:42", "ps:42", "start:42"]
    );
}

#[test]
fn macos_enumeration_propagates_malformed_or_permission_errors_but_omits_disappeared() {
    for broken in [
        ProcessError::Malformed {
            pid: 43,
            reason: "bad row".into(),
        },
        ProcessError::Inspection("permission denied".into()),
    ] {
        let inspector = VerifiedMacInspector::new(PartiallyBrokenMacSource { broken });
        assert!(inspector.processes_on_tty("/dev/ttys004").is_err());
    }
    let inspector = VerifiedMacInspector::new(PartiallyBrokenMacSource {
        broken: ProcessError::Disappeared(43),
    });
    assert_eq!(inspector.processes_on_tty("/dev/ttys004").unwrap().len(), 1);
}

#[test]
fn macos_command_boundary_bounds_output_and_kills_hung_children() {
    assert!(
        run_bounded_command(
            "/usr/bin/printf",
            &["123456789"],
            4,
            std::time::Duration::from_secs(1)
        )
        .is_err()
    );
    let started = std::time::Instant::now();
    assert!(
        run_bounded_command(
            "/usr/bin/sleep",
            &["10"],
            4,
            std::time::Duration::from_millis(20)
        )
        .is_err()
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
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
    assert_eq!(parsed.tty.as_deref(), Some("dev:136:1"));
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

#[cfg(target_os = "linux")]
#[test]
fn pane_tty_paths_use_same_device_identity_as_proc_stat() {
    let identity = canonical_tty_path(std::path::Path::new("/dev/null")).unwrap();
    assert!(identity.starts_with("dev:"));
}

#[cfg(target_os = "linux")]
#[test]
fn proc_enumeration_rejects_over_limit_and_entry_errors() {
    let over_limit = (0..=MAX_PROC_ENTRIES).map(|pid| Ok(pid.to_string()));
    assert!(matches!(
        collect_proc_pid_names(over_limit),
        Err(ProcessError::IncompleteEnumeration(_))
    ));
    assert!(matches!(
        collect_proc_pid_names([Ok("1".into()), Err("injected entry failure".into())]),
        Err(ProcessError::IncompleteEnumeration(_))
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_inspector_rejects_mid_read_pid_recycle_and_ignores_redirected_stdin() {
    use std::sync::Arc;
    let directory = tempfile::tempdir().unwrap();
    let process_dir = directory.path().join("42");
    std::fs::create_dir_all(&process_dir).unwrap();
    let stat = |start| format!("42 (claude) S 1 40 30 34817 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {start} 0");
    std::fs::write(process_dir.join("stat"), stat(100)).unwrap();
    std::fs::write(process_dir.join("status"), "Uid:\t1000\t1000\t1000\t1000\n").unwrap();
    std::fs::write(process_dir.join("cmdline"), b"claude\0").unwrap();
    std::fs::create_dir_all(process_dir.join("fd")).unwrap();
    std::fs::write(process_dir.join("fd/0"), b"redirected input").unwrap();
    let stat_path = process_dir.join("stat");
    let inspector = LinuxProcessInspector::from_proc_root_with_hook(
        directory.path(),
        Arc::new(move || std::fs::write(&stat_path, stat(101)).unwrap()),
    );
    assert_eq!(inspector.inspect(42), Err(ProcessError::Disappeared(42)));
}
