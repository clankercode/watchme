# WatchMe v1 Design

## Scope and source of truth

WatchMe is a local Rust 2024 supervisor for long-running coding-agent sessions. The implementation follows `/home/xertrov/Downloads/WatchMe-one-shot-bundle`, including its requirements, architecture, threat model, acceptance plan, schemas, fixtures, and conservative defaults, except for the command-contract override below.

Linux and macOS are the required v1 platforms. Herdr and tmux are first-class multiplexers. Claude Code and Codex have first-class adapters; other agents use versioned manifests and remain action-disabled when their capabilities cannot be established safely.

The project is dual-licensed under `Unlicense OR CC0-1.0`. The repository will include canonical text for both licenses and use the SPDX expression where package metadata permits it.

## Command contract

Bare `watchme` is the sole registration command. From a supported coding agent, the user runs:

```text
!watchme
```

The short-lived client discovers the ancestor coding-agent process, multiplexer pane, and durable session; registers that identity with the per-user daemon; reports success or an existing watcher; and exits. Registration takes no arguments and asks no interactive questions.

There is no `watchme start` subcommand. When bare `watchme` cannot identify a supported agent context, it prints concise help explaining that it must normally be invoked through `!watchme`, together with the relevant diagnostic command.

Administrative commands remain available: `status`, `list`, `explain`, `snapshot`, `logs`, `stop`, `doctor`, `providers`, `config`, and `daemon`. Explicit selectors needed for diagnostics or unusual environments belong on diagnostic/administrative commands rather than creating an alternative registration workflow. `WatchMe` is installed as an uppercase compatibility alias; lowercase `watchme` is canonical.

## Architecture

Use one Rust package and one installed binary, divided into focused internal modules rather than separate crates. The main boundaries are core types and policy, discovery and multiplexer integration, agent adapters, persistence and IPC, recovery, planner integration, and CLI/daemon orchestration. These are code-organization boundaries, not extra user-facing services or packages.

One `watchme` executable exposes both client and daemon behavior. A single owner-scoped daemon supervises all registered targets with one event loop, deduplicates registrations, persists transitions atomically, and exits after the last watcher plus the configured idle grace. The daemon never relaunches a terminated coding agent.

Subsystems communicate through narrow traits and typed records where substitution or platform testing requires them. Simple internal behavior stays as ordinary modules and functions. Core safety policy cannot be weakened by provider manifests, local configuration, terminal content, or planner output.

## Discovery and lifecycle

Registration starts at the short-lived `watchme` process and walks its ancestry past shell wrappers to find a known coding-agent executable. It cross-checks the candidate against pane tty, process group, process start time, executable, and multiplexer metadata. Ambiguous discovery fails closed.

Target identity includes multiplexer server/socket identity, pane metadata, PID, process start time, and available tty/process-group/executable evidence. Durable agent session and log discovery uses native references and process-correlated evidence before scored filesystem search. It never binds solely to the newest session file.

The watcher stops when the `(pid, process_start_time)` identity terminates, except for a short, strongly verified re-exec grace. Recycled PIDs, panes, replaced processes, and ambiguous sessions cannot receive input.

## Observation and recovery flow

The daemon prefers typed APIs and hooks, then structured logs, process metadata, native multiplexer state, bounded terminal tails, and finally alternate-agent interpretation. Every observation records provenance, confidence, timestamp, and evidence fingerprint. Contradictory higher-confidence evidence suppresses lower-confidence action.

Confirmed known states use deterministic recovery first. Claude recovery selects the labelled stop-and-wait option rather than a menu number, parses the reset conservatively, detects human intervention, waits without busy-polling, and verifies work after resuming. Codex recovery sends `/goal resume` only for a verified durable blocked-goal capacity case and verifies that the goal returns to an active state.

Unknown recoverable states may reach a planner from a different verified provider family. The planner receives only a bounded, redacted snapshot and returns strict schema-constrained actions. It cannot execute commands. The compiled policy engine independently rejects unsafe, stale, over-budget, or non-allowlisted actions.

Immediately before every input action, WatchMe revalidates target identity, current evidence, composer safety, user-intervention state, cooldowns, and attempt budgets. It sends literal text separately from allowlisted symbolic keys and then verifies progress using equal- or higher-confidence evidence. Failure to verify is not success. Unsafe, ambiguous, exhausted, credential, account, billing, permission-expanding, or destructive cases become `human_required`.

## Persistence, privacy, and errors

Runtime directories, sockets, state, snapshots, and hook markers are owner-only. State writes are atomic and transitions are auditable. After restart, the daemon reloads state but performs no action until it revalidates the live target and current evidence. Only one action transaction may run per target.

Terminal, log, hook, manifest, and planner content is untrusted. Inputs are bounded, ANSI/control sequences sanitized, paths constrained against traversal and symlink attacks, and common secrets redacted before persistence or planner use. WatchMe does not copy the full environment, enable telemetry, or automate authentication, billing, funding, upgrades, broad approvals, privilege escalation, or destructive actions.

Errors are typed as configuration, unsupported context, target terminated, retryable integration failure, policy denial, or human-required. CLI messages are concise and actionable; redacted audit logs retain the detector, evidence, state transition, policy decision, attempted action, and verification result.

## Testing and delivery

Development follows test-driven slices. Unit and property tests cover identities, parsers, incremental logs, state transitions, policy, redaction, configuration, manifests, planner validation, malformed inputs, clock behavior, and concurrency. Integration tests use a real tmux session with a fake agent and a schema-faithful fake Herdr service. Claude and Codex scenarios, pane/PID reuse, human intervention, log rotation, daemon restart, hostile terminal content, unsafe planner output, and duplicate registration are exercised without paid provider events.

Release gates include formatting, Clippy with warnings denied, all tests, release build, schema validation, available dependency/license/security audits, installer smoke tests, and a measured idle-resource benchmark. Documentation and compatibility claims report only tested or probed behavior and clearly distinguish structured recovery, deterministic terminal recovery, planner-assisted support, observation-only support, and untested agents.

The completed repository includes the bundle-required command, configuration, manifest, hook, service, privacy, troubleshooting, architecture, threat-model, testing, benchmark, compatibility, changelog, release, license, and third-party documentation.
