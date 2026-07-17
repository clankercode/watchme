# Real Codex Native Herdr Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make bare `watchme` bind the exact running Codex thread, observe real blocked-goal capacity failures, and atomically submit `/goal resume` through native Herdr protocol 16.

**Architecture:** Preserve the hardened Unix-socket transport while adding an explicit native Herdr wire dialect and exact pane/process correlation. Add a registration-time Codex attachment plus a read-only SQLite/bounded-rollout observer, promote existing process-only watchers in place, and authorize one atomic resume only from current structured evidence. Herdr focus/status remains optional corroboration and never overrides Codex state.

**Tech Stack:** Rust 2024, Tokio Unix sockets, Serde/JSON, `rusqlite 0.39.0` with bundled SQLite (compatible with the project's Rust 1.88 floor), existing atomic JSON store, native Herdr protocol 16, Cargo/Just test gates.

---

## Execution setup and file map

Execute this plan in a dedicated worktree created from the approved design
commit. Do not implement directly on the dirty or shared primary checkout.

```bash
git worktree add /home/xertrov/.config/superpowers/worktrees/watchme/codex-native-herdr-recovery -b codex-native-herdr-recovery master
cd /home/xertrov/.config/superpowers/worktrees/watchme/codex-native-herdr-recovery
```

Files and responsibilities after the change:

- `src/mux/herdr/mod.rs`: socket hardening, dialect negotiation, and the public
  `Herdr` multiplexer implementation.
- `src/mux/herdr/bridge.rs`: the existing `watchme.herdr` request/response wire
  contract.
- `src/mux/herdr/native.rs`: strict protocol-16 request/result types and native
  pane/process/read/input mapping.
- `src/codex_attachment.rs`: registration-only thread and open-file
  correlation; no observation or recovery policy.
- `src/agents/codex_state.rs`: read-only goal database lookup and bounded
  append-only rollout parsing.
- `src/agents/codex.rs`: classification, event construction, and recipes using
  normalized snapshots from `codex_state`.
- `src/model/state.rs`: backward-compatible optional Codex file bindings.
- `src/model/identity.rs`: persisted Herdr wire dialect.
- `src/model/action.rs`, `src/recovery/actuator.rs`, `src/policy.rs`: an explicit
  `SUBMIT_TEXT` action distinct from text insertion.
- `src/daemon/registry.rs`: exact process-to-native-Herdr promotion and trusted
  attachment refresh.
- `src/audit.rs`, `src/daemon/mod.rs`: redacted lifecycle audit records.
- `tests/herdr_contract.rs`: bridge and native protocol contract tests.
- `tests/codex_attachment.rs`: process/thread/file binding tests.
- `tests/codex_recovery.rs`: SQLite/rollout classification and recovery tests.
- `tests/cli.rs`: bare-registration and promotion integration tests.
- `tests/recovery_daemon_herdr_e2e.rs`: one atomic resume and verification.

### Task 1: Split the Herdr adapter without changing behavior

**Files:**
- Move: `src/mux/herdr.rs` → `src/mux/herdr/mod.rs`
- Create: `src/mux/herdr/bridge.rs`
- Modify: `src/mux/herdr/mod.rs`
- Test: `tests/herdr_contract.rs`

- [ ] **Step 1: Record the green bridge baseline**

Run:

```bash
cargo test --test herdr_contract
```

Expected: all existing Herdr bridge contract tests pass.

- [ ] **Step 2: Move the module and extract bridge-only wire types**

Run:

```bash
mkdir -p src/mux/herdr
git mv src/mux/herdr.rs src/mux/herdr/mod.rs
```

Create `src/mux/herdr/bridge.rs` with the existing bridge envelope isolated:

```rust
use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "watchme.herdr";
pub const SCHEMA_VERSION: u16 = 1;

#[derive(Serialize)]
pub(super) struct Request<'a, P> {
    pub schema_version: u16,
    pub protocol: &'static str,
    pub request_id: &'a str,
    pub method: &'a str,
    pub params: P,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Response<T> {
    pub schema_version: u16,
    pub protocol: String,
    pub request_id: String,
    pub method: String,
    pub ok: bool,
    pub result: Option<T>,
    pub error: Option<String>,
}
```

In `src/mux/herdr/mod.rs`, add `mod bridge;`, import these two types, and leave
all runtime behavior unchanged.

- [ ] **Step 3: Verify the refactor stays green**

Run:

```bash
cargo fmt --check
cargo test --test herdr_contract
```

Expected: formatting and all bridge tests pass.

- [ ] **Step 4: Commit the structural boundary**

```bash
git add src/mux/herdr tests/herdr_contract.rs
git commit -m "refactor: split Herdr wire adapter"
```

### Task 2: Negotiate and validate native Herdr protocol 16

**Files:**
- Create: `src/mux/herdr/native.rs`
- Modify: `src/mux/herdr/mod.rs`
- Modify: `src/model/identity.rs`
- Modify: `src/model/mod.rs`
- Test: `tests/herdr_contract.rs`

- [ ] **Step 1: Write failing native negotiation and identity tests**

Add a native response helper and a test to `tests/herdr_contract.rs`:

```rust
fn native_response(request: &Value, result: Value) -> Value {
    json!({"id": request["id"], "result": result})
}

#[test]
fn native_protocol_16_correlates_exact_pane_and_process() {
    let pid = std::process::id();
    let (_server, socket, requests) = spawn_fake(move |request, index| {
        let result = match (index, request["method"].as_str().unwrap()) {
            (0, "pane_info") => {
                return Some(json!({"id":"", "error": {
                    "code":"invalid_request", "message":"missing field id"
                }}));
            }
            (_, "ping") => json!({"type":"pong", "version":"0.7.4", "protocol":16}),
            (_, "pane.current") => json!({"type":"pane_current", "pane": {
                "pane_id":"pane-3", "terminal_id":"term-1", "workspace_id":"ws-1",
                "tab_id":"tab-2", "focused":true, "agent_status":"working",
                "revision":7, "cwd":"/repo", "foreground_cwd":"/repo"
            }}),
            (_, "pane.process_info") => json!({"type":"pane_process_info", "process_info": {
                "pane_id":"pane-3", "tty":"/dev/pts/8",
                "foreground_processes":[{"pid":pid,"name":"codex","argv":["codex"]}]
            }}),
            other => panic!("unexpected native request {other:?}"),
        };
        Some(native_response(&request, result))
    });
    let inspector = watchme::process::linux::LinuxProcessInspector::default();
    let start_time = watchme::process::ProcessInspector::inspect(&inspector, pid)
        .unwrap()
        .start_time;
    let mut process = ProcessIdentity::new(pid, start_time);
    process.tty = Some("/dev/pts/8".into());
    let herdr = Herdr::new(context(socket), Duration::from_millis(300)).unwrap();

    let identity = herdr.current_target_for_process(&process).unwrap();

    assert_eq!(identity.provider, "herdr");
    assert_eq!(identity.pane_id, "pane-3");
    assert_eq!(identity.process.pid, pid);
    assert!(identity.server_instance.contains("protocol-16"));
    assert!(requests.lock().unwrap().iter().any(|r| r["method"] == "pane.current"));
}
```

Add separate tests that reject protocol 17, mismatched response IDs, a pane ID
different from inherited context, an absent expected PID, and a TTY mismatch.

- [ ] **Step 2: Run the native contract test and verify RED**

Run:

```bash
cargo test --test herdr_contract native_protocol_16_correlates_exact_pane_and_process -- --exact
```

Expected: compilation fails because `current_target_for_process` and native
wire types do not exist.

- [ ] **Step 3: Add persisted wire dialect and strict native envelopes**

Add to `src/model/identity.rs`:

```rust
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HerdrWireProtocol {
    #[default]
    Auto,
    BridgeV1,
    Native16,
}
```

Add a `#[serde(default)] wire_protocol: HerdrWireProtocol` field to the Herdr
variant of `MultiplexerContext`. Existing serialized watchers therefore decode
as `Auto`; a verified new target persists `Native16`.

Create `src/mux/herdr/native.rs`:

```rust
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const PROTOCOL: u32 = 16;

#[derive(Serialize)]
pub(super) struct Request<'a, P> {
    pub id: &'a str,
    pub method: &'a str,
    pub params: P,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Success<T> {
    pub id: String,
    pub result: T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Failure {
    pub id: String,
    pub error: ErrorBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ResultValue {
    Pong { version: String, protocol: u32 },
    PaneCurrent { pane: Pane },
    PaneProcessInfo { process_info: ProcessInfo },
    PaneRead { read: ReadResult },
    AgentInfo { agent: AgentInfo },
    Ok,
}

#[derive(Deserialize)]
pub(super) struct Pane {
    pub pane_id: String,
    pub terminal_id: String,
    pub workspace_id: String,
    pub tab_id: String,
    pub focused: bool,
    pub agent_status: String,
    pub revision: u64,
    pub cwd: Option<String>,
    pub foreground_cwd: Option<String>,
    pub agent_session: Option<AgentSession>,
}

#[derive(Deserialize)]
pub(super) struct AgentSession {
    pub source: String,
    pub agent: String,
    pub kind: String,
    pub value: String,
}

#[derive(Deserialize)]
pub(super) struct AgentInfo {
    pub agent: Option<String>,
    pub agent_session: Option<AgentSession>,
    pub agent_status: String,
    pub screen_detection_skipped: Option<bool>,
    pub workspace_id: String,
    pub tab_id: String,
    pub pane_id: String,
    pub revision: u64,
}

#[derive(Deserialize)]
pub(super) struct ProcessInfo {
    pub pane_id: String,
    pub tty: Option<String>,
    pub foreground_processes: Vec<ForegroundProcess>,
}

#[derive(Deserialize)]
pub(super) struct ForegroundProcess {
    pub pid: u32,
    pub name: String,
    pub argv: Option<Vec<String>>,
    pub cwd: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ReadResult {
    pub pane_id: String,
    pub workspace_id: String,
    pub tab_id: String,
    pub source: String,
    pub format: String,
    pub text: String,
    pub revision: u64,
    pub truncated: bool,
}

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8], id: &str) -> Result<T, String> {
    if let Ok(success) = serde_json::from_slice::<Success<T>>(bytes) {
        return (success.id == id)
            .then_some(success.result)
            .ok_or_else(|| "native response ID mismatch".into());
    }
    let failure: Failure = serde_json::from_slice(bytes)
        .map_err(|error| format!("malformed native response: {error}"))?;
    if failure.id != id {
        return Err("native error response ID mismatch".into());
    }
    Err(format!("{}: {}", failure.error.code, failure.error.message))
}
```

In `Herdr`, cache the concrete dialect after the bridge probe identifies a
native envelope. Add `current_target_for_process(&ProcessIdentity)`, which calls
native `ping`, `pane.current`, and `pane.process_info`; requires protocol 16 and
the inherited IDs; requires the exact expected PID in `foreground_processes`;
and compares normalized TTYs. Build `server_instance` from native version,
protocol, and the already-validated socket device/inode.

Use exact native parameters: `ping` gets `{}`, `pane.current` gets
`{"caller_pane_id": CONTEXT_PANE}`, `pane.process_info` gets
`{"pane_id": CONTEXT_PANE}`, and `agent.get` gets
`{"target": CONTEXT_PANE}`. `agent.get` is supporting metadata only. A missing,
stale, focused, or `screen_detection_skipped = true` agent result cannot reject
otherwise valid Codex state and cannot authorize an action by itself. Re-export
`HerdrWireProtocol` from `src/model/mod.rs`, and update every `HerdrContext` and
`MultiplexerContext::Herdr` constructor with `Auto`, `BridgeV1`, or `Native16`
as appropriate.

- [ ] **Step 4: Run all Herdr contract tests**

```bash
cargo test --test herdr_contract
```

Expected: bridge behavior remains green and all native identity/error tests pass.

- [ ] **Step 5: Commit native negotiation**

```bash
git add src/model/identity.rs src/model/mod.rs src/mux/herdr tests/herdr_contract.rs
git commit -m "feat: negotiate native Herdr protocol 16"
```

### Task 3: Add bounded native capture and atomic text submission

**Files:**
- Modify: `src/mux/mod.rs`
- Modify: `src/mux/herdr/mod.rs`
- Modify: `src/mux/herdr/native.rs`
- Modify: `src/model/action.rs`
- Modify: `src/recovery/actuator.rs`
- Modify: `src/recovery/transaction.rs`
- Modify: `src/policy.rs`
- Modify: `src/planner/schema.rs`
- Modify: `src/daemon/recovery_runtime.rs`
- Modify: `src/agents/manifest.rs`
- Modify: `schemas/recovery-plan.schema.json`
- Modify: `schemas/snapshot.schema.json`
- Test: `tests/herdr_contract.rs`
- Test: `tests/observation_policy.rs`
- Test: `tests/planner_security.rs`

- [ ] **Step 1: Write failing native read and atomic-submit tests**

Add to `tests/herdr_contract.rs` a native fake that records requests, then:

```rust
let capture = herdr.capture_tail(&identity, 20, 4096).unwrap();
assert_eq!(capture.text, "Selected model is at capacity. Please try a different model.");
herdr.submit_literal(&identity, "/goal resume", &Safe).unwrap();

let requests = requests.lock().unwrap();
assert!(requests.iter().any(|request| request["method"] == "pane.read"
    && request["params"]["source"] == "recent_unwrapped"
    && request["params"]["lines"] == 20
    && request["params"]["strip_ansi"] == true));
assert_eq!(requests.iter().filter(|r| r["method"] == "pane.send_input").count(), 1);
let send = requests.iter().find(|r| r["method"] == "pane.send_input").unwrap();
assert_eq!(send["params"], json!({
    "pane_id":"pane-3", "text":"/goal resume", "keys":["Enter"]
}));
```

Also assert unsafe composer state sends no request, mismatched pane revision
sends no request, oversize reads fail before I/O, and a timeout after dispatch
returns `MuxError::CommandOutcomeUnknown` rather than a retryable protocol error.

- [ ] **Step 2: Verify RED**

```bash
cargo test --test herdr_contract native_capture_and_submit_are_bounded_and_atomic -- --exact
```

Expected: compilation fails because `submit_literal` and the ambiguous-outcome
error do not exist.

- [ ] **Step 3: Add explicit submit semantics**

Extend `MuxError` and `Multiplexer` in `src/mux/mod.rs`:

```rust
#[error("multiplexer command outcome is unknown: {0}")]
CommandOutcomeUnknown(String),

fn submit_literal(
    &self,
    identity: &MuxIdentity,
    text: &str,
    safety: &dyn ComposerSafety,
) -> Result<(), MuxError> {
    let _ = (identity, text, safety);
    Err(MuxError::Command("atomic text submission is unsupported".into()))
}
```

Add `SubmitText { text: String }` to `ActionKind`, an `Action::submit_text`
constructor with `TARGET_IDENTITY_MATCHES`, and the same literal bounds as
`SendText`. Update policy and planner schema handling so `SUBMIT_TEXT` is
permitted only with an empty composer and the existing fixed-safe-text rules.

Update `MuxActuator` so `SubmitText` calls `submit_literal`; keep `SendText`
calling `send_literal` so existing semantics do not silently change.
Update every exhaustive `ActionKind` match in the transaction and daemon
runtime so `SubmitText` is treated as an external side effect and routed only
through a multiplexer actuator. Generic/runtime and manifest actuators must not
silently emulate submission. Run `rg -n 'ActionKind::SendText' src tests` and
classify every match explicitly before the GREEN run.

Implement native `capture_tail` with `pane.read` and exact response bounds.
Implement native `submit_literal` with two identity checks and two composer
checks before one `pane.send_input` request containing both the text and
`["Enter"]`. Once the full request has been written, timeout, EOF, or malformed
acknowledgement maps to `CommandOutcomeUnknown`.

- [ ] **Step 4: Verify focused policy and schemas**

```bash
cargo test --test herdr_contract
cargo test --test observation_policy
cargo test --test planner_security
just schemas
```

Expected: all tests pass; schemas accept `SUBMIT_TEXT` and still reject control
characters, arbitrary keys, and untrusted planner submission.

- [ ] **Step 5: Commit capture and submission**

```bash
git add src/mux src/model/action.rs src/recovery/actuator.rs \
  src/recovery/transaction.rs src/policy.rs src/planner/schema.rs \
  src/daemon/recovery_runtime.rs src/agents/manifest.rs schemas tests/herdr_contract.rs \
  tests/observation_policy.rs tests/planner_security.rs
git commit -m "feat: add atomic native Herdr submission"
```

### Task 4: Bind the exact Codex thread and state files at registration

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `src/codex_attachment.rs`
- Modify: `src/lib.rs`
- Modify: `src/model/state.rs`
- Modify: `src/model/mod.rs`
- Modify: `src/registration_context.rs`
- Create: `tests/codex_attachment.rs`

- [ ] **Step 1: Add failing attachment tests with real open files**

Create `tests/codex_attachment.rs`. Its fixture must create owner-controlled
SQLite databases and keep the rollout/database handles open while attaching:

```rust
#[test]
fn linux_attachment_binds_resume_thread_and_open_codex_files() {
    let fixture = CodexProcessFixture::new("thr_demo", "/repo");
    let mut watcher = fixture.process_watcher();

    attach_process_correlated_codex_session_at(
        &mut watcher,
        fixture.proc_root(),
        None,
    );

    let reference = watcher.codex_session.as_ref().expect("Codex binding");
    assert_eq!(reference.thread_id, "thr_demo");
    let state = reference.structured_state.as_ref().expect("state files");
    assert_eq!(state.rollout.device, fixture.rollout_device());
    assert_eq!(state.goals_db.inode, fixture.goals_inode());
    assert_eq!(state.thread_db.inode, fixture.state_inode());
}
```

Add tests for no `resume THREAD` argument, conflicting Herdr session ID,
multiple rollout files where only one contains the exact thread ID, a rollout
not open by the target PID, replaced device/inode, wrong owner, world-writable
files, malformed cmdline, and a newest unrelated rollout. Every unsafe case
must leave `watcher.codex_session` as `None`.

- [ ] **Step 2: Verify RED**

```bash
cargo test --test codex_attachment linux_attachment_binds_resume_thread_and_open_codex_files -- --exact
```

Expected: compilation fails because the attachment module and structured
binding types do not exist.

- [ ] **Step 3: Add the SQLite dependency and binding model**

Run:

```bash
cargo add rusqlite@0.40.1 --features bundled
```

Add backward-compatible optional types to `src/model/state.rs`:

```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexBoundFile {
    pub canonical_path: String,
    pub device: u64,
    pub inode: u64,
    pub owner_uid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodexStructuredStateReference {
    pub rollout: CodexBoundFile,
    pub thread_db: CodexBoundFile,
    pub goals_db: CodexBoundFile,
}
```

Add to `CodexSessionReference`:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub structured_state: Option<CodexStructuredStateReference>,
```

Legacy references remain deserializable but are ineligible for the new observer
unless this field is present.
Re-export `CodexBoundFile` and `CodexStructuredStateReference` from
`src/model/mod.rs`, and update every existing `CodexSessionReference` literal in
unit/integration tests with `structured_state: None` before running GREEN.

- [ ] **Step 4: Implement exact Linux attachment**

In `src/codex_attachment.rs`, expose a production wrapper and a testable root:

```rust
pub fn attach_process_correlated_codex_session(
    watcher: &mut crate::model::WatcherState,
    herdr_session: Option<&str>,
) {
    #[cfg(target_os = "linux")]
    attach_process_correlated_codex_session_at(watcher, Path::new("/proc"), herdr_session);
}

#[cfg(target_os = "linux")]
pub fn attach_process_correlated_codex_session_at(
    watcher: &mut crate::model::WatcherState,
    proc_root: &Path,
    herdr_session: Option<&str>,
) {
    let process = match &watcher.target {
        TargetIdentity::Process { process }
        | TargetIdentity::Multiplexer { process, .. } => process.clone(),
    };
    let Some(argv_thread) = resume_thread_id(proc_root, process.pid) else { return };
    if herdr_session.is_some_and(|session| session != argv_thread) { return; }
    let Some(files) = discover_exact_open_state(proc_root, process.pid, &argv_thread) else { return };
    let Some(cwd) = process_cwd(proc_root, process.pid) else { return };
    let _ = watcher.set_codex_session(CodexSessionReference {
        thread_id: argv_thread,
        rollout_path: files.rollout.canonical_path.clone(),
        process_start_time: process.start_time,
        process_cwd: cwd.to_string_lossy().into_owned(),
        target_session: target_session(&watcher.target),
        rollout_binding: None,
        app_server_state_path: None,
        structured_state: Some(files),
    });
}
```

The helpers read bounded NUL-separated cmdline bytes; enumerate only
`/proc/PID/fd`; canonicalize each target; accept same-UID regular files that are
not world-writable; bind device/inode; and require exactly one rollout whose
filename or first bounded session-meta record contains the exact thread ID,
one open `state_*.sqlite` with an exact `threads` row, and one open
`goals_*.sqlite` with the expected `thread_goals` schema. Never scan a sessions
directory by recency.

For macOS, add a platform-neutral `attach_explicit_codex_session_from_values`
helper and call it only when all of these variables are present:
`WATCHME_CODEX_THREAD_ID`, `WATCHME_CODEX_PROCESS_PID`,
`WATCHME_CODEX_PROCESS_START_TIME`, `WATCHME_CODEX_PROCESS_CWD`,
`WATCHME_CODEX_ROLLOUT_PATH`, `WATCHME_CODEX_THREAD_DB_PATH`, and
`WATCHME_CODEX_GOALS_DB_PATH`. The helper must require the supplied PID/start
time/CWD to equal the resolved target, require the three canonical files to be
same-owner regular files that are not world-writable, verify their schemas and
exact thread rows, and reject partial or conflicting values. Add unit tests for
one complete valid value set, each missing field, wrong PID/start time, and a
path replacement. These tests run on Linux against temporary files even though
the environment wrapper is selected only on macOS.

Call this attachment from process, bridge-Herdr, native-Herdr, and tmux
registration after the target identity is finalized.

- [ ] **Step 5: Run attachment and state compatibility tests**

```bash
cargo test --test codex_attachment
cargo test --test state_store
```

Expected: exact correlation passes; ambiguous/unsafe fixtures fail closed; old
watcher JSON remains readable.

- [ ] **Step 6: Commit exact attachment**

```bash
git add Cargo.toml Cargo.lock src/codex_attachment.rs src/lib.rs \
  src/model/state.rs src/model/mod.rs src/registration_context.rs \
  tests/codex_attachment.rs
git commit -m "feat: bind exact Codex state at registration"
```

### Task 5: Observe real Codex goals and bounded rollout results

**Files:**
- Create: `src/agents/codex_state.rs`
- Modify: `src/agents/mod.rs`
- Modify: `src/agents/codex.rs`
- Modify: `src/daemon/recovery_runtime.rs`
- Test: `tests/codex_recovery.rs`

- [ ] **Step 1: Write failing realistic SQLite and append-only rollout tests**

Add helpers to `tests/codex_recovery.rs` that create the real tables and these
records:

```rust
write_rollout(&rollout, &[
    json!({"timestamp":"2026-07-17T00:00:00Z","type":"event_msg","payload":{
        "type":"task_started","turn_id":"turn-1"
    }}),
    json!({"timestamp":"2026-07-17T00:00:01Z","type":"response_item","payload":{
        "type":"message","role":"assistant","content":[{
            "type":"output_text",
            "text":"Selected model is at capacity. Please try a different model."
        }]
    }}),
    json!({"timestamp":"2026-07-17T00:00:01Z","type":"event_msg","payload":{
        "type":"task_complete","turn_id":"turn-1"
    }}),
]);
set_goal(&goals_db, "thr_demo", "blocked", 1_789_000_001_000_i64);

let snapshot = observe_bound_codex_state(&watcher).expect("capacity snapshot");
assert_eq!(snapshot.thread_id, "thr_demo");
assert_eq!(snapshot.goal_status.as_deref(), Some("blocked"));
assert_eq!(snapshot.last_error_category.as_deref(), Some("capacity_block"));
```

Pre-size a sparse rollout beyond 1 MiB and put valid complete records at the
tail. Add tests for active/complete/usage-limited/budget-limited goals, newer
user input, a newer active task, partial final JSON, a record above the byte
limit, truncation, rotation, wrong CWD/thread, database schema drift, focused
Herdr with `screen_detection_skipped`, and stale capacity text. Only the exact
blocked-capacity sequence returns `capacity_block`.

- [ ] **Step 2: Verify RED**

```bash
cargo test --test codex_recovery real_codex_sqlite_and_rollout_report_capacity -- --exact
```

Expected: compilation fails because `observe_bound_codex_state` does not exist.

- [ ] **Step 3: Implement read-only goal lookup and bounded tail parser**

In `src/agents/codex_state.rs`, define:

```rust
pub const MAX_ROLLOUT_TAIL_BYTES: u64 = 1024 * 1024;
pub const MAX_ROLLOUT_RECORD_BYTES: usize = 256 * 1024;

pub fn observe_bound_codex_state(watcher: &WatcherState) -> Option<CodexGoalSnapshot> {
    let reference = watcher.codex_session.as_ref()?;
    let state = reference.structured_state.as_ref()?;
    revalidate_target_and_files(watcher, reference, state)?;
    let goal = read_goal(&state.goals_db, &reference.thread_id)?;
    let terminal = latest_terminal_turn(&state.rollout, &reference.thread_id)?;
    normalize_goal_and_terminal(reference, goal, terminal)
}
```

Open SQLite with
`SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX`, execute
`PRAGMA query_only = ON`, verify required table columns, and bind the thread ID
as a query parameter. Revalidate device/inode/UID immediately before the query.

Use `FileExt::read_at` on Unix to read at most the final 1 MiB. Drop the first
fragment when the read starts after byte zero; require a newline-terminated
tail; reject any complete line over 256 KiB. Track `task_started`, exact
structured assistant message content, `task_complete`, newer user messages, and
newer tasks. Do not search arbitrary strings or screen text.

Add a `ProbedCodexSource::LocalState { snapshot }` arm in `codex.rs` before the
legacy App Server/fixture rollout arms. Make post-resume verification query this
same source and accept only a newer `active` goal for the same thread.

- [ ] **Step 4: Run Codex observer and daemon recovery tests**

```bash
cargo test --test codex_recovery
cargo test daemon::recovery_runtime
```

Expected: realistic state tests and all legacy fixture tests pass.

- [ ] **Step 5: Commit real Codex observation**

```bash
git add src/agents/codex_state.rs src/agents/mod.rs src/agents/codex.rs \
  src/daemon/recovery_runtime.rs tests/codex_recovery.rs
git commit -m "feat: observe real Codex blocked goals"
```

### Task 6: Promote an existing process watcher in place

**Files:**
- Modify: `src/daemon/registry.rs`
- Modify: `src/daemon/ipc_service.rs`
- Test: `src/daemon/registry.rs`
- Test: `tests/cli.rs`

- [ ] **Step 1: Write failing registry promotion tests**

Add to `src/daemon/registry.rs` tests that register a process watcher and then
a verified native-Herdr watcher with the same PID/start time:

```rust
let first = process_watcher("process-10-20", 10, 20);
let fresh = native_herdr_watcher("herdr-pane-10-20", 10, 20, codex_reference());
assert_eq!(registry.register(first).unwrap(), RegistrationOutcome::Added("process-10-20".into()));

let outcome = registry.register(fresh).unwrap();

assert_eq!(outcome, RegistrationOutcome::Revalidated("process-10-20".into()));
assert_eq!(registry.list().len(), 1);
let watcher = registry.get("process-10-20").unwrap();
assert!(matches!(watcher.target.observation_context(),
    Some(MultiplexerContext::Herdr { wire_protocol: HerdrWireProtocol::Native16, .. })));
assert!(watcher.codex_session.is_some());
assert!(watcher.last_observation.is_none());
assert!(watcher.observation_schedule.event_wake_pending);
```

Add rejection tests for different start time, a weaker process refresh trying
to downgrade native Herdr, conflicting pane identity, and conflicting Codex
thread attachment.

- [ ] **Step 2: Verify RED**

```bash
cargo test daemon::registry::tests::process_watcher_is_promoted_to_verified_native_herdr -- --exact
```

Expected: the second registration creates another watcher or returns the wrong
outcome.

- [ ] **Step 3: Implement exact process promotion**

Add these helpers to `src/daemon/registry.rs`:

```rust
fn exact_process_eq(left: &TargetIdentity, right: &TargetIdentity) -> bool {
    let left = target_process(left);
    let right = target_process(right);
    left.pid == right.pid && left.start_time == right.start_time
}

fn is_richer_target(existing: &TargetIdentity, fresh: &TargetIdentity) -> bool {
    matches!(existing, TargetIdentity::Process { .. })
        && matches!(fresh, TargetIdentity::Multiplexer { context: Some(_), needs_revalidation: false, .. })
}
```

During registration, search for an exact process match only when the fresh
target is richer. In `refresh_existing`, reject conflicting non-empty
attachments; otherwise replace the target, merge fresh trusted attachments,
set lifecycle to `Registered`, clear recovery and last observation, set
`event_wake_pending = true`, increment revision, persist atomically, and return
`Revalidated`. Never replace a rich target with a process target.

The existing IPC `Revalidated` branch already sends `SchedulerEvent::Resume`;
retain that wake behavior.

- [ ] **Step 4: Extend the bare CLI integration**

Change the native-Herdr CLI test so the fake returns valid protocol-16 pane and
process responses. Register once without Herdr, then invoke bare `watchme` with
the native environment and assert one persisted watcher whose target is Herdr
and whose `codex_session.structured_state` is present.

Run:

```bash
cargo test daemon::registry
cargo test --test cli bare_watchme_promotes_existing_process_watcher_to_native_herdr -- --exact
```

Expected: all promotion and CLI tests pass.

- [ ] **Step 5: Commit watcher promotion**

```bash
git add src/daemon/registry.rs src/daemon/ipc_service.rs tests/cli.rs
git commit -m "fix: promote existing Codex watchers in place"
```

### Task 7: Use atomic submission in the Codex recovery transaction

**Files:**
- Modify: `src/agents/codex.rs`
- Modify: `src/daemon/recovery_runtime.rs`
- Modify: `src/recovery/transaction.rs`
- Test: `tests/codex_recovery.rs`
- Test: `tests/action_transactions.rs`
- Test: `tests/recovery_daemon_herdr_e2e.rs`

- [ ] **Step 1: Write failing action and ambiguous-outcome tests**

Update the Codex recipe assertion:

```rust
assert!(matches!(action.kind,
    ActionKind::SubmitText { ref text } if text == "/goal resume"));
```

Add an e2e native fake that returns a blocked capacity state, records one
`pane.send_input`, and then changes the goal row to `active`. Assert the action
is sent once and verification returns the watcher to observing. In a second
test, close the socket after reading the full send request; assert exactly one
request and `HumanRequired` with an ambiguous-outcome reason.

- [ ] **Step 2: Verify RED**

```bash
cargo test --test codex_recovery codex_resume_recipe_submits_slash_command -- --exact
cargo test --test recovery_daemon_herdr_e2e native_capacity_resume_is_submitted_once -- --exact
```

Expected: the recipe still emits `SendText`, and native end-to-end recovery does
not complete.

- [ ] **Step 3: Change only the Codex recipe to `SubmitText`**

Replace the constructor in `resume_action`:

```rust
let mut action = Action::submit_text(
    "codex.goal_resume_once",
    resume_command,
    "durable Codex goal blocked after capacity backoff; composer revalidated",
    event.evidence_fingerprint.clone(),
);
```

Treat `SubmitText` as a side-effecting action everywhere `SendText` currently
participates in transaction ownership and dispatch. Preserve the pre-dispatch
exactly-once marker. Map `CommandOutcomeUnknown` directly to `HumanRequired` and
never retry that fingerprint. A definite error before the request write may use
the existing bounded attempt budget.

- [ ] **Step 4: Verify the complete recovery flow**

```bash
cargo test --test codex_recovery
cargo test --test action_transactions
cargo test --test recovery_daemon_herdr_e2e
```

Expected: wait/revalidate/submit/verify passes; ambiguous dispatch sends once
and hands off; auth/billing/safety/unknown/focused-skipped cases send nothing.

- [ ] **Step 5: Commit atomic Codex recovery**

```bash
git add src/agents/codex.rs src/daemon/recovery_runtime.rs \
  src/recovery/transaction.rs tests/codex_recovery.rs \
  tests/action_transactions.rs tests/recovery_daemon_herdr_e2e.rs
git commit -m "fix: atomically submit Codex goal resume"
```

### Task 8: Log registration and lifecycle transitions safely

**Files:**
- Modify: `src/audit.rs`
- Modify: `src/daemon/registry.rs`
- Modify: `src/daemon/mod.rs`
- Test: `tests/operability.rs`
- Test: `src/daemon/registry.rs`

- [ ] **Step 1: Write failing lifecycle-audit tests**

Add to `tests/operability.rs`:

```rust
let events = log.read_lines(Some("watcher-1"), 50).unwrap();
assert!(events.iter().any(|event| event.kind == "lifecycle"
    && event.state.as_deref() == Some("registered")));
assert!(events.iter().any(|event| event.kind == "lifecycle"
    && event.state.as_deref() == Some("waiting")));
assert!(events.iter().all(|event| !event.message.contains("prompt text")
    && !event.message.contains("HERDR_SOCKET_PATH")));
```

Add registry tests for added, existing, promoted, waiting, human-required,
stopped, and target-terminated audit events.

- [ ] **Step 2: Verify RED**

```bash
cargo test --test operability lifecycle_transitions_are_tailable_and_redacted -- --exact
```

Expected: no lifecycle audit records exist.

- [ ] **Step 3: Add a redacted lifecycle recorder**

Add to `src/audit.rs`:

```rust
pub fn record_lifecycle(
    paths: &WatchmePaths,
    watcher: &WatcherState,
    message: &str,
) -> io::Result<()> {
    let mut log = AuditLog::open(paths.state_file("audit.jsonl")?)?;
    log.append(&AuditEvent {
        schema_version: AUDIT_SCHEMA_VERSION.into(),
        recorded_at: now_rfc3339(),
        watcher_id: Some(watcher.watcher_id.clone()),
        kind: "lifecycle".into(),
        detector: None,
        evidence: None,
        state: Some(lifecycle_label(&watcher.lifecycle).into()),
        policy_decision: None,
        attempted_action: None,
        verification: None,
        message: message.into(),
    })
}
```

Give the production registry an optional `WatchmePaths` audit sink while
retaining `Registry::load` for isolated unit tests. After successful state
persistence, append only fixed messages such as `watcher registered`,
`watcher promoted`, `capacity wait scheduled`, `human handoff`, `watcher
stopped`, and `target terminated`. Audit failure must be reported to stderr but
must not roll back already-persisted watcher state. Never interpolate goal
text, terminal content, environment values, paths, or socket payloads.

- [ ] **Step 4: Verify logs and lifecycle behavior**

```bash
cargo test --test operability
cargo test daemon::registry
cargo test --test daemon_lifecycle
```

Expected: lifecycle events are visible, bounded/redacted, and daemon behavior
remains correct.

- [ ] **Step 5: Commit lifecycle logging**

```bash
git add src/audit.rs src/daemon/registry.rs src/daemon/mod.rs \
  tests/operability.rs tests/daemon_lifecycle.rs
git commit -m "feat: audit watcher lifecycle transitions"
```

### Task 9: Complete end-to-end acceptance, documentation, and local gates

**Files:**
- Modify: `tests/fixtures/fake_codex.rs`
- Modify: `tests/cli.rs`
- Modify: `tests/recovery_daemon_herdr_e2e.rs`
- Modify: `docs/compatibility.md`
- Modify: `README.md`

- [ ] **Step 1: Add the full bare-command acceptance test**

Extend `tests/fixtures/fake_codex.rs` so a test mode opens the exact rollout,
state DB, and goals DB handles before invoking bare WatchMe as
`codex resume thr_demo`. The schema-faithful native fake must serve protocol 16,
the inherited pane, the exact fixture PID/TTY, bounded reads, and atomic input.

The final CLI test must assert:

```rust
assert_eq!(watchers.len(), 1);
assert_eq!(watchers[0]["target"]["provider"], "herdr");
assert_eq!(watchers[0]["codex_session"]["thread_id"], "thr_demo");
assert_eq!(native_requests_for("pane.send_input").len(), 1);
assert_eq!(native_requests_for("pane.send_input")[0]["params"], json!({
    "pane_id":"w6:pD", "text":"/goal resume", "keys":["Enter"]
}));
assert!(audit_kinds().contains(&"lifecycle"));
```

- [ ] **Step 2: Run the complete bare-command acceptance test**

```bash
cargo test --test cli bare_watchme_recovers_realistic_native_herdr_capacity -- --exact
```

Expected: PASS. All production wiring was introduced under failing tests in
Tasks 2 through 8; this task is the final composition proof and must not add new
production behavior. If it fails, return to the owning earlier task, add the
smallest focused failing test there, and complete a new red-green cycle before
rerunning this acceptance test.

- [ ] **Step 3: Update compatibility and usage docs**

Document:

- native Herdr 0.7.4/protocol 16 support;
- Linux automatic exact Codex state correlation;
- macOS explicit-correlation limitation;
- focused/skipped Herdr status as optional corroboration only;
- atomic `/goal resume` and ambiguous-outcome handoff;
- `watchme logs WATCHER_ID --follow` for lifecycle events; and
- process-only observation when exact evidence is unavailable.

Remove the prior statement that native Herdr always falls back to process-only
supervision. Do not claim generic error recovery or a forced live provider
capacity test.

- [ ] **Step 4: Run focused and full verification**

```bash
cargo fmt --check
cargo test --test herdr_contract
cargo test --test codex_attachment
cargo test --test codex_recovery
cargo test --test recovery_daemon_herdr_e2e
cargo test --test cli
just gates
```

Expected: every command exits zero, strict Clippy has no warnings, release build
and schemas pass, and install smoke passes.

- [ ] **Step 5: Check production file sizes and review the diff**

```bash
wc -l src/mux/herdr/mod.rs src/mux/herdr/bridge.rs \
  src/mux/herdr/native.rs src/codex_attachment.rs \
  src/agents/codex.rs src/agents/codex_state.rs
git diff --check master...HEAD
git status --short
```

Expected: no production file exceeds 1,000 lines, no whitespace errors, and
only intentional files are modified.

- [ ] **Step 6: Commit final integration and docs**

```bash
git add tests/fixtures/fake_codex.rs tests/cli.rs \
  tests/recovery_daemon_herdr_e2e.rs docs/compatibility.md README.md
git commit -m "test: cover real Codex native Herdr recovery"
```

### Task 10: Install, deploy to x-left, and live-verify without forcing capacity

**Files:**
- No repository files unless live verification reveals a reproducible defect;
  any defect begins a new RED-GREEN cycle before another deployment.

- [ ] **Step 1: Merge the verified branch locally and install**

From the primary checkout after reviewing the worktree commits:

```bash
git merge --ff-only codex-native-herdr-recovery
just gates
just install
watchme --version
sha256sum target/release/watchme ~/.local/bin/watchme
```

Expected: fast-forward succeeds, gates pass again on `master`, and both hashes
match.

- [ ] **Step 2: Copy through xsm and verify the remote hash**

```bash
scp target/release/watchme xsm:/tmp/watchme-native-herdr
ssh xsm 'scp /tmp/watchme-native-herdr x-left:/tmp/watchme-native-herdr'
ssh xsm "ssh x-left 'install -m 755 /tmp/watchme-native-herdr ~/.local/bin/watchme && sha256sum ~/.local/bin/watchme'"
sha256sum target/release/watchme
```

Expected: local and x-left SHA-256 hashes are identical. Remove only the two
known staging files after verification.

- [ ] **Step 3: Restart only WatchMe and promote the live watcher**

On x-left:

```bash
watchme daemon stop
watchme daemon start
watchme
watchme status --json
```

Expected: one watcher for the Codex PID, native Herdr target context, exact
Codex thread binding, and no duplicate process watcher.

- [ ] **Step 4: Verify operability and safe degradation**

```bash
watchme logs WATCHER_ID --follow
watchme doctor
```

Expected: registration/promotion and observation-source lifecycle messages are
visible without prompt/session content. If the goal is active, WatchMe observes
without sending input. If a real capacity block occurs naturally, WatchMe must
log classification, wait, submit once, and verify active state. Do not induce a
provider failure.

- [ ] **Step 5: Final repository check and handoff**

```bash
git status --short --branch
git log --oneline --decorate -12
```

Expected: clean `master`, intentional local commits only, and no push, tag,
release, or publication.
