# Codex Context and Detached Daemon Start Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make bare `watchme` register from Codex's tty-less shell-command context and provide a reliable detached `watchme daemon start` command.

**Architecture:** Move registration context detection out of the oversized CLI module and make the invoking child's TTY an optional resolver hint while retaining strict multiplexer validation. Move daemon socket/startup orchestration into a focused module shared by lazy registration and explicit background start, leaving `daemon run` foreground-only.

**Tech Stack:** Rust 2024, clap, Tokio Unix sockets, rustix, assert_cmd, existing process-resolution and daemon IPC APIs.

---

### Task 1: TTY-less Codex registration

**Files:**
- Create: `src/registration_context.rs`
- Modify: `src/main.rs`
- Modify: `src/cli.rs:717-887`
- Test: `tests/cli.rs`

- [ ] **Step 1: Write the failing live ancestry regression test**

Add a test that compiles `tests/fixtures/fake_codex.rs` to a temporary executable named `codex`, starts it without a controlling TTY with isolated HOME/XDG paths, and polls `state/watchme/watchers.json`. Assert that registration succeeds and the stored target process executable is the fake `codex`; always kill the fixture and stop the isolated daemon.

- [ ] **Step 2: Run the regression test and verify RED**

Run: `cargo test --test cli bare_watchme_registers_from_ttyless_codex_ancestor -j1 --locked -- --exact --nocapture`

Expected: FAIL because bare WatchMe returns `unsupported context` and no watcher is persisted.

- [ ] **Step 3: Extract and minimally fix context detection**

Create `registration_context::detect_current()` from the existing `ProductionContextDetector::detect` logic. Construct resolver hints with `tty: current.tty.clone()` instead of returning early when it is `None`:

```rust
let hints = CandidateHints {
    tty: current.tty.clone(),
    process_group_id: current.process_group_id,
    session_leader_id: current.session_leader_id,
    uid: current.uid,
    executable_hint: None,
};
```

Keep the Herdr process/TTY identity check and tmux resolved-agent/pane TTY check unchanged. Make `cli::register_current_context` call `registration_context::detect_current()` before registration.

- [ ] **Step 4: Run focused and process-resolution tests and verify GREEN**

Run: `cargo test --test cli bare_watchme_registers_from_ttyless_codex_ancestor -j1 --locked -- --exact --nocapture && cargo test --test process_identity -j1 --locked`

Expected: both commands PASS.

- [ ] **Step 5: Commit the context fix**

```bash
git add src/main.rs src/cli.rs src/registration_context.rs tests/cli.rs
git commit -m "fix: detect Codex from ttyless shell commands"
```

### Task 2: Detached daemon startup

**Files:**
- Create: `src/daemon_client.rs`
- Modify: `src/main.rs`
- Modify: `src/cli.rs:43-51,602-670,889-1065`
- Test: `tests/cli.rs`

- [ ] **Step 1: Write failing detached-start regression tests**

Add an isolated CLI test with `stay_resident = true` that asserts the first `watchme daemon start` prints `daemon started`, a second invocation prints `daemon already running`, `daemon status` succeeds, and `daemon stop` cleans up. Retain the existing test proving `daemon run` remains foreground and honors configuration.

- [ ] **Step 2: Run the daemon-start test and verify RED**

Run: `cargo test --test cli daemon_start_detaches_waits_and_is_idempotent -j1 --locked -- --exact --nocapture`

Expected: FAIL with clap reporting that `start` is not a recognized daemon subcommand.

- [ ] **Step 3: Implement shared daemon client/startup orchestration**

Add `DaemonCommand::Start`. Move socket request, bounded readiness polling, owner-only diagnostic creation, child diagnostic sanitizing, and child spawning into `daemon_client.rs`. Expose:

```rust
pub fn request(paths: &WatchmePaths, request: &Request) -> std::io::Result<Response>;
pub fn start_and_request(
    paths: &WatchmePaths,
    request: &Request,
) -> Result<Response, WatchmeError>;
```

Spawn the current executable with `daemon run`, null stdin/stdout, diagnostic stderr, and `CommandExt::process_group(0)`. Use these functions from both `IpcRegistrationClient` and `daemon start`. Check `Request::Status { id: None }` before spawning so explicit startup is idempotent.

- [ ] **Step 4: Run daemon and CLI tests and verify GREEN**

Run: `cargo test --test cli -j1 --locked && cargo test --test daemon_lifecycle -j1 --locked`

Expected: both commands PASS, with only pre-existing ignored timing-sensitive tests reported ignored.

- [ ] **Step 5: Commit daemon startup**

```bash
git add src/main.rs src/cli.rs src/daemon_client.rs tests/cli.rs
git commit -m "feat: add detached daemon start"
```

### Task 3: User-facing command documentation

**Files:**
- Modify: `docs/commands.md`
- Modify: `docs/troubleshooting.md`
- Modify: `packaging/completions/watchme.bash`
- Modify: `packaging/man/watchme.1`
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add a failing completion assertion**

Extend the CLI/install-facing test coverage to read `packaging/completions/watchme.bash` and assert the daemon completion candidates contain `start run status stop`.

- [ ] **Step 2: Run the assertion and verify RED**

Run: `cargo test --test cli daemon_completion_includes_detached_start -j1 --locked -- --exact`

Expected: FAIL because completion currently contains only `run status stop`.

- [ ] **Step 3: Update all command surfaces**

Document `daemon start|run|status|stop`, state that `start` detaches and readiness-checks while honoring daemon residency configuration, retain the absence of top-level `watchme start`, and update troubleshooting to recommend `watchme daemon start` for interactive use and `daemon run` for foreground diagnostics/service managers.

- [ ] **Step 4: Run focused documentation and schema checks**

Run: `cargo test --test cli daemon_completion_includes_detached_start -j1 --locked -- --exact && bash scripts/validate-schemas.sh && git diff --check`

Expected: all commands PASS.

- [ ] **Step 5: Commit documentation**

```bash
git add README.md CHANGELOG.md docs/commands.md docs/troubleshooting.md packaging/completions/watchme.bash packaging/man/watchme.1 tests/cli.rs
git commit -m "docs: describe detached daemon startup"
```

### Task 4: Full verification, installation, and dogfooding

**Files:**
- Verify all files changed by Tasks 1-3.

- [ ] **Step 1: Check code size and focused separation**

Run: `wc -l src/cli.rs src/registration_context.rs src/daemon_client.rs && rg -n 'TODO|FIXME' src/cli.rs src/registration_context.rs src/daemon_client.rs`

Expected: `src/cli.rs` is below the 1,000-line soft limit and no untracked placeholder remains.

- [ ] **Step 2: Run the complete project gates**

Run: `just gates`

Expected: formatting, clippy, all tests, release build, schemas, and install smoke PASS.

- [ ] **Step 3: Review the exact committed scope**

Run: `git status --short --branch && git log --oneline --decorate -6 && git diff origin/master..HEAD --check && git diff --stat origin/master..HEAD`

Expected: no unintended tracked or untracked changes and only the approved implementation/documentation scope is committed.

- [ ] **Step 4: Install the verified release build**

Run: `just install`

Expected: the release binary, `WatchMe` alias, completion, and man page install successfully under `~/.local`.

- [ ] **Step 5: Dogfood the installed commands from the live Codex context**

Run the installed `watchme daemon stop` if a stale daemon exists, then run installed bare `watchme`, `watchme daemon status`, and a second bare `watchme`. Confirm the first registration lazily starts the daemon, status lists the watcher, and the second registration reports the existing watcher. Finally run `watchme doctor` and inspect any warnings without treating unrelated optional integration warnings as registration failure.

- [ ] **Step 6: Verify final repository state**

Run: `git status --short --branch`

Expected: clean working tree on the intended branch, ahead of the remote only by the intentional local commits.
