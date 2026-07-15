# Native Herdr Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make bare `watchme` register a verified Codex process when inherited Herdr variables point at the native Herdr 0.7.4 API instead of the provisional `watchme.herdr` bridge.

**Architecture:** Classify a strictly shaped native Herdr response as a typed multiplexer incompatibility only after all existing socket and transport checks pass and strict bridge decoding fails. Registration matches only that typed error and reuses a process-only watcher constructor; every other Herdr error remains fail-closed.

**Tech Stack:** Rust 2024, Tokio Unix sockets, Serde JSON, `assert_cmd`, Cargo/Just.

---

### Task 1: Classify native Herdr envelopes

**Files:**
- Modify: `src/mux/mod.rs`
- Modify: `src/mux/herdr.rs`
- Test: `tests/herdr_contract.rs`

- [ ] **Step 1: Write the failing contract test**

Add a test beside the response-envelope tests which makes `spawn_fake` return the observed native Herdr response and checks for a dedicated error:

```rust
#[test]
fn native_herdr_response_is_a_typed_protocol_incompatibility() {
    let (_server, socket, _) = spawn_fake(|_, _| {
        Some(json!({
            "id": "",
            "error": {
                "code": "invalid_request",
                "message": "invalid request: missing field `id`"
            }
        }))
    });
    let herdr = Herdr::new(context(socket), Duration::from_millis(200)).unwrap();
    assert!(matches!(
        herdr.current_target(),
        Err(MuxError::IncompatibleProtocol(_))
    ));
}
```

Also extend the neighboring malformed-response test with objects that have only `id`, malformed `error`, or both `result` and `error`; they must remain `MuxError::Protocol`.

- [ ] **Step 2: Run the focused test and prove RED**

Run:

```bash
cargo test --test herdr_contract native_herdr_response_is_a_typed_protocol_incompatibility -j1 --locked
```

Expected: compilation fails because `MuxError::IncompatibleProtocol` does not exist.

- [ ] **Step 3: Implement the minimal typed classifier**

Add to `MuxError`:

```rust
#[error("incompatible Herdr protocol: {0}")]
IncompatibleProtocol(String),
```

In `src/mux/herdr.rs`, add private recognition structs that require the native
fields while tolerating future unknown fields as Herdr documents, and require
exactly one of `result` or `error`:

```rust
#[derive(Deserialize)]
struct NativeResponse {
    id: String,
    result: Option<serde_json::Value>,
    error: Option<NativeError>,
}

#[derive(Deserialize)]
struct NativeError {
    code: String,
    message: String,
}

fn is_native_response(bytes: &[u8]) -> bool {
    serde_json::from_slice::<NativeResponse>(bytes).is_ok_and(|response| {
        let _ = (&response.id, response.error.as_ref().map(|e| (&e.code, &e.message)));
        matches!((response.result, response.error), (Some(_), None) | (None, Some(_)))
    })
}
```

When strict `Response<T>` decoding fails, return `IncompatibleProtocol` only
if this helper succeeds; otherwise preserve the current malformed-response
`Protocol` error.

- [ ] **Step 4: Run the full contract suite and prove GREEN**

Run:

```bash
cargo test --test herdr_contract -j1 --locked
```

Expected: all Herdr contract tests pass, including the new positive and negative envelope cases.

- [ ] **Step 5: Check production file size and commit**

Run `wc -l src/mux/herdr.rs src/mux/mod.rs`; both must remain below 1,000 lines.

```bash
git add src/mux/mod.rs src/mux/herdr.rs tests/herdr_contract.rs
git commit -m "fix: identify native Herdr protocol responses"
```

### Task 2: Fall back to verified process registration

**Files:**
- Modify: `src/registration_context.rs`
- Modify: `tests/cli.rs`

- [ ] **Step 1: Write the failing bare-CLI regression**

Refactor the existing tty-less fake-Codex registration setup into a test helper
which optionally injects all four `HERDR_*` context values. Add a Unix socket
fake which reads WatchMe's request and returns:

```json
{"id":"","error":{"code":"invalid_request","message":"invalid request: missing field `id`"}}
```

Add:

```rust
#[test]
fn bare_watchme_ignores_native_herdr_api_and_registers_codex_process() {
    let native = NativeHerdrFake::spawn();
    let persisted = bare_codex_registration(Some(native.path()));
    assert_eq!(persisted["watchers"][0]["target"]["kind"], "process");
}
```

The fake must record that it received one `watchme.herdr` request so the test
cannot pass merely by skipping Herdr detection.

- [ ] **Step 2: Run the focused test and prove RED**

Run:

```bash
cargo test --test cli bare_watchme_ignores_native_herdr_api_and_registers_codex_process -j1 --locked
```

Expected: FAIL because bare registration exits before persisting a watcher.

- [ ] **Step 3: Implement the narrow registration fallback**

Extract the existing non-multiplexer watcher construction into:

```rust
fn process_registration(resolved: ResolvedProcess) -> ResolvedRegistration
```

Make `herdr_registration` preserve `MuxError` through target lookup and express
the process/pane mismatch as `MuxError::IdentityChanged`. In `detect_current`,
match its result:

```rust
match herdr_registration(resolved.clone()) {
    Ok(registration) => return Ok(registration),
    Err(MuxError::IncompatibleProtocol(_)) => {
        return Ok(process_registration(resolved));
    }
    Err(error) => return Err(WatchmeError::UnsupportedContext(error.to_string())),
}
```

Do not fallback for any other variant.

- [ ] **Step 4: Run CLI and context tests and prove GREEN**

Run:

```bash
cargo test --test cli -j1 --locked
cargo test registration_context -j1 --locked
```

Expected: all CLI tests and registration-context unit tests pass.

- [ ] **Step 5: Check production file size and commit**

Run `wc -l src/registration_context.rs`; it must remain below 1,000 lines.

```bash
git add src/registration_context.rs tests/cli.rs
git commit -m "fix: fall back from native Herdr to process supervision"
```

### Task 3: Document, verify, install, and deploy

**Files:**
- Modify: `docs/compatibility.md`
- Modify: `docs/troubleshooting.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Update compatibility documentation**

Record the Herdr 0.7.4 probe, native protocol 16 envelope, and exact current
behavior: native Herdr metadata degrades to verified process supervision;
only a conforming `watchme.herdr` bridge grants Herdr pane capabilities.
Add a troubleshooting entry for incompatible native Herdr sockets.

- [ ] **Step 2: Run documentation and source checks**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -j1 -- -D warnings
git diff --check
```

Expected: exit 0 with no warnings.

- [ ] **Step 3: Run the full gate suite**

Run `just gates`.

Expected: core gates pass; only explicitly documented ignored timing-sensitive tests remain ignored.

- [ ] **Step 4: Commit documentation**

```bash
git add CHANGELOG.md docs/compatibility.md docs/troubleshooting.md
git commit -m "docs: explain native Herdr fallback"
```

- [ ] **Step 5: Merge, install, and dogfood locally**

Fast-forward the verified branch onto `master`, run `just install`, stop the
old local daemon, and run bare `watchme`. Confirm registration succeeds and
`watchme daemon status` reports the watcher without `human_required`.

- [ ] **Step 6: Deploy and verify `x-left`**

Copy `target/release/watchme` through `xsm` to an owner-controlled staging
filename on `x-left`, verify its SHA-256, atomically rename it to
`~/.local/bin/watchme`, and verify the installed version/hash. Ask the user to
run bare `watchme` in the already-running `x-left` Codex session; its inherited
Herdr environment is the final real-context proof.
