# Release checklist (WatchMe v1 / 0.1.0)

Reconciles the bundle Definition of Done with local command evidence. Publishing to GitHub / tagging is **out of scope** until explicitly authorized.

## Local gates (required)

Recorded on 2026-07-12 against this worktree (`feature/remaining-v1`), host Linux 7.0.10-arch1-1 x86_64.

| Gate | Command | Status |
|---|---|---|
| Format | `cargo fmt --check` | pass |
| Clippy | `cargo clippy --all-targets --all-features -j1 -- -D warnings` | pass |
| Tests | `cargo test --all-features -j1 --locked` | pass (294 tests; one `claude_daemon_e2e` flake cleared on immediate re-run of the full suite) |
| Release build | `cargo build --release -j1 --locked` | pass |
| Schema validation | `scripts/validate-schemas.sh` | pass (JSON parse of all `schemas/*.schema.json`; Draft202012 skipped — `jsonschema` Python module absent) |
| Install smoke | `cargo test --test install_smoke -j1 --locked` | pass (2 tests) |
| Real tmux integration | `cargo test --test tmux_integration -j1 --locked` | pass (included in full suite; tmux 3.6b) |
| Herdr contract | `cargo test --test herdr_contract -j1 --locked` | pass (15 contract tests; live Herdr skipped) |
| Idle benchmarks | `scripts/benchmark-idle.sh` (0/1/10 watchers, 35s, poll 15s) | pass — results in [benchmarks.md](benchmarks.md) |

Convenience: `just gates` runs fmt-check, clippy, test, build-release, schemas, install-smoke. Run `just bench` separately for idle benchmarks.

## Optional audits

| Audit | Status | Reason |
|---|---|---|
| `cargo audit` | skipped | tool not installed in this environment |
| `cargo deny` / license audit CLI | skipped | tool not installed; licenses recorded in `LICENSES/` + `THIRD-PARTY-NOTICES.md` |
| `shellcheck` on packaging scripts | skipped | shellcheck not installed; scripts reviewed manually |
| Live Herdr smoke | skipped | `herdr` binary absent on development host (see [compatibility.md](compatibility.md)) |
| Live Claude rate-limit menu | skipped | first-run security screen blocked menu probe (see [compatibility.md](compatibility.md)) |
| Direct syscall tracing (`perf`/`bpf`) | skipped | elevated tracing not required for v1 baseline; ctxt-switch proxy recorded |
| Schema Draft202012 deep validation | skipped | Python `jsonschema` module unavailable; schemas still JSON-parsed |

## Product DoD

- [x] `watchme` + `WatchMe` install via `scripts/install.sh`
- [x] Bare `!WatchMe`-style registration path (ancestor detection in tests)
- [x] Herdr + tmux adapters with identity/revalidation
- [x] Watcher stops on target death; PID/pane reuse guarded
- [x] Duplicate starts dedupe to one watcher / one supervisor
- [x] Session/log correlation confidence-scored
- [x] Steady-state observation defaults to ~1 minute
- [x] Claude structured/screen rate-limit path + budgets (fixture-backed where live UI unavailable)
- [x] Claude overload full-jitter backoff
- [x] Codex `/goal resume` under verified preconditions
- [x] Generic manifests shipped
- [x] Planner routing excludes failed provider family
- [x] Redacted planner snapshots; terminal untrusted
- [x] Schema + compiled policy reject unsafe actions
- [x] Idempotent, budgeted, auditable recovery with human escalation

## Security DoD

- [x] Owner-only runtime/state/IPC
- [x] No shell interpolation of untrusted data in hook command construction
- [x] Secrets redacted in logs/snapshots (tests)
- [x] Prompt-injection fixtures fail safely
- [x] Auth/billing/funding/upgrade/yolo/privilege/destructive never auto-execute
- [x] Config/manifests cannot weaken core policy
- [x] TOCTOU identity + composer checks before send

## Documentation DoD

- [x] Commands, config, manifests, hooks/services
- [x] Threat model + limitations
- [x] Compatibility matrix with tiers
- [x] Benchmarks doc with measured results
- [x] Changelog + this checklist
- [x] License + third-party notices

## Pre-publish (separate authorized step)

- [ ] Confirm clean `git status` after authorized publish prep
- [ ] Tag `v0.1.0` matching `Cargo.toml`
- [ ] Push + monitor CI/release workflows
- [ ] Attach platform archives + `SHA256SUMS`
- [ ] Edit release notes via `scripts/release-notes.sh` / `gh release edit`

Do **not** publish until the user explicitly authorizes it.
