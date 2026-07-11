# WatchMe Handoff

## Repository state

- Feature branch: `feature/watchme-v1`
- Handoff baseline: `f90e2ea` (`test: cover Claude daemon recovery flow`)
- Working tree was clean when this handoff was written.
- The feature branch is about to be merged into `master` at the user's request.
- Do not start new work from the root checkout unless it is on the merged `master` branch. The implementation worktree used during development was `/home/xertrov/.config/superpowers/worktrees/watchme/feature-watchme-v1`.

## What is complete and reviewed

Tasks 1–8 are implemented and independently reviewed:

- Secure Rust CLI/daemon, owner-only IPC/state, process identity, tmux and Herdr adapters.
- Observation, policy, durable recovery state, real wake IPC, bounded hostile-input processing, and strict action-plan schema handling.
- Production recovery transactions with durable prepare/uncertainty handling, supervised shutdown, real tmux/Herdr recovery paths, and immutable target/evidence checks.
- GitHub release infrastructure is merged into the feature branch:
  - `AGENTS.md`
  - `.github/workflows/ci.yml`
  - `.github/workflows/release.yml`
  - `scripts/reconcile-release.sh`
  - `scripts/release-notes.sh`
  - `scripts/test-reconcile-release.sh`

Task 9 (Claude) has substantial implementation, including:

- Real StopFailure hook matcher-group configuration and safe marker writer.
- Strict hook/transcript/session correlation and append-versus-replacement handling.
- Secure hook install/remove CLI commands.
- Rate-limit menu parser, reset parser, Claude wait/resume transaction semantics, and a fake-Herdr daemon E2E covering menu -> wait -> one verified resume.
- Claude Code 2.1.207 was locally probed in isolated bare tmux. `/rate-limit-options` was intercepted by the first-run renderer confirmation, no option was selected, and documentation records this honestly.

## Current blocker before calling Task 9 complete

Task 9 signoff found an important, adjacent configuration-contract defect:

- `config/config.example.toml` contains fields such as `config_version`, `[daemon]`, `[recovery]`, and `[security]`.
- `src/config.rs` uses strict `deny_unknown_fields` but currently supports only `[observation] poll interval/jitter`.
- `watchme config path|check|show` remains routed to `unavailable` in the CLI.

This means the documented config example cannot be loaded by the shipped program. Fix it before declaring Task 9 or the release complete. Preferred approach: extend the typed strict config model for the documented conservative daemon/recovery/security/planner settings, and implement secure `config path`, `check`, and redacted `show`; alternatively reduce the example only if documentation and requirements are revised consistently. Add tests that load the example, reject unknown fields, and exercise all config subcommands.

The interrupted config-fix worker was stopped before making any file changes.

## Remaining project milestones

1. Fix the configuration contract above and rerun Task 9 signoff.
2. Task 10: first-class Codex blocked-goal recovery.
3. Task 11: versioned generic provider manifests and support tiers.
4. Task 12: redacted alternate-provider planner with provider-family exclusion and strict plan validation.
5. Task 13: diagnostics, notifications, hooks/services, install/uninstall, docs, benchmarks, and operability.
6. Task 14: final full audits/reviews, public GitHub repository creation, CI verification, first semver tag, multi-platform release assets, and final release notes.

## Verification evidence at the handoff baseline

At `f90e2ea`, the Task 9 signoff ran successfully except for the configuration-contract blocker:

```text
cargo fmt --check                         PASS
cargo clippy --all-targets --all-features -- -D warnings  PASS
cargo test --all-features                 PASS (215 tests)
cargo build --release                     PASS
cargo check --target x86_64-apple-darwin --all-features   PASS
cargo check --target aarch64-apple-darwin --all-features  PASS
git diff --check                          PASS
```

Native macOS execution is still deferred to the configured GitHub macOS runners. Local cross-target checks compile successfully.

## Publishing instructions already encoded in the repo

Do not create/push/tag/release until the remaining milestones and final local gates pass. When ready, `AGENTS.md` requires the agent to:

1. Use `gh` to create/configure public `github.com/clankercode/watchme` with description/topics.
2. Push the merged branch and watch all CI runs to terminal success; inspect/fix failures rather than assuming success.
3. Tag a validated semantic version. The release workflow builds native Linux x86_64/aarch64 and macOS x86_64/aarch64 archives, checksums, and GitHub assets.
4. Wait for the release page, verify all assets/checksums, and reconcile complete notes from changes since the prior semantic version.

The release workflow and scripts have been independently reviewed for immutable action pins, idempotent release reconciliation, stable/prerelease Latest semantics, generated notes, and immutable-release behavior.

## Suggested first commands for the next agent

```bash
git status --short --branch
git log --oneline -8
cargo test --all-features --locked
sed -n '1,240p' HANDOFF.md
sed -n '1,260p' config/config.example.toml
sed -n '1,260p' src/config.rs
```

Then fix the config blocker using test-driven development, rerun Claude signoff, and continue the remaining milestones in order.
