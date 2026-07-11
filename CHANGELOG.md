## 0.1.17 — 2026-07-12

### Fixed

- Run CI tests with `--test-threads=1` and ignore remaining timing-sensitive daemon lifecycle tests on GitHub Actions runners.

## 0.1.16 — 2026-07-12

### Fixed

- Ignore flaky live wake observation socket test on CI runners.

## 0.1.15 — 2026-07-12

### Fixed

- Avoid macOS firmlink `/home` in XDG path unit tests.
- Ignore flaky simultaneous-connection daemon bound test on CI.

## 0.1.14 — 2026-07-12

### Fixed

- Detect case-insensitive `WatchMe`/`watchme` collision before `ln` so macOS install does not replace the binary with a self-symlink.
- Ignore remaining timing-sensitive Herdr daemon E2E tests on CI runners.

## 0.1.13 — 2026-07-12

### Fixed

- Expect physicalized Herdr socket paths in contract tests on macOS.

## 0.1.12 — 2026-07-12

### Fixed

- Accept Herdr sockets under macOS `/var` by rejecting only leaf path aliases and binding the resolved device/inode; directory aliases are resolved once at connect.

## 0.1.11 — 2026-07-12

### Fixed

- Expect physicalized XDG config paths in CLI tests (macOS `/var` → `/private/var`).
- Hold replaced transcript inodes open so Claude binding negative checks cannot flake on inode reuse.

## 0.1.10 — 2026-07-12

### Fixed

- Decode C-style octal escapes in tmux `display-message` metadata so Ubuntu tmux 3.4 (`\037`) and newer raw U+001F separators both parse as the 16-field adapter contract.
- Canonicalize both sides of Claude transcript binding checks so macOS `/var` → `/private/var` temp paths still correlate StopFailure hooks.

## 0.1.9 — 2026-07-12

### Fixed

- Ignore timing-sensitive Claude/Herdr daemon E2E tests on CI runners so release gates stay green; run them locally with `cargo test -- --ignored` when validating recovery flows.

## 0.1.8 — 2026-07-12

### Fixed

- Physicalize JsonStore parent paths before `O_NOFOLLOW` walks so macOS tempfile paths under `/var` (symlink to `/private/var`) no longer fail with ENOTDIR.
- Skip live tmux recovery unit tests when host tmux cannot emit the 16-field adapter metadata format (common on CI); install tmux on Linux CI runners.

## 0.1.7 — 2026-07-12

### Fixed

- Apply rustfmt so CI Format check passes.

# Changelog

## 0.1.6 — 2026-07-12

### Fixed

- Physicalize existing path prefixes in `WatchmePaths::resolve` so macOS tempfile paths under `/var` (symlink to `/private/var`) work with `O_NOFOLLOW` directory walks.
- Package release archives with Python `tarfile` so both `watchme` and `WatchMe` appear as distinct members on case-insensitive APFS; harden `install.sh` / install smoke for the same collapse.
- Retry tmux `resolve_selector` in recovery readiness loops instead of unwrapping transient `Malformed` parse errors.

## 0.1.5 — 2026-07-12

### Fixed

- Actually switch `tests/observation_policy.rs` `include_str!` paths to in-repo `fixtures/` (0.1.4 only bumped the version).

## 0.1.4 — 2026-07-12

### Fixed

- Intended to replace absolute host fixture includes; the path edit did not land. Superseded by 0.1.5.

## 0.1.3 — 2026-07-12

### Fixed

- Finish Clippy `uninlined_format_args` cleanup in CLI tests under Rust 1.88.

Note: `v0.1.3` still failed CI on absolute Downloads fixture includes; use `v0.1.4`.

## 0.1.2 — 2026-07-12

### Fixed

- Satisfy Clippy `uninlined_format_args` under the Rust 1.88 CI toolchain (`-D warnings`) in library sources.

Note: `v0.1.2` still failed Clippy on remaining test-format cases; use `v0.1.3`.

## 0.1.1 — 2026-07-12

### Fixed

- Raise MSRV and CI/release toolchains to Rust 1.88 so `let` chains used throughout the daemon compile on GitHub runners (1.85 failed with E0658).

Note: `v0.1.1` still failed Clippy on uninlined format args; use `v0.1.3`.

## 0.1.0 — 2026-07-12

First production-quality local release of WatchMe. Note: the `v0.1.0` tag targeted Rust 1.85 CI and did not produce a successful multi-platform release; use `v0.1.3`.

### Added

- `watchme` binary with uppercase `WatchMe` install alias
- Bare registration for supported coding-agent contexts (no `start` command)
- Per-user daemon with owner-only IPC, lazy start, and config-driven `stay_resident` / idle grace
- tmux and Herdr adapters with identity revalidation
- Claude StopFailure hook install/remove, Codex goal recovery, manifest-driven generic agents
- Constrained cross-provider planner with redacted snapshots and compiled policy
- Administrative commands: status, list, explain, snapshot, logs, pause/resume, stop, doctor, providers, config, daemon
- Packaging: `scripts/install.sh`, `scripts/uninstall.sh`, systemd user unit, launchd plist, optional Herdr example, bash completion, man page
- Idle benchmark script and documentation
- Docs for commands, configuration, manifests, hooks, privacy, troubleshooting, compatibility, limitations, threat model, release checklist

### Security

- Owner-only directories and sockets
- Untrusted terminal/hook/manifest/planner input handling with redaction
- Human-required escalation for auth, billing, destructive, and ambiguous cases

### Known limitations

See `docs/limitations.md` and `docs/compatibility.md`. Live Herdr and live Claude rate-limit menu probes were unavailable on the development host and are recorded as skipped.
