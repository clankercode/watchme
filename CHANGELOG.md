# Changelog

## 0.1.1 — 2026-07-12

### Fixed

- Raise MSRV and CI/release toolchains to Rust 1.88 so `let` chains used throughout the daemon compile on GitHub runners (1.85 failed with E0658).

## 0.1.0 — 2026-07-12

First production-quality local release of WatchMe. Note: the `v0.1.0` tag targeted Rust 1.85 CI and did not produce a successful multi-platform release; use `v0.1.1`.

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
