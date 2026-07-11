# Privacy, redaction, and retention

## Principles

- No runtime telemetry.
- No secrets in argv, logs, or snapshots (tests assert redaction of common secret patterns).
- Terminal/log/hook/manifest/planner content is untrusted and redacted before planner use or snapshot export.
- Managed directories and sockets are owner-only (`0700` / `0600`).

## Retention

- Audit log (`audit.jsonl` under XDG state) is bounded/rotated by retention policy in code.
- Snapshots default to redacted content (`watchme snapshot --redacted`).
- Uninstall without `--purge-state` leaves local config/state for the user to review.

## What is stored locally

- Watcher registry and recovery ledgers under XDG state
- Daemon socket under XDG runtime
- Optional Claude hook marker JSONL
- Config under XDG config

Nothing is uploaded by WatchMe itself.
