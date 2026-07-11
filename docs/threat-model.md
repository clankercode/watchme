# Observation and recovery threat model

Terminal captures, JSONL records, hooks, manifests, and planner output are untrusted. They can be malformed, oversized, partially written, rotated, prompt-injected, or crafted to emit terminal control protocols. WatchMe bounds reads, strips terminal protocols and controls, fingerprints redacted evidence, and never treats observed text as policy.

The compiled policy is the final authority. It denies unknown action types and never automates authentication, billing, funding, upgrades, secrets, broad permission approval, yolo/always-approve modes, privilege escalation, destructive operations, arbitrary shell/file/network actions, or relaunching a dead target. Configuration and manifests cannot widen this authority.

Before action, target identity, evidence freshness, source precedence, composer state, human intervention, cooldown, idempotency, and attempt/wait/planner budgets must pass. Restarted recovery requires live revalidation. Higher-ranked contradictory evidence suppresses lower-ranked action; screen-only evidence requires at least two stable observations, while a structured terminal failure can be handled immediately. Wall time is evidence only; monotonic time governs cooldowns so wall-clock jumps do not cause premature action.

## Process and IPC trust boundaries

- Managed config/state/runtime directories must be owner-only (`0700`); the daemon socket is `0600`.
- IPC accepts only peer UIDs matching the current effective UID.
- Hook installers merge marked WatchMe-owned entries only; uninstall removes those entries without rewriting unrelated agent settings.
- Install/uninstall scripts change only WatchMe-owned prefix paths unless `--purge-state` is explicit.
- Planner adapters run as separate processes with bounded I/O; their stdout is schema-validated JSON, never a shell script.

## Residual risks

- A compromised local user account can still operate WatchMe as that user.
- Terminal UIs that lack a verified adapter boundary remain observation-only; false comfort from screen text is rejected by policy.
- Optional service managers (systemd/launchd) widen lifetime of the daemon; keep `stay_resident` intentional.
- Live third-party CLIs evolve quickly; compatibility claims are limited to probed versions in `docs/compatibility.md`.

Full research threat notes from the one-shot bundle remain advisory; this document matches the shipped implementation.
