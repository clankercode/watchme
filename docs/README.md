# WatchMe documentation

User-facing overview lives in the repository root [README.md](../README.md).

## Guides

- [commands.md](commands.md) — CLI surface
- [configuration.md](configuration.md) — XDG config and conservative defaults
- [manifests.md](manifests.md) — provider/agent manifests
- [hooks.md](hooks.md) — Claude hook, systemd/launchd, Herdr example, exact files changed
- [privacy.md](privacy.md) — redaction, retention, no telemetry
- [troubleshooting.md](troubleshooting.md) — doctor, explain, common failures
- [compatibility.md](compatibility.md) — probed versions and support tiers
- [benchmarks.md](benchmarks.md) — measured idle resource baselines
- [limitations.md](limitations.md) — hard limits and human-required classes
- [threat-model.md](threat-model.md) — observation/recovery threat model
- [release-checklist.md](release-checklist.md) — gates and Definition of Done reconciliation

## Architecture notes

Implementation follows the one-shot bundle under `/home/xertrov/Downloads/WatchMe-one-shot-bundle/` with the command-contract override: bare `watchme` / `WatchMe` registers the current agent context; there is no `watchme start` registration alternative.
