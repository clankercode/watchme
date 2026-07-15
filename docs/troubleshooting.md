# Troubleshooting

## First steps

```bash
watchme doctor
watchme doctor --json
watchme doctor --strict
watchme explain [WATCHER_ID]
watchme status --json
watchme daemon status
```

`doctor` checks paths, permissions, config, tmux, Herdr, hooks, and providers.

## Common issues

| Symptom | Likely cause | Action |
|---|---|---|
| Bare `watchme` fails with unsupported context | No supported coding-agent ancestor, or multiplexer identity mismatch | Use shell escape `!WatchMe` from the agent, then run `watchme doctor` |
| `daemon unavailable` | Supervisor not running and lazy start failed | Run `watchme daemon start`; use `watchme daemon run` for foreground diagnostics; check `XDG_RUNTIME_DIR` permissions |
| Permission errors on state/runtime | Directory not owner-only | Fix modes to `0700`; remove group/other write |
| Claude hook not recovering | Missing correlation / macOS proof / first-run UI | See [compatibility.md](compatibility.md); install hook explicitly |
| Herdr checks warn | Herdr not installed or env unset | Optional; tmux path remains available |
| Herdr protocol error mentions unknown field `id` | Older WatchMe tried its provisional bridge contract against the native Herdr API | Upgrade WatchMe; current builds fall back to verified process supervision |
| Planner refused | Same provider family / disabled / budget | Expected; escalate or configure independent planner |

## Multiplexer notes

- **tmux**: real integration tests use isolated `-L` sockets. Pane rename/index changes must not break immutable identity.
- **Herdr**: Herdr 0.7.4's native socket API is detected but does not grant pane-control capabilities. WatchMe uses verified process supervision unless the socket implements the explicit `watchme.herdr` bridge contract.

## Logs

```bash
watchme logs [ID] [--follow]
```

Logs are size/retention bounded. Prefer `explain` for decision provenance.
