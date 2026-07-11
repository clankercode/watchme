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
| Bare `watchme` fails with unsupported context | Not inside a supported agent pane | Use shell escape `!WatchMe` from the agent, or run `doctor` |
| `daemon unavailable` | Supervisor not running and lazy start failed | `watchme daemon run` / check `XDG_RUNTIME_DIR` permissions |
| Permission errors on state/runtime | Directory not owner-only | Fix modes to `0700`; remove group/other write |
| Claude hook not recovering | Missing correlation / macOS proof / first-run UI | See [compatibility.md](compatibility.md); install hook explicitly |
| Herdr checks warn | Herdr not installed or env unset | Optional; tmux path remains available |
| Planner refused | Same provider family / disabled / budget | Expected; escalate or configure independent planner |

## Multiplexer notes

- **tmux**: real integration tests use isolated `-L` sockets. Pane rename/index changes must not break immutable identity.
- **Herdr**: live probe skipped when binary absent; contract fake covers the socket protocol.

## Logs

```bash
watchme logs [ID] [--follow]
```

Logs are size/retention bounded. Prefer `explain` for decision provenance.
