# Commands

Canonical binary: `watchme`. Uppercase alias: `WatchMe` (symlink installed by `scripts/install.sh`).

## Bare invocation

```bash
watchme
WatchMe
```

Registers the current coding-agent context when detection succeeds (tmux/Herdr + process correlation). Outside a supported context, exits non-zero and prints guidance to invoke via `!watchme` and run `watchme doctor`.

There is **no** `watchme start` command.

## Administrative commands

| Command | Purpose |
|---|---|
| `status [ID] [--json]` | Daemon/watcher status |
| `list [--json]` | List watchers |
| `explain [ID] [--json]` | Decision-chain provenance from audit |
| `snapshot [ID] [--redacted]` | Redacted diagnostic snapshot |
| `logs [ID] [--follow]` | Bounded audit/log follow |
| `stop <ID>\|--all [--json]` | Stop watcher(s); `--all` required when no ID |
| `pause <ID> [--json]` | Pause observation/recovery |
| `resume <ID> [--json]` | Resume a paused watcher |
| `doctor [--strict] [--json]` | Local diagnostics |
| `providers [--json]` | Built-in + manifest providers |
| `config path\|check\|show` | Config path, validate, redacted show |
| `daemon run\|status\|stop` | Per-user supervisor lifecycle |
| `hooks install-claude\|remove-claude [--dry-run] [--settings PATH] [--marker PATH]` | Claude StopFailure hook |

JSON envelopes use `schema_version = "1.0"` and `ok` boolean.

## Daemon behavior

- Lazy start: registration may spawn `daemon run` when the socket is absent.
- `daemon run` loads `$XDG_CONFIG_HOME/watchme/config.toml` for `idle_grace_seconds` and `stay_resident`.
- Default is non-resident: empty daemon exits after idle grace.
- Opt-in systemd/launchd helpers expect `stay_resident = true` in config.

## Hidden hook helper

`watchme watchme-hook-stop-failure --marker PATH` is hidden and used only by the installed Claude hook command.
