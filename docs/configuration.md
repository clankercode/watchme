# Configuration

## Paths

Follows XDG with secure fallbacks:

| Role | Path |
|---|---|
| Config | `$XDG_CONFIG_HOME/watchme/` (default `~/.config/watchme/`) |
| State | `$XDG_STATE_HOME/watchme/` (default `~/.local/state/watchme/`) |
| Runtime | `$XDG_RUNTIME_DIR/watchme/` (fallback `/tmp/watchme-<uid>/`) |

`watchme doctor` and daemon startup create these directories owner-only (`0700`). The daemon socket is `0600`.

## Loading

```bash
watchme config path
watchme config check
watchme config show
```

Copy `config/config.example.toml` to `config.toml` under the config directory. Unknown fields warn; `doctor --strict` rejects them. Project-local repository config is not auto-loaded.

## Notable defaults

- Observation poll interval: 60s with small jitter
- Idle grace: 30s; `stay_resident = false`
- Recovery budgets and cooldowns enabled
- Planning enabled but bounded; same-provider-family planners rejected
- Remote manifest updates off
- No telemetry

Unsafe automation (auth, billing, funding, upgrades, yolo/always-approve, privilege escalation, destructive actions) is absent from the config surface and cannot be enabled by manifests.

## Example

See `config/config.example.toml` and `config/herdr-plugin.example.toml` (illustrative Herdr bridge only).
