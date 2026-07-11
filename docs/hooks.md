# Hooks and service helpers

All installers are idempotent, dry-run capable where applicable, and report exact changed paths.

## Claude StopFailure hook

```bash
watchme hooks install-claude [--dry-run] [--settings PATH] [--marker PATH]
watchme hooks remove-claude [--dry-run] [--settings PATH] [--marker PATH]
```

**Files changed on install**

- Claude settings JSON (default `~/.claude/settings.json`): merges one WatchMe-owned `StopFailure` matcher/handler; does not overwrite unrelated groups
- Marker JSONL under XDG state (default under `~/.local/state/watchme/`): owner-only

**Uninstall** removes only the WatchMe-owned handler and does not delete unrelated Claude settings.

## Binary install / uninstall

```bash
./scripts/install.sh --prefix ~/.local [--from PATH|--build] [--dry-run] \
  [--with-systemd] [--with-launchd] [--with-herdr-action] \
  [--with-completions] [--with-man]
./scripts/uninstall.sh --prefix ~/.local [--dry-run] [--purge-state]
```

**Files changed by install (core)**

- `PREFIX/bin/watchme`
- `PREFIX/bin/WatchMe` → symlink to `watchme`

**Optional install artifacts**

| Flag | Path |
|---|---|
| `--with-systemd` | `PREFIX/lib/systemd/user/watchme.service` |
| `--with-launchd` | `PREFIX/share/watchme/launchd/com.clankercode.watchme.plist` |
| `--with-herdr-action` | `PREFIX/share/watchme/herdr/watchme-action.example.toml` |
| `--with-completions` | `PREFIX/share/bash-completion/completions/watchme` |
| `--with-man` | `PREFIX/share/man/man1/watchme.1` |

Default uninstall removes only those WatchMe-owned paths. Unrelated prefix files and XDG config/state remain. `--purge-state` also deletes XDG watchme directories.

## systemd user unit

Source: `packaging/systemd/watchme.service`.

Enable only after setting `stay_resident = true` in config if you want a resident empty supervisor. Default WatchMe starts lazily on registration and does not require a service manager.

## launchd

Source: `packaging/launchd/com.clankercode.watchme.plist`. Replace `REPLACE` user paths before loading.

## Optional Herdr action

`packaging/herdr/watchme-action.example.toml` is an illustrative bridge for the local `watchme.herdr` socket contract. It is **not** a verified upstream Herdr plugin format. See [compatibility.md](compatibility.md).
