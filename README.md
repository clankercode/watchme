# WatchMe

Local supervisor for long-running coding-agent sessions on Linux and macOS.

```text
!WatchMe
```

On case-sensitive Unix, the installer places the canonical `watchme` binary and an uppercase `WatchMe` symlink so that shell-escape spelling works.

## What it does

WatchMe discovers the current tmux or Herdr pane, identifies the coding-agent process and durable session, observes structured hooks/APIs/logs before terminal captures, applies known deterministic recoveries, and—only when those fail—asks a different provider family for a strictly schema-constrained recovery plan. Ambiguous, credential, billing, or unsafe prompts escalate to a human.

## Quick start

```bash
cargo build --release -j1 --locked
./scripts/install.sh --prefix ~/.local --from target/release/watchme
# optional helpers:
# ./scripts/install.sh --prefix ~/.local --from target/release/watchme \
#   --with-systemd --with-completions --with-man --with-herdr-action

watchme doctor
# From a supported coding-agent session / shell escape:
WatchMe
watchme status
watchme stop --all
./scripts/uninstall.sh --prefix ~/.local
```

Dry-run any install/uninstall with `--dry-run` to see exact paths that would change.

## Documentation

| Doc | Topic |
|---|---|
| [docs/README.md](docs/README.md) | Doc index |
| [docs/commands.md](docs/commands.md) | Command reference |
| [docs/configuration.md](docs/configuration.md) | Config reference |
| [docs/hooks.md](docs/hooks.md) | Hook/service install and changed files |
| [docs/manifests.md](docs/manifests.md) | Provider manifests |
| [docs/privacy.md](docs/privacy.md) | Privacy, redaction, retention |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Doctor / common failures |
| [docs/compatibility.md](docs/compatibility.md) | Tested versions and support tiers |
| [docs/benchmarks.md](docs/benchmarks.md) | Measured idle resource results |
| [docs/limitations.md](docs/limitations.md) | Known limits and human-required classes |
| [docs/threat-model.md](docs/threat-model.md) | Threat model |
| [docs/release-checklist.md](docs/release-checklist.md) | Release gates / Definition of Done |
| [CHANGELOG.md](CHANGELOG.md) | Version history |

## Development

```bash
just test          # cargo test --all-features -j1 --locked
just fmt-check
just clippy
just install-smoke
just bench         # idle benchmarks (0 and multi watcher)
just gates         # full local release gates
```

See [AGENTS.md](AGENTS.md) for release publication rules. Publishing to GitHub requires explicit authorization.

## License

`Unlicense OR CC0-1.0`. See `LICENSES/` and [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
