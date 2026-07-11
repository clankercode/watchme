# Compatibility

## Claude Code

Probe date: 2026-07-11 (Australia/Sydney). The local executable resolves to
`/home/xertrov/.local/bin/claude` and reports `Claude Code 2.1.207`. Its
read-only `--help` surface confirms interactive operation, `--continue`,
`--resume`, session IDs, and JSON/stream JSON output modes. It also exposes
`--include-hook-events` for stream JSON. The help probe itself did not alter
provider credentials or account state.

An isolated, temporary tmux probe then started `claude --bare` in a fresh
0700 directory and sent the documented local slash command
`/rate-limit-options`. On this host, an existing first-run fullscreen-renderer
confirmation intercepted the command. The bounded capture showed that prompt,
not a rate-limit menu; WatchMe sent no confirmation, cursor navigation, or
account-changing input, and immediately destroyed the tmux server and the
temporary directory. Therefore the rate-limit UI remains fixture-tested only
on this version; no live-menu compatibility claim is made from the probe.

WatchMe treats the local `StopFailure` hook, when installed, as structured
evidence only after exact session-ID and transcript-path correlation. The
hook installer safely merges a tagged `StopFailure` entry into an existing
owner-only `~/.claude/settings.json`; it does not overwrite other hooks, and
uninstall removes only its own tagged entry. Markers must be owner-owned,
regular, bounded JSONL files. WatchMe never chooses a transcript merely
because it is newest.

The terminal fallback is intentionally narrower than the installed UI:
two identical, trusted live captures are required before it recognizes the
semantic label `Stop and wait for limit to reset`. It sends only minimal
allowlisted cursor keys, then Enter, and never selects usage-credit, funding,
upgrade, login, billing, or account actions. Claude's native retry UI always
wins over WatchMe backoff. This support is fixture-tested, not a guarantee
that every future Claude Code UI layout remains action-compatible.

## Herdr

Probe date: 2026-07-11 (Australia/Sydney).

The read-only probe `command -v herdr` produced no output and exited non-zero on the development host. Consequently, no installed Herdr version, `--help` output, schema command, socket documentation, or upstream plugin API could be verified. No live Herdr state was opened or modified, and the live smoke test was skipped honestly because Herdr was absent.

WatchMe therefore implements and tests a fixed, local bridge contract rather than claiming compatibility with an unverified upstream API. The contract is newline-delimited JSON over the owner-owned Unix socket in `HERDR_SOCKET_PATH`, with `protocol = "watchme.herdr"`, `schema_version = 1`, unique request IDs, one request/response per connection, a 256 KiB response ceiling, and bounded timeouts. Context also requires `HERDR_WORKSPACE_ID`, `HERDR_TAB_ID`, and `HERDR_PANE_ID`.

The schema-faithful fake covers `pane_info`, `process_info`, bounded recent unwrapped `pane_read`, separate control-safe `send_text` and allowlisted symbolic `send_keys`, `agent_session`, `agent_state_events`, and `notification`. The client rejects partial, malformed, oversized, wrong-version, wrong-protocol, wrong-method, and mismatched-request responses. Success and failure are an exact union: success requires a non-null result and no error, while failure requires a non-null error and no result. One monotonic deadline covers connection, peer verification, write, response read, and parse; held or byte-dripping peers cannot renew it. It requires an absolute, canonical Unix socket owned by the current UID and not writable by group or others, rechecks the pathname device/inode after connecting, and uses Tokio's portable Unix peer-credential API on both Linux and macOS; unavailable or mismatched credentials fail closed. Target process, pane, and composer safety are revalidated at action boundaries, and terminal reads receive a post-read identity check. Persisted Herdr server identity combines the canonical socket path and provider-returned server ID, so either replacement changes target identity.

`config/herdr-plugin.example.toml` is an optional bridge configuration example only; it has no core UI dependency and is not represented as a verified upstream Herdr plugin format.
