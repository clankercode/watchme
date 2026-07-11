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
evidence only after exact session-ID, transcript-path, device/inode, process
start-time, CWD, and target-session correlation. The hook installer safely
merges a documented `StopFailure` matcher group and command handler into an
existing owner-only `~/.claude/settings.json`; it does not overwrite other
groups, and uninstall removes only that exact handler. Markers must be
owner-owned, regular, bounded JSONL files. WatchMe never chooses a transcript
merely because it is newest. Linux registration can instead correlate the
one owner-private standard Claude transcript already open by the target
process; macOS has no equivalent automatic open-file proof and therefore
requires the explicit supported correlation values or disables hook recovery.

Install or remove this optional integration explicitly with
`watchme hooks install-claude` and `watchme hooks remove-claude`.
`--dry-run` shows the resolved settings, marker, and escaped hook command
without writing either file; `--settings` and `--marker` support an explicit
owner-controlled location. Installation writes a fixed `watchme` command and
strict POSIX-single-quotes the marker path, so paths with spaces or shell
metacharacters remain literal data. Bare `watchme` remains registration only.
On macOS, Claude hook attachment additionally requires its explicit session,
transcript, marker, resolved agent PID/start-time, and canonical CWD
environment correlation. If that proof is unavailable WatchMe simply does
not enable hook recovery for that watcher.

The terminal fallback is observation-only on Claude Code 2.1.207. A second
isolated probe on 2026-07-12 again stopped at the first-run security screen;
WatchMe sent only `/rate-limit-options`, selected nothing, and destroyed the
temporary tmux server and HOME. It therefore did not establish a versioned
renderer boundary or a real limit menu for this build.

The implementation can act only when a supported adapter provides a bounded,
immediate live region: it requires two identical captures, one current cursor,
and the exact normalized `Stop and wait for limit to reset` label with a benign
reset suffix. It never searches arbitrary pane history. A correlated reset
can send the fixed resume text only after its margin, identity and composer
checks, and a new action-session-bound Claude working proof from that same live
target. Generic liveness and stale/lower-ranked evidence cannot verify it.
Because this host has not established the renderer boundary, neither menu
selection nor automatic resume is enabled here; an elapsed reset without that
proof remains a human hand-off.

## Herdr

Probe date: 2026-07-11 (Australia/Sydney).

The read-only probe `command -v herdr` produced no output and exited non-zero on the development host. Consequently, no installed Herdr version, `--help` output, schema command, socket documentation, or upstream plugin API could be verified. No live Herdr state was opened or modified, and the live smoke test was skipped honestly because Herdr was absent.

WatchMe therefore implements and tests a fixed, local bridge contract rather than claiming compatibility with an unverified upstream API. The contract is newline-delimited JSON over the owner-owned Unix socket in `HERDR_SOCKET_PATH`, with `protocol = "watchme.herdr"`, `schema_version = 1`, unique request IDs, one request/response per connection, a 256 KiB response ceiling, and bounded timeouts. Context also requires `HERDR_WORKSPACE_ID`, `HERDR_TAB_ID`, and `HERDR_PANE_ID`.

The schema-faithful fake covers `pane_info`, `process_info`, bounded recent unwrapped `pane_read`, separate control-safe `send_text` and allowlisted symbolic `send_keys`, `agent_session`, `agent_state_events`, and `notification`. The client rejects partial, malformed, oversized, wrong-version, wrong-protocol, wrong-method, and mismatched-request responses. Success and failure are an exact union: success requires a non-null result and no error, while failure requires a non-null error and no result. One monotonic deadline covers connection, peer verification, write, response read, and parse; held or byte-dripping peers cannot renew it. It requires an absolute, canonical Unix socket owned by the current UID and not writable by group or others, rechecks the pathname device/inode after connecting, and uses Tokio's portable Unix peer-credential API on both Linux and macOS; unavailable or mismatched credentials fail closed. Target process, pane, and composer safety are revalidated at action boundaries, and terminal reads receive a post-read identity check. Persisted Herdr server identity combines the canonical socket path and provider-returned server ID, so either replacement changes target identity.

`config/herdr-plugin.example.toml` is an optional bridge configuration example only; it has no core UI dependency and is not represented as a verified upstream Herdr plugin format.
