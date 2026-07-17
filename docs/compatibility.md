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

Probe date: 2026-07-16 (Australia/Sydney).

The development host and `x-left` report Herdr 0.7.4. Its bundled
`herdr api schema --json` describes native protocol 16: requests use `id`,
`method`, and `params`; responses use the same `id` with exactly one of
`result` or `error`. A read-only `herdr api snapshot` on `x-left` confirmed a
live protocol-16 server and the inherited workspace, tab, and pane context.
Herdr's [socket API documentation](https://herdr.dev/docs/socket-api/) is the
upstream reference for that native surface.

WatchMe supports Herdr's native protocol 16 for exact pane/process identity,
bounded recent-unwrapped reads, and atomic `pane.send_input`. Registration
requires the inherited workspace, tab, and pane IDs, the exact resolved Codex
PID in `pane.process_info`, and matching TTY and process start time. The
persisted dialect prevents later requests from being misdecoded as the older
bridge contract.

The adapter also retains a separate, fixed local bridge contract. The bridge is
newline-delimited JSON over the owner-owned Unix socket in
`HERDR_SOCKET_PATH`, with `protocol = "watchme.herdr"`, `schema_version = 1`,
unique request IDs, one request/response per connection, a 256 KiB response
ceiling, and bounded timeouts. Context also requires `HERDR_WORKSPACE_ID`,
`HERDR_TAB_ID`, and `HERDR_PANE_ID`.

When those inherited variables point at a native Herdr server, WatchMe first
performs its normal socket ownership, mode, peer-credential, size, newline,
and deadline checks, then explicitly negotiates protocol 16. Protocol 17 or
another unsupported version safely degrades to independently verified process
supervision. Partial environment, unsafe sockets, timeouts, arbitrary malformed
responses, and process/pane contradictions still fail closed.

On Linux, bare registration can bind the exact `codex resume THREAD` process to
the rollout, thread database, and goals database that process already has open.
The daemon reads those files read-only, revalidates owner/device/inode and live
PID/start-time/CWD on every observation, and accepts a capacity block only when
the exact latest completed turn contains Codex's capacity result and the same
thread's durable goal is blocked. On macOS, automatic `/proc/PID/fd`
correlation is unavailable; all explicit thread/process/CWD/rollout/database
values are required or the watcher remains non-recovering.

Herdr's agent status is screen-derived and may be missing or marked skipped for
a focused pane. WatchMe treats it as optional corroboration only: it cannot
mask exact Codex state and cannot authorize input. A verified recovery sends
the fixed `/goal resume` text and Enter in one `pane.send_input` request after
two immediate identity/composer checks. A lost or malformed acknowledgement is
recorded as a possible side effect and becomes human-required; it is never
blindly retried. Unknown composer layouts, typed drafts, stale capacity text,
and active/resumed goals remain observation-only.

The schema-faithful fake covers `pane_info`, `process_info`, bounded recent unwrapped `pane_read`, separate control-safe `send_text` and allowlisted symbolic `send_keys`, `agent_session`, `agent_state_events`, and `notification`. The client rejects partial, malformed, oversized, wrong-version, wrong-protocol, wrong-method, and mismatched-request responses. Success and failure are an exact union: success requires a non-null result and no error, while failure requires a non-null error and no result. One monotonic deadline covers connection, peer verification, write, response read, and parse; held or byte-dripping peers cannot renew it. It requires an absolute, canonical Unix socket owned by the current UID and not writable by group or others, rechecks the pathname device/inode after connecting, and uses Tokio's portable Unix peer-credential API on both Linux and macOS; unavailable or mismatched credentials fail closed. Target process, pane, and composer safety are revalidated at action boundaries, and terminal reads receive a post-read identity check. Persisted Herdr server identity combines the canonical socket path and provider-returned server ID, so either replacement changes target identity.

`config/herdr-plugin.example.toml` is an optional bridge configuration example only; it has no core UI dependency and is not represented as a verified upstream Herdr plugin format. The packaging helper `packaging/herdr/watchme-action.example.toml` is the same illustrative contract, installable via `scripts/install.sh --with-herdr-action`.

## tmux

Probe date: 2026-07-12. Host reports `tmux 3.6b`. Real integration tests use isolated `tmux -L` sockets with fake agent processes. Identity uses immutable server/session/window/pane identifiers plus process start-time correlation.

## Support tier summary

| Surface | Tier | Evidence |
|---|---|---|
| Claude Code 2.1.207 structured StopFailure hook | structured recovery (when correlated) | hook installer + fixture/e2e tests; live menu not established |
| Claude Code terminal rate-limit menu | deterministic terminal recovery (fixture-only on this host) | fixtures; live probe blocked by first-run UI |
| Codex blocked durable goal | structured / deterministic resume on Linux; explicit correlation on macOS | exact SQLite/rollout binding + recovery tests for atomic `/goal resume` |
| Herdr 0.7.4 native API | first-class protocol-16 identity/read/input adapter | schema-faithful contract tests + read-only live `x-left` probe |
| `watchme.herdr` bridge | contract-tested adapter | schema-faithful fake; no upstream bridge claim |
| tmux 3.6b | first-class multiplexer | real integration tests |
| Bundled generic manifests (opencode, pi, hermes, …) | observation-only to planner-assisted per manifest | bundled manifests + loader tests |
| Untested / unknown agents | untested → safe degradation | `unknown.toml` + doctor/providers |

Windows is out of scope for v1.
