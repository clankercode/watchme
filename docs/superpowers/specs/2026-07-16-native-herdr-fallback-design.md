# Native Herdr fallback design

## Problem

Bare `watchme` fails inside a Codex pane managed by Herdr 0.7.4. Herdr
injects `HERDR_SOCKET_PATH`, `HERDR_WORKSPACE_ID`, `HERDR_TAB_ID`, and
`HERDR_PANE_ID`, so WatchMe assumes that socket implements its provisional
`watchme.herdr` bridge contract. The native Herdr server instead implements
protocol 16: requests use `id`, `method`, and `params`, and responses use
`id` with either `result` or `error`. It therefore returns a valid native
error envelope which WatchMe currently reports as a fatal malformed response.

The installed Herdr schema and the live read-only `x-left` probe both confirm
the protocol mismatch. This change does not claim or implement native Herdr
pane control.

## Decision

WatchMe will distinguish a documented native Herdr response envelope from an
arbitrary malformed bridge response. When registration encounters that typed
incompatibility after it has independently resolved a supported coding-agent
ancestor, it will register the verified process target without multiplexer
capabilities. This preserves bare `watchme` as the primary workflow and lets
the Codex process/log adapter continue supervising the session.

The fallback applies only to a syntactically valid native envelope containing
a string `id` and exactly one of:

- a `result` value; or
- an `error` object with string `code` and `message` fields.

Unknown fields are tolerated only while recognizing the native envelope, in
line with Herdr's protocol guidance. WatchMe does not consume the result or
grant any Herdr capability from it.

## Safety and error handling

The Herdr socket retains its current canonical-path, ownership, mode, peer
credential, size, newline, and deadline checks before the response is
classified. The fallback never weakens process ancestry or UID correlation.

Partial Herdr environment, unsafe sockets, timeouts, invalid JSON, arbitrary
response shapes, legacy bridge contract violations, and process/pane identity
contradictions remain fatal unsupported-context errors. A genuine
`watchme.herdr` bridge continues to produce a Herdr-backed watcher.

Native protocol support is deliberately out of scope. Implementing it later
requires a complete adapter for identity, observation, capture, notification,
and guarded input rather than a registration-only facade.

## Implementation

Add a typed multiplexer error for an incompatible native Herdr protocol.
Classify the response only when strict bridge deserialization fails. Refactor
registration so it can match that typed error and reuse one process-only
registration helper; all other errors keep their current user-visible path.

Document that native Herdr currently degrades to verified process supervision
and that the provisional bridge remains the only Herdr pane-control contract.

## Verification

Use test-driven coverage at two boundaries:

1. A Herdr contract test feeds the native `id`/`error` envelope and expects the
   typed incompatibility error while neighboring malformed responses remain
   ordinary protocol failures.
2. A bare-CLI regression runs under a fake tty-less Codex ancestor with full
   Herdr environment and a native-envelope socket, then proves registration
   succeeds as a process watcher rather than a Herdr watcher.

Run the focused tests, formatting and strict clippy checks, the complete
`just gates` suite, `just install`, and live bare registration. Deploy the
verified release binary to `x-left` through `xsm`, compare checksums, and ask
the existing Codex session to rerun bare `watchme` for the final in-session
proof.
