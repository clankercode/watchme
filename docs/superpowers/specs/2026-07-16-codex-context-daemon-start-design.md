# Codex Context Detection and Detached Daemon Start

## Problem

Codex launches shell commands as direct descendants of the Codex process but
without a controlling TTY. WatchMe currently requires its own process to have a
TTY before it attempts agent ancestry resolution, so a normal `!watchme`
invocation fails with `unsupported context` even though the direct Codex
ancestor has a valid process identity, UID, and terminal.

`watchme daemon run` also intentionally occupies the foreground. That contract
is useful for systemd and launchd, but interactive users need an explicit way to
start the same daemon in the background without shell job-control syntax.

## Context Detection Design

The current child process TTY becomes optional input to process resolution.
WatchMe will continue to require correlated evidence: a known supported agent
must be found in the process ancestry or through existing terminal-scoped
discovery, and the resolver's confidence threshold remains unchanged. A
TTY-less child launched directly by Codex therefore succeeds through ancestry
and UID correlation; an unrelated tty-less process still has no supported agent
ancestor and fails closed.

When tmux or Herdr metadata is inherited, WatchMe will retain the existing
strict checks against the resolved agent identity and its TTY. The change does
not trust an environment variable as proof of agent context and does not weaken
multiplexer identity validation.

## Daemon Lifecycle Design

Add `watchme daemon start` for interactive background startup. It will:

1. Return successfully without spawning another process when the daemon already
   answers a status request.
2. Spawn the current WatchMe executable as `daemon run` with standard streams
   disconnected and a separate process group.
3. Poll the owner-only daemon socket until it answers or the bounded startup
   deadline expires.
4. Report sanitized child diagnostics if startup fails.

`watchme daemon run` remains a foreground operation for service managers. The
new `start` command honors the existing `idle_grace_seconds` and
`stay_resident` configuration. Bare `watchme` keeps its existing lazy-start
behavior and immediately registers its watcher, so users do not need to start
the daemon separately for normal use.

Daemon spawning and readiness handling will be shared between explicit
background startup and lazy registration to avoid diverging lifecycle behavior.

## Output and Errors

`watchme daemon start` prints `daemon started` after a newly spawned daemon is
ready and `daemon already running` when no spawn was needed. Spawn, readiness,
and diagnostic failures use the existing typed retryable-integration error
path. No daemon output remains attached to the invoking terminal.

## Testing

Regression coverage will prove:

- a tty-less child resolves a directly ancestral Codex process using correlated
  UID and ancestry evidence;
- unsupported tty-less invocation still fails closed;
- multiplexer validation continues to use the resolved agent's TTY;
- `daemon start` detaches, waits for readiness, and reports success;
- repeated `daemon start` is idempotent;
- the foreground `daemon run` behavior remains intact; and
- the installed binary can register from the live Codex command context and
  communicate with its lazily started daemon.

Command documentation, troubleshooting guidance, shell completion, and the man
page will describe `daemon start` while preserving the documented absence of a
top-level `watchme start` command.
