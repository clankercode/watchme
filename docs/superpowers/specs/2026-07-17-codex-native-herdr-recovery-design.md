# Real Codex Recovery Through Native Herdr

Date: 2026-07-17
Status: approved design, awaiting written-spec review

## Goal

Make bare `watchme` supervise the actual Codex session from which it is invoked,
recognize a durable goal blocked by transient model capacity, wait conservatively,
and submit the literal `/goal resume` to that same session through native Herdr.
WatchMe should autonomously resolve issues for which it has exact, current, and
safe evidence. Ambiguous identity, stale evidence, non-transient failures, unsafe
composer state, and unsupported protocols remain human hand-offs.

This work also makes those lifecycle decisions visible through
`watchme logs --follow` and upgrades an existing process-only watcher when bare
`watchme` is run again after installation.

## Incident Evidence

The live watcher on `x-left` registered and remained healthy, but every audit
record came from `process_metadata` and classified only process liveness as
`working`. It never entered the Codex adapter.

The implementation and live process exposed several independent gaps:

1. Production registration attaches a Claude transcript but never a Codex
   session reference. Codex tests construct a bound reference manually and
   therefore bypass registration.
2. The rollout probe requires a file below the project CWD, no larger than
   1 MiB, owner-only, and unchanged in size and mtime. Real Codex stores the
   rollout under `CODEX_HOME/sessions`; the observed file was approximately
   1.5 GB, append-only, and mode `0664`.
3. Native Herdr protocol 16 is recognized only as incompatible and registration
   falls back to a process target. A process target has no capture or input
   channel, so it cannot submit `/goal resume`.
4. The existing Codex resume recipe creates a text insertion action but does
   not submit Enter. A slash command left in the composer does not resume a
   goal.
5. Re-registering an exact existing process watcher returns `Existing` without
   merging a newly discovered Codex binding or promoting it to a verified
   multiplexer target.
6. Registration and lifecycle transitions are durable in `watchers.json` but
   are not consistently represented in the audit stream users tail.

The real Codex process supplied trustworthy correlation inputs: its verified
PID/start time, inherited Herdr workspace/tab/pane IDs, a command line naming
the resumed thread, open descriptors for that thread's rollout and Codex state
databases, and a `thread_goals` row keyed by the same thread ID. Native Herdr's
schema supplies pane identity, process metadata, bounded pane reads, and an
atomic `pane.send_input` request accepting literal text plus symbolic keys.

The goal had already been manually resumed before the later Herdr snapshot was
taken. Its then-current `working` value therefore says nothing about the status
Herdr exposed during the capacity incident. Native Herdr can also report that
screen detection was skipped. A focused pane, `screen_detection_skipped`, a
missing status, or a stale status must all be treated as absent corroboration;
none may override current structured Codex goal and turn evidence.

## Considered Approaches

### 1. Native Herdr plus exact Codex state correlation (selected)

Implement the small protocol-16 surface WatchMe needs, correlate the precise
Codex thread and state files to the watched PID, and require structured goal and
terminal-result evidence before acting. This is the only approach that supports
both safe observation and control of the existing session.

Trade-off: it adds protocol types and a read-only SQLite dependency, but keeps
each dependency behind a narrow adapter and exercises the real contracts.

### 2. Native Herdr status and terminal text only

Use Herdr's typed `blocked` status plus a stable screen capture containing the
capacity wording. This avoids reading Codex state databases.

Rejected because terminal text can be quoted, replayed, or stale. It is useful
as supporting and composer evidence, but not sufficient authorization for an
autonomous slash command.

### 3. Keep process-only supervision or launch another Codex app server

Process-only supervision cannot control the current pane. A separately launched
Codex app server would not be the already-running TUI connection and could
diverge from the user's active thread.

Rejected because neither option can guarantee the action reaches exactly the
registered session.

## Architecture

### Native Herdr transport

Retain the existing socket safety boundary: absolute canonical Unix socket,
owner and mode checks, peer credentials, device/inode recheck, bounded messages,
unique request IDs, and one monotonic deadline. Negotiate one of two explicit
wire dialects:

- the existing `watchme.herdr` bridge contract; or
- native Herdr protocol 16 with strict `id` and exactly one of `result` or
  `error`.

Native support is deliberately limited to:

- `pane.current`;
- `pane.process_info`;
- `pane.read` with bounded lines, text format, screen source, ANSI stripping;
- `agent.get` or snapshot fields when available for supporting status/session
  correlation; and
- `pane.send_input` with the exact text and `Enter` key in one request.

Every response must have the matching request ID and expected result variant.
Unknown result variants, protocol drift, malformed fields, unsafe socket state,
timeouts, and identity contradictions fail closed. Native protocol versions
other than 16 degrade to independently verified process supervision only.

Registration accepts a native Herdr target only when inherited
workspace/tab/pane IDs, `pane.current`, `pane.process_info`, the resolved Codex
PID/start time, UID, and TTY all agree. The persisted server identity includes
the canonical socket identity and native protocol/version so replacement or
upgrade forces revalidation.

### Exact Codex session binding

Add a registration-time Codex attachment module rather than embedding this
logic in CLI context detection.

A thread ID may come only from an exact source:

1. native Herdr `agent_session` for the registered pane when it names a Codex
   session ID;
2. a verified Codex command line of the form `codex resume THREAD_ID`; or
3. explicit supported correlation variables that include the thread ID,
   PID, start time, and canonical state paths.

If exact sources disagree or none exists, WatchMe keeps supervising but disables
Codex goal recovery. It never selects a newest session or rollout.

On Linux, the rollout, `state_*.sqlite`, and `goals_*.sqlite` files must be open
by the exact watched PID at registration. WatchMe captures canonical path,
device, inode, owner UID, and the relevant database schema version. On macOS,
where `/proc/PID/fd` is unavailable, automatic binding is disabled unless the
explicit correlation values and owner-controlled canonical files satisfy the
same identity checks.

At every observation, WatchMe revalidates process PID/start time, CWD, target
session, file identity, owner UID, and the process/file correlation available
on that platform. SQLite is opened read-only with query-only behavior. Only the
known `threads` and `thread_goals` columns are read, and both rows must match the
bound thread ID and process CWD.

The append-only rollout binding uses stable file identity (device/inode), not
size and mtime. Size is a cursor, not identity. The reader examines bounded,
complete JSONL records from the current tail/cursor and never loads the complete
rollout. Rotation, truncation behind the cursor, partial records, oversized
records, invalid JSON, or thread mismatch suppress recovery.

### Capacity classification

Autonomous capacity recovery requires all of the following:

- exact target process, Herdr pane, and Codex thread bindings remain valid;
- `thread_goals.status` for that thread is `blocked` or `paused`;
- the latest completed Codex turn for that same thread has a structured
  assistant terminal result matching the exact supported model-capacity error
  family;
- the evidence is newer than the last successful progress observation and is
  not followed by a newer active turn or human input; and
- the failure is transient rather than authentication, billing, safety,
  approval, usage-limit, explicit budget-limit, or unknown failure.

The exact observed wording, `Selected model is at capacity. Please try a
different model.`, is one supported capacity result. Matching is performed on
the structured assistant result payload, not arbitrary screen history. Screen
capture and a fresh, non-skipped Herdr agent status may corroborate the event
but cannot authorize it alone. Focused or skipped Herdr detection is not
negative evidence and cannot suppress a structured Codex capacity event.

Other resolvable conditions can gain recipes later only through the same
evidence/action contract: typed classification, exact target binding,
idempotence, bounded retries, and post-action verification. This change does
not introduce speculative recipes for unobserved failures.

### Recovery transaction

For a confirmed capacity block:

1. Persist a capacity event and enter a bounded jittered wait.
2. When due, re-read the same goal and latest turn evidence.
3. Require that the goal remains blocked, no newer human input or active turn
   exists, the pane identity/revision remains current, and the composer is
   empty.
4. Persist the exactly-once action marker before dispatch.
5. Call native `pane.send_input` once with `text = "/goal resume"` and
   `keys = ["Enter"]` so submission is atomic at the Herdr boundary.
6. Verify a newer structured goal state of `active` or `pursuing` for the same
   thread. Success returns to observing.

An ambiguous send result is never retried automatically. It becomes
`human_required`, because the command may already have been submitted. A
definite pre-dispatch refusal can be retried within the existing attempt and
cooldown budget. Exhausted attempts, changed identity, non-empty composer,
unknown goal state, or a non-capacity terminal result become human hand-offs.

### Existing watcher upgrade

Registration deduplication compares exact process PID/start time across a
process target and a richer multiplexer target. Running bare `watchme` again
promotes the existing watcher in place when the fresh native Herdr identity and
Codex binding validate. It preserves the watcher ID and audit history, clears
stale process-only observations, increments the revision, wakes observation,
and merges only fresh trusted attachment fields.

It must not create a second watcher for the same process. A weaker fresh target
never downgrades a richer target, and contradictory attachments are rejected
rather than merged.

### Audit visibility

Append bounded audit records for registration added/existing/promoted,
lifecycle transitions, wait scheduling, observation-source changes, action
authorization, dispatch, ambiguous outcomes, verification, human hand-off,
stop, and target termination. Do not log rollout content, goal text, prompts,
environment values, socket payloads, credentials, or terminal captures.

`watchme logs [ID] --follow` remains the tail command. A user should be able to
see that a capacity event was classified, why WatchMe waited, whether it
submitted `/goal resume`, and how verification ended without exposing private
session content.

## Error Handling and Compatibility

- Linux receives automatic Codex state correlation when exact open-file proof
  exists.
- macOS remains supported for registration and native Herdr control, but Codex
  goal recovery requires explicit exact state correlation until a safe native
  process-file proof is available.
- The existing `watchme.herdr` bridge remains supported.
- Native Herdr protocol drift does not fall through to unsafe best-effort
  parsing.
- Existing watcher state without new optional bindings remains readable and
  observation-only.
- Corrupt or incompatible Codex databases, rollouts, or watcher state never
  authorize an action.
- No secrets, prompts, terminal content, generated binaries, or machine paths
  are committed.

## TDD and Acceptance Tests

Implementation proceeds in red-green-refactor slices. Required tests include:

1. Native Herdr protocol-16 request/response fixtures for each supported method,
   matching IDs, exact result variants, protocol errors, deadlines, socket
   replacement, and peer-credential failure.
2. Registration against a schema-faithful native Herdr fake validates pane,
   process, TTY, and server identity and no longer falls back when all evidence
   agrees.
3. Exact Codex attachment tests cover Herdr session ID, `codex resume THREAD`,
   disagreement, missing proof, multiple open rollouts, file replacement,
   unsafe ownership, schema drift, and no-newest-file behavior.
4. A realistic append-only rollout larger than the old 1 MiB limit is read by
   bounded tail/cursor logic; growth preserves identity while rotation,
   truncation, partial lines, oversized records, and stale capacity results fail
   closed.
5. Read-only SQLite fixtures prove exact thread/CWD goal lookup and classify
   blocked capacity separately from active, complete, usage-limited,
   budget-limited, approval, auth, billing, safety, and unknown states.
6. Existing process-only registration is promoted in place with one watcher,
   fresh attachments, incremented revision, and an immediate observation wake.
7. Recovery integration proves wait, revalidation, one atomic native
   `pane.send_input` containing `/goal resume` plus `Enter`, no duplicate send,
   post-resume active verification, and human hand-off after ambiguous send.
8. Audit tests prove lifecycle records appear without private payloads.
9. Focused-pane tests prove `screen_detection_skipped`, missing status, and
   stale status neither authorize recovery nor mask valid structured Codex
   evidence.
10. CLI end-to-end coverage starts a fake Codex process, native Herdr socket,
   SQLite state, and rollout; bare `watchme` registers/promotes, observes a
   capacity block, submits once, and reports verified recovery.
11. Existing bridge, tmux, Claude, process-only fallback, daemon lifecycle,
    release build, schema, and install smoke gates remain green.

## Live Verification

After all local gates pass:

1. Commit and run `just install` locally.
2. Copy the release binary to `x-left` through `xsm`, verify the SHA-256 hash,
   and restart only the WatchMe daemon so it loads the updated observer and
   registry behavior.
3. Run bare `watchme` in the existing x-left Codex session and confirm the old
   process watcher is promoted rather than duplicated.
4. Confirm status identifies native Herdr and the exact Codex thread without
   exposing content.
5. Tail `watchme logs WATCHER_ID --follow` and verify useful lifecycle records.
6. Exercise a controlled fixture/fake capacity transition on x-left. A real
   provider capacity event may also be observed if it occurs naturally, but
   completion does not depend on forcing or manufacturing provider failure.

No push, tag, GitHub release, or publication is part of this work.
