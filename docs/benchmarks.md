# Idle benchmarks

Repeatable script: `scripts/benchmark-idle.sh`.

Measurements are observational baselines. **No pass/fail thresholds are invented.**

## How to run

```bash
just bench
# or:
./scripts/benchmark-idle.sh --watchers 0 --duration 35 --poll 15
./scripts/benchmark-idle.sh --watchers 1 --duration 35 --poll 15
./scripts/benchmark-idle.sh --watchers 10 --duration 35 --poll 15
```

JSON results land in `target/benchmark/idle-<N>w-result.json` (gitignored via `target/`).

## Environment under test

| Field | Value |
|---|---|
| Date | 2026-07-12 |
| Host | `x-game` |
| OS | Linux 7.0.10-arch1-1 |
| Arch | x86_64 |
| Binary | `target/release/watchme` (0.1.0) |
| Config | `stay_resident=true`, `poll_interval_seconds=15`, jitter 0 |
| Duration | ~34.4–34.5s wall per scenario (requested 35s) |
| `CLK_TCK` | 100 |
| Metrics source | `/proc/<pid>/{status,stat,io}` |
| Watcher targets | tmux `sleep 3600` panes registered as process identities |

Wakeups use voluntary + nonvoluntary context-switch deltas as a proxy. Direct syscall counts require elevated tracing (`perf`/`bpf`) and are recorded as unavailable.

## Results

Raw JSON: `target/benchmark/idle-{0,1,10}w-result.json` from the 2026-07-12 gate run.

### Zero watchers (idle resident daemon)

| Metric | Value |
|---|---|
| RSS min/max/last (KiB) | 17264 / 17264 / 17264 |
| CPU seconds | 0.0 |
| CPU % of wall | 0.0 |
| Read bytes Δ | 0 |
| Voluntary ctxt Δ | 117 |
| Nonvoluntary ctxt Δ | 0 |
| Child subprocesses (last) | 0 |
| Threads (last) | 1 |
| Wall seconds | 34.388 |

### One watcher (tmux sleep pane, process identity)

| Metric | Value |
|---|---|
| RSS min/max/last (KiB) | 17548 / 19200 / 19200 |
| CPU seconds | 0.0 |
| CPU % of wall | 0.0 |
| Read bytes Δ | 0 |
| Voluntary ctxt Δ | 119 |
| Nonvoluntary ctxt Δ | 0 |
| Child subprocesses (last) | 0 |
| Threads (last) | 1 |
| Wall seconds | 34.455 |

### Ten watchers

| Metric | Value |
|---|---|
| RSS min/max/last (KiB) | 17484 / 20328 / 20328 |
| CPU seconds | 0.01 |
| CPU % of wall | 0.029 |
| Read bytes Δ | 0 |
| Voluntary ctxt Δ | 154 |
| Nonvoluntary ctxt Δ | 3 |
| Child subprocesses (last) | 0 |
| Threads (last) | 1 |
| Wall seconds | 34.497 |

## Notes

- Default product poll interval remains 60s; these runs used 15s so at least one observation cycle fits in ~35s wall time.
- CPU seconds of `0.0` at `CLK_TCK=100` means less than one tick of user+system time accumulated across the sample window (honest under-resolution, not a claim of zero work).
- Subprocess count is direct children of the daemon PID only (tmux `sleep` targets are not daemon children).
- Syscalls: skipped (no elevated tracing). Wakeup proxy = context-switch deltas.
- Regression budgets should be derived later from these baselines, not invented up front.
