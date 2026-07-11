#!/usr/bin/env bash
# Repeatable idle-resource benchmark for WatchMe daemon.
# Measures RSS, CPU, wakeups/syscalls (when available), subprocess count, and
# bytes read. Does not invent pass/fail thresholds.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DURATION_SECS="${WATCHME_BENCH_DURATION:-35}"
POLL_SECS="${WATCHME_BENCH_POLL:-15}"
WATCHERS="${WATCHME_BENCH_WATCHERS:-0}"
OUT_DIR="${WATCHME_BENCH_OUT:-${REPO_ROOT}/target/benchmark}"
BINARY="${WATCHME_BENCH_BIN:-}"

usage() {
  cat <<EOF
Usage: benchmark-idle.sh [--watchers N] [--duration SECS] [--poll SECS] [--bin PATH]

Environment overrides: WATCHME_BENCH_WATCHERS, WATCHME_BENCH_DURATION,
WATCHME_BENCH_POLL, WATCHME_BENCH_BIN, WATCHME_BENCH_OUT.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --watchers) WATCHERS="$2"; shift 2 ;;
    --duration) DURATION_SECS="$2"; shift 2 ;;
    --poll) POLL_SECS="$2"; shift 2 ;;
    --bin) BINARY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "${OUT_DIR}"
if [[ -z "${BINARY}" ]]; then
  (cd "${REPO_ROOT}" && cargo build --release -j1 --locked)
  BINARY="${REPO_ROOT}/target/release/watchme"
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/watchme-bench.XXXXXX")"
cleanup() {
  if [[ -n "${DAEMON_PID:-}" ]] && kill -0 "${DAEMON_PID}" 2>/dev/null; then
    kill "${DAEMON_PID}" 2>/dev/null || true
    wait "${DAEMON_PID}" 2>/dev/null || true
  fi
  if [[ -n "${TMUX_SOCKET:-}" ]]; then
    tmux -L "${TMUX_SOCKET}" kill-server 2>/dev/null || true
  fi
  # Leave workdir for inspection when WATCHME_BENCH_KEEP=1
  if [[ "${WATCHME_BENCH_KEEP:-0}" != "1" ]]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT

HOME_DIR="${WORKDIR}/home"
CONFIG_HOME="${WORKDIR}/config"
STATE_HOME="${WORKDIR}/state"
RUNTIME_DIR="${WORKDIR}/run"
mkdir -p "${HOME_DIR}" "${CONFIG_HOME}/watchme" "${STATE_HOME}/watchme" "${RUNTIME_DIR}"
chmod 700 "${CONFIG_HOME}/watchme" "${STATE_HOME}/watchme" "${RUNTIME_DIR}"

cat > "${CONFIG_HOME}/watchme/config.toml" <<EOF
config_version = 1

[daemon]
idle_grace_seconds = 300
stay_resident = true
max_watchers = 128

[observation]
poll_interval_seconds = ${POLL_SECS}
poll_jitter_seconds = 0
EOF

export HOME="${HOME_DIR}"
export XDG_CONFIG_HOME="${CONFIG_HOME}"
export XDG_STATE_HOME="${STATE_HOME}"
export XDG_RUNTIME_DIR="${RUNTIME_DIR}"

SOCKET="${RUNTIME_DIR}/watchme/daemon.sock"
"${BINARY}" daemon run >"${WORKDIR}/daemon.out" 2>"${WORKDIR}/daemon.err" &
DAEMON_PID=$!

for _ in $(seq 1 80); do
  if [[ -S "${SOCKET}" ]]; then
    break
  fi
  sleep 0.05
done
if [[ ! -S "${SOCKET}" ]]; then
  echo "daemon socket did not appear" >&2
  cat "${WORKDIR}/daemon.err" >&2 || true
  exit 1
fi

TARGET_PIDS=()
if [[ "${WATCHERS}" -gt 0 ]]; then
  if ! command -v tmux >/dev/null 2>&1; then
    echo "tmux required for watcher benchmarks" >&2
    exit 1
  fi
  TMUX_SOCKET="watchme-bench-$$"
  tmux -f /dev/null -L "${TMUX_SOCKET}" new-session -d -s bench "sleep 3600"
  for i in $(seq 1 "${WATCHERS}"); do
    if [[ "${i}" -gt 1 ]]; then
      tmux -L "${TMUX_SOCKET}" new-window -d -t bench "sleep 3600"
    fi
  done
  # Register process-identity watchers against the sleep panes' PIDs.
  python3 - "${SOCKET}" "${TMUX_SOCKET}" "${WATCHERS}" <<'PY'
import os, socket, struct, sys, json, subprocess, time

sock_path, tmux_sock, n = sys.argv[1], sys.argv[2], int(sys.argv[3])

def pane_pids():
    out = subprocess.check_output(
        ["tmux", "-L", tmux_sock, "list-panes", "-a", "-F", "#{pane_pid}"],
        text=True,
    )
    return [int(x) for x in out.splitlines() if x.strip()]

def start_time(pid: int) -> int:
    # Linux: field 22 of /proc/pid/stat is starttime in clock ticks.
    with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as fh:
        data = fh.read()
    # Executable name may contain spaces/parentheses; split after last ')'.
    rest = data[data.rfind(")") + 2 :].split()
    return int(rest[19])

def send(req: dict):
    payload = json.dumps({"version": 1, **req}).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        s.connect(sock_path)
        s.sendall(struct.pack(">I", len(payload)) + payload)
        hdr = s.recv(4)
        (length,) = struct.unpack(">I", hdr)
        body = b""
        while len(body) < length:
            chunk = s.recv(length - len(body))
            if not chunk:
                break
            body += chunk
    return json.loads(body.decode())

pids = pane_pids()
if len(pids) < n:
    raise SystemExit(f"expected {n} panes, got {pids}")
for idx, pid in enumerate(pids[:n]):
    watcher = {
        "schema_version": 1,
        "watcher_id": f"bench-{idx}",
        "target": {
            "kind": "process",
            "schema_version": 2,
            "process": {
                "schema_version": 1,
                "pid": pid,
                "start_time": start_time(pid),
                "executable": None,
                "argv_digest": None,
                "uid": None,
                "process_group_id": None,
                "session_leader_id": None,
                "tty": None,
                "parent_digest": None,
            },
        },
        "lifecycle": {"state": "registered"},
        "revision": 0,
        "updated_at_unix_ms": int(time.time() * 1000),
    }
    resp = send({"type": "register", "watcher": watcher})
    if resp.get("type") != "registered":
        raise SystemExit(f"register failed: {resp}")
print("registered", n)
PY
fi

SAMPLE_LOG="${OUT_DIR}/idle-${WATCHERS}w-samples.tsv"
RESULT_JSON="${OUT_DIR}/idle-${WATCHERS}w-result.json"
{
  echo -e "ts_ms\trss_kb\tutime_ticks\tstime_ticks\tthreads\tchildren\tread_bytes\tvoluntary_ctxt\tnonvoluntary_ctxt"
} > "${SAMPLE_LOG}"

python3 - "${DAEMON_PID}" "${DURATION_SECS}" "${SAMPLE_LOG}" "${RESULT_JSON}" "${WATCHERS}" "${POLL_SECS}" <<'PY'
import json, os, sys, time

pid = int(sys.argv[1])
duration = float(sys.argv[2])
sample_log = sys.argv[3]
result_path = sys.argv[4]
watchers = int(sys.argv[5])
poll = int(sys.argv[6])

def read_status(pid):
    data = {}
    with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
        for line in fh:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip()
    rss = int(data.get("VmRSS", "0").split()[0])
    threads = int(data.get("Threads", "0").split()[0])
    return rss, threads

def read_stat(pid):
    with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
        raw = fh.read()
    rest = raw[raw.rfind(")") + 2 :].split()
    utime = int(rest[11])
    stime = int(rest[12])
    return utime, stime

def read_io(pid):
    path = f"/proc/{pid}/io"
    if not os.path.exists(path):
        return None
    values = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            values[k.strip()] = int(v.strip())
    return values.get("read_bytes")

def read_ctxt(pid):
    vol = nonvol = None
    with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("voluntary_ctxt_switches:"):
                vol = int(line.split(":")[1])
            elif line.startswith("nonvoluntary_ctxt_switches:"):
                nonvol = int(line.split(":")[1])
    return vol, nonvol

def child_count(pid):
    # Direct children only.
    count = 0
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", encoding="utf-8") as fh:
                raw = fh.read()
            rest = raw[raw.rfind(")") + 2 :].split()
            ppid = int(rest[1])
            if ppid == pid:
                count += 1
        except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError, ValueError):
            continue
    return count

# Optional syscall counter via /proc/<pid>/syscall is not cumulative; use
# context switches as a wakeup proxy when available.
start = time.time()
samples = []
first = None
last = None
with open(sample_log, "a", encoding="utf-8") as out:
    while time.time() - start < duration:
        now_ms = int(time.time() * 1000)
        rss, threads = read_status(pid)
        utime, stime = read_stat(pid)
        read_bytes = read_io(pid)
        vol, nonvol = read_ctxt(pid)
        children = child_count(pid)
        row = {
            "ts_ms": now_ms,
            "rss_kb": rss,
            "utime_ticks": utime,
            "stime_ticks": stime,
            "threads": threads,
            "children": children,
            "read_bytes": read_bytes,
            "voluntary_ctxt": vol,
            "nonvoluntary_ctxt": nonvol,
        }
        samples.append(row)
        if first is None:
            first = row
        last = row
        out.write(
            f"{now_ms}\t{rss}\t{utime}\t{stime}\t{threads}\t{children}\t"
            f"{'' if read_bytes is None else read_bytes}\t"
            f"{'' if vol is None else vol}\t"
            f"{'' if nonvol is None else nonvol}\n"
        )
        out.flush()
        time.sleep(1.0)

clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
elapsed = (last["ts_ms"] - first["ts_ms"]) / 1000.0 if first and last else duration
cpu_ticks = (last["utime_ticks"] + last["stime_ticks"]) - (first["utime_ticks"] + first["stime_ticks"])
cpu_seconds = cpu_ticks / float(clk_tck)
cpu_pct = (cpu_seconds / elapsed * 100.0) if elapsed > 0 else 0.0
rss_values = [s["rss_kb"] for s in samples]
read_delta = None
if first["read_bytes"] is not None and last["read_bytes"] is not None:
    read_delta = last["read_bytes"] - first["read_bytes"]
vol_delta = None
if first["voluntary_ctxt"] is not None and last["voluntary_ctxt"] is not None:
    vol_delta = last["voluntary_ctxt"] - first["voluntary_ctxt"]
nonvol_delta = None
if first["nonvoluntary_ctxt"] is not None and last["nonvoluntary_ctxt"] is not None:
    nonvol_delta = last["nonvoluntary_ctxt"] - first["nonvoluntary_ctxt"]

result = {
    "tool": "scripts/benchmark-idle.sh",
    "host": os.uname().sysname + " " + os.uname().release,
    "machine": os.uname().machine,
    "watchers": watchers,
    "poll_interval_seconds": poll,
    "duration_seconds": elapsed,
    "clk_tck": clk_tck,
    "rss_kb": {
        "min": min(rss_values) if rss_values else None,
        "max": max(rss_values) if rss_values else None,
        "last": rss_values[-1] if rss_values else None,
    },
    "cpu_seconds": round(cpu_seconds, 6),
    "cpu_percent_of_wall": round(cpu_pct, 4),
    "subprocess_children_last": last["children"] if last else None,
    "threads_last": last["threads"] if last else None,
    "read_bytes_delta": read_delta,
    "voluntary_ctxt_switches_delta": vol_delta,
    "nonvoluntary_ctxt_switches_delta": nonvol_delta,
    "wakeup_proxy": "voluntary+nonvoluntary context switches from /proc/<pid>/status",
    "syscalls": "not directly available without elevated tracing; skipped",
    "notes": [
        "Idle measurement with stay_resident=true and configured poll interval.",
        "No pass/fail threshold is asserted; results are observational baselines.",
    ],
}
with open(result_path, "w", encoding="utf-8") as fh:
    json.dump(result, fh, indent=2)
    fh.write("\n")
print(json.dumps(result, indent=2))
PY

echo "wrote ${RESULT_JSON}"
echo "samples ${SAMPLE_LOG}"
