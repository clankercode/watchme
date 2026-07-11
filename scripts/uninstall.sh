#!/usr/bin/env bash
# Remove WatchMe-owned install artifacts; preserve unrelated files and XDG state.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: uninstall.sh [options]

Options:
  --prefix DIR          Installation prefix (default: ~/.local)
  --bin-dir DIR         Binary directory (default: PREFIX/bin)
  --purge-state         Also remove XDG config/state/runtime watchme directories
  --dry-run             Print planned removals without deleting files
  -h, --help            Show this help

Only WatchMe-owned paths under the prefix are removed. Unrelated files in the
same prefix (and user agent configs) are preserved unless --purge-state is set.
Reports every changed (or would-change) path on stdout.
EOF
}

PREFIX="${HOME}/.local"
BIN_DIR=""
PURGE_STATE=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --purge-state) PURGE_STATE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "${BIN_DIR}" ]]; then
  BIN_DIR="${PREFIX}/bin"
fi

report() {
  local path="$1"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf 'DRY-RUN would remove %s\n' "${path}"
  else
    printf 'changed: %s (removed)\n' "${path}"
  fi
}

remove_path() {
  local path="$1"
  if [[ ! -e "${path}" && ! -L "${path}" ]]; then
    return 0
  fi
  report "${path}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 0
  fi
  rm -f "${path}"
}

remove_dir_if_empty() {
  local path="$1"
  if [[ ! -d "${path}" ]]; then
    return 0
  fi
  if [[ -n "$(find "${path}" -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)" ]]; then
    return 0
  fi
  report "${path}"
  if [[ "${DRY_RUN}" -eq 0 ]]; then
    rmdir "${path}" 2>/dev/null || true
  fi
}

# Binary + alias
remove_path "${BIN_DIR}/WatchMe"
remove_path "${BIN_DIR}/watchme"

# Optional packaging helpers installed by install.sh
remove_path "${PREFIX}/lib/systemd/user/watchme.service"
remove_path "${PREFIX}/share/watchme/launchd/com.clankercode.watchme.plist"
remove_path "${PREFIX}/share/watchme/herdr/watchme-action.example.toml"
remove_path "${PREFIX}/share/bash-completion/completions/watchme"
remove_path "${PREFIX}/share/man/man1/watchme.1"

# Best-effort cleanup of empty WatchMe-owned dirs only.
remove_dir_if_empty "${PREFIX}/share/watchme/launchd"
remove_dir_if_empty "${PREFIX}/share/watchme/herdr"
remove_dir_if_empty "${PREFIX}/share/watchme"
remove_dir_if_empty "${PREFIX}/lib/systemd/user"
remove_dir_if_empty "${PREFIX}/lib/systemd"
remove_dir_if_empty "${PREFIX}/share/bash-completion/completions"
remove_dir_if_empty "${PREFIX}/share/man/man1"

if [[ "${PURGE_STATE}" -eq 1 ]]; then
  CONFIG_HOME="${XDG_CONFIG_HOME:-${HOME}/.config}"
  STATE_HOME="${XDG_STATE_HOME:-${HOME}/.local/state}"
  RUNTIME_HOME="${XDG_RUNTIME_DIR:-/tmp/watchme-$(id -u)}"
  for path in \
    "${CONFIG_HOME}/watchme" \
    "${STATE_HOME}/watchme" \
    "${RUNTIME_HOME}/watchme"
  do
    if [[ -e "${path}" ]]; then
      report "${path}"
      if [[ "${DRY_RUN}" -eq 0 ]]; then
        rm -rf "${path}"
      fi
    fi
  done
fi

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "DRY-RUN complete; no files removed under ${PREFIX}"
else
  echo "uninstalled WatchMe-owned files from ${PREFIX}"
fi
