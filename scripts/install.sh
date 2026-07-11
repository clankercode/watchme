#!/usr/bin/env bash
# Install watchme plus the uppercase WatchMe alias into an isolated or user prefix.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Options:
  --prefix DIR          Installation prefix (default: ~/.local)
  --bin-dir DIR         Binary directory (default: PREFIX/bin)
  --from PATH           Install this prebuilt watchme binary (skip cargo build)
  --build               Build release binary with cargo before install
  --with-systemd        Install systemd user unit under PREFIX/lib/systemd/user
  --with-launchd        Install launchd plist under PREFIX/share/watchme/launchd
  --with-herdr-action   Install optional Herdr bridge example under PREFIX/share/watchme/herdr
  --with-completions    Install bash completion under PREFIX/share/bash-completion/completions
  --with-man            Install man page under PREFIX/share/man/man1
  --dry-run             Print planned changes without writing files
  -h, --help            Show this help

Reports every changed (or would-change) path on stdout.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PREFIX="${HOME}/.local"
BIN_DIR=""
FROM_BIN=""
DO_BUILD=0
WITH_SYSTEMD=0
WITH_LAUNCHD=0
WITH_HERDR=0
WITH_COMPLETIONS=0
WITH_MAN=0
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --from) FROM_BIN="$2"; shift 2 ;;
    --build) DO_BUILD=1; shift ;;
    --with-systemd) WITH_SYSTEMD=1; shift ;;
    --with-launchd) WITH_LAUNCHD=1; shift ;;
    --with-herdr-action) WITH_HERDR=1; shift ;;
    --with-completions) WITH_COMPLETIONS=1; shift ;;
    --with-man) WITH_MAN=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "${BIN_DIR}" ]]; then
  BIN_DIR="${PREFIX}/bin"
fi

if [[ -z "${FROM_BIN}" ]]; then
  if [[ "${DO_BUILD}" -eq 1 ]]; then
    (cd "${REPO_ROOT}" && cargo build --release -j1 --locked)
    FROM_BIN="${REPO_ROOT}/target/release/watchme"
  elif [[ -x "${REPO_ROOT}/target/release/watchme" ]]; then
    FROM_BIN="${REPO_ROOT}/target/release/watchme"
  elif [[ -x "${REPO_ROOT}/target/debug/watchme" ]]; then
    FROM_BIN="${REPO_ROOT}/target/debug/watchme"
  else
    echo "no watchme binary found; pass --from PATH or --build" >&2
    exit 1
  fi
fi

if [[ ! -f "${FROM_BIN}" ]]; then
  echo "binary not found: ${FROM_BIN}" >&2
  exit 1
fi

report() {
  local action="$1"
  local path="$2"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    printf 'DRY-RUN would %s %s\n' "${action}" "${path}"
  else
    printf 'changed: %s (%s)\n' "${path}" "${action}"
  fi
}

install_file() {
  local src="$1"
  local dest="$2"
  local mode="${3:-0644}"
  report "install" "${dest}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 0
  fi
  mkdir -p "$(dirname "${dest}")"
  install -m "${mode}" "${src}" "${dest}"
}

install_link() {
  local target="$1"
  local dest="$2"
  report "symlink" "${dest} -> ${target}"
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    return 0
  fi
  mkdir -p "$(dirname "${dest}")"
  ln -sfn "${target}" "${dest}"
}

DEST_BIN="${BIN_DIR}/watchme"
DEST_ALIAS="${BIN_DIR}/WatchMe"

install_file "${FROM_BIN}" "${DEST_BIN}" 0755
install_link "watchme" "${DEST_ALIAS}"

if [[ "${WITH_SYSTEMD}" -eq 1 ]]; then
  install_file \
    "${REPO_ROOT}/packaging/systemd/watchme.service" \
    "${PREFIX}/lib/systemd/user/watchme.service" \
    0644
fi

if [[ "${WITH_LAUNCHD}" -eq 1 ]]; then
  install_file \
    "${REPO_ROOT}/packaging/launchd/com.clankercode.watchme.plist" \
    "${PREFIX}/share/watchme/launchd/com.clankercode.watchme.plist" \
    0644
fi

if [[ "${WITH_HERDR}" -eq 1 ]]; then
  install_file \
    "${REPO_ROOT}/packaging/herdr/watchme-action.example.toml" \
    "${PREFIX}/share/watchme/herdr/watchme-action.example.toml" \
    0644
fi

if [[ "${WITH_COMPLETIONS}" -eq 1 ]]; then
  install_file \
    "${REPO_ROOT}/packaging/completions/watchme.bash" \
    "${PREFIX}/share/bash-completion/completions/watchme" \
    0644
fi

if [[ "${WITH_MAN}" -eq 1 ]]; then
  install_file \
    "${REPO_ROOT}/packaging/man/watchme.1" \
    "${PREFIX}/share/man/man1/watchme.1" \
    0644
fi

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "DRY-RUN complete; no files written under ${PREFIX}"
else
  echo "installed watchme to ${DEST_BIN} (alias ${DEST_ALIAS})"
fi
