#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

is_semver_tag() {
  local tag="$1" core prerelease identifier
  local -a identifiers=()
  local pattern='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
  [[ "$tag" =~ $pattern ]] || return 1
  core="${tag#v}"
  core="${core%%+*}"
  prerelease=""
  if [[ "$core" == *-* ]]; then
    prerelease="${core#*-}"
  fi
  IFS=. read -r -a identifiers <<<"$prerelease"
  for identifier in "${identifiers[@]}"; do
    if [[ "$identifier" =~ ^[0-9]+$ && ${#identifier} -gt 1 && "$identifier" == 0* ]]; then
      return 1
    fi
  done
}

numeric_compare() {
  local left="$1" right="$2"
  if ((${#left} < ${#right})); then printf '%s\n' -1
  elif ((${#left} > ${#right})); then printf '%s\n' 1
  elif [[ "$left" < "$right" ]]; then printf '%s\n' -1
  elif [[ "$left" > "$right" ]]; then printf '%s\n' 1
  else printf '%s\n' 0
  fi
}

semver_compare() {
  local left="${1#v}" right="${2#v}" index comparison
  local -a left_parts=() right_parts=()
  local left_base="${left%%+*}" right_base="${right%%+*}"
  local left_core="${left_base%%-*}" right_core="${right_base%%-*}"
  local left_pre="" right_pre=""
  [[ "$left_base" == *-* ]] && left_pre="${left_base#*-}"
  [[ "$right_base" == *-* ]] && right_pre="${right_base#*-}"
  IFS=. read -r -a left_parts <<<"$left_core"
  IFS=. read -r -a right_parts <<<"$right_core"
  for index in 0 1 2; do
    comparison="$(numeric_compare "${left_parts[index]}" "${right_parts[index]}")"
    [[ "$comparison" != 0 ]] && { printf '%s\n' "$comparison"; return; }
  done
  [[ -z "$left_pre" && -z "$right_pre" ]] && { printf '0\n'; return; }
  [[ -z "$left_pre" ]] && { printf '1\n'; return; }
  [[ -z "$right_pre" ]] && { printf '%s\n' -1; return; }
  IFS=. read -r -a left_parts <<<"$left_pre"
  IFS=. read -r -a right_parts <<<"$right_pre"
  for ((index = 0; index < ${#left_parts[@]} || index < ${#right_parts[@]}; index++)); do
    ((index >= ${#left_parts[@]})) && { printf '%s\n' -1; return; }
    ((index >= ${#right_parts[@]})) && { printf '1\n'; return; }
    if [[ "${left_parts[index]}" =~ ^[0-9]+$ && "${right_parts[index]}" =~ ^[0-9]+$ ]]; then
      comparison="$(numeric_compare "${left_parts[index]}" "${right_parts[index]}")"
    elif [[ "${left_parts[index]}" =~ ^[0-9]+$ ]]; then comparison=-1
    elif [[ "${right_parts[index]}" =~ ^[0-9]+$ ]]; then comparison=1
    elif [[ "${left_parts[index]}" < "${right_parts[index]}" ]]; then comparison=-1
    elif [[ "${left_parts[index]}" > "${right_parts[index]}" ]]; then comparison=1
    else comparison=0
    fi
    [[ "$comparison" != 0 ]] && { printf '%s\n' "$comparison"; return; }
  done
  printf '0\n'
}

sanitize_subject() {
  LC_ALL=C.UTF-8 perl -CS -pe '
    s/[\x{0000}-\x{001F}\x{007F}-\x{009F}\x{061C}\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}]//g;
    s/([\\`*_{}\[\]<>\(\)#+.!|~\-:\@])/\\$1/g;
  '
}

if [[ "${1:-}" == --validate-tag ]]; then
  is_semver_tag "${2:-}" || { printf 'error: invalid SemVer 2.0.0 tag: %s\n' "${2:-}" >&2; exit 1; }
  exit 0
fi

current_tag="${1:-$(git describe --tags --exact-match 2>/dev/null)}"
is_semver_tag "$current_tag" || { printf 'error: invalid SemVer 2.0.0 tag: %s\n' "$current_tag" >&2; exit 1; }
git rev-parse --verify --quiet "${current_tag}^{commit}" >/dev/null || { printf 'error: unresolved tag: %s\n' "$current_tag" >&2; exit 1; }

previous_tag=""
# Select the highest strictly lower SemVer-precedence ancestor. Prereleases
# participate normally; build metadata is intentionally precedence-neutral.
while IFS= read -r candidate; do
  is_semver_tag "$candidate" || continue
  [[ "$(semver_compare "$candidate" "$current_tag")" == -1 ]] || continue
  if [[ -z "$previous_tag" || "$(semver_compare "$candidate" "$previous_tag")" == 1 ]]; then
    previous_tag="$candidate"
  fi
done < <(git tag --merged "${current_tag}^{commit}")

if [[ -n "$previous_tag" ]]; then range="${previous_tag}..${current_tag}"; comparison="since ${previous_tag}"
else range="$current_tag"; comparison="across the complete project history"
fi

declare -a breaking=() features=() fixes=() documentation=() other=()
breaking_pattern='^[a-zA-Z]+(\([^)]*\))?!:'
feature_pattern='^feat(\([^)]*\))?:'
fix_pattern='^fix(\([^)]*\))?:'
docs_pattern='^docs?(\([^)]*\))?:'
while IFS= read -r commit; do
  raw_subject="$(git show -s --format=%s "$commit")"
  body="$(git show -s --format=%B "$commit")"
  subject="$(printf '%s' "$raw_subject" | sanitize_subject)"
  entry="- ${subject} ([${commit:0:7}](../../commit/${commit}))"
  if [[ "$raw_subject" =~ $breaking_pattern ]] || grep -q '^BREAKING[ -]CHANGE:' <<<"$body"; then breaking+=("$entry")
  elif [[ "$raw_subject" =~ $feature_pattern ]]; then features+=("$entry")
  elif [[ "$raw_subject" =~ $fix_pattern ]]; then fixes+=("$entry")
  elif [[ "$raw_subject" =~ $docs_pattern ]]; then documentation+=("$entry")
  else other+=("$entry")
  fi
done < <(git log "$range" --no-merges --format=%H)

print_group() { local title="$1"; shift; printf '### %s\n\n' "$title"; if (($#)); then printf '%s\n' "$@"; else printf 'None.\n'; fi; printf '\n'; }
count=$((${#breaking[@]} + ${#features[@]} + ${#fixes[@]} + ${#documentation[@]} + ${#other[@]}))
cat <<EOF
# WatchMe ${current_tag}

## Summary

WatchMe ${current_tag} contains ${count} non-merge changes ${comparison}. It supports Linux and macOS coding-agent sessions.

## Changes ${comparison^}

EOF
print_group 'Breaking changes' "${breaking[@]}"; print_group 'Features' "${features[@]}"; print_group 'Fixes' "${fixes[@]}"; print_group 'Documentation' "${documentation[@]}"; print_group 'Other changes' "${other[@]}"
cat <<EOF
## Installation and upgrade

Download and verify the matching archive. Extract it and copy \`watchme\` to a directory on \`PATH\`. Keep the included \`WatchMe\` symbolic-link alias beside it if used. To upgrade, replace both existing entries.

## Artifacts

- \`watchme-${current_tag}-x86_64-unknown-linux-gnu.tar.gz\`
- \`watchme-${current_tag}-aarch64-unknown-linux-gnu.tar.gz\`
- \`watchme-${current_tag}-x86_64-apple-darwin.tar.gz\`
- \`watchme-${current_tag}-aarch64-apple-darwin.tar.gz\`
- \`SHA256SUMS\`

## Checksums and verification

Run \`sha256sum --check SHA256SUMS\` on Linux or \`shasum -a 256 -c SHA256SUMS\` on macOS. CI runs formatting and Clippy once, then tests and release-builds all four native targets. Release automation validates tag/version equality, smoke-tests binaries, checks archive contents, and verifies local and downloaded checksums before publication.

## Compatibility and support

Linux and macOS x86_64/aarch64 are supported. Windows is unsupported. See \`docs/compatibility.md\` for provider details.

## Known limitations

- Windows is not supported.
- Herdr uses WatchMe's local bridge contract because an upstream Herdr API was unavailable for v1 verification.
EOF
