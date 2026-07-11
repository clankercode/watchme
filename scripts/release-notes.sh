#!/usr/bin/env bash
set -euo pipefail

current_tag="${1:-$(git describe --tags --exact-match 2>/dev/null)}"
if [[ ! "$current_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'error: expected a SemVer tag, got %q\n' "$current_tag" >&2
  exit 1
fi
git rev-parse --verify --quiet "${current_tag}^{commit}" >/dev/null || {
  printf 'error: tag does not resolve to a commit: %s\n' "$current_tag" >&2
  exit 1
}

previous_tag="$({
  git tag --merged "${current_tag}^{commit}" --list 'v[0-9]*' --sort=-version:refname
} | while IFS= read -r tag; do
  if [[ "$tag" != "$current_tag" ]]; then
    printf '%s\n' "$tag"
    break
  fi
done)"

if [[ -n "$previous_tag" ]]; then
  range="${previous_tag}..${current_tag}"
  comparison="since ${previous_tag}"
else
  range="$current_tag"
  comparison="across the complete project history"
fi

declare -a breaking=() features=() fixes=() documentation=() other=()
breaking_subject_pattern='^[a-zA-Z]+(\([^)]*\))?!:'
feature_subject_pattern='^feat(\([^)]*\))?:'
fix_subject_pattern='^fix(\([^)]*\))?:'
docs_subject_pattern='^docs?(\([^)]*\))?:'
while IFS= read -r commit; do
  subject="$(git show -s --format=%s "$commit")"
  body="$(git show -s --format=%B "$commit")"
  subject="${subject//&/&amp;}"
  subject="${subject//</&lt;}"
  subject="${subject//>/&gt;}"
  entry="- ${subject} ([${commit:0:7}](../../commit/${commit}))"

  if [[ "$subject" =~ $breaking_subject_pattern ]] ||
     grep -q '^BREAKING[ -]CHANGE:' <<<"$body"; then
    breaking+=("$entry")
  elif [[ "$subject" =~ $feature_subject_pattern ]]; then
    features+=("$entry")
  elif [[ "$subject" =~ $fix_subject_pattern ]]; then
    fixes+=("$entry")
  elif [[ "$subject" =~ $docs_subject_pattern ]]; then
    documentation+=("$entry")
  else
    other+=("$entry")
  fi
done < <(git log "$range" --no-merges --format=%H)

commit_count=$((${#breaking[@]} + ${#features[@]} + ${#fixes[@]} + ${#documentation[@]} + ${#other[@]}))

print_group() {
  local title="$1"
  shift
  printf '### %s\n\n' "$title"
  if (($# == 0)); then
    printf 'None.\n\n'
  else
    printf '%s\n' "$@"
    printf '\n'
  fi
}

cat <<EOF
# WatchMe ${current_tag}

## Summary

WatchMe ${current_tag} contains ${commit_count} non-merge changes ${comparison}.
It provides a local supervisor for long-running coding-agent sessions on Linux
and macOS.

## Changes ${comparison^}

EOF
print_group 'Breaking changes' "${breaking[@]}"
print_group 'Features' "${features[@]}"
print_group 'Fixes' "${fixes[@]}"
print_group 'Documentation' "${documentation[@]}"
print_group 'Other changes' "${other[@]}"

cat <<EOF
## Installation and upgrade

Download the archive matching your platform, then verify it against
\`SHA256SUMS\` before extraction. Extract the archive and copy \`watchme\` to a
directory on your \`PATH\`. The included \`WatchMe\` symbolic link is the
uppercase compatibility alias and must remain beside \`watchme\` if used.

For an upgrade, replace the existing \`watchme\` binary and \`WatchMe\` alias
with the files from the new archive.

## Artifacts

- \`watchme-${current_tag}-x86_64-unknown-linux-gnu.tar.gz\`
- \`watchme-${current_tag}-aarch64-unknown-linux-gnu.tar.gz\`
- \`watchme-${current_tag}-x86_64-apple-darwin.tar.gz\`
- \`watchme-${current_tag}-aarch64-apple-darwin.tar.gz\`
- \`SHA256SUMS\`

## Checksums and verification

On Linux, run \`sha256sum --check SHA256SUMS\`. On macOS, run
\`shasum -a 256 -c SHA256SUMS\`. The release workflow validates the Cargo
version against the tag, builds and smoke-tests each native binary, verifies
both executable names in every archive, and rechecks all generated SHA-256
checksums before publication. CI runs formatting, Clippy, tests, and a release
build on all four supported system and architecture combinations.

## Compatibility and support

Release binaries support Linux and macOS on x86_64 and aarch64. Windows is not
supported. See \`docs/compatibility.md\` for provider-specific compatibility.

## Known limitations

- Windows is not supported.
- Herdr integration follows WatchMe's local bridge contract because an
  installed upstream Herdr API was unavailable for verification during v1
  development.
EOF
