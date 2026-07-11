#!/usr/bin/env bash
set -euo pipefail

current_tag="${1:-$(git describe --tags --exact-match 2>/dev/null)}"
if [[ ! "$current_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  printf 'error: expected a SemVer tag, got %q\n' "$current_tag" >&2
  exit 1
fi

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
  printf '# WatchMe %s\n\nChanges since %s:\n\n' "$current_tag" "$previous_tag"
else
  range="$current_tag"
  printf '# WatchMe %s\n\nComplete changelog:\n\n' "$current_tag"
fi

git log "$range" --no-merges --pretty='- %s ([`%h`](../../commit/%H))'

cat <<'EOF'

## Installation

Download the archive for your platform, verify it with `SHA256SUMS`, extract
it, and place `watchme` and its `WatchMe` alias on your `PATH`.

## Compatibility

Supported release platforms are Linux and macOS on x86_64 and aarch64.

## Checksums and artifacts

Verify an archive with `sha256sum -c SHA256SUMS` (Linux) or
`shasum -a 256 -c SHA256SUMS` (macOS).

## Known limitations

See the compatibility documentation in the repository. Windows is not
supported.
EOF
