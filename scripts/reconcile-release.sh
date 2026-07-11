#!/usr/bin/env bash
set -euo pipefail

tag="${1:?usage: reconcile-release.sh TAG DIST NOTES_FILE}"
dist="${2:?usage: reconcile-release.sh TAG DIST NOTES_FILE}"
notes_file="${3:?usage: reconcile-release.sh TAG DIST NOTES_FILE}"
title="WatchMe ${tag}"

scripts/release-notes.sh --validate-tag "$tag"
test -f "$notes_file"

version="${tag#v}"
version="${version%%+*}"
if [[ "$version" == *-* ]]; then
  expected_prerelease=true
  prerelease_flag=(--prerelease)
  latest_flag=(--latest=false)
else
  expected_prerelease=false
  prerelease_flag=(--prerelease=false)
  latest_flag=(--latest)
fi

expected_assets=(
  "watchme-${tag}-x86_64-unknown-linux-gnu.tar.gz"
  "watchme-${tag}-aarch64-unknown-linux-gnu.tar.gz"
  "watchme-${tag}-x86_64-apple-darwin.tar.gz"
  "watchme-${tag}-aarch64-apple-darwin.tar.gz"
  SHA256SUMS
)
for asset in "${expected_assets[@]}"; do
  test -f "${dist}/${asset}"
done

release_json() {
  gh release view "$tag" \
    --json isDraft,isImmutable,name,body,assets,isPrerelease
}

verify_release() {
  local json="$1" expected_draft="$2" verify_dir
  verify_dir="$(mktemp -d)"
  cleanup_dirs+=("$verify_dir")

  test "$(jq -r .isDraft <<<"$json")" = "$expected_draft" || return 1
  test "$(jq -r .isPrerelease <<<"$json")" = "$expected_prerelease" || return 1
  test "$(jq -r .name <<<"$json")" = "$title" || return 1
  jq -j .body <<<"$json" >"${verify_dir}/REMOTE_NOTES.md" || return 1
  cmp "$notes_file" "${verify_dir}/REMOTE_NOTES.md" || return 1

  printf '%s\n' "${expected_assets[@]}" | LC_ALL=C sort >"${verify_dir}/expected-assets" || return 1
  jq -r '.assets[].name' <<<"$json" | LC_ALL=C sort >"${verify_dir}/actual-assets" || return 1
  cmp "${verify_dir}/expected-assets" "${verify_dir}/actual-assets" || return 1

  gh release download "$tag" --dir "$verify_dir" --clobber || return 1
  cmp "${dist}/SHA256SUMS" "${verify_dir}/SHA256SUMS" || return 1
  (cd "$verify_dir" && sha256sum --check SHA256SUMS) || return 1
}

cleanup_dirs=()
cleanup() {
  local directory
  for directory in "${cleanup_dirs[@]}"; do rm -rf "$directory"; done
}
trap cleanup EXIT

if json="$(release_json 2>/dev/null)"; then
  if [[ "$(jq -r .isDraft <<<"$json")" == false ]]; then
    if verify_release "$json" false; then
      printf 'Published release %s already matches; no changes required.\n' "$tag"
      exit 0
    fi
    if [[ "$(jq -r .isImmutable <<<"$json")" == true ]]; then
      printf 'error: immutable release %s differs; publish a new corrected version tag\n' "$tag" >&2
    else
      printf 'error: published release %s differs; refusing to mutate it, publish a new corrected version tag\n' "$tag" >&2
    fi
    exit 1
  fi
  gh release edit "$tag" --draft --title "$title" \
    --notes-file "$notes_file" "${prerelease_flag[@]}"
else
  gh release create "$tag" --draft --verify-tag --title "$title" \
    --notes-file "$notes_file" "${prerelease_flag[@]}"
fi

gh release upload "$tag" \
  "${dist}"/*.tar.gz "${dist}/SHA256SUMS" --clobber
json="$(release_json)"
verify_release "$json" true

gh release edit "$tag" --draft=false --title "$title" \
  --notes-file "$notes_file" "${prerelease_flag[@]}" "${latest_flag[@]}"
json="$(release_json)"
verify_release "$json" false
