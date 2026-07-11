#!/usr/bin/env bash
set -euo pipefail

if [[ "${0##*/}" == gh ]]; then
  state="${MOCK_GH_STATE:?}"
  printf '%q ' "$@" >>"$state/log"
  printf '\n' >>"$state/log"
  shift # release
  command="$1"
  shift
  case "$command" in
    view)
      test -f "$state/exists" || exit 1
      assets="$(find "$state/assets" -maxdepth 1 -type f -printf '%f\n' | jq -Rsc 'split("\n")[:-1] | map({name: .})')"
      jq -n --argjson draft "$(<"$state/draft")" \
        --argjson immutable "$(<"$state/immutable")" \
        --argjson prerelease "$(<"$state/prerelease")" \
        --arg name "$(<"$state/name")" --rawfile body "$state/body" \
        --argjson assets "$assets" \
        '{isDraft:$draft,isImmutable:$immutable,isPrerelease:$prerelease,name:$name,body:$body,assets:$assets}'
      ;;
    list)
      jq -n --arg tag "$(<"$state/tag")" --argjson latest "$(<"$state/latest")" \
        '[{tagName:$tag,isLatest:$latest}]'
      ;;
    create|edit)
      touch "$state/exists"
      [[ "$command" == create ]] && printf true >"$state/draft"
      while (($#)); do
        case "$1" in
          --draft) printf true >"$state/draft" ;;
          --draft=false) printf false >"$state/draft" ;;
          --prerelease) printf true >"$state/prerelease" ;;
          --prerelease=false) printf false >"$state/prerelease" ;;
          --latest) printf true >"$state/latest" ;;
          --latest=false) printf false >"$state/latest" ;;
          --title) shift; printf '%s' "$1" >"$state/name" ;;
          --notes-file) shift; cp "$1" "$state/body" ;;
        esac
        shift
      done
      ;;
    upload)
      shift # tag
      while (($#)); do
        [[ "$1" == --clobber ]] || cp "$1" "$state/assets/"
        shift
      done
      ;;
    download)
      shift # tag
      destination=.
      while (($#)); do
        if [[ "$1" == --dir ]]; then shift; destination="$1"; fi
        shift
      done
      cp "$state/assets/"* "$destination/"
      ;;
    *) exit 2 ;;
  esac
  exit 0
fi

repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/dist"
ln -s "$repo/scripts/test-reconcile-release.sh" "$work/bin/gh"
export PATH="$work/bin:$PATH"

make_dist() {
  local tag="$1" target
  rm -rf "$work/dist"
  mkdir "$work/dist"
  for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-apple-darwin aarch64-apple-darwin; do
    printf '%s\n' "$target" >"$work/dist/watchme-${tag}-${target}.tar.gz"
  done
  (cd "$work/dist" && sha256sum -- *.tar.gz >SHA256SUMS)
  printf '# Notes for %s\n' "$tag" >"$work/notes.md"
}

reset_state() {
  export MOCK_GH_STATE="$work/state"
  rm -rf "$MOCK_GH_STATE"
  mkdir -p "$MOCK_GH_STATE/assets"
  : >"$MOCK_GH_STATE/log"
  printf false >"$MOCK_GH_STATE/immutable"
  printf false >"$MOCK_GH_STATE/prerelease"
  printf false >"$MOCK_GH_STATE/draft"
  printf false >"$MOCK_GH_STATE/latest"
  : >"$MOCK_GH_STATE/tag"
  : >"$MOCK_GH_STATE/name"
  : >"$MOCK_GH_STATE/body"
}

run_reconcile() {
  printf '%s' "$1" >"$MOCK_GH_STATE/tag"
  (cd "$repo" && scripts/reconcile-release.sh "$1" "$work/dist" "$work/notes.md")
}

# Absent stable release: create a draft, verify it, then publish as latest.
reset_state
make_dist v1.2.3
run_reconcile v1.2.3
test "$(<"$MOCK_GH_STATE/draft")" = false
test "$(<"$MOCK_GH_STATE/prerelease")" = false
test "$(<"$MOCK_GH_STATE/latest")" = true
grep -q 'create.*--draft' "$MOCK_GH_STATE/log"
grep -q -- '--latest ' "$MOCK_GH_STATE/log"

# Partial draft rerun: update and replace its incomplete assets, then publish.
reset_state
make_dist v1.2.3
touch "$MOCK_GH_STATE/exists"
printf true >"$MOCK_GH_STATE/draft"
run_reconcile v1.2.3
grep -q 'edit.*--draft' "$MOCK_GH_STATE/log"
grep -q 'upload.*--clobber' "$MOCK_GH_STATE/log"

# Correct published immutable release: verify and perform no mutation.
printf true >"$MOCK_GH_STATE/immutable"
: >"$MOCK_GH_STATE/log"
run_reconcile v1.2.3
! grep -Eq ' (create|edit|upload) ' "$MOCK_GH_STATE/log"

# Latest mismatch on an immutable stable release fails without mutation.
printf false >"$MOCK_GH_STATE/latest"
: >"$MOCK_GH_STATE/log"
if run_reconcile v1.2.3 2>"$work/latest-error"; then exit 1; fi
grep -q 'new corrected version tag' "$work/latest-error"
! grep -Eq ' (create|edit|upload) ' "$MOCK_GH_STATE/log"
printf true >"$MOCK_GH_STATE/latest"

# Mismatched immutable release: fail explicitly without mutation.
printf 'wrong notes\n' >"$MOCK_GH_STATE/body"
: >"$MOCK_GH_STATE/log"
if run_reconcile v1.2.3 2>"$work/error"; then exit 1; fi
grep -q 'new corrected version tag' "$work/error"
! grep -Eq ' (create|edit|upload) ' "$MOCK_GH_STATE/log"

# Prerelease: preserve prerelease state and never mark Latest.
reset_state
make_dist v1.2.3-rc.1
run_reconcile v1.2.3-rc.1
test "$(<"$MOCK_GH_STATE/prerelease")" = true
test "$(<"$MOCK_GH_STATE/latest")" = false
grep -q -- '--prerelease ' "$MOCK_GH_STATE/log"
grep -q -- '--latest=false' "$MOCK_GH_STATE/log"

# Correct published prerelease is also a verified no-op.
printf true >"$MOCK_GH_STATE/immutable"
: >"$MOCK_GH_STATE/log"
run_reconcile v1.2.3-rc.1
! grep -Eq ' (create|edit|upload) ' "$MOCK_GH_STATE/log"

printf 'release reconciliation fixtures passed\n'
