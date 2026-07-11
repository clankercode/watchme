# Agent instructions

## Project intent

WatchMe is deliberately a small, local tool. Preserve the bare `watchme`
registration experience, conservative safety defaults, and the supported
Linux and macOS scope. Do not add secrets, credentials, generated binaries,
or machine-specific state to the repository.

## Publishing releases

Only publish when the user has explicitly authorized publication. Use the
GitHub CLI (`gh`) for repository and release administration.

For the initial publication:

1. Create `github.com/clankercode/watchme` as a **public** repository with
   `gh repo create clankercode/watchme --public --source=. --remote=origin`.
2. Configure the description "Local supervisor for long-running coding-agent
   sessions" and homepage `https://github.com/clankercode/watchme` with
   `gh repo edit`. Set
   relevant topics, including `rust`, `cli`, `developer-tools`, `tmux`,
   `coding-agents`, and `automation`. Never place tokens or private data in
   repository metadata, commands, logs, commits, or release notes.
3. Push the intended branch only after local checks pass. Confirm the remote
   and default branch before pushing.

For every release:

1. Confirm the working tree and release commit are intentional and all local
   checks pass. Update `Cargo.toml` to the SemVer version being released.
2. Review all changes since the previous SemVer tag. For the first release,
   review the complete project history. Prepare release notes that accurately
   cover every user-visible change; do not rely solely on generated notes.
   The previous release is the highest strictly lower SemVer precedence tag
   that is an ancestor of the current tag. Ignore malformed, equal-precedence,
   higher, and non-ancestor tags. Prereleases participate in SemVer precedence;
   build metadata does not.
3. Create and push an annotated `vMAJOR.MINOR.PATCH` tag. The tag version must
   exactly match `[package].version` in `Cargo.toml`.
4. Monitor every CI and release workflow with `gh run list`, `gh run watch`,
   and `gh pr checks` when a pull request exists. Wait for every relevant run
   to reach a terminal state. Never report success while jobs are queued or in
   progress.
5. If a run fails, inspect it with `gh run view --log-failed`, diagnose the
   actual cause, fix it, rerun the complete relevant checks, and retry with a
   new tag when release immutability requires one. Do not hide, bypass, or
   prematurely dismiss failed checks.
6. Wait until the GitHub release page exists. Then automatically replace or
   enrich its generated description using `gh release edit --notes-file`.
   Include:
   - all changes since the prior SemVer tag (or the complete changelog for the
     first release), grouped for readers;
   - installation and upgrade instructions;
   - supported platforms and compatibility notes;
   - the exact artifact names and checksum verification instructions;
   - checks performed for the release; and
   - known limitations and breaking changes, even when the list is empty.
7. Inspect the final release with `gh release view` and the GitHub API. Verify
   that all four platform archives and `SHA256SUMS` are attached, downloads
   succeed, archive contents include both `watchme` and the `WatchMe` alias,
   and every checksum matches. Verify the release description after editing.
   A matching published release is already complete and must not be mutated.
   If any published release differs, fail and create a corrected version tag;
   never silently unpublish it. Only incomplete drafts may be updated. Mark
   SemVer prereleases as prereleases and never as Latest; stable releases are
   explicitly eligible to become Latest.

The supported release artifacts are Linux x86_64, Linux aarch64, macOS
x86_64, and macOS aarch64. Do not claim Windows support or claim a release is
complete before the release page, notes, assets, and checks have all been
verified.
