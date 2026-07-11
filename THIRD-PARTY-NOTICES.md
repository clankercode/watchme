# Third-party notices and clean-room guidance

This bundle contains original specifications, schemas, synthetic fixtures, and reference scripts prepared from public documentation and repository research. It does not include third-party source files or binaries.

## amux

- Project: `mixpeek/amux`
- Repository: `https://github.com/mixpeek/amux`
- Reviewed snapshot: commit `69b73f7a805c67d527c1d3fd179803a3670ec4f6`
- Reviewed license heading: **MIT License + Commons Clause**.
- The Commons Clause states that the license grant does not include the right to sell the software as defined by that license condition.

Use in this bundle: behavioral prior art only—tmux watchdog architecture, rate-limit menu handling, reset-time classes, budgets, and intervention checks. No amux source is included. The WatchMe implementation agent should perform a clean-room implementation and must not copy amux code unless the intended distribution and license obligations have been reviewed consciously.

## claude-auto-retry

- Project: `cheapestinference/claude-auto-retry`
- Repository: `https://github.com/cheapestinference/claude-auto-retry`
- Reviewed repository presented an MIT license.

Use in this bundle: architectural and operational lessons from public README/design notes—label-based menu selection, timezone-aware waiting, foreground checks, `StopFailure`, structured JSONL preference, full jitter, pane/PID reuse, monitor cleanup, composer safety, debounce, and golden captures. No source is included. If the implementation copies any code rather than reimplementing behavior, preserve the upstream copyright/license notice and document exact provenance.

## Herdr

- Project: `ogulcancelik/herdr`
- Repository: `https://github.com/ogulcancelik/herdr`
- Documentation and a Grok detection manifest were reviewed to understand public local APIs, process/session metadata, agent detection, and `grok-build` alias behavior.

Use in this bundle: integration specification and example plugin sketch. No Herdr code or manifest content is reproduced verbatim as a complete file. The implementation should depend on Herdr only through documented local interfaces and follow Herdr’s current license for any copied data/code.

## OpenAI Codex, Anthropic Claude Code, OpenCode, Pi, Hermes, Kimi, OpenHands

Public documentation and/or public repository source were reviewed to identify supported noninteractive modes, structured output, session controls, hooks, and safety caveats. No source code from these projects is distributed in this bundle.

Their names and marks are used descriptively to identify compatibility targets. WatchMe should not imply endorsement or official affiliation.

## Research papers

- Harsh Shah, “LogJack: Indirect Prompt Injection Through Cloud Logs Against LLM Debugging Agents,” arXiv:2604.15368 (2026).
- “Architecting Secure AI Agents: Perspectives on System-Level Defenses Against Indirect Prompt Injection Attacks,” arXiv:2603.30016 (2026).

Use in this bundle: security motivation and architectural guidance. No paper text is reproduced beyond short titles and paraphrased findings.

## Synthetic fixtures

Files under `fixtures/` are intentionally synthetic or paraphrased. They are not represented as exact proprietary UI captures and should not be used as the sole compatibility evidence for a release. The completed WatchMe project should provide a process for adding real, redacted, permission-cleared golden captures.

## Dependency policy for the implementation

The implementation agent must:

1. produce a dependency/license inventory;
2. preserve all required notices;
3. avoid copying code from incompatible or unclear licenses;
4. pin/lock dependencies and run available license/security audits;
5. document any generated code or schema derived from an upstream interface;
6. keep remote manifest updates disabled until signature and rollback controls exist.
