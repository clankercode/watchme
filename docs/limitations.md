# Limitations

## Hard product limits

- Linux and macOS only for v1. No Windows support claim.
- Bare registration only; no alternate `start` workflow.
- Does not relaunch dead agents by default.
- Does not automate authentication, billing, funding, upgrades, credential entry, yolo/always-approve, privilege escalation, or destructive actions.
- Planner cannot execute shell/file/network commands; only allowlisted pane actions after validation.
- Same provider family cannot plan recovery for its own failure.
- Screen-only evidence requires stable confirmation; many agents remain observation-only without adapter boundaries.

## Human-required classes

Escalate to a human (never auto-act) for:

- ambiguous or contradictory evidence
- exhausted attempt/wait/planner budgets
- credentials / secrets prompts
- account, billing, funding, plan upgrade
- broad permission expansion
- destructive or privilege-escalating confirmations
- unknown approval flows
- identity TOCTOU failures / PID or pane reuse suspicion

## Compatibility honesty

See [compatibility.md](compatibility.md). Live Claude rate-limit menus were not established on the development host (first-run security screen). Native Herdr protocol 16 was probed read-only on `x-left`; no provider capacity failure was induced. Support tiers are evidence-backed only.

## Resource claims

Idle cost is measured, not claimed as zero. See [benchmarks.md](benchmarks.md).
