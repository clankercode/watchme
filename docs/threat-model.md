# Observation and recovery threat model

Terminal captures, JSONL records, hooks, manifests, and planner output are untrusted. They can be malformed, oversized, partially written, rotated, prompt-injected, or crafted to emit terminal control protocols. WatchMe bounds reads, strips terminal protocols and controls, fingerprints redacted evidence, and never treats observed text as policy.

The compiled policy is the final authority. It denies unknown action types and never automates authentication, billing, funding, upgrades, secrets, broad permission approval, yolo/always-approve modes, privilege escalation, destructive operations, arbitrary shell/file/network actions, or relaunching a dead target. Configuration and manifests cannot widen this authority.

Before action, target identity, evidence freshness, source precedence, composer state, human intervention, cooldown, idempotency, and attempt/wait/planner budgets must pass. Restarted recovery requires live revalidation. Higher-ranked contradictory evidence suppresses lower-ranked action; screen-only evidence requires at least two stable observations, while a structured terminal failure can be handled immediately. Wall time is evidence only; monotonic time governs cooldowns so wall-clock jumps do not cause premature action.
