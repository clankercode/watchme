# Compatibility

## Herdr

Probe date: 2026-07-11 (Australia/Sydney).

The read-only probe `command -v herdr` produced no output and exited non-zero on the development host. Consequently, no installed Herdr version, `--help` output, schema command, socket documentation, or upstream plugin API could be verified. No live Herdr state was opened or modified, and the live smoke test was skipped honestly because Herdr was absent.

WatchMe therefore implements and tests a fixed, local bridge contract rather than claiming compatibility with an unverified upstream API. The contract is newline-delimited JSON over the owner-owned Unix socket in `HERDR_SOCKET_PATH`, with `protocol = "watchme.herdr"`, `schema_version = 1`, unique request IDs, one request/response per connection, a 256 KiB response ceiling, and bounded timeouts. Context also requires `HERDR_WORKSPACE_ID`, `HERDR_TAB_ID`, and `HERDR_PANE_ID`.

The schema-faithful fake covers `pane_info`, `process_info`, bounded recent unwrapped `pane_read`, separate control-safe `send_text` and allowlisted symbolic `send_keys`, `agent_session`, `agent_state_events`, and `notification`. The client rejects partial, malformed, oversized, wrong-version, wrong-protocol, and mismatched-request responses. It requires an absolute, canonical Unix socket owned by the current UID and not writable by group or others; a real bridge must also validate its connecting peer UID. Target process, pane, and composer safety are revalidated at action boundaries, and terminal reads receive a post-read identity check. Persisted Herdr server identity combines the canonical socket path and provider-returned server ID, so either replacement changes target identity.

`config/herdr-plugin.example.toml` is an optional bridge configuration example only; it has no core UI dependency and is not represented as a verified upstream Herdr plugin format.
