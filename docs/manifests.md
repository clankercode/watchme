# Provider manifests

Manifests describe detection and bounded observation/recovery recipes for generic agents. They cannot weaken compiled policy.

## Bundled manifests

Shipped under `manifests/`:

`gemini.toml`, `grok.toml`, `hermes.toml`, `kimi.toml`, `opencode.toml`, `openhands.toml`, `pi.toml`, `unknown.toml`

Schema: `schemas/provider-manifest.schema.json`.

## Authoring

1. Start from `config/` examples and the schema.
2. Keep recipes allowlisted (pane text/keys, waits, checks only).
3. Set `version_range` and `unknown_version_policy` conservatively.
4. Place trusted local overrides under the configured local manifests directory; they must remain owner-controlled.

## Support tiers

Reported by `watchme providers` and documented in [compatibility.md](compatibility.md):

- structured recovery
- deterministic terminal recovery
- planner-assisted
- observation-only
- untested

Never claim a higher tier than fixtures/probes support.
