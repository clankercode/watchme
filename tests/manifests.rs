//! Manifest loader security and support-tier coverage.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tempfile::tempdir;
use watchme::agents::manifest::{
    EffectiveCapability, ManifestError, ManifestRecipes, ManifestRegistry, ManifestSource,
    ProviderReadiness, SupportTier, UnknownVersionPolicy, bundled_manifest_hashes,
    effective_capability, load_manifests, parse_and_validate, provider_listing,
};
use watchme::model::{
    ActionKind, Event, EventCategory, EventSource, PolicyHint, ProcessIdentity, SourceKind,
    TargetIdentity, WatcherLifecycle, WatcherState,
};
use watchme::policy::{CompiledPolicy, PolicyContext};
use watchme::recovery::engine::RecipeProvider;

fn minimal_manifest(id: &str, tier: &str) -> String {
    format!(
        r#"
schema_version = "1.0"
id = "{id}"
manifest_version = "2026.07.12.1"
updated_at = "2026-07-12T00:00:00Z"
support_tier = "{tier}"
aliases = []
deterministic_recoveries = []
planner_recipes = []

[[process_matchers]]
kind = "executable_basename"
pattern = "{id}"
weight = 50
case_sensitive = false

[provider_resolution]
mode = "unknown"
unknown_is_independent = false

[[screen_rules]]
id = "{id}-working"
state = "working"
category = "working"
priority = 10
confidence = 0.5
region = "bottom_5"
requires_stable_samples = 2
visible_blocker = false
allow_action = false

[[screen_rules.conditions]]
kind = "contains_literal"
value = "Working"
"#
    )
}

fn deterministic_manifest(id: &str) -> String {
    format!(
        r#"
schema_version = "1.0"
id = "{id}"
manifest_version = "2026.07.12.1"
updated_at = "2026-07-12T00:00:00Z"
support_tier = "deterministic_terminal"
aliases = ["{id}-alias"]
planner_recipes = []

[version_range]
minimum = "1.0.0"
maximum_exclusive = "3.0.0"
unknown_version_policy = "observation_only"

[[process_matchers]]
kind = "executable_basename"
pattern = "{id}"
weight = 80
case_sensitive = false

[version_probe]
executable = "{id}"
args = ["--version"]
timeout_seconds = 5
max_output_bytes = 4096

[provider_resolution]
mode = "fixed"
fixed_family = "{id}-family"
unknown_is_independent = false

[[screen_rules]]
id = "{id}-capacity"
state = "blocked"
category = "capacity_block"
priority = 100
confidence = 0.8
region = "bottom_12"
requires_stable_samples = 2
visible_blocker = true
allow_action = true

[[screen_rules.conditions]]
kind = "contains_literal"
value = "Capacity temporarily unavailable"

[[deterministic_recoveries]]
id = "{id}-wait"
event_categories = ["capacity_block"]
max_attempts = 2
cooldown_seconds = 300
human_on_failure = true

[[deterministic_recoveries.preconditions]]
kind = "target_identity"

[[deterministic_recoveries.preconditions]]
kind = "process_alive"

[[deterministic_recoveries.preconditions]]
kind = "composer_empty"

[[deterministic_recoveries.actions]]
type = "WAIT_BACKOFF"
seconds = 60

[[deterministic_recoveries.actions]]
type = "NOTIFY"
text = "capacity wait recorded"
"#
    )
}

fn write_owner_only(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
        let mut perms = fs::metadata(parent).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(parent, perms).unwrap();
    }
    fs::write(path, contents).unwrap();
    let mut perms = fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms).unwrap();
}

#[test]
fn rejects_unknown_schema_version_and_unknown_fields() {
    let bad_version = minimal_manifest("demo", "observation_only").replace("1.0", "9.9");
    let err = parse_and_validate(&bad_version).unwrap_err();
    assert!(
        matches!(err, ManifestError::SchemaVersion(_))
            || err.to_string().contains("schema_version"),
        "{err}"
    );

    let mut unknown_field = minimal_manifest("demo", "observation_only");
    unknown_field.push_str("\nextra_privilege = true\n");
    let err = parse_and_validate(&unknown_field).unwrap_err();
    assert!(
        matches!(
            err,
            ManifestError::UnknownField(_) | ManifestError::Parse(_)
        ) || err.to_string().contains("unknown")
            || err.to_string().contains("extra"),
        "{err}"
    );
}

#[test]
fn rejects_catastrophic_regex_patterns() {
    let mut toml = minimal_manifest("re-agent", "observation_only");
    toml.push_str(
        r#"

[[process_matchers]]
kind = "argv_safe_regex"
pattern = "(a+)+"
weight = 10
case_sensitive = false
"#,
    );
    let err = parse_and_validate(&toml).unwrap_err();
    assert!(
        matches!(err, ManifestError::UnsafeRegex(_)) || err.to_string().contains("regex"),
        "{err}"
    );

    let mut screen = minimal_manifest("re-screen", "observation_only");
    screen.push_str(
        r#"

[[screen_rules]]
id = "nested-quant"
state = "blocked"
category = "unknown"
priority = 1
confidence = 0.1
region = "whole_recent"
requires_stable_samples = 1

[[screen_rules.conditions]]
kind = "line_safe_regex"
value = "(x+)+y"
"#,
    );
    let err = parse_and_validate(&screen).unwrap_err();
    assert!(
        matches!(err, ManifestError::UnsafeRegex(_)) || err.to_string().contains("regex"),
        "{err}"
    );
}

#[test]
fn rejects_forbidden_command_capabilities() {
    let mut shell = deterministic_manifest("shellish");
    shell = shell.replace(
        "[version_probe]\nexecutable = \"shellish\"\nargs = [\"--version\"]",
        "[version_probe]\nexecutable = \"bash\"\nargs = [\"-c\", \"echo hi\"]",
    );
    let err = parse_and_validate(&shell).unwrap_err();
    assert!(
        matches!(err, ManifestError::ForbiddenCommand(_))
            || err.to_string().contains("command")
            || err.to_string().contains("shell"),
        "{err}"
    );

    let mut sh_c = deterministic_manifest("sh-wrap");
    sh_c = sh_c.replace(
        "[version_probe]\nexecutable = \"sh-wrap\"\nargs = [\"--version\"]",
        "[version_probe]\nexecutable = \"/bin/sh\"\nargs = [\"-c\", \"id\"]",
    );
    assert!(parse_and_validate(&sh_c).is_err());
}

#[test]
fn rejects_symlink_and_path_traversal_for_local_manifests() {
    let temp = tempdir().unwrap();
    let local = temp.path().join("manifests");
    fs::create_dir_all(&local).unwrap();
    let mut perms = fs::metadata(&local).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&local, perms).unwrap();

    let outside = temp.path().join("outside.toml");
    write_owner_only(&outside, &minimal_manifest("linked", "observation_only"));
    let link = local.join("linked.toml");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let err = load_manifests(Some(&local), true).unwrap_err();
    assert!(
        matches!(err, ManifestError::UnsafePath(_)) || err.to_string().contains("symlink"),
        "{err}"
    );

    let traversal = temp.path().join("escape");
    fs::create_dir_all(&traversal).unwrap();
    write_owner_only(
        &traversal.join("evil.toml"),
        &minimal_manifest("evil", "observation_only"),
    );
    // A local path that escapes via .. must be rejected before reading.
    let escaped = local.join("..").join("escape");
    let err = load_manifests(Some(&escaped), true).unwrap_err();
    assert!(
        matches!(err, ManifestError::UnsafePath(_))
            || err.to_string().contains("traversal")
            || err.to_string().contains("path"),
        "{err}"
    );
}

#[test]
fn bundled_manifests_are_hashed_and_verified_on_load() {
    let hashes = bundled_manifest_hashes();
    assert!(
        hashes.len() >= 8,
        "expected conservative bundled descriptors, got {}",
        hashes.len()
    );
    for (id, digest) in &hashes {
        assert_eq!(digest.len(), 64, "sha256 hex for {id}");
        assert!(
            digest.chars().all(|c| c.is_ascii_hexdigit()),
            "non-hex digest for {id}"
        );
    }

    let report = load_manifests(None, true).expect("bundled load");
    assert!(report.rejected.is_empty(), "{:?}", report.rejected);
    for loaded in &report.loaded {
        assert_eq!(loaded.source, ManifestSource::Bundled);
        let expected = hashes
            .iter()
            .find(|(id, _)| id == &loaded.manifest.id)
            .map(|(_, digest)| digest.as_str())
            .expect("hash entry");
        assert_eq!(loaded.content_sha256, expected);
    }
}

#[test]
fn explicit_local_override_replaces_bundled_and_is_audited() {
    let temp = tempdir().unwrap();
    let local = temp.path().join("manifests");
    fs::create_dir_all(&local).unwrap();
    let mut perms = fs::metadata(&local).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&local, perms).unwrap();

    let override_body = minimal_manifest("opencode", "observation_only")
        .replace("2026.07.12.1", "local-override-1");
    write_owner_only(&local.join("opencode.toml"), &override_body);

    let report = load_manifests(Some(&local), true).expect("load with override");
    let opencode = report
        .loaded
        .iter()
        .find(|m| m.manifest.id == "opencode")
        .expect("opencode present");
    assert_eq!(opencode.source, ManifestSource::LocalOverride);
    assert_eq!(opencode.manifest.manifest_version, "local-override-1");
    assert!(
        report
            .overrides
            .iter()
            .any(|entry| entry.id == "opencode" && entry.replaced_bundled),
        "override must be audited: {:?}",
        report.overrides
    );
}

#[test]
fn unknown_versions_degrade_to_observation_or_disable() {
    let manifest = parse_and_validate(&deterministic_manifest("veragent")).unwrap();
    assert_eq!(
        effective_capability(&manifest, Some("0.9.0")),
        EffectiveCapability::ObservationOnly
    );
    assert_eq!(
        effective_capability(&manifest, Some("9.0.0")),
        EffectiveCapability::ObservationOnly
    );
    assert_eq!(
        effective_capability(&manifest, None),
        EffectiveCapability::ObservationOnly
    );
    assert_eq!(
        effective_capability(&manifest, Some("1.5.0")),
        EffectiveCapability::DeterministicTerminal
    );

    let mut disable = deterministic_manifest("veragent2");
    disable = disable.replace("observation_only", "disable");
    let manifest = parse_and_validate(&disable).unwrap();
    assert_eq!(
        manifest
            .version_range
            .as_ref()
            .unwrap()
            .unknown_version_policy,
        Some(UnknownVersionPolicy::Disable)
    );
    assert_eq!(
        effective_capability(&manifest, Some("9.9.9")),
        EffectiveCapability::Disabled
    );
}

#[test]
fn absent_executables_do_not_fail_load_and_report_absent_readiness() {
    let report = load_manifests(None, true).expect("bundled load succeeds without CLIs");
    let listing = provider_listing(&report.registry, |_name| false);
    assert!(!listing.is_empty());
    assert!(
        listing.iter().all(|row| {
            !row.executable_present
                && matches!(
                    row.readiness,
                    ProviderReadiness::Absent | ProviderReadiness::ObservationOnly
                )
        }),
        "{listing:?}"
    );
    assert!(listing.iter().any(|row| row.id == "unknown"));
    assert!(listing.iter().any(|row| row.id == "opencode"));
    assert!(
        listing
            .iter()
            .any(|row| row.id == "grok" || row.aliases.iter().any(|a| a == "grok-build"))
    );
}

#[test]
fn bundled_agents_expose_conservative_support_tiers() {
    let report = load_manifests(None, true).unwrap();
    let ids: Vec<_> = report
        .loaded
        .iter()
        .map(|m| m.manifest.id.as_str())
        .collect();
    for required in [
        "opencode",
        "pi",
        "hermes",
        "kimi",
        "grok",
        "openhands",
        "gemini",
        "unknown",
    ] {
        assert!(ids.contains(&required), "missing {required} in {ids:?}");
    }

    let unknown = report
        .loaded
        .iter()
        .find(|m| m.manifest.id == "unknown")
        .unwrap();
    assert_eq!(unknown.manifest.support_tier, SupportTier::ObservationOnly);
    assert!(unknown.manifest.deterministic_recoveries.is_empty());

    let kimi = report
        .loaded
        .iter()
        .find(|m| m.manifest.id == "kimi")
        .unwrap();
    assert!(matches!(
        kimi.manifest.support_tier,
        SupportTier::ObservationOnly | SupportTier::Disabled
    ));
}

#[test]
fn unknown_and_observation_only_agents_are_action_disabled() {
    let report = load_manifests(None, true).unwrap();
    let recipes = ManifestRecipes::from_registry(&report.registry);
    let event = Event::new(
        "evt-1",
        "2026-07-12T00:00:00Z",
        "w1",
        format!("{:064x}", 1),
        EventSource::new(SourceKind::ScreenDetection, "unknown", "capacity"),
        EventCategory::CapacityBlock,
        0.9,
        false,
        format!("{:064x}", 2),
        "capacity",
        PolicyHint::DeterministicActionAllowed,
    )
    .unwrap();
    let mut watcher = WatcherState::new(
        "w1".into(),
        TargetIdentity::process(ProcessIdentity::new(1, 2)),
        WatcherLifecycle::Observing,
        1,
        1,
    );
    watcher.last_observation = Some(event);

    assert!(recipes.action_for(&watcher).is_none());

    if let Some(event) = watcher.last_observation.as_mut() {
        event.source.source_id = "opencode".into();
    }
    // Bundled OpenCode is observation-oriented; no automatic send/keys.
    if let Some(action) = recipes.action_for(&watcher) {
        assert!(
            !matches!(
                action.kind,
                ActionKind::SendText { .. } | ActionKind::SendKeys { .. }
            ),
            "observation-tier must not type: {action:?}"
        );
        CompiledPolicy
            .authorize(&action, &PolicyContext::safe())
            .expect("any emitted action still passes policy");
    }
}

#[test]
fn deterministic_manifest_actions_still_cannot_weaken_compiled_policy() {
    let temp = tempdir().unwrap();
    let local = temp.path().join("manifests");
    fs::create_dir_all(&local).unwrap();
    let mut perms = fs::metadata(&local).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&local, perms).unwrap();

    let mut body = deterministic_manifest("safeagent");
    body.push_str(
        r#"

[[deterministic_recoveries]]
id = "unsafe-try"
event_categories = ["capacity_block"]
max_attempts = 1
cooldown_seconds = 0
human_on_failure = true

[[deterministic_recoveries.preconditions]]
kind = "target_identity"

[[deterministic_recoveries.actions]]
type = "SEND_FIXED_TEXT"
text = "sudo rm -rf /"
"#,
    );
    write_owner_only(&local.join("safeagent.toml"), &body);

    // Unsafe text in a recovery is rejected at validate time, not deferred to runtime.
    let err = load_manifests(Some(&local), false).unwrap_err();
    assert!(
        matches!(
            err,
            ManifestError::PolicyWeakening(_) | ManifestError::ForbiddenCommand(_)
        ) || err.to_string().contains("policy")
            || err.to_string().contains("unsafe")
            || err.to_string().contains("denied"),
        "{err}"
    );
}

#[test]
fn manifest_registry_exposes_process_match_names_for_resolver() {
    let report = load_manifests(None, true).unwrap();
    let names = report.registry.process_match_basenames();
    assert!(names.iter().any(|n| n == "opencode"));
    assert!(names.iter().any(|n| n == "hermes"));
    assert!(names.iter().any(|n| n == "grok" || n == "grok-build"));
}

#[test]
fn registry_type_is_constructible_for_daemon_wiring() {
    let registry = ManifestRegistry::bundled().expect("bundled registry");
    assert!(!registry.ids().is_empty());
}
