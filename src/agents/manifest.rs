//! Strict provider/agent manifests: detection and bounded recipes only.
//! Manifests cannot weaken compiled policy or execute arbitrary shell.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::model::{Action, ActionKind, Condition, EventCategory, StatusCheck, WatcherState};
use crate::policy::{CompiledPolicy, PolicyContext, is_safe_send_text};
use crate::recovery::engine::RecipeProvider;

const SCHEMA_VERSION: &str = "1.0";
const MAX_REGEX_SIZE: usize = 64 * 1024;

/// Embedded bundled manifests and their expected SHA-256 digests.
const BUNDLED_MANIFESTS: &[(&str, &str, &str)] = &[
    (
        "gemini",
        include_str!("../../manifests/gemini.toml"),
        "1f3169cf4d4ba274883edc1ec61c981e531d8a7206794c6dcf8d4547195ef05b",
    ),
    (
        "grok",
        include_str!("../../manifests/grok.toml"),
        "8b68301484b17c1d212d113aa5de3ba75bfba9e23d9e7cfd35c219e1e3cd08d4",
    ),
    (
        "hermes",
        include_str!("../../manifests/hermes.toml"),
        "7612c6850fbf70a9dccdc918b59aba820b7689099fb14b57d173e8280b1ebd0c",
    ),
    (
        "kimi",
        include_str!("../../manifests/kimi.toml"),
        "e110122e9811e760886e3855d756e6bf61e9550606787b791d63a6261f2e5683",
    ),
    (
        "opencode",
        include_str!("../../manifests/opencode.toml"),
        "6b3e230cbdd7f8d87b89d9e801ddbd16ebca2acb1828ed1c036607e7b47c3286",
    ),
    (
        "openhands",
        include_str!("../../manifests/openhands.toml"),
        "3f0f40f5516d7ce017af47ef3175108f16a491a59cd4b7bfd4df8ee9b19b2a30",
    ),
    (
        "pi",
        include_str!("../../manifests/pi.toml"),
        "cc54e8d8548050adf1671265e790f2e7c516652444d2d3efe187fbf4913f4e35",
    ),
    (
        "unknown",
        include_str!("../../manifests/unknown.toml"),
        "2383870b6b0d1e655dca68d90afa766f7bb25257b6285dd4185442003e9339b5",
    ),
];

const FORBIDDEN_SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "csh",
    "tcsh",
    "ksh",
    "busybox",
    "pwsh",
    "powershell",
    "cmd",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "osascript",
];

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("unsupported manifest schema_version: {0}")]
    SchemaVersion(String),
    #[error("manifest parse error: {0}")]
    Parse(String),
    #[error("unknown or forbidden field: {0}")]
    UnknownField(String),
    #[error("unsafe regex pattern: {0}")]
    UnsafeRegex(String),
    #[error("forbidden command capability: {0}")]
    ForbiddenCommand(String),
    #[error("unsafe manifest path: {0}")]
    UnsafePath(String),
    #[error("bundled manifest hash mismatch for {0}")]
    HashMismatch(String),
    #[error("manifest would weaken compiled policy: {0}")]
    PolicyWeakening(String),
    #[error("invalid manifest content: {0}")]
    Invalid(String),
    #[error("io error: {0}")]
    Io(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportTier {
    Structured,
    DeterministicTerminal,
    PlannerAssisted,
    ObservationOnly,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownVersionPolicy {
    ObservationOnly,
    Disable,
    AllowExactRules,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectiveCapability {
    Structured,
    DeterministicTerminal,
    PlannerAssisted,
    ObservationOnly,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderReadiness {
    Tested,
    Probed,
    ObservationOnly,
    Absent,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestSource {
    Bundled,
    LocalOverride,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderManifest {
    pub schema_version: String,
    pub id: String,
    pub manifest_version: String,
    pub updated_at: String,
    #[serde(default)]
    pub min_watchme_version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub source_url: Option<String>,
    pub support_tier: SupportTier,
    pub aliases: Vec<String>,
    #[serde(default)]
    pub version_range: Option<VersionRange>,
    pub process_matchers: Vec<ProcessMatcher>,
    #[serde(default)]
    pub version_probe: Option<CommandSpec>,
    pub provider_resolution: ProviderResolution,
    #[serde(default)]
    pub session_sources: Vec<SessionSource>,
    #[serde(default)]
    pub structured_sources: Vec<StructuredSource>,
    pub screen_rules: Vec<ScreenRule>,
    #[serde(default)]
    pub composer_rules: Vec<ScreenRule>,
    pub deterministic_recoveries: Vec<RecoveryRecipe>,
    pub planner_recipes: Vec<PlannerRecipe>,
    #[serde(default)]
    pub fixture_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    #[serde(default)]
    pub minimum: Option<String>,
    #[serde(default)]
    pub maximum_exclusive: Option<String>,
    #[serde(default)]
    pub unknown_version_policy: Option<UnknownVersionPolicy>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessMatcher {
    pub kind: ProcessMatcherKind,
    pub pattern: String,
    pub weight: i32,
    #[serde(default)]
    pub case_sensitive: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessMatcherKind {
    ExecutableBasename,
    ExecutableRealpath,
    ArgvLiteral,
    ArgvSafeRegex,
    EnvironmentHint,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub executable: String,
    pub args: Vec<String>,
    pub timeout_seconds: u32,
    pub max_output_bytes: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderResolution {
    pub mode: ProviderResolutionMode,
    #[serde(default)]
    pub fixed_family: Option<String>,
    #[serde(default)]
    pub argv_flag_names: Vec<String>,
    #[serde(default)]
    pub environment_names: Vec<String>,
    #[serde(default = "false_bool")]
    pub unknown_is_independent: bool,
}

fn false_bool() -> bool {
    false
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderResolutionMode {
    Fixed,
    Argv,
    Environment,
    ConfigMetadata,
    RuntimeProbe,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionSource {
    pub kind: SessionSourceKind,
    pub priority: i32,
    #[serde(default)]
    pub environment_name: Option<String>,
    #[serde(default)]
    pub path_template: Option<String>,
    #[serde(default)]
    pub json_pointer: Option<String>,
    #[serde(default = "true_bool")]
    pub requires_cwd_match: bool,
    #[serde(default = "true_bool")]
    pub requires_process_time_match: bool,
}

fn true_bool() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionSourceKind {
    HerdrAgentSession,
    HookPayload,
    TypedApi,
    ProcessEnvironment,
    OpenFile,
    JsonlMetadata,
    StateDatabase,
    BoundedGlob,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredSource {
    pub id: String,
    pub kind: StructuredSourceKind,
    pub priority: i32,
    #[serde(default)]
    pub event_selector: Option<String>,
    #[serde(default)]
    pub terminal_only: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredSourceKind {
    Hook,
    Jsonl,
    LocalApi,
    StateDatabase,
    HerdrState,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenRule {
    pub id: String,
    pub state: ScreenState,
    pub category: String,
    pub priority: i32,
    pub confidence: f64,
    pub region: ScreenRegion,
    pub conditions: Vec<ScreenCondition>,
    pub requires_stable_samples: u8,
    #[serde(default)]
    pub visible_blocker: bool,
    #[serde(default)]
    pub allow_action: bool,
    #[serde(default)]
    pub version_note: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenState {
    Working,
    Idle,
    Blocked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenRegion {
    #[serde(rename = "bottom_2")]
    Bottom2,
    #[serde(rename = "bottom_5")]
    Bottom5,
    #[serde(rename = "bottom_12")]
    Bottom12,
    WholeRecent,
    Detection,
    MenuBlock,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenCondition {
    pub kind: ScreenConditionKind,
    pub value: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenConditionKind {
    ContainsLiteral,
    NotContainsLiteral,
    LineSafeRegex,
    BottomLineContains,
    LabelledMenuOption,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRecipe {
    pub id: String,
    pub event_categories: Vec<String>,
    pub preconditions: Vec<TemplatePrecondition>,
    pub actions: Vec<TemplateAction>,
    pub max_attempts: u32,
    pub cooldown_seconds: u64,
    pub human_on_failure: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplatePrecondition {
    pub kind: TemplatePreconditionKind,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplatePreconditionKind {
    TargetIdentity,
    ProcessAlive,
    ComposerEmpty,
    MenuStable,
    EventCategory,
    GoalState,
    NoHumanIntervention,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateAction {
    #[serde(rename = "type")]
    pub action_type: TemplateActionType,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub keys: Vec<String>,
    #[serde(default)]
    pub seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TemplateActionType {
    WaitParsedReset,
    WaitBackoff,
    SendFixedText,
    SendFixedKeys,
    CheckAgentState,
    CheckGoalState,
    Notify,
    HumanRequired,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerRecipe {
    pub id: String,
    pub command: CommandSpec,
    pub output_mode: PlannerOutputMode,
    pub schema_enforced: bool,
    pub requires_isolated_cwd: bool,
    pub tools_disabled: bool,
    pub auto_approval_disabled: bool,
    pub provider_family_source: PlannerFamilySource,
    #[serde(default)]
    pub fixed_provider_family: Option<String>,
    pub enabled_by_default: bool,
    #[serde(default)]
    pub unsafe_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerOutputMode {
    Json,
    Jsonl,
    TextThenValidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerFamilySource {
    Fixed,
    CliArgs,
    ConfigProbe,
    RuntimeProbe,
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LoadedManifest {
    pub manifest: ProviderManifest,
    pub source: ManifestSource,
    pub content_sha256: String,
    pub path: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverrideAudit {
    pub id: String,
    pub replaced_bundled: bool,
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RejectedManifest {
    pub path: Option<PathBuf>,
    pub reason: String,
}

#[derive(Clone, Debug, Default)]
pub struct ManifestRegistry {
    by_id: BTreeMap<String, LoadedManifest>,
}

#[derive(Clone, Debug)]
pub struct ManifestLoadReport {
    pub loaded: Vec<LoadedManifest>,
    pub overrides: Vec<OverrideAudit>,
    pub rejected: Vec<RejectedManifest>,
    pub registry: ManifestRegistry,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProviderStatus {
    pub id: String,
    pub aliases: Vec<String>,
    pub support_tier: SupportTier,
    pub readiness: ProviderReadiness,
    pub executable_present: bool,
    pub local_override: bool,
    pub manifest_version: String,
}

#[derive(Clone, Default)]
pub struct ManifestRecipes {
    by_source: BTreeMap<String, LoadedManifest>,
}

impl ManifestRegistry {
    pub fn bundled() -> Result<Self, ManifestError> {
        Ok(load_manifests(None, true)?.registry)
    }

    pub fn ids(&self) -> Vec<String> {
        self.by_id.keys().cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<&LoadedManifest> {
        self.by_id.get(id)
    }

    pub fn process_match_basenames(&self) -> Vec<String> {
        let mut names = Vec::new();
        for loaded in self.by_id.values() {
            for matcher in &loaded.manifest.process_matchers {
                if matcher.kind == ProcessMatcherKind::ExecutableBasename
                    && !names.iter().any(|n| n == &matcher.pattern)
                {
                    names.push(matcher.pattern.clone());
                }
            }
        }
        names
    }
}

impl ManifestRecipes {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_registry(registry: &ManifestRegistry) -> Self {
        let mut by_source = BTreeMap::new();
        for loaded in registry.by_id.values() {
            by_source.insert(loaded.manifest.id.clone(), loaded.clone());
            for alias in &loaded.manifest.aliases {
                by_source.insert(alias.clone(), loaded.clone());
            }
            for matcher in &loaded.manifest.process_matchers {
                if matcher.kind == ProcessMatcherKind::ExecutableBasename {
                    by_source.insert(matcher.pattern.clone(), loaded.clone());
                }
            }
        }
        Self { by_source }
    }

    pub fn bundled() -> Result<Self, ManifestError> {
        Ok(Self::from_registry(&ManifestRegistry::bundled()?))
    }
}

impl RecipeProvider for ManifestRecipes {
    fn action_for(&self, watcher: &WatcherState) -> Option<Action> {
        let event = watcher.last_observation.as_ref()?;
        let loaded = self.by_source.get(&event.source.source_id)?;
        let version = event
            .metadata
            .get("agent_version")
            .and_then(|value| value.as_str());
        let capability = effective_capability(&loaded.manifest, version);
        if matches!(
            capability,
            EffectiveCapability::ObservationOnly
                | EffectiveCapability::Disabled
                | EffectiveCapability::PlannerAssisted
        ) {
            // Planner-assisted agents wait for Task 12; observation/disabled never act.
            return None;
        }
        let category = category_slug(event.category);
        let recipe = loaded
            .manifest
            .deterministic_recoveries
            .iter()
            .find(|recipe| {
                recipe
                    .event_categories
                    .iter()
                    .any(|entry| entry == &category)
            })?;
        let action = recipe_to_action(recipe, event.evidence_fingerprint.as_str())?;
        CompiledPolicy
            .authorize(&action, &PolicyContext::safe())
            .ok()?;
        Some(action)
    }
}

pub fn bundled_manifest_hashes() -> Vec<(String, String)> {
    BUNDLED_MANIFESTS
        .iter()
        .map(|(id, _, digest)| ((*id).to_owned(), (*digest).to_owned()))
        .collect()
}

pub fn parse_and_validate(toml_text: &str) -> Result<ProviderManifest, ManifestError> {
    let manifest: ProviderManifest = toml::from_str(toml_text).map_err(|error| {
        let message = error.to_string();
        if message.contains("unknown field") {
            ManifestError::UnknownField(message)
        } else {
            ManifestError::Parse(message)
        }
    })?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub fn validate_manifest(manifest: &ProviderManifest) -> Result<(), ManifestError> {
    if manifest.schema_version != SCHEMA_VERSION {
        return Err(ManifestError::SchemaVersion(
            manifest.schema_version.clone(),
        ));
    }
    validate_slug(&manifest.id, "id")?;
    if manifest.manifest_version.is_empty() || manifest.manifest_version.len() > 64 {
        return Err(ManifestError::Invalid("manifest_version bounds".into()));
    }
    if chrono::DateTime::parse_from_rfc3339(&manifest.updated_at).is_err() {
        return Err(ManifestError::Invalid("updated_at must be RFC3339".into()));
    }
    if manifest.aliases.len() > 32 {
        return Err(ManifestError::Invalid("too many aliases".into()));
    }
    for alias in &manifest.aliases {
        validate_slug(alias, "alias")?;
    }
    if manifest.process_matchers.is_empty() || manifest.process_matchers.len() > 32 {
        return Err(ManifestError::Invalid("process_matchers bounds".into()));
    }
    for matcher in &manifest.process_matchers {
        validate_process_matcher(matcher)?;
    }
    if let Some(probe) = &manifest.version_probe {
        validate_command_spec(probe)?;
    }
    if manifest.provider_resolution.unknown_is_independent {
        return Err(ManifestError::PolicyWeakening(
            "unknown_is_independent must be false".into(),
        ));
    }
    for rule in manifest
        .screen_rules
        .iter()
        .chain(manifest.composer_rules.iter())
    {
        validate_screen_rule(rule)?;
    }
    if matches!(
        manifest.support_tier,
        SupportTier::ObservationOnly | SupportTier::Disabled
    ) && manifest
        .deterministic_recoveries
        .iter()
        .any(recipe_has_input_action)
    {
        return Err(ManifestError::PolicyWeakening(
            "observation_only/disabled manifests cannot declare input recoveries".into(),
        ));
    }
    for recipe in &manifest.deterministic_recoveries {
        validate_recovery_recipe(recipe)?;
    }
    for recipe in &manifest.planner_recipes {
        validate_planner_recipe(recipe)?;
    }
    Ok(())
}

pub fn effective_capability(
    manifest: &ProviderManifest,
    version: Option<&str>,
) -> EffectiveCapability {
    let base = match manifest.support_tier {
        SupportTier::Structured => EffectiveCapability::Structured,
        SupportTier::DeterministicTerminal => EffectiveCapability::DeterministicTerminal,
        SupportTier::PlannerAssisted => EffectiveCapability::PlannerAssisted,
        SupportTier::ObservationOnly => EffectiveCapability::ObservationOnly,
        SupportTier::Disabled => EffectiveCapability::Disabled,
    };
    let Some(range) = manifest.version_range.as_ref() else {
        return base;
    };
    let policy = range
        .unknown_version_policy
        .unwrap_or(UnknownVersionPolicy::ObservationOnly);
    let in_range = version
        .map(|value| version_in_range(value, range))
        .unwrap_or(None);
    match in_range {
        Some(true) => base,
        Some(false) | None => match policy {
            UnknownVersionPolicy::ObservationOnly => EffectiveCapability::ObservationOnly,
            UnknownVersionPolicy::Disable => EffectiveCapability::Disabled,
            UnknownVersionPolicy::AllowExactRules => base,
        },
    }
}

pub fn load_manifests(
    local_dir: Option<&Path>,
    include_bundled: bool,
) -> Result<ManifestLoadReport, ManifestError> {
    let mut by_id: BTreeMap<String, LoadedManifest> = BTreeMap::new();
    let mut overrides = Vec::new();
    let rejected = Vec::new();

    if include_bundled {
        for (id, content, expected) in BUNDLED_MANIFESTS {
            let digest = sha256_hex(content.as_bytes());
            if digest != *expected {
                return Err(ManifestError::HashMismatch((*id).into()));
            }
            let manifest = parse_and_validate(content)?;
            if manifest.id != *id {
                return Err(ManifestError::Invalid(format!(
                    "bundled id mismatch: file {id} declares {}",
                    manifest.id
                )));
            }
            by_id.insert(
                manifest.id.clone(),
                LoadedManifest {
                    manifest,
                    source: ManifestSource::Bundled,
                    content_sha256: digest,
                    path: None,
                },
            );
        }
    }

    if let Some(dir) = local_dir {
        validate_manifest_directory(dir)?;
        let entries = fs::read_dir(dir).map_err(|error| ManifestError::Io(error.to_string()))?;
        for entry in entries {
            let entry = entry.map_err(|error| ManifestError::Io(error.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
                continue;
            }
            validate_manifest_file(&path, dir)?;
            let content =
                fs::read_to_string(&path).map_err(|error| ManifestError::Io(error.to_string()))?;
            let manifest = parse_and_validate(&content)?;
            let digest = sha256_hex(content.as_bytes());
            let replaced = by_id.contains_key(&manifest.id);
            if replaced {
                overrides.push(OverrideAudit {
                    id: manifest.id.clone(),
                    replaced_bundled: true,
                    path: path.clone(),
                });
            }
            by_id.insert(
                manifest.id.clone(),
                LoadedManifest {
                    manifest,
                    source: ManifestSource::LocalOverride,
                    content_sha256: digest,
                    path: Some(path),
                },
            );
        }
    }

    let loaded: Vec<_> = by_id.values().cloned().collect();
    let registry = ManifestRegistry { by_id };
    Ok(ManifestLoadReport {
        loaded,
        overrides,
        rejected,
        registry,
    })
}

pub fn provider_listing(
    registry: &ManifestRegistry,
    executable_present: impl Fn(&str) -> bool,
) -> Vec<ProviderStatus> {
    registry
        .by_id
        .values()
        .map(|loaded| {
            let names = loaded
                .manifest
                .process_matchers
                .iter()
                .filter(|matcher| matcher.kind == ProcessMatcherKind::ExecutableBasename)
                .map(|matcher| matcher.pattern.as_str())
                .collect::<Vec<_>>();
            let present = names.iter().any(|name| executable_present(name));
            let readiness = if matches!(loaded.manifest.support_tier, SupportTier::Disabled) {
                ProviderReadiness::Disabled
            } else if !present {
                ProviderReadiness::Absent
            } else {
                match loaded.manifest.support_tier {
                    SupportTier::Structured => ProviderReadiness::Tested,
                    SupportTier::DeterministicTerminal => ProviderReadiness::Probed,
                    SupportTier::PlannerAssisted | SupportTier::ObservationOnly => {
                        ProviderReadiness::ObservationOnly
                    }
                    SupportTier::Disabled => ProviderReadiness::Disabled,
                }
            };
            ProviderStatus {
                id: loaded.manifest.id.clone(),
                aliases: loaded.manifest.aliases.clone(),
                support_tier: loaded.manifest.support_tier,
                readiness,
                executable_present: present,
                local_override: loaded.source == ManifestSource::LocalOverride,
                manifest_version: loaded.manifest.manifest_version.clone(),
            }
        })
        .collect()
}

fn validate_slug(value: &str, label: &str) -> Result<(), ManifestError> {
    let ok = !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(ManifestError::Invalid(format!("invalid {label}: {value}")))
    }
}

fn validate_process_matcher(matcher: &ProcessMatcher) -> Result<(), ManifestError> {
    if matcher.pattern.is_empty() || matcher.pattern.len() > 256 {
        return Err(ManifestError::Invalid(
            "process matcher pattern bounds".into(),
        ));
    }
    if !(-100..=100).contains(&matcher.weight) {
        return Err(ManifestError::Invalid(
            "process matcher weight bounds".into(),
        ));
    }
    if matcher.kind == ProcessMatcherKind::ArgvSafeRegex {
        validate_safe_regex(&matcher.pattern)?;
    }
    Ok(())
}

fn validate_screen_rule(rule: &ScreenRule) -> Result<(), ManifestError> {
    validate_slug(&rule.id, "screen rule id")?;
    if !(0.0..=1.0).contains(&rule.confidence) || !rule.confidence.is_finite() {
        return Err(ManifestError::Invalid("screen confidence bounds".into()));
    }
    if rule.conditions.is_empty() || rule.conditions.len() > 16 {
        return Err(ManifestError::Invalid("screen conditions bounds".into()));
    }
    if !(1..=5).contains(&rule.requires_stable_samples) {
        return Err(ManifestError::Invalid(
            "requires_stable_samples bounds".into(),
        ));
    }
    for condition in &rule.conditions {
        if condition.value.is_empty() || condition.value.len() > 512 {
            return Err(ManifestError::Invalid(
                "screen condition value bounds".into(),
            ));
        }
        if condition.kind == ScreenConditionKind::LineSafeRegex {
            validate_safe_regex(&condition.value)?;
        }
    }
    Ok(())
}

fn validate_command_spec(spec: &CommandSpec) -> Result<(), ManifestError> {
    if spec.executable.is_empty() || spec.executable.len() > 256 {
        return Err(ManifestError::ForbiddenCommand("executable bounds".into()));
    }
    if !spec
        .executable
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '+' | '-'))
    {
        return Err(ManifestError::ForbiddenCommand(
            "executable has illegal characters".into(),
        ));
    }
    if spec.executable.contains("..") {
        return Err(ManifestError::ForbiddenCommand(
            "executable path traversal".into(),
        ));
    }
    let basename = spec
        .executable
        .rsplit('/')
        .next()
        .unwrap_or(spec.executable.as_str())
        .to_ascii_lowercase();
    if FORBIDDEN_SHELLS.iter().any(|shell| *shell == basename) {
        return Err(ManifestError::ForbiddenCommand(format!(
            "shell/interpreter executable forbidden: {basename}"
        )));
    }
    if spec.args.len() > 32 {
        return Err(ManifestError::ForbiddenCommand("too many args".into()));
    }
    for arg in &spec.args {
        if arg.len() > 512 {
            return Err(ManifestError::ForbiddenCommand("arg too long".into()));
        }
        let lower = arg.to_ascii_lowercase();
        if lower == "-c"
            || lower == "--command"
            || lower == "-e"
            || lower.contains("yolo")
            || lower.contains("auto-approve")
            || lower.contains("dangerously")
        {
            return Err(ManifestError::ForbiddenCommand(format!(
                "forbidden argument: {arg}"
            )));
        }
    }
    if !(1..=300).contains(&spec.timeout_seconds) {
        return Err(ManifestError::ForbiddenCommand("timeout bounds".into()));
    }
    if !(1..=10_000_000).contains(&spec.max_output_bytes) {
        return Err(ManifestError::ForbiddenCommand(
            "max_output_bytes bounds".into(),
        ));
    }
    Ok(())
}

fn validate_recovery_recipe(recipe: &RecoveryRecipe) -> Result<(), ManifestError> {
    validate_slug(&recipe.id, "recovery id")?;
    if recipe.event_categories.is_empty() || recipe.event_categories.len() > 16 {
        return Err(ManifestError::Invalid("event_categories bounds".into()));
    }
    if recipe.preconditions.is_empty() || recipe.actions.is_empty() {
        return Err(ManifestError::Invalid(
            "recovery requires preconditions and actions".into(),
        ));
    }
    if !(1..=10).contains(&recipe.max_attempts) {
        return Err(ManifestError::Invalid("max_attempts bounds".into()));
    }
    for action in &recipe.actions {
        match action.action_type {
            TemplateActionType::SendFixedText => {
                let text = action.text.as_deref().unwrap_or("");
                if text.is_empty() || !is_safe_send_text(text) {
                    return Err(ManifestError::PolicyWeakening(format!(
                        "SEND_FIXED_TEXT rejected by compiled allowlist: {text}"
                    )));
                }
            }
            TemplateActionType::SendFixedKeys => {
                if action.keys.is_empty()
                    || !action.keys.iter().all(|key| {
                        matches!(
                            key.as_str(),
                            "ENTER"
                                | "ESCAPE"
                                | "UP"
                                | "DOWN"
                                | "LEFT"
                                | "RIGHT"
                                | "TAB"
                                | "BACKTAB"
                        )
                    })
                {
                    return Err(ManifestError::PolicyWeakening(
                        "SEND_FIXED_KEYS has non-allowlisted keys".into(),
                    ));
                }
            }
            TemplateActionType::WaitBackoff => {
                let seconds = action.seconds.unwrap_or(0);
                if !(1..=86400).contains(&seconds) {
                    return Err(ManifestError::Invalid("WAIT_BACKOFF seconds bounds".into()));
                }
            }
            TemplateActionType::Notify => {
                let text = action.text.as_deref().unwrap_or("");
                if text.is_empty() || text.len() > 512 || text.chars().any(|c| c.is_control()) {
                    return Err(ManifestError::Invalid("NOTIFY text bounds".into()));
                }
            }
            TemplateActionType::WaitParsedReset
            | TemplateActionType::CheckAgentState
            | TemplateActionType::CheckGoalState
            | TemplateActionType::HumanRequired => {}
        }
    }
    Ok(())
}

fn validate_planner_recipe(recipe: &PlannerRecipe) -> Result<(), ManifestError> {
    validate_slug(&recipe.id, "planner id")?;
    validate_command_spec(&recipe.command)?;
    if !recipe.requires_isolated_cwd {
        return Err(ManifestError::PolicyWeakening(
            "planner recipes require isolated cwd".into(),
        ));
    }
    if !recipe.tools_disabled || !recipe.auto_approval_disabled {
        return Err(ManifestError::PolicyWeakening(
            "planner recipes must disable tools and auto-approval".into(),
        ));
    }
    if !recipe.schema_enforced && recipe.enabled_by_default {
        return Err(ManifestError::PolicyWeakening(
            "enabled planner recipes must enforce schema".into(),
        ));
    }
    Ok(())
}

fn recipe_has_input_action(recipe: &RecoveryRecipe) -> bool {
    recipe.actions.iter().any(|action| {
        matches!(
            action.action_type,
            TemplateActionType::SendFixedText | TemplateActionType::SendFixedKeys
        )
    })
}

fn validate_safe_regex(pattern: &str) -> Result<(), ManifestError> {
    if pattern.is_empty() || pattern.len() > 512 {
        return Err(ManifestError::UnsafeRegex("length bounds".into()));
    }
    if looks_catastrophic(pattern) {
        return Err(ManifestError::UnsafeRegex(format!(
            "catastrophic pattern rejected: {pattern}"
        )));
    }
    RegexBuilder::new(pattern)
        .size_limit(MAX_REGEX_SIZE)
        .dfa_size_limit(MAX_REGEX_SIZE)
        .build()
        .map_err(|error| ManifestError::UnsafeRegex(error.to_string()))?;
    Ok(())
}

fn looks_catastrophic(pattern: &str) -> bool {
    static NESTED: OnceLock<regex::Regex> = OnceLock::new();
    let nested = NESTED.get_or_init(|| {
        regex::Regex::new(r"\([^()]*[+*][^()]*\)[+*?]").expect("nested quantifier detector")
    });
    if nested.is_match(pattern) {
        return true;
    }
    // Backreferences and unbounded counted nesting heuristics.
    pattern.contains('\\')
        && pattern.chars().any(|c| c.is_ascii_digit())
        && pattern
            .as_bytes()
            .windows(2)
            .any(|pair| pair[0] == b'\\' && pair[1].is_ascii_digit())
}

fn validate_manifest_directory(dir: &Path) -> Result<(), ManifestError> {
    if !dir.is_absolute()
        || dir
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(ManifestError::UnsafePath(
            "manifest directory must be absolute without traversal".into(),
        ));
    }
    let meta = fs::symlink_metadata(dir).map_err(|error| ManifestError::Io(error.to_string()))?;
    if meta.file_type().is_symlink() {
        return Err(ManifestError::UnsafePath(
            "manifest directory must not be a symlink".into(),
        ));
    }
    if !meta.is_dir() {
        return Err(ManifestError::UnsafePath(
            "manifest path is not a directory".into(),
        ));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ManifestError::UnsafePath(
            "manifest directory must be owner-only".into(),
        ));
    }
    Ok(())
}

fn validate_manifest_file(path: &Path, root: &Path) -> Result<(), ManifestError> {
    if path
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(ManifestError::UnsafePath(
            "manifest path traversal rejected".into(),
        ));
    }
    let meta = fs::symlink_metadata(path).map_err(|error| ManifestError::Io(error.to_string()))?;
    if meta.file_type().is_symlink() {
        return Err(ManifestError::UnsafePath(
            "manifest file must not be a symlink".into(),
        ));
    }
    if !meta.is_file() {
        return Err(ManifestError::UnsafePath(
            "manifest path is not a regular file".into(),
        ));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o133 != 0 {
        return Err(ManifestError::UnsafePath(
            "manifest file must not be group/other writable or executable".into(),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| ManifestError::Io(error.to_string()))?;
    let root = fs::canonicalize(root).map_err(|error| ManifestError::Io(error.to_string()))?;
    if !canonical.starts_with(&root) {
        return Err(ManifestError::UnsafePath(
            "manifest escaped local directory".into(),
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn version_in_range(version: &str, range: &VersionRange) -> Option<bool> {
    let parsed = parse_version(version)?;
    if let Some(min) = range.minimum.as_deref() {
        let min = parse_version(min)?;
        if parsed < min {
            return Some(false);
        }
    }
    if let Some(max) = range.maximum_exclusive.as_deref() {
        let max = parse_version(max)?;
        if parsed >= max {
            return Some(false);
        }
    }
    Some(true)
}

fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.trim().split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn category_slug(category: EventCategory) -> String {
    serde_json::to_value(category)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{category:?}").to_ascii_lowercase())
}

fn recipe_to_action(recipe: &RecoveryRecipe, fingerprint: &str) -> Option<Action> {
    let template = recipe.actions.first()?;
    let kind = match template.action_type {
        TemplateActionType::WaitBackoff => ActionKind::WaitDuration {
            duration_seconds: template.seconds.unwrap_or(60),
        },
        TemplateActionType::SendFixedText => ActionKind::SendText {
            text: template.text.clone()?,
        },
        TemplateActionType::SendFixedKeys => ActionKind::SendKeys {
            keys: template.keys.clone(),
        },
        TemplateActionType::Notify => ActionKind::Notify {
            severity: "info".into(),
            message: template.text.clone().unwrap_or_else(|| recipe.id.clone()),
        },
        TemplateActionType::HumanRequired => ActionKind::Escalate {
            level: "human_required".into(),
        },
        TemplateActionType::CheckAgentState => ActionKind::CheckStatus {
            check: StatusCheck {
                kind: "AGENT_STATE".into(),
                value: None,
            },
        },
        TemplateActionType::CheckGoalState => ActionKind::CheckStatus {
            check: StatusCheck {
                kind: "GOAL_STATE".into(),
                value: None,
            },
        },
        TemplateActionType::WaitParsedReset => return None,
    };
    let mut action = Action::new(
        format!("manifest.{}", recipe.id),
        kind,
        format!("manifest recovery {}", recipe.id),
        fingerprint,
        30,
    );
    for precondition in &recipe.preconditions {
        action.preconditions.push(map_precondition(precondition));
    }
    Some(action)
}

fn map_precondition(precondition: &TemplatePrecondition) -> Condition {
    let (kind, value) = match precondition.kind {
        TemplatePreconditionKind::TargetIdentity => ("TARGET_IDENTITY_MATCHES", None),
        TemplatePreconditionKind::ProcessAlive => ("PROCESS_ALIVE", None),
        TemplatePreconditionKind::ComposerEmpty => ("COMPOSER_EMPTY", None),
        TemplatePreconditionKind::MenuStable => ("MENU_STABLE", None),
        TemplatePreconditionKind::EventCategory => (
            "EVENT_CATEGORY_IS",
            precondition
                .value
                .as_ref()
                .map(|value| serde_json::Value::String(value.clone())),
        ),
        TemplatePreconditionKind::GoalState => (
            "GOAL_STATE_IS",
            precondition
                .value
                .as_ref()
                .map(|value| serde_json::Value::String(value.clone())),
        ),
        TemplatePreconditionKind::NoHumanIntervention => ("NO_HUMAN_INTERVENTION", None),
    };
    Condition {
        kind: kind.into(),
        value,
    }
}
