use std::collections::BTreeMap;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

pub const EVENT_SCHEMA_VERSION: &str = "1.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    TypedApi,
    Hook,
    StructuredLog,
    ProcessMetadata,
    HerdrAgentState,
    ScreenDetection,
    Planner,
    Internal,
}

impl SourceKind {
    pub const fn rank(self) -> u8 {
        match self {
            Self::TypedApi => 8,
            Self::Hook => 7,
            Self::StructuredLog => 6,
            Self::ProcessMetadata => 5,
            Self::HerdrAgentState => 4,
            Self::ScreenDetection => 3,
            Self::Planner => 2,
            Self::Internal => 1,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventSource {
    pub kind: SourceKind,
    pub source_id: String,
    pub rule_or_field: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_version: Option<String>,
}
impl EventSource {
    pub fn new(kind: SourceKind, source_id: impl Into<String>, rule: impl Into<String>) -> Self {
        Self {
            kind,
            source_id: source_id.into(),
            rule_or_field: rule.into(),
            source_version: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Working,
    Idle,
    WaitingForModel,
    WaitingForTool,
    WaitingForUser,
    PermissionPrompt,
    QuestionPrompt,
    UsageLimit,
    SessionLimit,
    WeeklyLimit,
    ModelCreditExhausted,
    TransientOverload,
    CapacityBlock,
    AuthenticationFailure,
    BillingFailure,
    InvalidRequest,
    ModelUnavailable,
    SafetyBlock,
    PausedGoal,
    BlockedGoal,
    ContextLimit,
    TerminalFailure,
    Crashed,
    Terminated,
    UnknownBlocked,
    Recovered,
    HumanIntervention,
}

impl EventCategory {
    pub const fn is_actionable(self) -> bool {
        !matches!(
            self,
            Self::Working
                | Self::Idle
                | Self::Recovered
                | Self::HumanIntervention
                | Self::Terminated
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyHint {
    ObserveOnly,
    DeterministicActionAllowed,
    WaitAllowed,
    PlannerAllowed,
    HumanRequired,
    StopWatching,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventReset {
    pub source_text: String,
    pub parsed_at: String,
    #[serde(default)]
    pub timezone: Option<String>,
    pub confidence: f64,
    #[serde(default)]
    pub margin_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Event {
    pub schema_version: String,
    pub event_id: String,
    pub observed_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monotonic_sequence: Option<u64>,
    pub watcher_id: String,
    pub target_identity_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_family: Option<String>,
    pub source: EventSource,
    pub category: EventCategory,
    pub confidence: f64,
    pub terminal: bool,
    pub evidence_fingerprint: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reset: Option<EventReset>,
    pub policy_hint: PolicyHint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl Event {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_id: impl Into<String>,
        observed_at: impl Into<String>,
        watcher_id: impl Into<String>,
        target_hash: impl Into<String>,
        source: EventSource,
        category: EventCategory,
        confidence: f64,
        terminal: bool,
        fingerprint: impl Into<String>,
        summary: impl Into<String>,
        policy_hint: PolicyHint,
    ) -> Result<Self, String> {
        let event = Self {
            schema_version: EVENT_SCHEMA_VERSION.into(),
            event_id: event_id.into(),
            observed_at: observed_at.into(),
            monotonic_sequence: None,
            watcher_id: watcher_id.into(),
            target_identity_hash: target_hash.into(),
            agent_id: None,
            session_id: None,
            provider_family: None,
            source,
            category,
            confidence,
            terminal,
            evidence_fingerprint: fingerprint.into(),
            summary: summary.into(),
            redacted_evidence: None,
            reset: None,
            policy_hint,
            supersedes_event_id: None,
            metadata: BTreeMap::new(),
        };
        event.validate()?;
        Ok(event)
    }
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != EVENT_SCHEMA_VERSION {
            return Err("unsupported event schema version".into());
        }
        if !(0.0..=1.0).contains(&self.confidence) || !self.confidence.is_finite() {
            return Err("confidence outside 0..=1".into());
        }
        validate_id(&self.event_id)?;
        validate_id(&self.watcher_id)?;
        validate_hash(&self.target_identity_hash)?;
        validate_hash(&self.evidence_fingerprint)?;
        if self.summary.is_empty()
            || self.summary.len() > 1000
            || self.source.source_id.is_empty()
            || self.source.rule_or_field.is_empty()
        {
            return Err("invalid bounded event text".into());
        }
        if chrono::DateTime::parse_from_rfc3339(&self.observed_at).is_err()
            || self.source.source_id.len() > 256
            || self.source.rule_or_field.len() > 256
            || self
                .source
                .source_version
                .as_ref()
                .is_some_and(|value| value.len() > 128)
            || self.agent_id.as_ref().is_some_and(|value| value.len() > 64)
            || self
                .session_id
                .as_ref()
                .is_some_and(|value| value.len() > 256)
            || self
                .provider_family
                .as_ref()
                .is_some_and(|value| value.len() > 64)
            || self
                .redacted_evidence
                .as_ref()
                .is_some_and(|value| value.len() > 4000)
            || self
                .supersedes_event_id
                .as_ref()
                .is_some_and(|value| value.len() > 96)
            || self.metadata.values().any(|value| {
                !matches!(
                    value,
                    serde_json::Value::Null
                        | serde_json::Value::Bool(_)
                        | serde_json::Value::Number(_)
                        | serde_json::Value::String(_)
                )
            })
        {
            return Err("event violates schema bounds".into());
        }
        if let Some(reset) = &self.reset
            && (reset.source_text.is_empty()
                || reset.source_text.len() > 500
                || chrono::DateTime::parse_from_rfc3339(&reset.parsed_at).is_err()
                || !(0.0..=1.0).contains(&reset.confidence)
                || reset.margin_seconds.is_some_and(|margin| margin > 3600)
                || reset
                    .timezone
                    .as_ref()
                    .is_some_and(|value| value.len() > 128))
        {
            return Err("invalid reset".into());
        }
        if self.metadata.len() > 32 {
            return Err("too many metadata fields".into());
        }
        Ok(())
    }
}
fn validate_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .enumerate()
            .all(|(i, b)| b.is_ascii_alphanumeric() || (i > 0 && b"._:-".contains(&b)))
    {
        Err("invalid id".into())
    } else {
        Ok(())
    }
}
fn validate_hash(value: &str) -> Result<(), String> {
    if !(16..=128).contains(&value.len()) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Err("invalid hash".into())
    } else {
        Ok(())
    }
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: String,
            event_id: String,
            observed_at: String,
            #[serde(default)]
            monotonic_sequence: Option<u64>,
            watcher_id: String,
            target_identity_hash: String,
            #[serde(default)]
            agent_id: Option<String>,
            #[serde(default)]
            session_id: Option<String>,
            #[serde(default)]
            provider_family: Option<String>,
            source: EventSource,
            category: EventCategory,
            confidence: f64,
            terminal: bool,
            evidence_fingerprint: String,
            summary: String,
            #[serde(default)]
            redacted_evidence: Option<String>,
            #[serde(default)]
            reset: Option<EventReset>,
            policy_hint: PolicyHint,
            #[serde(default)]
            supersedes_event_id: Option<String>,
            #[serde(default)]
            metadata: BTreeMap<String, serde_json::Value>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let event = Self {
            schema_version: wire.schema_version,
            event_id: wire.event_id,
            observed_at: wire.observed_at,
            monotonic_sequence: wire.monotonic_sequence,
            watcher_id: wire.watcher_id,
            target_identity_hash: wire.target_identity_hash,
            agent_id: wire.agent_id,
            session_id: wire.session_id,
            provider_family: wire.provider_family,
            source: wire.source,
            category: wire.category,
            confidence: wire.confidence,
            terminal: wire.terminal,
            evidence_fingerprint: wire.evidence_fingerprint,
            summary: wire.summary,
            redacted_evidence: wire.redacted_evidence,
            reset: wire.reset,
            policy_hint: wire.policy_hint,
            supersedes_event_id: wire.supersedes_event_id,
            metadata: wire.metadata,
        };
        event.validate().map_err(D::Error::custom)?;
        Ok(event)
    }
}
