use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

pub const ACTION_SCHEMA_VERSION: &str = "1.0";
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ActionKind {
    WaitDuration { duration_seconds: u64 },
    Capture { max_lines: u16 },
    CheckStatus { check: String },
    SendText { text: String },
    SendKeys { keys: Vec<String> },
    Notify { message: String },
    Escalate { level: String },
    StopWatching,
    Noop,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Action {
    pub schema_version: String,
    pub action_id: String,
    #[serde(flatten)]
    pub kind: ActionKind,
    pub reason: String,
    pub evidence_fingerprint: String,
    pub timeout_seconds: u64,
}
impl Action {
    pub fn new(
        id: impl Into<String>,
        kind: ActionKind,
        reason: impl Into<String>,
        fingerprint: impl Into<String>,
        timeout_seconds: u64,
    ) -> Self {
        Self {
            schema_version: ACTION_SCHEMA_VERSION.into(),
            action_id: id.into(),
            kind,
            reason: reason.into(),
            evidence_fingerprint: fingerprint.into(),
            timeout_seconds,
        }
    }
    pub fn send_text(
        id: impl Into<String>,
        text: impl Into<String>,
        reason: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self::new(
            id,
            ActionKind::SendText { text: text.into() },
            reason,
            fingerprint,
            30,
        )
    }
}
impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: String,
            action_id: String,
            #[serde(flatten)]
            kind: ActionKind,
            reason: String,
            evidence_fingerprint: String,
            timeout_seconds: u64,
        }
        let w = Wire::deserialize(d)?;
        if w.schema_version != ACTION_SCHEMA_VERSION
            || w.action_id.is_empty()
            || w.timeout_seconds == 0
            || w.timeout_seconds > 86400
        {
            return Err(D::Error::custom("invalid action"));
        }
        Ok(Self {
            schema_version: w.schema_version,
            action_id: w.action_id,
            kind: w.kind,
            reason: w.reason,
            evidence_fingerprint: w.evidence_fingerprint,
            timeout_seconds: w.timeout_seconds,
        })
    }
}
