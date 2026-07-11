use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusCheck {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ActionKind {
    WaitUntil { at: String },
    WaitDuration { duration_seconds: u64 },
    Capture { source: String, max_lines: u16 },
    CheckStatus { check: StatusCheck },
    SendText { text: String },
    SendKeys { keys: Vec<String> },
    Notify { severity: String, message: String },
    Escalate { level: String },
    StopWatching,
    Noop,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Action {
    #[serde(flatten)]
    pub kind: ActionKind,
    pub action_id: String,
    pub reason: String,
    pub preconditions: Vec<Condition>,
    pub expected_outcomes: Vec<Condition>,
    pub timeout_seconds: u64,
}

impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let mut object = serde_json::Map::deserialize(deserializer)?;
        let action_id = take(&mut object, "action_id").map_err(D::Error::custom)?;
        let reason = take(&mut object, "reason").map_err(D::Error::custom)?;
        let preconditions = take(&mut object, "preconditions").map_err(D::Error::custom)?;
        let expected_outcomes = take(&mut object, "expected_outcomes").map_err(D::Error::custom)?;
        let timeout_seconds = take(&mut object, "timeout_seconds").map_err(D::Error::custom)?;
        let kind =
            serde_json::from_value(serde_json::Value::Object(object)).map_err(D::Error::custom)?;
        let action = Self {
            kind,
            action_id,
            reason,
            preconditions,
            expected_outcomes,
            timeout_seconds,
        };
        action.validate().map_err(D::Error::custom)?;
        Ok(action)
    }
}

fn take<T: serde::de::DeserializeOwned>(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<T, serde_json::Error> {
    serde_json::from_value(object.remove(key).unwrap_or(serde_json::Value::Null))
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
            action_id: id.into(),
            kind,
            reason: reason.into(),
            preconditions: vec![Condition {
                kind: "EVIDENCE_FINGERPRINT_MATCHES".into(),
                value: Some(serde_json::Value::String(fingerprint.into())),
            }],
            expected_outcomes: vec![Condition {
                kind: "NO_STATE_CHANGE_EXPECTED".into(),
                value: None,
            }],
            timeout_seconds,
        }
    }

    pub fn send_text(
        id: impl Into<String>,
        text: impl Into<String>,
        reason: impl Into<String>,
        fingerprint: impl Into<String>,
    ) -> Self {
        let mut action = Self::new(
            id,
            ActionKind::SendText { text: text.into() },
            reason,
            fingerprint.into(),
            30,
        );
        action.preconditions.push(Condition {
            kind: "TARGET_IDENTITY_MATCHES".into(),
            value: None,
        });
        action
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if !valid_id(&self.action_id)
            || self.action_id.len() > 96
            || self.reason.is_empty()
            || self.reason.len() > 500
            || self.timeout_seconds == 0
            || self.timeout_seconds > 86_400
        {
            return Err("invalid common action fields");
        }
        if self.preconditions.len() > 12
            || self.expected_outcomes.is_empty()
            || self.expected_outcomes.len() > 6
        {
            return Err("invalid action conditions");
        }
        if !self.preconditions.iter().all(valid_precondition)
            || !self.expected_outcomes.iter().all(valid_outcome)
        {
            return Err("invalid condition kind or value");
        }
        match &self.kind {
            ActionKind::WaitUntil { at } if valid_datetime(at) => Ok(()),
            ActionKind::WaitDuration { duration_seconds }
                if (1..=86_400).contains(duration_seconds) =>
            {
                Ok(())
            }
            ActionKind::Capture { source, max_lines }
                if matches!(
                    source.as_str(),
                    "screen_detection" | "screen_recent" | "structured_state" | "log_tail"
                ) && (1..=300).contains(max_lines) =>
            {
                Ok(())
            }
            ActionKind::CheckStatus { check } if valid_check(check) => Ok(()),
            ActionKind::SendText { text }
                if !self.preconditions.is_empty() && !text.is_empty() && text.len() <= 512 =>
            {
                Ok(())
            }
            ActionKind::SendKeys { keys }
                if !self.preconditions.is_empty()
                    && !keys.is_empty()
                    && keys.len() <= 16
                    && keys.iter().all(|key| valid_key(key)) =>
            {
                Ok(())
            }
            ActionKind::Notify { severity, message }
                if matches!(severity.as_str(), "info" | "warning" | "error" | "critical")
                    && !message.is_empty()
                    && message.len() <= 500 =>
            {
                Ok(())
            }
            ActionKind::Escalate { level }
                if matches!(
                    level.as_str(),
                    "alternate_planner" | "independent_second_opinion" | "human_required"
                ) =>
            {
                Ok(())
            }
            ActionKind::StopWatching | ActionKind::Noop => Ok(()),
            _ => Err("invalid action variant fields"),
        }
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && b"._:-".contains(&byte))
        })
}
fn scalar_value(condition: &Condition) -> bool {
    condition.value.as_ref().is_none_or(|value| match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => true,
        serde_json::Value::String(text) => text.len() <= 256,
        _ => false,
    })
}
fn valid_precondition(condition: &Condition) -> bool {
    scalar_value(condition)
        && matches!(
            condition.kind.as_str(),
            "TARGET_IDENTITY_MATCHES"
                | "PROCESS_ALIVE"
                | "SESSION_ID_MATCHES"
                | "EVIDENCE_FINGERPRINT_MATCHES"
                | "COMPOSER_EMPTY"
                | "MENU_STABLE"
                | "AGENT_STATE_IS"
                | "GOAL_STATE_IS"
                | "EVENT_CATEGORY_IS"
                | "NO_HUMAN_INTERVENTION"
                | "CURRENT_TIME_AT_OR_AFTER"
        )
}
fn valid_outcome(condition: &Condition) -> bool {
    scalar_value(condition)
        && matches!(
            condition.kind.as_str(),
            "AGENT_WORKING"
                | "AGENT_IDLE"
                | "BLOCK_CLEARED"
                | "GOAL_ACTIVE_OR_PURSUING"
                | "MENU_DISMISSED"
                | "WAIT_STATE_RECORDED"
                | "PROCESS_TERMINATED"
                | "HUMAN_NOTIFIED"
                | "NO_STATE_CHANGE_EXPECTED"
        )
}

fn valid_datetime(value: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(value).is_ok()
}
fn valid_key(key: &str) -> bool {
    matches!(
        key,
        "ENTER"
            | "ESCAPE"
            | "UP"
            | "DOWN"
            | "LEFT"
            | "RIGHT"
            | "TAB"
            | "BACKTAB"
            | "CTRL_C"
            | "CTRL_D"
            | "CTRL_L"
            | "HOME"
            | "END"
            | "PAGE_UP"
            | "PAGE_DOWN"
    )
}
fn valid_check(check: &StatusCheck) -> bool {
    matches!(
        check.kind.as_str(),
        "PROCESS_ALIVE"
            | "TARGET_IDENTITY"
            | "AGENT_STATE"
            | "GOAL_STATE"
            | "EVENT_CLEARED"
            | "COMPOSER_EMPTY"
            | "SCREEN_CONTAINS_LITERAL"
            | "SCREEN_NOT_CONTAINS_LITERAL"
    ) && check.value.as_ref().is_none_or(|value| value.len() <= 256)
}
