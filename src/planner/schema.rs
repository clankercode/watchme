//! Strict recovery-plan JSON decoding and policy-facing validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Deserialize;
use serde_json::Value;

use crate::model::{Action, ActionKind};
use crate::policy::{CompiledPolicy, PolicyContext};

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPlan {
    pub schema_version: String,
    pub plan_id: String,
    pub generated_at: String,
    pub valid_until: String,
    pub target: PlanTarget,
    pub diagnosis: PlanDiagnosis,
    pub actions: Vec<Action>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanTarget {
    pub watcher_id: String,
    pub process_pid: u32,
    pub process_start_time: String,
    pub mux_kind: String,
    #[serde(default)]
    pub mux_server_id: Option<String>,
    pub pane_id: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    pub evidence_fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDiagnosis {
    pub category: String,
    pub confidence: f64,
    pub summary: String,
    pub failed_provider_family: String,
    pub planner_provider_family: String,
    pub human_required: bool,
    #[serde(default)]
    pub uncertainties: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PlanValidationContext {
    pub failed_provider_family: String,
    pub planner_provider_family: String,
    pub evidence_fingerprint: String,
    pub watcher_id: String,
    pub process_pid: u32,
    pub process_start_time: String,
    pub mux_kind: String,
    pub pane_id: String,
    pub now_rfc3339: String,
    pub allowed_actions: BTreeSet<String>,
}

#[derive(Debug)]
pub struct SchemaError {
    message: String,
}

impl SchemaError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SchemaError {}

/// Parse JSON while rejecting duplicate object keys at any depth.
pub fn from_str_strict(input: &str) -> Result<Value, SchemaError> {
    parse_rejecting_duplicates(input)
}

fn parse_rejecting_duplicates(input: &str) -> Result<Value, SchemaError> {
    let mut parser = StrictParser {
        bytes: input.as_bytes(),
        index: 0,
    };
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.index != parser.bytes.len() {
        return Err(SchemaError::new("trailing data after JSON value"));
    }
    Ok(value)
}

struct StrictParser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> StrictParser<'a> {
    fn skip_ws(&mut self) {
        while self
            .bytes
            .get(self.index)
            .is_some_and(|b| b.is_ascii_whitespace())
        {
            self.index += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn bump(&mut self) -> Result<u8, SchemaError> {
        let byte = self
            .peek()
            .ok_or_else(|| SchemaError::new("unexpected end of JSON"))?;
        self.index += 1;
        Ok(byte)
    }

    fn parse_value(&mut self) -> Result<Value, SchemaError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b't') => self.parse_literal(b"true", Value::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", Value::Bool(false)),
            Some(b'n') => self.parse_literal(b"null", Value::Null),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(other) => Err(SchemaError::new(format!(
                "unexpected JSON byte {}",
                other as char
            ))),
            None => Err(SchemaError::new("empty JSON")),
        }
    }

    fn parse_literal(&mut self, expected: &[u8], value: Value) -> Result<Value, SchemaError> {
        for &byte in expected {
            if self.bump()? != byte {
                return Err(SchemaError::new("invalid JSON literal"));
            }
        }
        Ok(value)
    }

    fn parse_object(&mut self) -> Result<Value, SchemaError> {
        assert_eq!(self.bump()?, b'{');
        self.skip_ws();
        let mut map = BTreeMap::new();
        if self.peek() == Some(b'}') {
            self.index += 1;
            return Ok(Value::Object(map.into_iter().collect()));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(SchemaError::new("object key must be a string"));
            }
            let key = self.parse_string()?;
            if map.contains_key(&key) {
                return Err(SchemaError::new(format!("duplicate key: {key}")));
            }
            self.skip_ws();
            if self.bump()? != b':' {
                return Err(SchemaError::new("expected ':' after object key"));
            }
            let value = self.parse_value()?;
            map.insert(key, value);
            self.skip_ws();
            match self.bump()? {
                b',' => continue,
                b'}' => break,
                _ => return Err(SchemaError::new("expected ',' or '}' in object")),
            }
        }
        Ok(Value::Object(map.into_iter().collect()))
    }

    fn parse_array(&mut self) -> Result<Value, SchemaError> {
        assert_eq!(self.bump()?, b'[');
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.index += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.bump()? {
                b',' => continue,
                b']' => break,
                _ => return Err(SchemaError::new("expected ',' or ']' in array")),
            }
        }
        Ok(Value::Array(items))
    }

    fn parse_string(&mut self) -> Result<String, SchemaError> {
        let start = self.index;
        if self.bump()? != b'"' {
            return Err(SchemaError::new("expected string"));
        }
        loop {
            match self.bump()? {
                b'"' => break,
                b'\\' => {
                    let escaped = self.bump()?;
                    if escaped == b'u' {
                        for _ in 0..4 {
                            let digit = self.bump()?;
                            if !digit.is_ascii_hexdigit() {
                                return Err(SchemaError::new("invalid unicode escape"));
                            }
                        }
                    }
                }
                byte if byte < 0x20 => return Err(SchemaError::new("control character in string")),
                _ => {}
            }
        }
        let literal = std::str::from_utf8(&self.bytes[start..self.index])
            .map_err(|_| SchemaError::new("invalid utf-8 string"))?;
        serde_json::from_str(literal).map_err(|error| SchemaError::new(error.to_string()))
    }

    fn parse_number(&mut self) -> Result<Value, SchemaError> {
        let start = self.index;
        if self.peek() == Some(b'-') {
            self.index += 1;
        }
        if self.peek() == Some(b'0') {
            self.index += 1;
        } else if self.peek().is_some_and(|b| b.is_ascii_digit()) {
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.index += 1;
            }
        } else {
            return Err(SchemaError::new("invalid number"));
        }
        if self.peek() == Some(b'.') {
            self.index += 1;
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(SchemaError::new("invalid number"));
            }
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.index += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.index += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.index += 1;
            }
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(SchemaError::new("invalid exponent"));
            }
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.index += 1;
            }
        }
        let slice = std::str::from_utf8(&self.bytes[start..self.index])
            .map_err(|_| SchemaError::new("invalid number encoding"))?;
        serde_json::from_str(slice).map_err(|error| SchemaError::new(error.to_string()))
    }
}

/// Decode a recovery plan with duplicate-key rejection and schema bounds.
pub fn decode_recovery_plan(input: &str) -> Result<RecoveryPlan, SchemaError> {
    let value = parse_rejecting_duplicates(input)?;
    let plan: RecoveryPlan =
        serde_json::from_value(value).map_err(|error| SchemaError::new(error.to_string()))?;
    validate_plan_bounds(&plan)?;
    Ok(plan)
}

fn validate_plan_bounds(plan: &RecoveryPlan) -> Result<(), SchemaError> {
    if plan.schema_version != "1.0" {
        return Err(SchemaError::new("unsupported schema_version"));
    }
    if plan.actions.len() > 12 {
        return Err(SchemaError::new("too many actions"));
    }
    if plan.diagnosis.summary.is_empty() || plan.diagnosis.summary.len() > 1000 {
        return Err(SchemaError::new("diagnosis summary bounds"));
    }
    if !(0.0..=1.0).contains(&plan.diagnosis.confidence) {
        return Err(SchemaError::new("confidence bounds"));
    }
    if plan.target.evidence_fingerprint.len() < 16
        || plan.target.evidence_fingerprint.len() > 128
        || !plan
            .target
            .evidence_fingerprint
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(SchemaError::new("evidence fingerprint bounds"));
    }
    for action in &plan.actions {
        action
            .validate()
            .map_err(|error| SchemaError::new(error.to_string()))?;
    }
    Ok(())
}

/// Validate a decoded plan against target/evidence/family policy and return actions.
pub fn validate_recovery_plan(
    plan: &RecoveryPlan,
    context: &PlanValidationContext,
) -> Result<Vec<Action>, SchemaError> {
    if plan.diagnosis.failed_provider_family != context.failed_provider_family {
        return Err(SchemaError::new("failed provider family mismatch"));
    }
    if plan.diagnosis.planner_provider_family != context.planner_provider_family {
        return Err(SchemaError::new("planner provider family mismatch"));
    }
    if plan.diagnosis.planner_provider_family == plan.diagnosis.failed_provider_family {
        return Err(SchemaError::new("same-provider planner plan rejected"));
    }
    if plan.target.evidence_fingerprint != context.evidence_fingerprint
        || plan.target.watcher_id != context.watcher_id
        || plan.target.process_pid != context.process_pid
        || plan.target.process_start_time != context.process_start_time
        || plan.target.mux_kind != context.mux_kind
        || plan.target.pane_id != context.pane_id
    {
        return Err(SchemaError::new("target or evidence mismatch"));
    }
    let generated = chrono::DateTime::parse_from_rfc3339(&plan.generated_at)
        .map_err(|_| SchemaError::new("invalid generated_at"))?;
    let valid_until = chrono::DateTime::parse_from_rfc3339(&plan.valid_until)
        .map_err(|_| SchemaError::new("invalid valid_until"))?;
    let now = chrono::DateTime::parse_from_rfc3339(&context.now_rfc3339)
        .map_err(|_| SchemaError::new("invalid now"))?;
    if now > valid_until || generated > valid_until {
        return Err(SchemaError::new("plan expired or stale"));
    }

    let policy = CompiledPolicy;
    let mut policy_context = PolicyContext::safe();
    policy_context.evidence_fingerprint = Some(context.evidence_fingerprint.clone());
    policy_context.failed_provider_family = Some(context.failed_provider_family.clone());
    policy_context.planner_provider_family = Some(context.planner_provider_family.clone());
    policy_context.goal_state = Some("blocked".into());
    policy_context.wall_time_rfc3339 = Some(context.now_rfc3339.clone());

    let mut actions = Vec::with_capacity(plan.actions.len());
    for action in &plan.actions {
        let type_name = action_type_name(&action.kind);
        if !context.allowed_actions.contains(type_name) {
            return Err(SchemaError::new(format!(
                "action type not allowlisted: {type_name}"
            )));
        }
        if matches!(
            &action.kind,
            ActionKind::SendText { text } | ActionKind::SubmitText { text }
                if prohibited_text(text)
        ) {
            return Err(SchemaError::new("prohibited send text"));
        }
        policy
            .authorize(action, &policy_context)
            .map_err(|error| SchemaError::new(error.to_string()))?;
        actions.push(action.clone());
    }
    Ok(actions)
}

fn action_type_name(kind: &ActionKind) -> &'static str {
    match kind {
        ActionKind::WaitUntil { .. } => "WAIT_UNTIL",
        ActionKind::WaitDuration { .. } => "WAIT_DURATION",
        ActionKind::Capture { .. } => "CAPTURE",
        ActionKind::CheckStatus { .. } => "CHECK_STATUS",
        ActionKind::SendText { .. } => "SEND_TEXT",
        ActionKind::SubmitText { .. } => "SUBMIT_TEXT",
        ActionKind::SendKeys { .. } => "SEND_KEYS",
        ActionKind::Notify { .. } => "NOTIFY",
        ActionKind::Escalate { .. } => "ESCALATE",
        ActionKind::StopWatching => "STOP_WATCHING",
        ActionKind::Noop => "NOOP",
    }
}

fn prohibited_text(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("http://")
        || lower.contains("https://")
        || [
            "login",
            "sign in",
            "billing",
            "fund",
            "credit",
            "upgrade",
            "approve",
            "permission",
            "yolo",
            "sudo",
            "rm -rf",
            "password",
            "token",
            "secret",
            "curl ",
            "/bin/sh",
            "shell",
        ]
        .iter()
        .any(|word| lower.contains(word))
}
