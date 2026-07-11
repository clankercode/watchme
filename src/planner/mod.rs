//! Constrained alternate-provider planner broker.

pub mod process;
pub mod router;
pub mod schema;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::{PlanningConfig, SecurityConfig};
use crate::error::WatchmeError;
use crate::model::Action;
use crate::planner::process::{PlannerProcessRequest, run_planner_process};
use crate::planner::router::{PlannerRouter, ResolvedPlanner};
use crate::planner::schema::{PlanValidationContext, decode_recovery_plan, validate_recovery_plan};
use crate::redact::{RedactionReport, redact_json, redact_text};

#[derive(Clone, Debug)]
pub struct SnapshotObservation {
    pub event_id: String,
    pub category: String,
    pub source_kind: String,
    pub confidence: f64,
    pub summary: String,
    pub observed_at: String,
}

#[derive(Clone, Debug)]
pub struct SnapshotBuildInput {
    pub snapshot_id: String,
    pub created_at: String,
    pub watcher_id: String,
    pub watcher_state: String,
    pub evidence_fingerprint: String,
    pub mux_kind: String,
    pub pane_id: String,
    pub process_pid: u32,
    pub process_start_time: String,
    pub identity_hash: String,
    pub agent_id: Option<String>,
    pub provider_family: Option<String>,
    pub failed_provider_family: String,
    pub terminal_text: Option<String>,
    pub observations: Vec<SnapshotObservation>,
    pub allowed_actions: Vec<String>,
    pub max_snapshot_bytes: usize,
    pub extra_secret_names: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotRedaction {
    pub performed: bool,
    pub replacement_count: usize,
    pub categories: Vec<String>,
    pub raw_evidence_included: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedactedSnapshot {
    pub schema_version: String,
    pub snapshot_id: String,
    pub created_at: String,
    pub watcher: SnapshotWatcher,
    pub target: SnapshotTarget,
    pub agent: SnapshotAgent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<SnapshotTerminal>,
    pub observations: Vec<SnapshotObservationJson>,
    pub attempts: Vec<Value>,
    pub allowed_actions: Vec<String>,
    pub redaction: SnapshotRedaction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotWatcher {
    pub watcher_id: String,
    pub state: String,
    pub evidence_fingerprint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotTarget {
    pub mux_kind: String,
    pub pane_id: String,
    pub process_pid: u32,
    pub process_start_time: String,
    pub identity_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotAgent {
    pub agent_id: Option<String>,
    pub provider_family: Option<String>,
    pub failed_provider_family: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotTerminal {
    pub source: String,
    pub line_count: u32,
    pub text: String,
    pub truncated: bool,
    pub ansi_removed: bool,
    pub control_sequences_removed: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotObservationJson {
    pub event_id: String,
    pub category: String,
    pub source_kind: String,
    pub confidence: f64,
    pub summary: String,
    pub observed_at: String,
}

/// Build a bounded, redacted planner snapshot.
pub fn build_redacted_snapshot(
    input: SnapshotBuildInput,
) -> Result<RedactedSnapshot, WatchmeError> {
    let mut report = RedactionReport::default();
    let mut terminal = None;
    if let Some(text) = input.terminal_text {
        let (redacted, partial) = redact_text(&text, &input.extra_secret_names);
        report.merge(&partial);
        let mut truncated = false;
        let mut bounded = redacted;
        // Keep terminal well under the snapshot budget.
        let terminal_budget = input.max_snapshot_bytes.saturating_mul(3) / 4;
        if bounded.len() > terminal_budget.max(256) {
            bounded.truncate(terminal_budget.max(256));
            while !bounded.is_char_boundary(bounded.len()) {
                bounded.pop();
            }
            truncated = true;
        }
        let line_count = bounded.lines().count().min(300) as u32;
        terminal = Some(SnapshotTerminal {
            source: "recent".into(),
            line_count,
            text: bounded,
            truncated,
            ansi_removed: true,
            control_sequences_removed: 0,
        });
    }

    let mut observations = Vec::new();
    for observation in input.observations.into_iter().take(32) {
        let (summary, partial) = redact_text(&observation.summary, &input.extra_secret_names);
        report.merge(&partial);
        observations.push(SnapshotObservationJson {
            event_id: observation.event_id,
            category: observation.category,
            source_kind: observation.source_kind,
            confidence: observation.confidence,
            summary,
            observed_at: observation.observed_at,
        });
    }
    if observations.is_empty() {
        return Err(WatchmeError::Configuration(
            "snapshot requires at least one observation".into(),
        ));
    }

    let mut categories: Vec<_> = report.categories.into_iter().collect();
    categories.sort();
    let snapshot = RedactedSnapshot {
        schema_version: "1.0".into(),
        snapshot_id: input.snapshot_id,
        created_at: input.created_at,
        watcher: SnapshotWatcher {
            watcher_id: input.watcher_id,
            state: input.watcher_state,
            evidence_fingerprint: input.evidence_fingerprint,
        },
        target: SnapshotTarget {
            mux_kind: input.mux_kind,
            pane_id: input.pane_id,
            process_pid: input.process_pid,
            process_start_time: input.process_start_time,
            identity_hash: input.identity_hash,
        },
        agent: SnapshotAgent {
            agent_id: input.agent_id,
            provider_family: input.provider_family,
            failed_provider_family: input.failed_provider_family,
        },
        terminal,
        observations,
        attempts: Vec::new(),
        allowed_actions: input.allowed_actions,
        redaction: SnapshotRedaction {
            performed: true,
            replacement_count: report.replacement_count,
            categories,
            raw_evidence_included: false,
        },
    };

    let encoded = serde_json::to_vec(&snapshot)
        .map_err(|error| WatchmeError::Configuration(error.to_string()))?;
    if encoded.len() > input.max_snapshot_bytes {
        return Err(WatchmeError::Configuration(format!(
            "snapshot exceeds max_snapshot_bytes ({})",
            input.max_snapshot_bytes
        )));
    }
    Ok(snapshot)
}

#[derive(Clone, Debug)]
pub struct PlannerRequest {
    pub session_id: String,
    pub event_id: String,
    pub failed_provider_family: String,
    pub snapshot_json: Value,
    pub day_key: String,
    pub resolved: Vec<ResolvedPlanner>,
}

#[derive(Clone, Debug)]
pub struct PlannerResult {
    pub planner_id: String,
    pub provider_family: String,
    pub actions: Vec<Action>,
    pub used_second_opinion: bool,
}

#[derive(Default)]
struct BudgetState {
    active: u32,
    per_event: HashMap<String, u32>,
    per_session_day: HashMap<(String, String), u32>,
}

/// Global planner broker with concurrency and daily/session budgets.
#[derive(Clone)]
pub struct PlannerBroker {
    planning: PlanningConfig,
    security: SecurityConfig,
    budgets: Arc<Mutex<BudgetState>>,
}

impl PlannerBroker {
    pub fn new(planning: PlanningConfig, security: SecurityConfig) -> Self {
        Self {
            planning,
            security,
            budgets: Arc::new(Mutex::new(BudgetState::default())),
        }
    }

    pub fn router(&self) -> PlannerRouter {
        PlannerRouter::new(self.planning.clone())
    }

    pub fn request_plan(&self, request: PlannerRequest) -> Result<PlannerResult, WatchmeError> {
        if !self.planning.enabled {
            return Err(WatchmeError::HumanRequired(
                "planning disabled; human required".into(),
            ));
        }
        if request.resolved.is_empty() {
            return Err(WatchmeError::HumanRequired(
                "no independent planner available".into(),
            ));
        }

        self.acquire_budget(&request)?;
        let result = self.invoke_with_optional_fallback(&request);
        self.release_concurrency();
        match result {
            Ok(plan) => {
                self.commit_budget(&request);
                Ok(plan)
            }
            Err(error) => Err(error),
        }
    }

    fn acquire_budget(&self, request: &PlannerRequest) -> Result<(), WatchmeError> {
        let mut budgets = self.budgets.lock().expect("planner budget lock");
        if budgets.active >= self.planning.max_concurrent_calls {
            return Err(WatchmeError::PolicyDenied(
                "planner concurrency budget denied".into(),
            ));
        }
        let event_count = budgets
            .per_event
            .get(&request.event_id)
            .copied()
            .unwrap_or(0);
        if event_count >= self.planning.max_calls_per_event {
            return Err(WatchmeError::PolicyDenied(
                "planner per-event budget denied".into(),
            ));
        }
        let session_key = (request.session_id.clone(), request.day_key.clone());
        let session_count = budgets
            .per_session_day
            .get(&session_key)
            .copied()
            .unwrap_or(0);
        if session_count >= self.planning.max_calls_per_session_per_day {
            return Err(WatchmeError::PolicyDenied(
                "planner per-session daily budget denied".into(),
            ));
        }
        budgets.active += 1;
        Ok(())
    }

    fn commit_budget(&self, request: &PlannerRequest) {
        let mut budgets = self.budgets.lock().expect("planner budget lock");
        *budgets
            .per_event
            .entry(request.event_id.clone())
            .or_insert(0) += 1;
        *budgets
            .per_session_day
            .entry((request.session_id.clone(), request.day_key.clone()))
            .or_insert(0) += 1;
    }

    fn release_concurrency(&self) {
        let mut budgets = self.budgets.lock().expect("planner budget lock");
        budgets.active = budgets.active.saturating_sub(1);
    }

    fn invoke_with_optional_fallback(
        &self,
        request: &PlannerRequest,
    ) -> Result<PlannerResult, WatchmeError> {
        let (redacted_snapshot, _) =
            redact_json(&request.snapshot_json, &self.security.extra_secret_names);
        let mut last_error = WatchmeError::HumanRequired("no planner succeeded".into());
        let max_attempts = if self.planning.allow_independent_second_opinion {
            2.min(request.resolved.len())
        } else {
            1.min(request.resolved.len())
        };

        for (index, planner) in request.resolved.iter().take(max_attempts).enumerate() {
            match self.invoke_one(planner, &redacted_snapshot, &request.failed_provider_family) {
                Ok(actions) => {
                    return Ok(PlannerResult {
                        planner_id: planner.id.clone(),
                        provider_family: planner.provider_family.clone(),
                        actions,
                        used_second_opinion: index > 0,
                    });
                }
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    fn invoke_one(
        &self,
        planner: &ResolvedPlanner,
        snapshot: &Value,
        failed_family: &str,
    ) -> Result<Vec<Action>, WatchmeError> {
        let cwd = tempfile::tempdir()
            .map_err(|error| WatchmeError::RetryableIntegration(error.to_string()))?;
        let stdin = serde_json::to_vec(snapshot)
            .map_err(|error| WatchmeError::Configuration(error.to_string()))?;
        let output = run_planner_process(&PlannerProcessRequest {
            executable: planner.executable.clone(),
            args: planner.args.clone(),
            cwd: cwd.path().to_path_buf(),
            stdin,
            timeout: Duration::from_secs(self.planning.timeout_seconds.max(1)),
            max_output_bytes: self.planning.max_output_bytes as usize,
            extra_env: BTreeMap::new(),
        })
        .map_err(|error| {
            if error.is_timeout() {
                WatchmeError::RetryableIntegration(error.to_string())
            } else if error.is_output_limit() {
                WatchmeError::PolicyDenied(error.to_string())
            } else {
                WatchmeError::RetryableIntegration(error.to_string())
            }
        })?;

        let text = String::from_utf8_lossy(&output.stdout);
        let plan = decode_recovery_plan(text.trim()).map_err(|error| {
            WatchmeError::PolicyDenied(format!("planner schema rejected: {error}"))
        })?;
        let context = PlanValidationContext {
            failed_provider_family: failed_family.to_owned(),
            planner_provider_family: planner.provider_family.clone(),
            evidence_fingerprint: plan.target.evidence_fingerprint.clone(),
            watcher_id: plan.target.watcher_id.clone(),
            process_pid: plan.target.process_pid,
            process_start_time: plan.target.process_start_time.clone(),
            mux_kind: plan.target.mux_kind.clone(),
            pane_id: plan.target.pane_id.clone(),
            now_rfc3339: plan.generated_at.clone(),
            allowed_actions: BTreeSet::from([
                "WAIT_UNTIL".into(),
                "WAIT_DURATION".into(),
                "CAPTURE".into(),
                "CHECK_STATUS".into(),
                "SEND_TEXT".into(),
                "SEND_KEYS".into(),
                "NOTIFY".into(),
                "ESCALATE".into(),
                "STOP_WATCHING".into(),
                "NOOP".into(),
            ]),
        };
        // Ensure plan family matches the selected planner and differs from failed.
        if plan.diagnosis.planner_provider_family != planner.provider_family {
            return Err(WatchmeError::PolicyDenied(
                "planner family mismatch in plan".into(),
            ));
        }
        validate_recovery_plan(&plan, &context)
            .map_err(|error| WatchmeError::PolicyDenied(error.to_string()))
    }
}
