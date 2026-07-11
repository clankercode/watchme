use serde::Serialize;
use thiserror::Error;

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Error)]
#[allow(
    dead_code,
    reason = "milestone establishes the complete error taxonomy"
)]
pub enum WatchmeError {
    #[error("unsupported context: {0}")]
    UnsupportedContext(String),
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("target terminated: {0}")]
    TargetTerminated(String),
    #[error("retryable integration failure: {0}")]
    RetryableIntegration(String),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("human action required: {0}")]
    HumanRequired(String),
    #[error("capability unavailable: {message}")]
    CapabilityUnavailable { message: String, json: bool },
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    schema_version: &'static str,
    ok: bool,
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'static str,
    message: &'a str,
}

impl WatchmeError {
    pub fn render(&self) {
        if let Self::CapabilityUnavailable {
            message,
            json: true,
        } = self
        {
            let envelope = ErrorEnvelope {
                schema_version: SCHEMA_VERSION,
                ok: false,
                error: ErrorBody {
                    code: "capability_unavailable",
                    message,
                },
            };
            println!(
                "{}",
                serde_json::to_string(&envelope).expect("error envelope is serializable")
            );
        } else {
            eprintln!("watchme: {self}");
        }
    }
}
