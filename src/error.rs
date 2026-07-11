use thiserror::Error;

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
    #[error("capability unavailable: {0}")]
    CapabilityUnavailable(String),
}

impl WatchmeError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedContext(_) => "unsupported_context",
            Self::Configuration(_) => "configuration",
            Self::TargetTerminated(_) => "target_terminated",
            Self::RetryableIntegration(_) => "retryable_integration",
            Self::PolicyDenied(_) => "policy_denied",
            Self::HumanRequired(_) => "human_required",
            Self::CapabilityUnavailable(_) => "capability_unavailable",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::UnsupportedContext(message)
            | Self::Configuration(message)
            | Self::TargetTerminated(message)
            | Self::RetryableIntegration(message)
            | Self::PolicyDenied(message)
            | Self::HumanRequired(message)
            | Self::CapabilityUnavailable(message) => message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_errors_have_stable_codes() {
        let cases = [
            (
                WatchmeError::UnsupportedContext("x".into()),
                "unsupported_context",
            ),
            (WatchmeError::Configuration("x".into()), "configuration"),
            (
                WatchmeError::TargetTerminated("x".into()),
                "target_terminated",
            ),
            (
                WatchmeError::RetryableIntegration("x".into()),
                "retryable_integration",
            ),
            (WatchmeError::PolicyDenied("x".into()), "policy_denied"),
            (WatchmeError::HumanRequired("x".into()), "human_required"),
            (
                WatchmeError::CapabilityUnavailable("x".into()),
                "capability_unavailable",
            ),
        ];

        for (error, expected_code) in cases {
            assert_eq!(error.code(), expected_code);
            assert_eq!(error.message(), "x");
        }
    }
}
