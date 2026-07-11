use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use crate::error::WatchmeError;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Status(IdAndJson),
    List(JsonOutput),
    Explain(OptionalId),
    Snapshot(SnapshotOptions),
    Logs(LogOptions),
    Stop(StopOptions),
    Doctor(DoctorOptions),
    Providers(JsonOutput),
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
}

#[derive(Debug, Args)]
struct OptionalId {
    id: Option<String>,
}

#[derive(Debug, Args)]
struct IdAndJson {
    id: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct JsonOutput {
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct SnapshotOptions {
    id: Option<String>,
    #[arg(long)]
    redacted: bool,
}

#[derive(Debug, Args)]
struct LogOptions {
    id: Option<String>,
    #[arg(long)]
    follow: bool,
}

#[derive(Debug, Args)]
struct StopOptions {
    id: Option<String>,
    #[arg(long, conflicts_with = "id")]
    all: bool,
}

#[derive(Debug, Args)]
struct DoctorOptions {
    #[arg(long)]
    strict: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Path,
    Check,
    Show,
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    Run,
    Status,
    Stop,
}

const SCHEMA_VERSION: &str = "1.0";

pub struct CliFailure {
    error: WatchmeError,
    json: bool,
}

#[derive(Serialize)]
struct ErrorEnvelope {
    schema_version: &'static str,
    ok: bool,
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

impl CliFailure {
    pub fn render(&self) {
        if self.json {
            println!("{}", self.json_line());
        } else {
            eprintln!("watchme: {}", self.error);
        }
    }

    fn json_line(&self) -> String {
        let envelope = ErrorEnvelope {
            schema_version: SCHEMA_VERSION,
            ok: false,
            error: ErrorBody {
                code: self.error.code(),
                message: self.error.message().to_owned(),
            },
        };
        serde_json::to_string(&envelope).expect("error envelope is serializable")
    }
}

impl From<WatchmeError> for CliFailure {
    fn from(error: WatchmeError) -> Self {
        Self { error, json: false }
    }
}

pub fn run() -> Result<(), CliFailure> {
    let cli = Cli::parse();
    match cli.command {
        None => register_current_context().map_err(Into::into),
        Some(command) => Err(unavailable(command)),
    }
}

fn register_current_context() -> Result<(), WatchmeError> {
    register_with_detector(&ProductionContextDetector)
}

fn register_with_detector(detector: &impl RegistrationContextDetector) -> Result<(), WatchmeError> {
    match detector.detect() {
        Some(context) => attempt_registration(context),
        None => Err(WatchmeError::UnsupportedContext(
            "invoke WatchMe normally as !watchme from a supported coding-agent session; run `watchme doctor` for diagnostics"
                .to_owned(),
        )),
    }
}

#[derive(Clone, Copy, Debug)]
struct AgentContext;

trait RegistrationContextDetector {
    fn detect(&self) -> Option<AgentContext>;
}

struct ProductionContextDetector;

impl RegistrationContextDetector for ProductionContextDetector {
    fn detect(&self) -> Option<AgentContext> {
        // Process ancestry verification is introduced in the discovery milestone.
        None
    }
}

fn attempt_registration(_context: AgentContext) -> Result<(), WatchmeError> {
    Err(WatchmeError::CapabilityUnavailable(
        "registration is not implemented yet".to_owned(),
    ))
}

fn unavailable(command: Command) -> CliFailure {
    let json = match command {
        Command::Status(options) => options.json,
        Command::List(options) | Command::Providers(options) => options.json,
        Command::Doctor(options) => options.json,
        _ => false,
    };
    CliFailure {
        error: WatchmeError::CapabilityUnavailable(
            "this administrative capability is not implemented yet".to_owned(),
        ),
        json,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedContextDetector;

    impl RegistrationContextDetector for FixedContextDetector {
        fn detect(&self) -> Option<AgentContext> {
            Some(AgentContext)
        }
    }

    #[test]
    fn detected_context_reaches_registration_attempt_boundary() {
        let error = register_with_detector(&FixedContextDetector)
            .expect_err("registration is not implemented in this milestone");

        assert!(matches!(error, WatchmeError::CapabilityUnavailable(_)));
        assert_eq!(
            error.to_string(),
            "capability unavailable: registration is not implemented yet"
        );
    }

    #[test]
    fn json_renderer_handles_every_typed_error() {
        let errors = [
            WatchmeError::UnsupportedContext("x".into()),
            WatchmeError::Configuration("x".into()),
            WatchmeError::TargetTerminated("x".into()),
            WatchmeError::RetryableIntegration("x".into()),
            WatchmeError::PolicyDenied("x".into()),
            WatchmeError::HumanRequired("x".into()),
            WatchmeError::CapabilityUnavailable("x".into()),
        ];

        for error in errors {
            let expected_code = error.code();
            let rendered = CliFailure { error, json: true }.json_line();
            let value: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
            assert_eq!(value["schema_version"], "1.0");
            assert_eq!(value["ok"], false);
            assert_eq!(value["error"]["code"], expected_code);
            assert_eq!(value["error"]["message"], "x");
        }
    }
}
