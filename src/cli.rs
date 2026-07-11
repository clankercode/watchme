use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

use watchme::daemon;
use watchme::ipc::protocol::{Request, Response};
use watchme::ipc::{read_response, write_request};
use watchme::paths::WatchmePaths;

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
        Some(Command::Status(options)) => admin(Request::Status, options.json),
        Some(Command::List(options)) => admin(Request::List, options.json),
        Some(Command::Stop(options)) => admin(
            Request::Stop {
                id: options.id,
                all: options.all,
            },
            false,
        ),
        Some(Command::Daemon {
            command: DaemonCommand::Run,
        }) => run_daemon(),
        Some(Command::Daemon {
            command: DaemonCommand::Status,
        }) => admin(Request::Status, false),
        Some(Command::Daemon {
            command: DaemonCommand::Stop,
        }) => admin(Request::Shutdown, false),
        Some(command) => Err(unavailable(command)),
    }
}

fn runtime_paths() -> Result<WatchmePaths, CliFailure> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| WatchmeError::Configuration("HOME is not set".into()))?;
    let config = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let state = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from);
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    WatchmePaths::resolve(
        Path::new(&home),
        config.as_deref(),
        state.as_deref(),
        runtime.as_deref(),
    )
    .map_err(|error| WatchmeError::Configuration(error.to_string()).into())
}

fn local_runtime() -> Result<tokio::runtime::Runtime, CliFailure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| WatchmeError::RetryableIntegration(error.to_string()).into())
}

fn run_daemon() -> Result<(), CliFailure> {
    let paths = runtime_paths()?;
    local_runtime()?
        .block_on(daemon::run(&paths, Duration::from_secs(30), false))
        .map_err(|error| WatchmeError::RetryableIntegration(error.to_string()).into())
}

fn admin(request: Request, json: bool) -> Result<(), CliFailure> {
    let paths = runtime_paths()?;
    let socket = paths.runtime_dir().join("daemon.sock");
    let response = local_runtime()?
        .block_on(async {
            let mut stream = tokio::net::UnixStream::connect(socket).await?;
            write_request(&mut stream, &request, Duration::from_secs(2))
                .await
                .map_err(std::io::Error::other)?;
            read_response(&mut stream, Duration::from_secs(2))
                .await
                .map_err(std::io::Error::other)
        })
        .map_err(|error| CliFailure {
            error: WatchmeError::RetryableIntegration(format!("daemon unavailable: {error}")),
            json,
        })?;
    render_response(response, json)
}

fn render_response(response: Response, json: bool) -> Result<(), CliFailure> {
    if json {
        #[derive(Serialize)]
        struct SuccessEnvelope<'a> {
            schema_version: &'static str,
            ok: bool,
            response: &'a Response,
        }
        println!(
            "{}",
            serde_json::to_string(&SuccessEnvelope {
                schema_version: SCHEMA_VERSION,
                ok: true,
                response: &response
            })
            .expect("response is serializable")
        );
        return Ok(());
    }
    match response {
        Response::Status { running, watchers } => println!(
            "daemon: {}\nwatchers: {watchers}",
            if running { "running" } else { "stopped" }
        ),
        Response::Watchers { watchers } if watchers.is_empty() => println!("no watchers"),
        Response::Watchers { watchers } => {
            for watcher in watchers {
                println!("{}\t{:?}", watcher.watcher_id, watcher.lifecycle);
            }
        }
        Response::Registered {
            watcher_id,
            existing,
        } => println!(
            "{} watcher {watcher_id}",
            if existing { "existing" } else { "registered" }
        ),
        Response::Stopped => println!("stopped"),
        Response::Error { code, message } => {
            return Err(CliFailure {
                error: WatchmeError::RetryableIntegration(format!("{code}: {message}")),
                json,
            });
        }
    }
    Ok(())
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
