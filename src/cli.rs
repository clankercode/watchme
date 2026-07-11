use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;

use watchme::client::ResolvedRegistration;
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
    Pause(TargetOptions),
    Resume(TargetOptions),
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
    #[arg(value_parser = parse_target_id)]
    id: Option<String>,
}

#[derive(Debug, Args)]
struct IdAndJson {
    #[arg(value_parser = parse_target_id)]
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
    #[arg(value_parser = parse_target_id)]
    id: Option<String>,
    #[arg(long)]
    redacted: bool,
}

#[derive(Debug, Args)]
struct LogOptions {
    #[arg(value_parser = parse_target_id)]
    id: Option<String>,
    #[arg(long)]
    follow: bool,
}

#[derive(Debug, Args)]
struct StopOptions {
    #[arg(value_parser = parse_target_id)]
    id: Option<String>,
    #[arg(long, conflicts_with = "id")]
    all: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct TargetOptions {
    #[arg(value_parser = parse_target_id)]
    id: String,
    #[arg(long)]
    json: bool,
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

fn parse_target_id(value: &str) -> Result<String, String> {
    if value.is_empty() {
        Err("target ID must not be empty".into())
    } else {
        Ok(value.to_owned())
    }
}

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
        Some(Command::Status(options)) => admin(Request::Status { id: options.id }, options.json),
        Some(Command::List(options)) => admin(Request::List, options.json),
        Some(Command::Stop(options)) if options.id.is_none() && !options.all => Err(CliFailure {
            error: WatchmeError::Configuration("stop requires a watcher ID or --all".into()),
            json: options.json,
        }),
        Some(Command::Stop(options)) => admin(
            Request::Stop {
                id: options.id,
                all: options.all,
            },
            options.json,
        ),
        Some(Command::Pause(options)) => admin(Request::Pause { id: options.id }, options.json),
        Some(Command::Resume(options)) => admin(Request::Resume { id: options.id }, options.json),
        Some(Command::Daemon {
            command: DaemonCommand::Run,
        }) => run_daemon(),
        Some(Command::Daemon {
            command: DaemonCommand::Status,
        }) => admin(Request::Status { id: None }, false),
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
        Response::Status { running, watchers } => {
            println!(
                "daemon: {}\nwatchers: {}",
                if running { "running" } else { "stopped" },
                watchers.len()
            );
            for watcher in watchers {
                println!(
                    "{}\t{}",
                    watcher.watcher_id,
                    lifecycle_name(&watcher.lifecycle)
                );
            }
        }
        Response::Watchers { watchers } if watchers.is_empty() => println!("no watchers"),
        Response::Watchers { watchers } => {
            for watcher in watchers {
                println!(
                    "{}\t{}",
                    watcher.watcher_id,
                    lifecycle_name(&watcher.lifecycle)
                );
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
        Response::Updated { watcher } => println!(
            "{}\t{}",
            watcher.watcher_id,
            lifecycle_name(&watcher.lifecycle)
        ),
        Response::Error { code, message } => {
            return Err(CliFailure {
                error: WatchmeError::RetryableIntegration(format!("{code}: {message}")),
                json,
            });
        }
    }
    Ok(())
}

fn lifecycle_name(lifecycle: &watchme::model::WatcherLifecycle) -> &'static str {
    use watchme::model::WatcherLifecycle;
    match lifecycle {
        WatcherLifecycle::Registered => "registered",
        WatcherLifecycle::Observing => "observing",
        WatcherLifecycle::Paused => "paused",
        WatcherLifecycle::Recovering { .. } => "recovering",
        WatcherLifecycle::Waiting { .. } => "waiting",
        WatcherLifecycle::HumanRequired { .. } => "human_required",
        WatcherLifecycle::TargetTerminated => "target_terminated",
        WatcherLifecycle::Stopped { .. } => "stopped",
    }
}

fn register_current_context() -> Result<(), WatchmeError> {
    register_with_detector(&ProductionContextDetector, &IpcRegistrationClient)
}

fn register_with_detector(
    detector: &impl RegistrationContextDetector,
    client: &impl RegistrationClient,
) -> Result<(), WatchmeError> {
    match detector.detect() {
        Some(registration) => client.register(registration),
        None => Err(WatchmeError::UnsupportedContext(
            "invoke WatchMe normally as !watchme from a supported coding-agent session; run `watchme doctor` for diagnostics"
                .to_owned(),
        )),
    }
}

trait RegistrationContextDetector {
    fn detect(&self) -> Option<ResolvedRegistration>;
}

trait RegistrationClient {
    fn register(&self, registration: ResolvedRegistration) -> Result<(), WatchmeError>;
}

struct ProductionContextDetector;

impl RegistrationContextDetector for ProductionContextDetector {
    fn detect(&self) -> Option<ResolvedRegistration> {
        // Process ancestry verification is introduced in the discovery milestone.
        None
    }
}

struct IpcRegistrationClient;

impl RegistrationClient for IpcRegistrationClient {
    fn register(&self, registration: ResolvedRegistration) -> Result<(), WatchmeError> {
        let paths = runtime_paths().map_err(|failure| failure.error)?;
        let request = Request::Register {
            watcher: Box::new(registration.watcher),
        };
        match request_daemon(&paths, &request) {
            Ok(response) => render_response(response, false).map_err(|failure| failure.error),
            Err(_) => {
                let executable = std::env::current_exe()
                    .map_err(|error| WatchmeError::RetryableIntegration(error.to_string()))?;
                ProcessCommand::new(executable)
                    .args(["daemon", "run"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|error| WatchmeError::RetryableIntegration(error.to_string()))?;
                for _ in 0..50 {
                    std::thread::sleep(Duration::from_millis(10));
                    if let Ok(response) = request_daemon(&paths, &request) {
                        return render_response(response, false).map_err(|failure| failure.error);
                    }
                }
                Err(WatchmeError::RetryableIntegration(
                    "daemon did not become ready".into(),
                ))
            }
        }
    }
}

fn request_daemon(paths: &WatchmePaths, request: &Request) -> std::io::Result<Response> {
    let socket = paths.runtime_dir().join("daemon.sock");
    local_runtime()
        .map_err(|failure| std::io::Error::other(failure.error))?
        .block_on(async {
            let mut stream = tokio::net::UnixStream::connect(socket).await?;
            write_request(&mut stream, request, Duration::from_secs(2))
                .await
                .map_err(std::io::Error::other)?;
            read_response(&mut stream, Duration::from_secs(2))
                .await
                .map_err(std::io::Error::other)
        })
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
        fn detect(&self) -> Option<ResolvedRegistration> {
            Some(ResolvedRegistration {
                watcher: watchme::model::WatcherState::new(
                    "watcher-1".into(),
                    watchme::model::TargetIdentity::process(watchme::model::ProcessIdentity::new(
                        1, 2,
                    )),
                    watchme::model::WatcherLifecycle::Registered,
                    0,
                    1,
                ),
            })
        }
    }

    struct FixedRegistrationClient;
    impl RegistrationClient for FixedRegistrationClient {
        fn register(&self, registration: ResolvedRegistration) -> Result<(), WatchmeError> {
            assert_eq!(registration.watcher.watcher_id, "watcher-1");
            Ok(())
        }
    }

    #[test]
    fn detected_context_reaches_registration_attempt_boundary() {
        register_with_detector(&FixedContextDetector, &FixedRegistrationClient).unwrap();
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
