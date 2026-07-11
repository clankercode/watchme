use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::Duration;

use watchme::audit::{
    AuditLog, DecisionChain, RetentionPolicy, append_decision, explain_decision,
    load_decision_chains,
};
use watchme::client::ResolvedRegistration;
use watchme::config::Config;
use watchme::daemon;
use watchme::doctor::{list_providers, run_doctor};
use watchme::ipc::protocol::{Request, Response};
use watchme::ipc::{read_response, write_request};
use watchme::mux::Multiplexer;
use watchme::mux::herdr::{Herdr, HerdrContext};
use watchme::mux::tmux::Tmux;
use watchme::paths::WatchmePaths;
use watchme::process::{CandidateHints, ProcessInspector, ProcessResolver};

use crate::error::WatchmeError;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(hide = true)]
    WatchmeHookStopFailure(HookStopFailure),
    Hooks {
        #[command(subcommand)]
        command: crate::hook_cli::HooksCommand,
    },
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

#[derive(Debug, Args)]
struct HookStopFailure {
    #[arg(long)]
    marker: PathBuf,
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
const DAEMON_STARTUP_TIMEOUT: Duration = Duration::from_secs(3);
const INITIAL_STARTUP_BACKOFF: Duration = Duration::from_millis(20);
const MAX_STARTUP_BACKOFF: Duration = Duration::from_millis(200);
const MAX_DAEMON_DIAGNOSTIC_BYTES: usize = 512;

fn parse_target_id(value: &str) -> Result<String, String> {
    if value.is_empty() {
        Err("target ID must not be empty".into())
    } else {
        Ok(value.to_owned())
    }
}

pub struct CliFailure {
    error: WatchmeError,
    daemon_error: Option<(String, String)>,
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
    code: String,
    message: String,
}

impl CliFailure {
    pub fn render(&self) {
        if self.json {
            println!("{}", self.json_line());
        } else if let Some((code, message)) = &self.daemon_error {
            eprintln!("watchme: {code}: {message}");
        } else {
            eprintln!("watchme: {}", self.error);
        }
    }

    fn json_line(&self) -> String {
        let envelope = ErrorEnvelope {
            schema_version: SCHEMA_VERSION,
            ok: false,
            error: ErrorBody {
                code: self
                    .daemon_error
                    .as_ref()
                    .map_or_else(|| self.error.code().to_owned(), |error| error.0.clone()),
                message: self
                    .daemon_error
                    .as_ref()
                    .map_or_else(|| self.error.message().to_owned(), |error| error.1.clone()),
            },
        };
        serde_json::to_string(&envelope).expect("error envelope is serializable")
    }
}

impl From<WatchmeError> for CliFailure {
    fn from(error: WatchmeError) -> Self {
        Self {
            error,
            daemon_error: None,
            json: false,
        }
    }
}

pub fn run() -> Result<(), CliFailure> {
    let cli = Cli::parse();
    match cli.command {
        None => register_current_context().map_err(Into::into),
        Some(Command::WatchmeHookStopFailure(options)) => {
            hook_stop_failure(options).map_err(Into::into)
        }
        Some(Command::Hooks { command }) => hook_lifecycle(command).map_err(Into::into),
        Some(Command::Status(options)) => admin(Request::Status { id: options.id }, options.json),
        Some(Command::List(options)) => admin(Request::List, options.json),
        Some(Command::Stop(options)) if options.id.is_none() && !options.all => Err(CliFailure {
            error: WatchmeError::Configuration("stop requires a watcher ID or --all".into()),
            daemon_error: None,
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
        Some(Command::Config { command }) => config_command(command).map_err(Into::into),
        Some(Command::Explain(options)) => explain_command(options).map_err(Into::into),
        Some(Command::Snapshot(options)) => snapshot_command(options).map_err(Into::into),
        Some(Command::Logs(options)) => logs_command(options).map_err(Into::into),
        Some(Command::Doctor(options)) => doctor_command(options),
        Some(Command::Providers(options)) => providers_command(options).map_err(Into::into),
    }
}

fn config_command(command: ConfigCommand) -> Result<(), WatchmeError> {
    let paths = runtime_paths().map_err(|failure| failure.error)?;
    let config_path = paths.config_dir().join("config.toml");
    match command {
        ConfigCommand::Path => {
            println!("{}", config_path.display());
            Ok(())
        }
        ConfigCommand::Check => {
            Config::load_layers([config_path.as_path()])
                .map_err(|error| WatchmeError::Configuration(error.to_string()))?;
            println!("configuration ok");
            Ok(())
        }
        ConfigCommand::Show => {
            let config = Config::load_layers([config_path.as_path()])
                .map_err(|error| WatchmeError::Configuration(error.to_string()))?;
            print!("{}", config.render_redacted_toml());
            Ok(())
        }
    }
}

fn load_config(paths: &WatchmePaths) -> Result<Config, WatchmeError> {
    let config_path = paths.config_dir().join("config.toml");
    Config::load_layers([config_path.as_path()])
        .map_err(|error| WatchmeError::Configuration(error.to_string()))
}

fn audit_log(paths: &WatchmePaths) -> Result<AuditLog, WatchmeError> {
    let path = paths
        .state_file("audit.jsonl")
        .map_err(|error| WatchmeError::Configuration(error.to_string()))?;
    AuditLog::open(path).map_err(|error| WatchmeError::Configuration(error.to_string()))
}

fn explain_command(options: OptionalId) -> Result<(), WatchmeError> {
    let paths = runtime_paths().map_err(|failure| failure.error)?;
    let _ = paths.create_owner_only();
    let mut log = audit_log(&paths)?;
    let chains = load_decision_chains(&mut log)
        .map_err(|error| WatchmeError::Configuration(error.to_string()))?;
    let chain = explain_decision(&chains, options.id.as_deref()).map_err(|message| {
        WatchmeError::Configuration(format!("{message}; daemon may be down or audit empty"))
    })?;
    print_decision_chain(&chain);
    Ok(())
}

fn print_decision_chain(chain: &DecisionChain) {
    println!("watcher: {}", chain.watcher_id);
    println!("detector: {}", chain.detector);
    println!("evidence: {}", chain.evidence);
    println!("state: {}", chain.state);
    println!("policy_decision: {}", chain.policy_decision);
    println!("attempted_action: {}", chain.attempted_action);
    println!("verification: {}", chain.verification);
}

fn snapshot_command(options: SnapshotOptions) -> Result<(), WatchmeError> {
    let paths = runtime_paths().map_err(|failure| failure.error)?;
    let _ = paths.create_owner_only();
    let id = options
        .id
        .ok_or_else(|| WatchmeError::Configuration("snapshot requires a watcher ID".into()))?;
    let snap_dir = paths.state_dir().join("snapshots");
    let path = snap_dir.join(format!("{id}.json"));
    if !path.exists() {
        return Err(WatchmeError::Configuration(format!(
            "no watcher snapshot found for {id}"
        )));
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|error| WatchmeError::Configuration(error.to_string()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|error| WatchmeError::Configuration(error.to_string()))?;
    // Snapshots are always emitted redacted; --redacted is accepted for clarity.
    let _ = options.redacted;
    let (redacted, report) = watchme::redact::redact_json(&value, &[]);
    let mut output = redacted;
    if let Some(object) = output.as_object_mut() {
        object.insert(
            "redaction".into(),
            serde_json::json!({
                "performed": true,
                "replacement_count": report.replacement_count,
                "categories": report.categories.iter().cloned().collect::<Vec<_>>(),
                "raw_evidence_included": false,
            }),
        );
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&output)
            .map_err(|error| WatchmeError::Configuration(error.to_string()))?
    );
    Ok(())
}

fn logs_command(options: LogOptions) -> Result<(), WatchmeError> {
    let paths = runtime_paths().map_err(|failure| failure.error)?;
    let _ = paths.create_owner_only();
    let config = load_config(&paths).unwrap_or_default();
    let mut log = audit_log(&paths)?;
    let retention = RetentionPolicy::from(&config.retention);
    let _ = log.apply_retention(&retention, &chrono_now());
    if options.follow {
        return follow_logs(&mut log, options.id.as_deref());
    }
    let events = log
        .read_lines(options.id.as_deref(), 200)
        .map_err(|error| WatchmeError::Configuration(error.to_string()))?;
    if events.is_empty() {
        return Err(WatchmeError::Configuration(
            "no audit events found for watcher".into(),
        ));
    }
    for event in events {
        println!(
            "{}",
            serde_json::to_string(&event)
                .map_err(|error| WatchmeError::Configuration(error.to_string()))?
        );
    }
    Ok(())
}

fn follow_logs(log: &mut AuditLog, watcher_id: Option<&str>) -> Result<(), WatchmeError> {
    let mut offset = 0_u64;
    // Print existing lines first, then poll for appends.
    let existing = log
        .read_lines(watcher_id, 200)
        .map_err(|error| WatchmeError::Configuration(error.to_string()))?;
    for event in &existing {
        println!(
            "{}",
            serde_json::to_string(event)
                .map_err(|error| WatchmeError::Configuration(error.to_string()))?
        );
    }
    if let Ok(meta) = std::fs::metadata(log.path()) {
        offset = meta.len();
    }
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let (events, next) = log
            .follow_from(offset, watcher_id, 64 * 1024)
            .map_err(|error| WatchmeError::Configuration(error.to_string()))?;
        offset = next;
        for event in events {
            println!(
                "{}",
                serde_json::to_string(&event)
                    .map_err(|error| WatchmeError::Configuration(error.to_string()))?
            );
        }
    }
}

fn doctor_command(options: DoctorOptions) -> Result<(), CliFailure> {
    let paths = runtime_paths()?;
    let _ = paths.create_owner_only();
    let config = load_config(&paths).unwrap_or_default();
    let report = run_doctor(
        &paths,
        &config,
        watchme::doctor::DoctorOptions {
            strict: options.strict,
            json: options.json,
        },
    );
    if options.json {
        println!(
            "{}",
            serde_json::to_string(&report).expect("doctor report serializable")
        );
    } else {
        for check in &report.checks {
            let status = match check.status {
                watchme::doctor::CheckStatus::Ok => "ok",
                watchme::doctor::CheckStatus::Warn => "warn",
                watchme::doctor::CheckStatus::Fail => "fail",
            };
            println!("{status}\t{}\t{}", check.name, check.message);
        }
        if report.ok {
            println!("doctor: ok");
        } else {
            println!("doctor: problems found");
        }
    }
    if report.ok {
        Ok(())
    } else {
        Err(CliFailure {
            error: WatchmeError::Configuration("doctor reported problems".into()),
            daemon_error: None,
            json: false,
        })
    }
}

fn providers_command(options: JsonOutput) -> Result<(), WatchmeError> {
    let paths = runtime_paths().map_err(|failure| failure.error)?;
    let config = load_config(&paths).unwrap_or_default();
    let providers = list_providers(&config).map_err(WatchmeError::Configuration)?;
    if options.json {
        #[derive(Serialize)]
        struct Envelope<'a> {
            schema_version: &'static str,
            ok: bool,
            providers: &'a [watchme::doctor::ProviderRow],
        }
        println!(
            "{}",
            serde_json::to_string(&Envelope {
                schema_version: SCHEMA_VERSION,
                ok: true,
                providers: &providers,
            })
            .expect("providers envelope serializable")
        );
    } else {
        for provider in providers {
            println!(
                "{}\t{}\t{}\t{}",
                provider.id,
                provider.support_tier,
                provider.readiness,
                if provider.first_class {
                    "first_class"
                } else {
                    "manifest"
                }
            );
        }
    }
    Ok(())
}

fn chrono_now() -> String {
    let now: chrono::DateTime<chrono::Utc> = std::time::SystemTime::now().into();
    now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Persist a decision chain for later `explain` (daemon/recovery callers).
#[allow(dead_code)]
pub fn record_decision_chain(
    paths: &WatchmePaths,
    chain: &DecisionChain,
) -> Result<(), WatchmeError> {
    let mut log = audit_log(paths)?;
    append_decision(&mut log, chain).map_err(|error| WatchmeError::Configuration(error.to_string()))
}

fn hook_lifecycle(command: crate::hook_cli::HooksCommand) -> Result<(), WatchmeError> {
    let (options, install) = match command {
        crate::hook_cli::HooksCommand::InstallClaude(options) => (options, true),
        crate::hook_cli::HooksCommand::RemoveClaude(options) => (options, false),
    };
    let paths = runtime_paths().map_err(|failure| failure.error)?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| WatchmeError::Configuration("HOME is not set".into()))?;
    let settings = options
        .settings
        .unwrap_or_else(|| home.join(".claude/settings.json"));
    let marker = match options.marker {
        Some(marker) => marker,
        None => paths
            .state_file("claude-stop-failure.jsonl")
            .map_err(|error| WatchmeError::Configuration(error.to_string()))?,
    };
    if options.dry_run {
        let command = watchme::hooks::claude::stop_failure_command(&marker)
            .map_err(WatchmeError::Configuration)?;
        println!(
            "{} Claude hook\nsettings: {}\nmarker: {}\ncommand: {}",
            if install {
                "would install"
            } else {
                "would remove"
            },
            settings.display(),
            marker.display(),
            command
        );
        return Ok(());
    }
    if install {
        paths
            .create_owner_only()
            .map_err(|error| WatchmeError::Configuration(error.to_string()))?;
    }
    let changed = if install {
        watchme::hooks::claude::install_stop_failure_hook(&settings, &marker)
    } else {
        watchme::hooks::claude::remove_stop_failure_hook(&settings, &marker)
    }
    .map_err(WatchmeError::Configuration)?;
    println!(
        "Claude hook {}{}",
        if install { "installed" } else { "removed" },
        if changed {
            ""
        } else {
            " (already in requested state)"
        }
    );
    Ok(())
}

fn hook_stop_failure(options: HookStopFailure) -> Result<(), WatchmeError> {
    const MAX_HOOK_PAYLOAD_BYTES: usize = 8192;
    let mut payload = Vec::new();
    std::io::stdin()
        .take((MAX_HOOK_PAYLOAD_BYTES + 1) as u64)
        .read_to_end(&mut payload)
        .map_err(|_| {
            WatchmeError::RetryableIntegration("cannot read Claude hook payload".into())
        })?;
    if payload.len() > MAX_HOOK_PAYLOAD_BYTES {
        return Err(WatchmeError::PolicyDenied(
            "Claude hook payload exceeds size limit".into(),
        ));
    }
    let marker = watchme::hooks::claude::parse_stop_failure_payload(&payload)
        .map_err(WatchmeError::PolicyDenied)?;
    watchme::hooks::claude::write_marker(&options.marker, &marker)
        .map_err(|_| WatchmeError::PolicyDenied("Claude hook marker path is unsafe".into()))
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
            daemon_error: None,
            json,
        })?;
    render_response(response, json)
}

fn render_response(response: Response, json: bool) -> Result<(), CliFailure> {
    if let Response::Error { code, message } = &response {
        return Err(CliFailure {
            error: WatchmeError::RetryableIntegration(message.clone()),
            daemon_error: Some((code.clone(), message.clone())),
            json,
        });
    }
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
        Response::Error { .. } => unreachable!("daemon errors return before success rendering"),
        Response::Acknowledged => println!("acknowledged"),
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
        Ok(registration) => client.register(registration),
        Err(error) => Err(error),
    }
}

fn unsupported_registration_context() -> WatchmeError {
    WatchmeError::UnsupportedContext(
            "invoke WatchMe normally as !watchme from a supported coding-agent session; run `watchme doctor` for diagnostics"
                .to_owned(),
        )
}

trait RegistrationContextDetector {
    fn detect(&self) -> Result<ResolvedRegistration, WatchmeError>;
}

trait RegistrationClient {
    fn register(&self, registration: ResolvedRegistration) -> Result<(), WatchmeError>;
}

struct ProductionContextDetector;

impl RegistrationContextDetector for ProductionContextDetector {
    fn detect(&self) -> Result<ResolvedRegistration, WatchmeError> {
        #[cfg(target_os = "linux")]
        let inspector = watchme::process::linux::LinuxProcessInspector::default();
        #[cfg(target_os = "macos")]
        let inspector = watchme::process::macos::MacOsProcessInspector::default();
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(unsupported_registration_context());

        let current_pid = std::process::id();
        let current = inspector
            .inspect(current_pid)
            .map_err(|_| unsupported_registration_context())?;
        let tty = current.tty.ok_or_else(unsupported_registration_context)?;
        let hints = CandidateHints {
            tty: Some(tty),
            process_group_id: current.process_group_id,
            session_leader_id: current.session_leader_id,
            uid: current.uid,
            executable_hint: None,
        };
        let resolved = {
            let names = watchme::agents::manifest::ManifestRegistry::bundled()
                .map(|registry| registry.process_match_basenames())
                .unwrap_or_default();
            ProcessResolver::with_manifest_names(names)
                .resolve(&inspector, current_pid, &hints)
                .map_err(|error| WatchmeError::UnsupportedContext(error.to_string()))?
        };

        if std::env::var_os("HERDR_SOCKET_PATH").is_some()
            || std::env::var_os("HERDR_WORKSPACE_ID").is_some()
            || std::env::var_os("HERDR_TAB_ID").is_some()
            || std::env::var_os("HERDR_PANE_ID").is_some()
        {
            let herdr = Herdr::new(
                HerdrContext::from_environment()
                    .map_err(|error| WatchmeError::UnsupportedContext(error.to_string()))?,
                Duration::from_secs(2),
            )
            .map_err(|error| WatchmeError::UnsupportedContext(error.to_string()))?;
            let pane = herdr
                .current_target()
                .map_err(|error| WatchmeError::UnsupportedContext(error.to_string()))?;
            if pane.process != resolved.identity
                || normalize_tty(pane.tty.as_str())
                    != normalize_tty(resolved.identity.tty.as_deref().unwrap_or_default())
            {
                return Err(WatchmeError::UnsupportedContext(
                    "agent ancestor and Herdr pane process/TTY identities do not match".into(),
                ));
            }
            let watcher_id = format!(
                "herdr-{}-{}-{}",
                pane.pane_id, resolved.identity.pid, resolved.identity.start_time
            );
            let mut watcher = watchme::model::WatcherState::new(
                watcher_id,
                watchme::model::TargetIdentity::herdr(
                    pane.server,
                    pane.server_instance,
                    pane.session_id,
                    pane.window_id,
                    pane.pane_id,
                    pane.tty,
                    resolved.identity,
                ),
                watchme::model::WatcherLifecycle::Registered,
                0,
                unix_time_ms(),
            );
            watchme::claude_attachment::attach_process_correlated_claude_session(&mut watcher);
            return Ok(ResolvedRegistration { watcher });
        }

        if std::env::var_os("TMUX").is_some() || std::env::var_os("TMUX_PANE").is_some() {
            let tmux = Tmux::from_environment(Duration::from_secs(2))
                .map_err(|error| WatchmeError::UnsupportedContext(error.to_string()))?;
            let pane = tmux
                .current_target()
                .map_err(|error| WatchmeError::UnsupportedContext(error.to_string()))?;
            let resolved_tty = resolved.identity.tty.as_deref().unwrap_or_default();
            if normalize_tty(resolved_tty)
                != normalize_tty(pane.process.tty.as_deref().unwrap_or_default())
            {
                return Err(WatchmeError::UnsupportedContext(
                    "agent process and tmux pane TTY identities do not match".into(),
                ));
            }
            let watcher_id = format!(
                "tmux-{}-{}-{}",
                pane.pane_id.trim_start_matches('%'),
                resolved.identity.pid,
                resolved.identity.start_time
            );
            let mut watcher = watchme::model::WatcherState::new(
                watcher_id,
                watchme::model::TargetIdentity::tmux(
                    pane.server,
                    pane.server_instance,
                    pane.session_id,
                    pane.window_id,
                    pane.pane_id,
                    pane.tty,
                    resolved.identity,
                    None,
                ),
                watchme::model::WatcherLifecycle::Registered,
                0,
                unix_time_ms(),
            );
            watchme::claude_attachment::attach_process_correlated_claude_session(&mut watcher);
            return Ok(ResolvedRegistration { watcher });
        }
        let watcher_id = format!(
            "process-{}-{}",
            resolved.identity.pid, resolved.identity.start_time
        );
        let mut watcher = watchme::model::WatcherState::new(
            watcher_id,
            watchme::model::TargetIdentity::process(resolved.identity),
            watchme::model::WatcherLifecycle::Registered,
            0,
            unix_time_ms(),
        );
        watchme::claude_attachment::attach_process_correlated_claude_session(&mut watcher);
        Ok(ResolvedRegistration { watcher })
    }
}

fn normalize_tty(tty: &str) -> &str {
    tty.strip_prefix("/dev/").unwrap_or(tty)
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
                paths
                    .create_owner_only()
                    .map_err(|error| WatchmeError::RetryableIntegration(error.to_string()))?;
                let (diagnostic_file, diagnostic_path) = open_startup_diagnostic(&paths)
                    .map_err(|error| WatchmeError::RetryableIntegration(error.to_string()))?;
                let mut child = ProcessCommand::new(executable)
                    .args(["daemon", "run"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::from(diagnostic_file))
                    .spawn()
                    .map_err(|error| WatchmeError::RetryableIntegration(error.to_string()))?;
                let readiness =
                    wait_for_readiness(&SystemWaitClock, DAEMON_STARTUP_TIMEOUT, |remaining| {
                        request_daemon_with_timeout(&paths, &request, remaining)
                    });
                match readiness {
                    Ok(response) => {
                        render_response(response, false).map_err(|failure| failure.error)
                    }
                    Err(error) => {
                        let diagnostic = child_failure_diagnostic(&mut child, &diagnostic_path);
                        Err(WatchmeError::RetryableIntegration(format!(
                            "daemon did not become ready: {error}{diagnostic}"
                        )))
                    }
                }
            }
        }
    }
}

fn open_startup_diagnostic(paths: &WatchmePaths) -> std::io::Result<(std::fs::File, PathBuf)> {
    let path = paths.runtime_dir().join("daemon-startup.log");
    let file = rustix::fs::open(
        &path,
        rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::TRUNC
            | rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::from_bits_truncate(0o600),
    )
    .map(std::fs::File::from)
    .map_err(std::io::Error::from)?;
    rustix::fs::fchmod(&file, rustix::fs::Mode::from_bits_truncate(0o600))
        .map_err(std::io::Error::from)?;
    Ok((file, path))
}

trait WaitClock {
    fn now(&self) -> std::time::Instant;
    fn sleep(&self, duration: Duration);
}

struct SystemWaitClock;

impl WaitClock for SystemWaitClock {
    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

fn wait_for_readiness<T, E>(
    clock: &impl WaitClock,
    timeout: Duration,
    mut attempt: impl FnMut(Duration) -> Result<T, E>,
) -> Result<T, E> {
    let deadline = clock.now() + timeout;
    let mut backoff = INITIAL_STARTUP_BACKOFF;
    loop {
        let remaining = deadline.saturating_duration_since(clock.now());
        match attempt(remaining) {
            Ok(value) => return Ok(value),
            Err(error) => {
                let now = clock.now();
                if now >= deadline {
                    return Err(error);
                }
                clock.sleep(backoff.min(deadline.duration_since(now)));
                backoff = (backoff * 2).min(MAX_STARTUP_BACKOFF);
            }
        }
    }
}

fn child_failure_diagnostic(child: &mut std::process::Child, path: &Path) -> String {
    let status = match child.try_wait() {
        Ok(Some(status)) => Some(status),
        Ok(None) | Err(_) => {
            let _ = child.kill();
            child.wait().ok()
        }
    };
    let mut stderr = Vec::new();
    if let Ok(mut file) = std::fs::File::open(path) {
        use std::io::Read as _;
        let _ = file
            .by_ref()
            .take((MAX_DAEMON_DIAGNOSTIC_BYTES + 1) as u64)
            .read_to_end(&mut stderr);
    }
    let diagnostic = sanitize_daemon_stderr(&stderr);
    match (status, diagnostic.is_empty()) {
        (Some(status), false) => format!("; child {status}: {diagnostic}"),
        (Some(status), true) => format!("; child {status}"),
        (None, false) => format!("; child diagnostic: {diagnostic}"),
        (None, true) => String::new(),
    }
}

fn sanitize_daemon_stderr(stderr: &[u8]) -> String {
    let source = String::from_utf8_lossy(&stderr[..stderr.len().min(MAX_DAEMON_DIAGNOSTIC_BYTES)]);
    let mut sanitized = String::new();
    for line in source.lines() {
        if !sanitized.is_empty() {
            sanitized.push('\n');
        }
        let lower = line.to_ascii_lowercase();
        if ["token", "secret", "password", "credential", "api_key"]
            .iter()
            .any(|marker| lower.contains(marker))
        {
            sanitized.push_str("[redacted]");
        } else {
            sanitized.extend(line.chars().filter(|character| !character.is_control()));
        }
        if sanitized.len() >= MAX_DAEMON_DIAGNOSTIC_BYTES {
            sanitized.truncate(MAX_DAEMON_DIAGNOSTIC_BYTES);
            break;
        }
    }
    sanitized
}

fn request_daemon(paths: &WatchmePaths, request: &Request) -> std::io::Result<Response> {
    request_daemon_with_timeout(paths, request, Duration::from_secs(2))
}

fn request_daemon_with_timeout(
    paths: &WatchmePaths,
    request: &Request,
    timeout: Duration,
) -> std::io::Result<Response> {
    let socket = paths.runtime_dir().join("daemon.sock");
    local_runtime()
        .map_err(|failure| std::io::Error::other(failure.error))?
        .block_on(within_attempt_deadline(timeout, async {
            let mut stream = tokio::net::UnixStream::connect(socket).await?;
            write_request(&mut stream, request, timeout)
                .await
                .map_err(std::io::Error::other)?;
            read_response(&mut stream, timeout)
                .await
                .map_err(std::io::Error::other)
        }))
}

async fn within_attempt_deadline<T>(
    timeout: Duration,
    future: impl std::future::Future<Output = std::io::Result<T>>,
) -> std::io::Result<T> {
    tokio::time::timeout(timeout, future).await.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "daemon readiness deadline elapsed",
        )
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    struct FixedContextDetector;

    impl RegistrationContextDetector for FixedContextDetector {
        fn detect(&self) -> Result<ResolvedRegistration, WatchmeError> {
            Ok(ResolvedRegistration {
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
            let rendered = CliFailure {
                error,
                daemon_error: None,
                json: true,
            }
            .json_line();
            let value: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
            assert_eq!(value["schema_version"], "1.0");
            assert_eq!(value["ok"], false);
            assert_eq!(value["error"]["code"], expected_code);
            assert_eq!(value["error"]["message"], "x");
        }
    }

    struct FakeWaitClock {
        now: Cell<std::time::Instant>,
        sleeps: RefCell<Vec<Duration>>,
    }

    impl WaitClock for FakeWaitClock {
        fn now(&self) -> std::time::Instant {
            self.now.get()
        }

        fn sleep(&self, duration: Duration) {
            self.sleeps.borrow_mut().push(duration);
            self.now.set(self.now.get() + duration);
        }
    }

    #[test]
    fn startup_readiness_uses_bounded_deadline_and_backoff() {
        let clock = FakeWaitClock {
            now: Cell::new(std::time::Instant::now()),
            sleeps: RefCell::new(Vec::new()),
        };
        let started = clock.now();
        let mut attempts = 0;
        let mut budgets = Vec::new();
        let result = wait_for_readiness(&clock, Duration::from_secs(2), |remaining| {
            budgets.push(remaining);
            attempts += 1;
            Err::<(), _>(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "not ready",
            ))
        });

        assert!(result.is_err());
        assert!(attempts > 5);
        assert_eq!(budgets[0], Duration::from_secs(2));
        assert!(budgets.windows(2).all(|pair| pair[0] >= pair[1]));
        assert_eq!(clock.now().duration_since(started), Duration::from_secs(2));
        let sleeps = clock.sleeps.borrow();
        assert!(
            sleeps[..sleeps.len() - 1]
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
        );
        assert!(
            sleeps
                .iter()
                .all(|delay| *delay <= Duration::from_millis(200))
        );
    }

    #[test]
    fn readiness_attempt_future_is_bounded_by_remaining_deadline() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let started = std::time::Instant::now();
        let error = runtime
            .block_on(within_attempt_deadline(
                Duration::from_millis(25),
                std::future::pending::<std::io::Result<()>>(),
            ))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(150));
    }

    #[test]
    fn daemon_stderr_diagnostics_are_bounded_and_redact_secret_lines() {
        let diagnostic = sanitize_daemon_stderr(
            b"failed to bind runtime socket\nAPI_TOKEN=super-secret\npassword=hunter2\n",
        );
        assert_eq!(
            diagnostic,
            "failed to bind runtime socket\n[redacted]\n[redacted]"
        );
        assert!(diagnostic.len() <= MAX_DAEMON_DIAGNOSTIC_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn daemon_startup_diagnostic_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::TempDir::new().unwrap();
        let paths =
            WatchmePaths::resolve(temp.path(), None, None, Some(&temp.path().join("run"))).unwrap();
        paths.create_owner_only().unwrap();
        let (_file, path) = open_startup_diagnostic(&paths).unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
