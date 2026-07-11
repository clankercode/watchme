use clap::{Args, Parser, Subcommand};

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

pub fn run() -> Result<(), WatchmeError> {
    let cli = Cli::parse();
    match cli.command {
        None => register_current_context(),
        Some(command) => Err(unavailable(command)),
    }
}

fn register_current_context() -> Result<(), WatchmeError> {
    match supported_agent_context() {
        Some(context) => attempt_registration(context),
        None => Err(WatchmeError::UnsupportedContext(
            "invoke WatchMe normally as !watchme from a supported coding-agent session; run `watchme doctor` for diagnostics"
                .to_owned(),
        )),
    }
}

#[derive(Clone, Copy, Debug)]
enum AgentContext {
    Claude,
    Codex,
}

fn supported_agent_context() -> Option<AgentContext> {
    match std::env::var("WATCHME_TEST_AGENT_CONTEXT").as_deref() {
        Ok("claude") => Some(AgentContext::Claude),
        Ok("codex") => Some(AgentContext::Codex),
        _ => None,
    }
}

fn attempt_registration(_context: AgentContext) -> Result<(), WatchmeError> {
    Err(WatchmeError::CapabilityUnavailable {
        message: "registration is not implemented yet".to_owned(),
        json: false,
    })
}

fn unavailable(command: Command) -> WatchmeError {
    let json = match command {
        Command::Status(options) => options.json,
        Command::List(options) | Command::Providers(options) => options.json,
        Command::Doctor(options) => options.json,
        _ => false,
    };
    WatchmeError::CapabilityUnavailable {
        message: "this administrative capability is not implemented yet".to_owned(),
        json,
    }
}
