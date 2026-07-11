//! Public administrative Claude hook command shapes.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub(crate) enum HooksCommand {
    /// Install WatchMe's owner-only Claude StopFailure hook.
    InstallClaude(HookLifecycleOptions),
    /// Remove only WatchMe's Claude StopFailure hook entry.
    RemoveClaude(HookLifecycleOptions),
}

#[derive(Debug, Args)]
pub(crate) struct HookLifecycleOptions {
    /// Claude settings file. Defaults to ~/.claude/settings.json.
    #[arg(long)]
    pub(crate) settings: Option<PathBuf>,
    /// Owner-only WatchMe marker file. Defaults under XDG state.
    #[arg(long)]
    pub(crate) marker: Option<PathBuf>,
    /// Print the resolved paths without changing Claude settings.
    #[arg(long)]
    pub(crate) dry_run: bool,
}
