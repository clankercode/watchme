mod cli;
mod error;
mod hook_cli;
mod registration_context;

use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            error.render();
            ExitCode::FAILURE
        }
    }
}
