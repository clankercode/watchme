mod cli;
mod error;

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
