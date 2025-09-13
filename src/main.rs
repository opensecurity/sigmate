use clap::Parser;
use sigmate::cli::Cli;
use sigmate::commands::{clean, configure, sign, trust, verify};
use sigmate::error::AppError;
use sigmate::ui::logger::Logger;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let logger = Logger::new(cli.debug, !cli.no_emojis);

    let result = match cli.command {
        sigmate::cli::Commands::Sign(args) => sign::execute(args, &logger),
        sigmate::cli::Commands::Verify(args) => verify::execute(args, &logger),
        sigmate::cli::Commands::Trust(args) => trust::execute(args, &logger),
        sigmate::cli::Commands::Configure(args) => configure::execute(args, &logger),
        sigmate::cli::Commands::Clean(args) => clean::execute(args, &logger),
    };

    match result {
        Ok(exit_code) => exit_code,
        Err(e) => {
            if let AppError::IdempotencyCheckFailed(errors) = e {
                logger.warn("Idempotency check failed. The following files have been modified since they were last signed:", None);
                for err_file in errors {
                    logger.warn(&format!("  - {}", err_file), None);
                }
                logger.info("\nUse the --force flag to overwrite the existing invalid signatures.", None);
                return ExitCode::from(2);
            }
            logger.error(&format!("{}", e), None);
            ExitCode::FAILURE
        }
    }
}