use crate::app_config::ConfigManager;
use crate::cli::ConfigureArgs;
use crate::error::AppError;
use crate::ui::logger::{print_json, Logger};
use crate::utils;
use serde_json::json;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

pub fn execute(args: ConfigureArgs, logger: &Logger) -> Result<ExitCode, AppError> {
    let mut config_manager = ConfigManager::new()?;
    let is_non_interactive = args.private_key_path.is_some()
        || args.signer_identity.is_some()
        || args.keyring_path.is_some();

    if is_non_interactive {
        if !args.json {
            logger.info("Updating configuration non-interactively...", Some("🤖"));
        }
        if let Some(path) = &args.private_key_path {
            config_manager.set_private_key_path(path.clone());
            if !args.json {
                logger.success(
                    &format!("Default private key set to: {}", path.display()),
                    Some("🔑"),
                );
            }
        }
        if let Some(identity) = &args.signer_identity {
            config_manager.set_signer_identity(identity.clone());
            if !args.json {
                logger.success(
                    &format!("Default signer identity set to: {}", identity),
                    Some("👤"),
                );
            }
        }
        if let Some(path) = &args.keyring_path {
            config_manager.set_keyring_path(path.clone());
            if !args.json {
                logger.success(&format!("Keyring path set to: {}", path.display()), Some("📂"));
            }
        }
    } else {
        logger.info("Configuring Sigmate User Defaults (Interactive)", Some("⚙️"));
        logger.info(&format!("Configuration will be saved to: {}", config_manager.get_config_path().display()), None);

        let current_priv_key = config_manager.get_private_key_path().and_then(|p| p.to_str().map(String::from)).unwrap_or_default();
        let new_priv_key_str = prompt_with_default("Enter path to your default private key", &current_priv_key)?;
        let new_priv_key_path = PathBuf::from(new_priv_key_str);
        if !new_priv_key_path.as_os_str().is_empty() && !new_priv_key_path.exists() {
            return Err(AppError::InvalidInput("Private key path does not exist.".to_string()));
        }
        config_manager.set_private_key_path(new_priv_key_path);
        
        let current_dir = std::env::current_dir().map_err(|e| AppError::Io { path: PathBuf::from("."), source: e})?;
        let git_author = utils::git::get_git_author(&current_dir)?.unwrap_or_default();
        let current_identity = config_manager.get_signer_identity().unwrap_or(git_author);
        let new_identity = prompt_with_default("Enter your default signer identity", &current_identity)?;
        config_manager.set_signer_identity(new_identity);
        
        let default_keyring = ConfigManager::get_default_keyring_path()?.to_str().unwrap_or_default().to_string();
        let current_keyring = config_manager.get_keyring_path()?.to_str().unwrap_or(&default_keyring).to_string();
        let new_keyring_str = prompt_with_default("Enter path for your public key keyring directory", &current_keyring)?;
        config_manager.set_keyring_path(PathBuf::from(new_keyring_str));
    }

    config_manager.save()?;
    if args.json {
        print_json(&json!({
            "status": "success",
            "message": "Configuration saved.",
            "config_file": config_manager.get_config_path()
        }));
    } else {
        logger.success("Configuration saved successfully!", Some("✅"));
    }

    Ok(ExitCode::SUCCESS)
}

fn prompt_with_default(prompt_text: &str, default: &str) -> Result<String, AppError> {
    print!("{} [{}]: ", prompt_text, default);
    io::stdout().flush().map_err(|e| AppError::Io {
        path: PathBuf::from("<stdout>"),
        source: e,
    })?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| AppError::Io {
        path: PathBuf::from("<stdin>"),
        source: e,
    })?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}