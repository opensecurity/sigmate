use crate::app_config::ConfigManager;
use crate::cli::{
    TrustAddArgs, TrustArgs, TrustCommands, TrustListArgs, TrustRemoveArgs, TrustUpdateArgs,
};
use crate::domain::trust::VerificationStatus;
use crate::error::AppError;
use crate::infrastructure::crypto::key_handler;
use crate::infrastructure::persistence::json_trust_store::JsonTrustStore;
use crate::ui::logger::Logger;
use crate::ui::trust_presenter;
use crate::utils::files::sanitize_filename;
use std::fs;
use std::process::ExitCode;
use std::str::FromStr;

pub fn execute(args: TrustArgs, logger: &Logger) -> Result<ExitCode, AppError> {
    match args.command {
        TrustCommands::Add(add_args) => add_key(add_args, logger),
        TrustCommands::List(list_args) => list_keys(list_args, logger),
        TrustCommands::Remove(remove_args) => remove_key(remove_args, logger),
        TrustCommands::Update(update_args) => update_key_status(update_args, logger),
    }
}

fn add_key(args: TrustAddArgs, logger: &Logger) -> Result<ExitCode, AppError> {
    let config = ConfigManager::new()?;
    let keyring_path = config.get_keyring_path()?;
    let mut store = JsonTrustStore::new()?;

    let key_alias = sanitize_filename(&args.name);
    if key_alias.is_empty() {
        return Err(AppError::InvalidInput(
            "The provided --name is invalid or results in an empty alias.".to_string(),
        ));
    }

    let key_data = fs::read(&args.keyfile).map_err(|e| AppError::Io {
        path: args.keyfile.clone(),
        source: e,
    })?;

    let verifying_key = key_handler::get_verifying_key_from_pem(&key_data)?;
    let new_fingerprint = key_handler::get_key_fingerprint(&verifying_key)?;

    if let Some(existing_key) = store.get_key_entry(&new_fingerprint) {
        logger.info(
            &format!(
                "Key with fingerprint {} already exists in trust store with name '{}'. No action needed.",
                new_fingerprint, existing_key.name
            ),
            Some("✅"),
        );
        return Ok(ExitCode::SUCCESS);
    }

    let keyring_dest_path = keyring_path.join(format!("{}.pub", key_alias));
    if keyring_dest_path.exists() && !args.force {
        let existing_key_data = fs::read(&keyring_dest_path).map_err(|e| AppError::Io {
            path: keyring_dest_path.clone(),
            source: e,
        })?;
        let existing_verifying_key = key_handler::get_verifying_key_from_pem(&existing_key_data)?;
        let existing_fingerprint = key_handler::get_key_fingerprint(&existing_verifying_key)?;

        if existing_fingerprint != new_fingerprint {
            return Err(AppError::InvalidInput(format!(
            "A different key with the name '{}' (alias: '{}') already exists. Use --force to overwrite.",
            args.name,
            key_alias
        )));
        }
    }

    store.add(
        new_fingerprint.clone(),
        args.name.clone(),
        args.org,
        args.added_by,
        "Ed25519".to_string(),
    )?;

    fs::copy(&args.keyfile, &keyring_dest_path).map_err(|e| AppError::Io {
        path: args.keyfile,
        source: e,
    })?;

    logger.success(
        &format!("Trusted key entry added for '{}'", args.name),
        Some("✅"),
    );
    logger.info(&format!("  ↳ Fingerprint: {}", new_fingerprint), None);
    logger.info(
        &format!(
            "  ↳ Key file stored in keyring: {}",
            keyring_dest_path.display()
        ),
        None,
    );

    Ok(ExitCode::SUCCESS)
}

fn list_keys(args: TrustListArgs, logger: &Logger) -> Result<ExitCode, AppError> {
    let store = JsonTrustStore::new()?;
    let keys = store.list_all();
    trust_presenter::display_trusted_keys(&keys, &args, logger);
    Ok(ExitCode::SUCCESS)
}

fn remove_key(args: TrustRemoveArgs, logger: &Logger) -> Result<ExitCode, AppError> {
    let mut store = JsonTrustStore::new()?;
    if !store.is_fingerprint_present(&args.fingerprint) {
        logger.info(
            &format!(
                "Key with fingerprint {} not found in trust store. No action needed.",
                args.fingerprint
            ),
            None,
        );
        return Ok(ExitCode::SUCCESS);
    }

    store.remove(&args.fingerprint)?;
    logger.success(
        &format!(
            "Key entry removed from trust store for fingerprint: {}",
            args.fingerprint
        ),
        Some("🗑️"),
    );
    logger.info(
        "  Note: The key file itself must be removed from the keyring directory manually.",
        None,
    );
    Ok(ExitCode::SUCCESS)
}

fn update_key_status(args: TrustUpdateArgs, logger: &Logger) -> Result<ExitCode, AppError> {
    let mut store = JsonTrustStore::new()?;
    let status = VerificationStatus::from_str(&args.status)?;
    store.update_verification_status(&args.fingerprint, status, args.updated_by, args.notes)?;
    logger.success(
        &format!("Key status updated for fingerprint: {}", args.fingerprint),
        Some("✅"),
    );
    Ok(ExitCode::SUCCESS)
}