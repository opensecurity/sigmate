use crate::app_config::{ConfigManager, SIGNATURES_FOLDER};
use crate::cli::SignArgs;
use crate::error::AppError;
use crate::services::signing_service::{ChecksumTask, SigningService};
use crate::ui::logger::{print_json, Logger};
use crate::utils::{files, git};
use chrono::{Duration, Utc};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub fn execute(args: SignArgs, logger: &Logger) -> Result<ExitCode, AppError> {
    let config = ConfigManager::new()?;

    let effective_key_path = args.key.clone().or_else(|| config.get_private_key_path());
    let is_crypto = effective_key_path.is_some();

    if (args.raw || args.meta || args.both || args.sbom) && !is_crypto {
        return Err(AppError::InvalidInput(
            "A private key must be provided via the --key flag or 'sigmate configure'.".into(),
        ));
    }

    let mut checksum_tasks = Vec::new();
    if args.gen_md5sums {
        checksum_tasks.push(ChecksumTask { algo: "md5", output_filename: "MD5SUMS".into() });
    }
    if args.gen_sha1sums {
        checksum_tasks.push(ChecksumTask { algo: "sha1", output_filename: "SHA1SUMS".into() });
    }
    if args.gen_sha256sums {
        checksum_tasks.push(ChecksumTask { algo: "sha256", output_filename: "SHA256SUMS".into() });
    }
     if args.gen_sha512sums {
        checksum_tasks.push(ChecksumTask { algo: "sha512", output_filename: "SHA512SUMS".into() });
    }

    if !is_crypto && checksum_tasks.is_empty() {
        return Err(AppError::InvalidInput("No operation specified. Provide a crypto signing flag (e.g. --both) or a checksum generation flag (e.g. --gen-sha256sums).".into()));
    }

    let key_data = if let Some(path) = &effective_key_path {
        fs::read(path).map_err(|e| AppError::Io { path: path.clone(), source: e })?
    } else {
        Vec::new()
    };

    let (files_to_process, base_dir) = find_files_to_process(&args, logger)?;
    if files_to_process.is_empty() {
        if !args.json {
            logger.warn("No files found to process with the given inputs.", Some("🤷"));
        }
        return Ok(ExitCode::SUCCESS);
    }

    let output_dir = args.signatures_output.clone().unwrap_or_else(|| base_dir.join(SIGNATURES_FOLDER));
    fs::create_dir_all(&output_dir).map_err(|e| AppError::Io { path: output_dir.clone(), source: e })?;

    let git_author_identity = git::get_git_author(&base_dir).ok().flatten();
    let effective_identity = args
        .identity
        .clone()
        .or_else(|| config.get_signer_identity())
        .or(git_author_identity)
        .unwrap_or_default();
        
    let host = args.host.clone().unwrap_or_else(|| hostname::get().map_or("unknown_host".to_string(), |s| s.to_string_lossy().to_string()));
    let version_info = git::get_git_info_object(&base_dir)?;
    let expires_at = args.expires_in.map(|h| (Utc::now() + Duration::hours(h as i64)).to_rfc3339());

    let service = SigningService {
        files_to_process: &files_to_process,
        key_data: &key_data,
        password_env_var: args.key_password_env.as_deref(),
        output_dir: &output_dir,
        base_dir: &base_dir,
        identity: &effective_identity,
        host: &host,
        version_info,
        should_write_raw: args.raw || args.both,
        should_write_meta: args.meta || args.both,
        should_write_sbom: args.sbom,
        checksum_tasks,
        no_abspath: args.no_abspath,
        expires_at,
        force: args.force,
    };
    
    let result_summary = service.execute()?;

    if args.json {
        print_json(&json!(result_summary));
    } else {
        if let Some(path) = &result_summary.meta_file_path {
            logger.info(&format!("Successfully wrote metadata to {}", path.display()), Some("🧾"));
        }
        if let Some(path) = &result_summary.sbom_file_path {
             logger.info(&format!("Successfully wrote SBOM to {}", path.display()), Some("📦"));
        }
        for task in &result_summary.checksum_files_generated {
            logger.info(&format!("Successfully wrote checksum file to {}", task.display()), Some("🧮"));
        }
        
        if result_summary.files_skipped_count > 0 {
             logger.info(&format!("Skipped {} files (already signed and valid).", result_summary.files_skipped_count), Some("👍"));
        }
        
        logger.info(&format!("Processed {} new files.", result_summary.files_processed_count), Some("✍️ "));
        logger.success("All operations completed successfully.", Some("🎉"));
    }
    
    Ok(ExitCode::SUCCESS)
}

fn find_files_to_process(args: &SignArgs, logger: &Logger) -> Result<(Vec<PathBuf>, PathBuf), AppError> {
    if let Some(walk_path) = &args.walk {
        let files = files::collect_files(walk_path, logger)?;
        return Ok((files, walk_path.clone()));
    }
    if let Some(list_path) = &args.file_list {
        let paths_from_list = files::read_file_list(list_path)?;
        let mut all_files = Vec::new();
        let list_base = list_path.parent().unwrap_or(Path::new(""));
        for path in paths_from_list {
            let full_path = list_base.join(path);
            if full_path.is_dir() {
                all_files.extend(files::collect_files(&full_path, logger)?);
            } else if full_path.is_file() {
                all_files.push(full_path);
            }
        }
        return Ok((all_files, list_base.to_path_buf()));
    }
    if let Some(target) = &args.target_path_or_file {
        if target.is_dir() {
            let files = files::collect_files(target, logger)?;
            return Ok((files, target.clone()));
        } else {
            return Ok((vec![target.clone()], target.parent().unwrap_or(Path::new("")).to_path_buf()));
        }
    }
    unreachable!("No input source specified for signing operation, but clap should prevent this.");
}