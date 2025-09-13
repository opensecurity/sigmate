use crate::app_config::{ConfigManager, SIGNATURES_FOLDER};
use crate::cli::VerifyArgs;
use crate::error::AppError;
use crate::services::{VerificationResult, VerificationService};
use crate::ui::logger::{print_json, Logger};
use crate::utils::files::{self, sanitize_filename};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub fn execute(args: VerifyArgs, logger: &Logger) -> Result<ExitCode, AppError> {
    let is_checksum_mode = args.checksum_file.is_some();
    let effective_key_path = resolve_key_path(&args)?;

    if effective_key_path.is_none() && !is_checksum_mode {
        return Err(AppError::InvalidInput(
            "Must specify either --key/--signer or --checksum-file.".into(),
        ));
    }

    let base_dir = args
        .walk
        .clone()
        .or_else(|| {
            args.target_path_or_file.as_ref().map(|p| {
                if p.is_dir() {
                    p.clone()
                } else {
                    p.parent().unwrap_or(Path::new("")).to_path_buf()
                }
            })
        })
        .unwrap_or_else(|| {
            if let Some(checksum_path) = &args.checksum_file {
                checksum_path.parent().unwrap_or(Path::new("")).to_path_buf()
            } else {
                std::env::current_dir().expect("Cannot get current directory")
            }
        });

    let files_to_verify = find_files_to_verify(&args, logger)?;

    if let Some(key_path) = effective_key_path {
        if files_to_verify.is_empty() {
            if !args.json {
                logger.warn("No files found to verify.", Some("🤷"));
            }
            return Ok(ExitCode::SUCCESS);
        }
        let key_data =
            fs::read(&key_path).map_err(|e| AppError::Io { path: key_path, source: e })?;
        let sig_dir = args
            .signatures_input
            .clone()
            .unwrap_or_else(|| base_dir.join(SIGNATURES_FOLDER));

        let service = VerificationService {
            files: &files_to_verify,
            key_data: &key_data,
            sig_type: &args.sig_type,
            sig_dir: &sig_dir,
            base_dir: &base_dir,
            require_trusted: args.require_trusted,
        };
        let results = service.verify_signatures()?;
        print_crypto_results(&results, args.json, logger);
        if results.iter().all(|r| r.overall_verified) {
            Ok(ExitCode::SUCCESS)
        } else {
            Ok(ExitCode::FAILURE)
        }
    } else if let Some(checksum_path) = &args.checksum_file {
        let service = VerificationService {
            files: &files_to_verify,
            key_data: &[],
            sig_type: "",
            sig_dir: checksum_path.parent().unwrap(),
            base_dir: &base_dir,
            require_trusted: false,
        };
        let results = service.verify_checksums(checksum_path, &args.checksum_algo)?;
        print_checksum_results(&results, args.json, logger);
        if results.iter().all(|r| r.overall_verified) {
            Ok(ExitCode::SUCCESS)
        } else {
            Ok(ExitCode::FAILURE)
        }
    } else {
        unreachable!();
    }
}

fn resolve_key_path(args: &VerifyArgs) -> Result<Option<PathBuf>, AppError> {
    if let Some(key_path) = &args.key {
        return Ok(Some(key_path.clone()));
    }
    if let Some(signer_name) = &args.signer {
        let config = ConfigManager::new()?;
        let keyring_path = config.get_keyring_path()?;
        let key_alias = sanitize_filename(signer_name);
        let potential_key_path = keyring_path.join(format!("{}.pub", key_alias));
        if !potential_key_path.is_file() {
            return Err(AppError::InvalidInput(format!(
                "Signer '{}' not found in keyring: {}",
                signer_name,
                potential_key_path.display()
            )));
        }
        return Ok(Some(potential_key_path));
    }
    Ok(None)
}

fn find_files_to_verify(
    args: &VerifyArgs,
    logger: &Logger,
) -> Result<Vec<PathBuf>, AppError> {
    if let Some(walk_path) = &args.walk {
        return files::collect_files(walk_path, logger);
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
        return Ok(all_files);
    }
    if let Some(target) = &args.target_path_or_file {
        if target.is_dir() {
            return files::collect_files(target, logger);
        } else {
            return Ok(vec![target.clone()]);
        }
    }
    if args.checksum_file.is_some() {
        return Ok(vec![]);
    }
    Ok(vec![])
}

fn print_crypto_results(results: &[VerificationResult], json_output: bool, logger: &Logger) {
    if json_output {
        print_json(&json!(results));
        return;
    }

    for (i, result) in results.iter().enumerate() {
        let file_path = result.file.file_name().unwrap_or_default().to_string_lossy();
        if result.overall_verified {
            logger.success(&format!("VERIFIED: {}", file_path), Some("✅"));
        } else {
            logger.error(&format!("FAILED: {}", file_path), Some("❌"));
        }

        let source = result
            .metadata_source
            .as_ref()
            .or(result.signature_file.as_ref());
        if let Some(s) = source {
            logger.info(
                &format!(
                    "  ├─ Source: {}",
                    s.file_name().unwrap_or_default().to_string_lossy()
                ),
                None,
            );
        }
        if result.expected_hash.is_some() {
            if result.actual_hash == result.expected_hash {
                logger.success("  ├─ Content Hash:  Matches", None);
            } else {
                logger.error("  ├─ Content Hash:  MISMATCH", None);
                logger.error(
                    &format!(
                        "  │  ├─ Expected: {}",
                        result.expected_hash.as_deref().unwrap_or("")
                    ),
                    None,
                );
                logger.error(
                    &format!(
                        "  │  └─ Actual:   {}",
                        result.actual_hash.as_deref().unwrap_or("")
                    ),
                    None,
                );
            }
        }
        if result.valid_signature {
            logger.success("  ├─ Signature:       Valid", None);
        } else if source.is_some() {
            logger.error("  ├─ Signature:       INVALID", None);
        }

        if let Some(expired) = result.expired {
            if expired {
                logger.warn("  ├─ Expiration:    EXPIRED", None);
            } else {
                logger.success("  ├─ Expiration:    OK", None);
            }
        }
        if let Some(trusted) = result.trusted_signer {
            if trusted {
                logger.success("  └─ Signer Trust:  Trusted", None);
            } else {
                logger.warn("  └─ Signer Trust:  NOT TRUSTED", None);
            }
        }
        if let Some(err) = &result.error {
            logger.error(&format!("  └─ Error: {}", err), None);
        }

        if i < results.len() - 1 {
            println!();
        }
    }
}

fn print_checksum_results(results: &[VerificationResult], json_output: bool, logger: &Logger) {
    if json_output {
        print_json(&json!(results));
        return;
    }
    for result in results {
        let file_path = result.file.file_name().unwrap_or_default().to_string_lossy();
        if result.overall_verified {
            logger.success(
                &format!("MATCH: {} ({})", file_path, result.algorithm_used.as_deref().unwrap_or("")),
                Some("✅"),
            );
        } else {
            logger.error(&format!("MISMATCH: {}", file_path), Some("❌"));
            if let (Some(expected), Some(actual)) = (&result.expected_hash, &result.actual_hash) {
                logger.error(&format!("  ├─ Expected: {}", expected), None);
                logger.error(&format!("  └─ Actual:   {}", actual), None);
            }
            if let Some(err) = &result.error {
                logger.error(&format!("  └─ Error: {}", err), None);
            }
        }
    }
}