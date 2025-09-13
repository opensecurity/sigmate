use crate::app_config::SIGNATURES_FOLDER;
use crate::cli::CleanArgs;
use crate::error::AppError;
use crate::ui::logger::Logger;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

const DEFAULT_CHECKSUM_FILENAMES: &[&str] = &["MD5SUMS", "SHA1SUMS", "SHA256SUMS", "SHA512SUMS"];

fn get_protected_paths() -> HashSet<PathBuf> {
    let mut paths = HashSet::new();
    if let Some(home) = dirs::home_dir() {
        paths.insert(home.clone());
        if let Some(parent) = home.parent() {
            paths.insert(parent.to_path_buf());
        }
    }
    paths.insert(PathBuf::from("/"));
    paths.insert(PathBuf::from("/etc"));
    paths.insert(PathBuf::from("/var"));
    paths.insert(PathBuf::from("/usr"));
    paths.insert(PathBuf::from("/tmp"));
    paths
}

pub fn execute(args: CleanArgs, logger: &Logger) -> Result<ExitCode, AppError> {
    let mut paths_to_delete: Vec<PathBuf> = Vec::new();
    let protected_paths = get_protected_paths();
    let current_dir = std::env::current_dir().map_err(|e| AppError::Io {
        path: PathBuf::from("."),
        source: e,
    })?;

    let path_was_specified = args.path.is_some();
    let scan_dir = args
        .path
        .unwrap_or_else(|| current_dir.join(SIGNATURES_FOLDER));

    if !scan_dir.is_dir() {
        logger.info(
            "Nothing to clean. No artifact directory specified or found.",
            Some("✨"),
        );
        return Ok(ExitCode::SUCCESS);
    }

    logger.info(
        &format!("Scanning for Sigmate artifacts in: {}", scan_dir.display()),
        Some("🔍"),
    );

    if protected_paths.contains(&scan_dir) {
        return Err(AppError::InvalidInput(format!(
            "Refusing to clean protected system directory: {}",
            scan_dir.display()
        )));
    }

    let meta_file = scan_dir.join("sigmate.meta.json");
    let sbom_file = scan_dir.join("sigmate.sbom.json");

    if meta_file.is_file() || sbom_file.is_file() {
        paths_to_delete.push(scan_dir);
    } else {
        logger.warn(
            &format!(
                "Directory '{}' does not contain 'sigmate.meta.json' or 'sigmate.sbom.json'.",
                scan_dir.display()
            ),
            Some("⚠️"),
        );
        logger.warn(
            "This could be an output directory from a '--raw' only signing operation, or an unrelated folder.",
            Some("ℹ️"),
        );
        logger.warn(
            "To prevent accidental data loss, sigmate will not remove this directory automatically.",
            Some("🛡️"),
        );
        logger.warn("Please inspect and delete it manually if you are sure.", None);
    }

    if !path_was_specified {
        for filename in DEFAULT_CHECKSUM_FILENAMES {
            let checksum_file = current_dir.join(filename);
            if checksum_file.is_file() {
                paths_to_delete.push(checksum_file);
            }
        }
    }

    if paths_to_delete.is_empty() {
        logger.info("No artifacts confirmed for cleanup.", Some("✨"));
        return Ok(ExitCode::SUCCESS);
    }

    logger.warn("The following will be PERMANENTLY DELETED:", Some("🗑️"));
    for p in &paths_to_delete {
        let item_type = if p.is_dir() { "directory" } else { "file" };
        println!("  - {} ({})", p.display(), item_type);
    }

    print!("\nAre you sure you want to proceed? (y/N) ");
    io::stdout().flush().map_err(|e| AppError::Io {
        path: PathBuf::from("<stdout>"),
        source: e,
    })?;

    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation).map_err(|e| AppError::Io {
        path: PathBuf::from("<stdin>"),
        source: e,
    })?;

    if confirmation.trim().to_lowercase() != "y" {
        logger.error("Cleanup aborted by user.", None);
        return Ok(ExitCode::from(2));
    }

    for p in paths_to_delete {
        if p.is_dir() {
            fs::remove_dir_all(&p).map_err(|e| AppError::Io { path: p, source: e })?;
        } else if p.is_file() {
            fs::remove_file(&p).map_err(|e| AppError::Io { path: p, source: e })?;
        }
    }

    logger.success("Cleanup successful.", Some("✅"));

    Ok(ExitCode::SUCCESS)
}
