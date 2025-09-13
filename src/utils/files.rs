use crate::error::AppError;
use crate::ui::logger::Logger;
use ignore::WalkBuilder;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_EXCLUDED_EXTENSIONS: &[&str] = &["sig", "sigmeta.json"];

pub fn should_skip_file(path: &Path) -> bool {
    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    file_name.starts_with('.') || DEFAULT_EXCLUDED_EXTENSIONS.contains(&extension)
}

pub fn collect_files(base_dir: &Path, logger: &Logger) -> Result<Vec<PathBuf>, AppError> {
    logger.debug(
        &format!("Collecting files from {}", base_dir.display()),
        Some("📁"),
    );

    let mut collected = Vec::new();
    let mut walker = WalkBuilder::new(base_dir);
    walker
        .standard_filters(true)
        .hidden(true)
        .add_custom_ignore_filename(".sigmateignore");

    for result in walker.build() {
        match result {
            Ok(entry) => {
                let path = entry.path();
                if path.is_file() && !should_skip_file(path) {
                    collected.push(path.to_path_buf());
                }
            }
            Err(e) => {
                logger.warn(&format!("Error walking directory: {}", e), Some("⚠️"));
            }
        }
    }
    Ok(collected)
}

pub fn build_output_path(
    file_path: &Path,
    content_base_dir: &Path,
    extension_suffix: &str,
    output_root_dir: &Path,
) -> Result<PathBuf, AppError> {
    let relative_path = file_path
        .strip_prefix(content_base_dir)
        .unwrap_or(Path::new(file_path.file_name().unwrap_or_default()));

    let mut artifact_output_path = output_root_dir.join(relative_path);
    let original_extension = artifact_output_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let new_extension = format!("{}{}", original_extension, extension_suffix);
    artifact_output_path.set_extension(new_extension);

    if let Some(parent) = artifact_output_path.parent() {
        fs::create_dir_all(parent).map_err(|e| AppError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    Ok(artifact_output_path)
}

pub fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' | ' ' | '.' => '_',
            _ => c,
        })
        .collect()
}

pub fn read_file_list(path: &Path) -> Result<Vec<PathBuf>, AppError> {
    let content = fs::read_to_string(path).map_err(|e| AppError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(PathBuf::from)
        .collect())
}

pub fn remove_dot_slash_prefix(p: &Path) -> PathBuf {
    if let Ok(stripped) = p.strip_prefix("./") {
        stripped.to_path_buf()
    } else {
        p.to_path_buf()
    }
}