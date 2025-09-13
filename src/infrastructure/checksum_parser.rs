use crate::error::AppError;
use regex::Regex;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ParsedChecksumEntry {
    pub filename: String,
    pub expected_hash: String,
    pub algorithm: Option<String>,
}

pub fn parse_checksum_file(
    checksum_file_path: &Path,
) -> Result<Vec<ParsedChecksumEntry>, AppError> {
    let content = fs::read_to_string(checksum_file_path).map_err(|e| AppError::Io {
        path: checksum_file_path.to_path_buf(),
        source: e,
    })?;

    // Regex for GNU style: <hash>  <filename>
    let gnu_re = Regex::new(r"^(?P<hash>[a-fA-F0-9]+)\s+[\s*]?(?P<filename>.+?)\s*$")
        .map_err(|_| AppError::Checksum("Failed to compile GNU regex".into()))?;

    // Regex for BSD style: ALGO (filename) = <hash>
    let bsd_re =
        Regex::new(r"^(?P<algo>[A-Za-z0-9]+)\s*\((?P<filename>.+?)\)\s*=\s*(?P<hash>[a-fA-F0-9]+)\s*$")
            .map_err(|_| AppError::Checksum("Failed to compile BSD regex".into()))?;

    let mut entries = Vec::new();

    for line in content.lines() {
        let stripped_line = line.trim();
        if stripped_line.is_empty() || stripped_line.starts_with('#') {
            continue;
        }

        if let Some(caps) = bsd_re.captures(stripped_line) {
            if let (Some(algo), Some(filename), Some(hash)) =
                (caps.name("algo"), caps.name("filename"), caps.name("hash"))
            {
                entries.push(ParsedChecksumEntry {
                    filename: filename.as_str().to_string(),
                    expected_hash: hash.as_str().to_lowercase(),
                    algorithm: Some(algo.as_str().to_lowercase()),
                });
                continue;
            }
        }

        if let Some(caps) = gnu_re.captures(stripped_line) {
            if let (Some(hash), Some(filename)) = (caps.name("hash"), caps.name("filename")) {
                entries.push(ParsedChecksumEntry {
                    filename: filename.as_str().to_string(),
                    expected_hash: hash.as_str().to_lowercase(),
                    algorithm: None, // Algorithm is implicit in GNU style
                });
            }
        }
    }

    Ok(entries)
}