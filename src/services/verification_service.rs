use crate::app_config::SIGMATE_META_FILE;
use crate::domain::signature::SignatureMetadata;
use crate::error::AppError;
use crate::infrastructure::checksum_parser;
use crate::infrastructure::crypto::key_handler;
use crate::infrastructure::crypto::signing;
use crate::infrastructure::hashing;
use crate::infrastructure::persistence::json_trust_store::JsonTrustStore;
use crate::utils::files;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct VerificationResult {
    pub file: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_source: Option<PathBuf>,
    pub valid_signature: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_signer: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_hash: Option<String>,
    pub overall_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm_used: Option<String>,
}

pub struct VerificationService<'a> {
    pub files: &'a [PathBuf],
    pub key_data: &'a [u8],
    pub sig_type: &'a str,
    pub sig_dir: &'a Path,
    pub base_dir: &'a Path,
    pub require_trusted: bool,
}

impl<'a> VerificationService<'a> {
    pub fn verify_signatures(&self) -> Result<Vec<VerificationResult>, AppError> {
        let verifying_key = key_handler::get_verifying_key_from_pem(self.key_data)?;
        let key_fingerprint = key_handler::get_key_fingerprint(&verifying_key)?;

        let trust_store = if self.require_trusted {
            Some(JsonTrustStore::new()?)
        } else {
            None
        };
        let trusted_signer =
            trust_store.as_ref().map(|ts| ts.is_fingerprint_actively_trusted(&key_fingerprint));

        let central_meta_path = self.sig_dir.join(SIGMATE_META_FILE);
        let central_meta_store = self.load_central_metadata(&central_meta_path)?;

        let mut results = Vec::new();
        for file_path in self.files {
            results.push(self.verify_signature_for_file(
                file_path,
                &verifying_key,
                &central_meta_store,
                trusted_signer,
            ));
        }
        Ok(results)
    }

    pub fn verify_checksums(
        &self,
        checksum_file: &Path,
        algo_hint: &str,
    ) -> Result<Vec<VerificationResult>, AppError> {
        let entries = checksum_parser::parse_checksum_file(checksum_file)?;
        let mut results = Vec::new();

        let files_to_check = if self.files.is_empty() {
            entries
                .iter()
                .map(|e| self.base_dir.join(&e.filename))
                .collect()
        } else {
            self.files.to_vec()
        };

        let checksum_map: HashMap<String, (String, Option<String>)> = entries
            .into_iter()
            .map(|e| (e.filename, (e.expected_hash, e.algorithm)))
            .collect();

        for file_to_check in files_to_check {
            let mut result = VerificationResult {
                file: file_to_check.clone(),
                ..Default::default()
            };

            let relative_path = file_to_check
                .strip_prefix(self.base_dir)
                .unwrap_or(&file_to_check)
                .to_string_lossy()
                .to_string();

            if let Some((expected_hash, parsed_algo)) = checksum_map.get(&relative_path) {
                result.expected_hash = Some(expected_hash.clone());
                
                let algo_to_use = parsed_algo.as_deref().unwrap_or(algo_hint);
                result.algorithm_used = Some(algo_to_use.to_string());

                if !file_to_check.exists() {
                    result.error = Some("File not found on disk.".to_string());
                } else {
                    let file_data = fs::read(&file_to_check)
                        .map_err(|e| AppError::Io { path: file_to_check.clone(), source: e })?;
                    let actual_hash = hashing::hash_data(&file_data, algo_to_use)?;
                    result.actual_hash = Some(actual_hash.clone());

                    if actual_hash.eq_ignore_ascii_case(expected_hash) {
                        result.overall_verified = true;
                    } else {
                        result.error = Some("Hash mismatch.".to_string());
                    }
                }
            } else {
                result.error = Some("File not found in checksum list.".to_string());
            }
            results.push(result);
        }
        Ok(results)
    }

    fn verify_signature_for_file(
        &self,
        file_path: &Path,
        key: &VerifyingKey,
        meta_store: &HashMap<PathBuf, SignatureMetadata>,
        trusted_signer: Option<bool>,
    ) -> VerificationResult {
        let mut result = VerificationResult {
            file: files::remove_dot_slash_prefix(file_path),
            trusted_signer,
            ..Default::default()
        };

        let file_data = match fs::read(file_path) {
            Ok(data) => data,
            Err(e) => {
                result.error = Some(format!("Failed to read file: {}", e));
                result.overall_verified = false;
                return result;
            }
        };
        result.actual_hash = hashing::hash_data(&file_data, "sha256").ok();

        let signature_bytes;
        let rel_path = file_path.strip_prefix(self.base_dir).unwrap_or(file_path);

        if self.sig_type == "meta" || (self.sig_type == "auto" && meta_store.contains_key(rel_path))
        {
            if let Some(meta) = meta_store.get(rel_path) {
                result.metadata_source = Some(files::remove_dot_slash_prefix(&self.sig_dir.join(SIGMATE_META_FILE)));
                result.expected_hash = Some(meta.file_hash.clone());

                if result.actual_hash != result.expected_hash {
                    result.error =
                        Some("File content hash does not match hash in metadata.".to_string());
                }

                if let Some(exp_str) = &meta.expires_at {
                    if let Ok(exp_dt) = DateTime::parse_from_rfc3339(exp_str) {
                        let expired = Utc::now() > exp_dt.with_timezone(&Utc);
                        result.expired = Some(expired);
                        if expired && result.error.is_none() {
                            result.error = Some("Signature has expired.".to_string());
                        }
                    } else if result.error.is_none() {
                        result.error = Some("Invalid expiration timestamp in metadata.".to_string());
                    }
                } else {
                    result.expired = Some(false);
                }

                signature_bytes = match B64.decode(&meta.signature) {
                    Ok(bytes) => Some(bytes),
                    Err(_) => {
                        if result.error.is_none() {
                           result.error = Some("Failed to decode base64 signature from metadata.".into());
                        }
                        None
                    }
                };
            } else {
                result.error = Some(format!("No metadata found for file {}", file_path.display()));
                signature_bytes = None;
            }
        } else {
            let sig_path_res =
                crate::utils::files::build_output_path(file_path, self.base_dir, ".sig", self.sig_dir);
            if let Ok(p) = sig_path_res {
                if p.exists() {
                    result.signature_file = Some(files::remove_dot_slash_prefix(&p));
                    signature_bytes = fs::read(p).ok();
                } else {
                    signature_bytes = None;
                }
            } else {
                signature_bytes = None;
            }
        }

        if let Some(sig) = signature_bytes {
            match signing::verify_signature(key, &file_data, &sig) {
                Ok(is_valid) => {
                    result.valid_signature = is_valid;
                    if !is_valid && result.error.is_none() {
                        result.error = Some("Cryptographic signature verification failed.".to_string());
                    }
                }
                Err(e) => result.error = Some(e.to_string()),
            }
        } else if result.error.is_none() {
            result.error = Some("No signature data found to verify.".to_string());
        }
        
        if self.require_trusted && result.trusted_signer != Some(true) && result.error.is_none() {
            result.error = Some("Signer's key is not actively trusted.".to_string());
        }

        result.overall_verified = result.error.is_none();

        result
    }

    fn load_central_metadata(
        &self,
        path: &Path,
    ) -> Result<HashMap<PathBuf, SignatureMetadata>, AppError> {
        if !path.exists() {
            return Ok(HashMap::new());
        }
        let content = fs::read_to_string(path)
            .map_err(|e| AppError::Io { path: path.to_path_buf(), source: e })?;
        
        if content.trim().is_empty() {
            return Ok(HashMap::new());
        }

        let entries: Vec<SignatureMetadata> = match serde_json::from_str(&content) {
            Ok(entries) => entries,
            Err(e) => return Err(AppError::Json(e)),
        };
        Ok(entries
            .into_iter()
            .map(|e| (e.relpath.clone(), e))
            .collect())
    }
}