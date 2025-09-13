use crate::app_config::{SIGMATE_META_FILE, SIGMATE_SBOM_FILE, VERSION};
use crate::domain::sbom::{
    CycloneDxSbom, SbomAuthor, SbomComponent, SbomHash, SbomMetadata, SbomProperty, SbomSignature,
    SbomTool, ExternalReference,
};
use crate::domain::signature::{GitInfo, SignatureMetadata, ToolMetadata};
use crate::error::AppError;
use crate::infrastructure::crypto::key_handler;
use crate::infrastructure::crypto::signing;
use crate::infrastructure::hashing;
use crate::utils::{files, git};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Serialize, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct SigningSummary {
    pub overall_status: String,
    pub files_processed_count: usize,
    pub files_skipped_count: usize,
    pub meta_file_path: Option<PathBuf>,
    pub sbom_file_path: Option<PathBuf>,
    pub checksum_files_generated: Vec<PathBuf>,
}

pub struct ChecksumTask<'a> {
    pub algo: &'a str,
    pub output_filename: PathBuf,
}

pub struct SigningService<'a> {
    pub files_to_process: &'a [PathBuf],
    pub key_data: &'a [u8],
    pub password_env_var: Option<&'a str>,
    pub output_dir: &'a Path,
    pub base_dir: &'a Path,
    pub identity: &'a str,
    pub host: &'a str,
    pub version_info: Option<HashMap<String, GitInfo>>,
    pub should_write_raw: bool,
    pub should_write_meta: bool,
    pub should_write_sbom: bool,
    pub checksum_tasks: Vec<ChecksumTask<'a>>,
    pub no_abspath: bool,
    pub expires_at: Option<String>,
    pub force: bool,
}

impl<'a> SigningService<'a> {
    pub fn execute(&self) -> Result<SigningSummary, AppError> {
        let is_crypto_signing =
            !self.key_data.is_empty() && (self.should_write_raw || self.should_write_meta || self.should_write_sbom);
        let signing_key = if is_crypto_signing {
            Some(key_handler::load_signing_key(
                self.key_data,
                self.password_env_var,
            )?)
        } else {
            None
        };
        let verifying_key = signing_key.as_ref().map(|sk| sk.verifying_key());
        let key_fingerprint = verifying_key.as_ref().map(key_handler::get_key_fingerprint).transpose()?.unwrap_or_default();

        let mut meta_entries = Vec::new();
        let mut sbom_components = Vec::new();
        let mut checksums: HashMap<String, Vec<(String, String)>> = HashMap::new();
        
        let mut files_to_sign = Vec::new();
        let mut idempotency_errors = Vec::new();
        
        let existing_meta = if !self.force && (self.should_write_meta || self.should_write_raw) {
            self.load_existing_metadata()?
        } else {
            HashMap::new()
        };

        for file_path in self.files_to_process {
            if !self.force {
                match self.is_already_signed_and_valid(file_path, verifying_key.as_ref(), &existing_meta) {
                    Ok(true) => { /* Skip this file */ },
                    Ok(false) => files_to_sign.push(file_path),
                    Err(AppError::ExistingSignatureInvalid(path)) => {
                        idempotency_errors.push(path.display().to_string());
                    },
                    Err(e) => return Err(e),
                }
            } else {
                files_to_sign.push(file_path);
            }
        }

        if !idempotency_errors.is_empty() {
            return Err(AppError::IdempotencyCheckFailed(idempotency_errors));
        }

        for file_path in &files_to_sign {
            self.process_file(
                file_path,
                signing_key.as_ref(),
                &key_fingerprint,
                &mut checksums,
                &mut meta_entries,
                &mut sbom_components,
            )?;
        }

        let summary = SigningSummary {
            overall_status: "success".to_string(),
            files_processed_count: files_to_sign.len(),
            files_skipped_count: self.files_to_process.len() - files_to_sign.len(),
            meta_file_path: if self.should_write_meta && !meta_entries.is_empty() {
                Some(files::remove_dot_slash_prefix(&self.write_meta_file(&meta_entries)?))
            } else {
                None
            },
            sbom_file_path: if self.should_write_sbom && !sbom_components.is_empty() {
                Some(files::remove_dot_slash_prefix(&self.write_sbom_file(sbom_components)?))
            } else {
                None
            },
            checksum_files_generated: self
                .write_all_checksum_files(&checksums)?
                .into_iter()
                .map(|p| files::remove_dot_slash_prefix(&p))
                .collect(),
        };

        Ok(summary)
    }
    
    fn is_already_signed_and_valid(&self, file_path: &Path, verifying_key: Option<&VerifyingKey>, existing_meta: &HashMap<PathBuf, SignatureMetadata>) -> Result<bool, AppError> {
        if let Some(key) = verifying_key {
            let sig_output_path = files::build_output_path(file_path, self.base_dir, ".sig", self.output_dir)?;
            if sig_output_path.exists() {
                let file_data = fs::read(file_path).map_err(|e| AppError::Io { path: file_path.to_path_buf(), source: e})?;
                let sig_data = fs::read(&sig_output_path).map_err(|e| AppError::Io { path: sig_output_path, source: e})?;
                if signing::verify_signature(key, &file_data, &sig_data)? {
                    return Ok(true);
                } else {
                    return Err(AppError::ExistingSignatureInvalid(file_path.to_path_buf()));
                }
            }

            let rel_path = file_path.strip_prefix(self.base_dir).unwrap_or(file_path);
            if let Some(meta_entry) = existing_meta.get(rel_path) {
                let file_data = fs::read(file_path).map_err(|e| AppError::Io { path: file_path.to_path_buf(), source: e})?;
                let current_hash = hashing::hash_data(&file_data, "sha256")?;
                if current_hash == meta_entry.file_hash {
                    return Ok(true);
                } else {
                    return Err(AppError::ExistingSignatureInvalid(file_path.to_path_buf()));
                }
            }
        }
        Ok(false)
    }

    fn load_existing_metadata(&self) -> Result<HashMap<PathBuf, SignatureMetadata>, AppError> {
        let meta_path = self.output_dir.join(SIGMATE_META_FILE);
        if !meta_path.exists() { return Ok(HashMap::new()); }
        let content = fs::read_to_string(&meta_path).map_err(|e| AppError::Io { path: meta_path, source: e})?;
        if content.trim().is_empty() { return Ok(HashMap::new()); }
        let entries: Vec<SignatureMetadata> = serde_json::from_str(&content)?;
        Ok(entries.into_iter().map(|e| (e.relpath.clone(), e)).collect())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_file(&self, file_path: &Path, signing_key: Option<&SigningKey>, key_fingerprint: &str, checksums: &mut HashMap<String, Vec<(String, String)>>, meta_entries: &mut Vec<SignatureMetadata>, sbom_components: &mut Vec<SbomComponent>) -> Result<(), AppError> {
        let file_data = fs::read(file_path).map_err(|e| AppError::Io { path: file_path.to_path_buf(), source: e })?;
        let relpath = file_path.strip_prefix(self.base_dir).unwrap_or(file_path);
        let relpath_str = relpath.to_string_lossy().to_string();

        for task in &self.checksum_tasks {
            let hash = hashing::hash_data(&file_data, task.algo)?;
            checksums.entry(task.algo.to_string()).or_default().push((hash, relpath_str.clone()));
        }

        if let Some(key) = signing_key {
            let signature = key_handler::sign_data(key, &file_data);

            let signature_file_path_for_meta = if self.should_write_raw {
                let sig_output_path = files::build_output_path(file_path, self.base_dir, ".sig", self.output_dir)?;
                fs::write(&sig_output_path, signature.to_bytes()).map_err(|e| AppError::Io { path: sig_output_path.clone(), source: e })?;

                if self.no_abspath {
                    Some(files::remove_dot_slash_prefix(&sig_output_path))
                } else {
                    Some(fs::canonicalize(&sig_output_path).map_err(|e| AppError::Io { path: sig_output_path, source: e })?)
                }
            } else {
                None
            };

            let meta_entry = SignatureMetadata {
                file: files::remove_dot_slash_prefix(&PathBuf::from(file_path.file_name().unwrap_or_default())),
                relpath: files::remove_dot_slash_prefix(relpath),
                abspath: if self.no_abspath { None } else { Some(fs::canonicalize(file_path).map_err(|e| AppError::Io { path: file_path.to_path_buf(), source: e })?) },
                created_at: Utc::now().to_rfc3339(),
                expires_at: self.expires_at.clone(),
                tool: ToolMetadata {
                    name: "sigmate".to_string(),
                    version: VERSION.to_string(),
                    language: "rust".to_string(),
                },
                signer_identity: self.identity.to_string(),
                signer_host: self.host.to_string(),
                signature_algorithm: "Ed25519".to_string(),
                hash_algorithm: "sha256".to_string(),
                file_hash: hashing::hash_data(&file_data, "sha256")?,
                signature: B64.encode(signature.to_bytes()),
                signature_hash: hashing::hash_data(&signature.to_bytes(), "sha256")?,
                key_fingerprint: key_fingerprint.to_string(),
                signature_file: signature_file_path_for_meta,
                version: self.version_info.clone(),
            };
            
            if self.should_write_sbom {
                sbom_components.push(self.build_sbom_component(&meta_entry)?);
            }
            if self.should_write_meta {
                meta_entries.push(meta_entry);
            }
        }
        Ok(())
    }

    fn write_all_checksum_files(&self, checksums: &HashMap<String, Vec<(String, String)>>) -> Result<Vec<PathBuf>, AppError> {
        let mut paths = Vec::new();
        for task in &self.checksum_tasks {
            if let Some(lines) = checksums.get(task.algo) {
                let path = self.output_dir.join(&task.output_filename);
                if !path.exists() || self.force {
                    let mut file = fs::File::create(&path).map_err(|e| AppError::Io { path: path.clone(), source: e})?;
                    for (hash, filename) in lines {
                        writeln!(file, "{}  {}", hash, filename).map_err(|e| AppError::Io { path: path.clone(), source: e})?;
                    }
                }
                paths.push(path);
            }
        }
        Ok(paths)
    }

    fn build_sbom_component(&self, meta: &SignatureMetadata) -> Result<SbomComponent, AppError> {
        let properties = vec![
            SbomProperty {
                name: "sigmate:relpath".to_string(),
                value: Some(meta.relpath.display().to_string()),
            },
            SbomProperty {
                name: "sigmate:abspath".to_string(),
                value: meta.abspath.as_ref().map(|p| p.display().to_string()),
            },
        ];
        Ok(SbomComponent {
            r#type: "file".to_string(),
            bom_ref: meta.relpath.display().to_string(),
            name: meta.file.display().to_string(),
            version: meta.version.clone(),
            hashes: vec![SbomHash { alg: "SHA-256".to_string(), content: meta.file_hash.clone() }],
            signatures: vec![SbomSignature { algorithm: meta.signature_algorithm.clone(), value: meta.signature.clone() }],
            properties,
        })
    }

    fn write_meta_file(&self, entries: &[SignatureMetadata]) -> Result<PathBuf, AppError> {
        let path = self.output_dir.join(SIGMATE_META_FILE);
        let content = serde_json::to_string_pretty(entries)?;
        fs::write(&path, content).map_err(|e| AppError::Io { path: path.clone(), source: e })?;
        Ok(path)
    }

    fn write_sbom_file(&self, components: Vec<SbomComponent>) -> Result<PathBuf, AppError> {
        let path = self.output_dir.join(SIGMATE_SBOM_FILE);
        if !path.exists() || self.force {
            let git_author = git::get_git_author(self.base_dir)?.unwrap_or_else(|| "Unknown Author".to_string());
            let sbom = CycloneDxSbom {
                bom_format: "CycloneDX".to_string(),
                spec_version: "1.5".to_string(),
                serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
                version: 1,
                metadata: SbomMetadata {
                    timestamp: Utc::now().to_rfc3339(),
                    tools: vec![SbomTool {
                        vendor: "opensecurity".to_string(),
                        name: "sigmate".to_string(),
                        version: VERSION.to_string(),
                        external_references: Some(vec![
                            ExternalReference {
                                url: "https://github.com/opensecurity/sigmate".to_string(),
                                r#type: "vcs".to_string(),
                            },
                            ExternalReference {
                                url: "https://github.com/opensecurity".to_string(),
                                r#type: "website".to_string(),
                            }
                        ]),
                    }],
                    authors: vec![SbomAuthor { name: git_author }],
                },
                components,
            };
            let content = serde_json::to_string_pretty(&sbom)?;
            fs::write(&path, content).map_err(|e| AppError::Io { path: path.clone(), source: e })?;
        }
        Ok(path)
    }
}