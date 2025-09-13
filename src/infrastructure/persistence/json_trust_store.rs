use crate::app_config;
use crate::domain::trust::{TrustedKey, TrustStore, VerificationStatus};
use crate::error::AppError;
use chrono::Utc;
use std::fs;
use std::path::PathBuf;

pub struct JsonTrustStore {
    store: TrustStore,
    path: PathBuf,
}

impl JsonTrustStore {
    pub fn new() -> Result<Self, AppError> {
        let path = app_config::ConfigManager::get_trust_store_path()?;
        let mut store = Self {
            store: TrustStore::default(),
            path,
        };
        store.load()?;
        Ok(store)
    }

    fn load(&mut self) -> Result<(), AppError> {
        if !self.path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&self.path).map_err(|e| AppError::Io {
            path: self.path.clone(),
            source: e,
        })?;

        if content.trim().is_empty() {
            return Ok(());
        }

        // Revert to the simple, direct deserialization.
        // Serde will now correctly use the `alias` attributes defined in `domain/trust.rs`.
        self.store = serde_json::from_str(&content)?;

        Ok(())
    }

    pub fn save(&self) -> Result<(), AppError> {
        let parent = self.path.parent().ok_or_else(|| {
            AppError::Io {
                path: self.path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Parent directory not found",
                ),
            }
        })?;
        fs::create_dir_all(parent).map_err(|e| AppError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;

        let temp_path = self.path.with_extension("json.tmp");
        let content = serde_json::to_string_pretty(&self.store)?;
        fs::write(&temp_path, content).map_err(|e| AppError::Io {
            path: temp_path.clone(),
            source: e,
        })?;

        fs::rename(&temp_path, &self.path).map_err(|e| AppError::Io {
            path: temp_path,
            source: e,
        })?;

        Ok(())
    }

    pub fn get_key_entry(&self, fingerprint: &str) -> Option<&TrustedKey> {
        self.store
            .trusted_keys
            .iter()
            .find(|k| k.fingerprint == fingerprint)
    }

    pub fn is_fingerprint_present(&self, fingerprint: &str) -> bool {
        self.get_key_entry(fingerprint).is_some()
    }

    pub fn is_fingerprint_actively_trusted(&self, fingerprint: &str) -> bool {
        self.get_key_entry(fingerprint)
            .is_some_and(|k| k.verification_status == VerificationStatus::Verified)
    }

    pub fn add(
        &mut self,
        fingerprint: String,
        name: String,
        org: Option<String>,
        added_by: String,
        algo: String,
    ) -> Result<(), AppError> {
        if self.is_fingerprint_present(&fingerprint) {
            return Err(AppError::TrustStore(format!(
                "Fingerprint {} is already in the trust store.",
                fingerprint
            )));
        }

        let new_key = TrustedKey {
            fingerprint,
            name,
            org,
            added_by,
            added_at: Utc::now(),
            algo,
            last_verified_at: None,
            verified_by: None,
            verification_status: VerificationStatus::Pending,
            notes: "".to_string(),
        };

        self.store.trusted_keys.push(new_key);
        self.save()
    }

    pub fn remove(&mut self, fingerprint: &str) -> Result<(), AppError> {
        let initial_len = self.store.trusted_keys.len();
        self.store
            .trusted_keys
            .retain(|k| k.fingerprint != fingerprint);

        if self.store.trusted_keys.len() == initial_len {
            return Err(AppError::TrustStore(format!(
                "Key with fingerprint {} not found in the trust store.",
                fingerprint
            )));
        }

        self.save()
    }

    pub fn update_verification_status(
        &mut self,
        fingerprint: &str,
        status: VerificationStatus,
        updated_by: String,
        notes: Option<String>,
    ) -> Result<(), AppError> {
        let key_entry = self
            .store
            .trusted_keys
            .iter_mut()
            .find(|k| k.fingerprint == fingerprint)
            .ok_or_else(|| {
                AppError::TrustStore(format!(
                    "Key with fingerprint {} not found in the trust store.",
                    fingerprint
                ))
            })?;

        key_entry.verification_status = status;
        key_entry.last_verified_at = Some(Utc::now());
        key_entry.verified_by = Some(updated_by);
        if let Some(n) = notes {
            key_entry.notes = n;
        }

        self.save()
    }

    pub fn list_all(&self) -> Vec<TrustedKey> {
        let mut keys = self.store.trusted_keys.clone();
        keys.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        keys
    }
}