use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;

const APP_DIR_NAME: &str = "sigmate";
const CONFIG_FILE_NAME: &str = "config.json";
const KEYRING_DIR_NAME: &str = "public_keys";
const TRUST_STORE_FILE_NAME: &str = "trusted_public_keys.json";
pub const SIGNATURES_FOLDER: &str = "signatures";
pub const SIGMATE_META_FILE: &str = "sigmate.meta.json";
pub const SIGMATE_SBOM_FILE: &str = "sigmate.sbom.json";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AppConfig {
    pub private_key_path: Option<PathBuf>,
    pub signer_identity: Option<String>,
    pub keyring_path: Option<PathBuf>,
}

pub struct ConfigManager {
    config: AppConfig,
    config_path: PathBuf,
}

impl ConfigManager {
    pub fn new() -> Result<Self, AppError> {
        let config_dir = Self::get_config_dir()?;
        let config_path = config_dir.join(CONFIG_FILE_NAME);
        let mut manager = Self {
            config: AppConfig::default(),
            config_path,
        };
        manager.load()?;
        Ok(manager)
    }

    fn get_config_dir() -> Result<PathBuf, AppError> {
        dirs::config_dir()
            .map(|p| p.join(APP_DIR_NAME))
            .ok_or_else(|| AppError::Config("Could not determine config directory.".into()))
    }

    pub fn get_trust_store_path() -> Result<PathBuf, AppError> {
        Ok(Self::get_config_dir()?.join(TRUST_STORE_FILE_NAME))
    }

    pub fn get_default_keyring_path() -> Result<PathBuf, AppError> {
        Ok(Self::get_config_dir()?.join(KEYRING_DIR_NAME))
    }
    
    fn load(&mut self) -> Result<(), AppError> {
        if self.config_path.exists() {
            let content = fs::read_to_string(&self.config_path).map_err(|e| AppError::Io {
                path: self.config_path.clone(),
                source: e,
            })?;
            if !content.trim().is_empty() {
                 self.config = serde_json::from_str(&content)?;
            }
        }
        
        if self.config.keyring_path.is_none() {
            self.config.keyring_path = Some(Self::get_default_keyring_path()?);
        }

        Ok(())
    }

    pub fn save(&self) -> Result<(), AppError> {
        let config_dir = self.config_path.parent().ok_or_else(|| {
            AppError::Config("Invalid configuration file path.".to_string())
        })?;
        fs::create_dir_all(config_dir).map_err(|e| AppError::Io {
            path: config_dir.to_path_buf(),
            source: e,
        })?;
        let content = serde_json::to_string_pretty(&self.config)?;
        fs::write(&self.config_path, content).map_err(|e| AppError::Io {
            path: self.config_path.clone(),
            source: e,
        })
    }

    pub fn get_private_key_path(&self) -> Option<PathBuf> {
        env::var("SIGMATE_PRIVATE_KEY_PATH").map(PathBuf::from).ok().or_else(|| self.config.private_key_path.clone())
    }

    pub fn get_signer_identity(&self) -> Option<String> {
        env::var("SIGMATE_SIGNER_IDENTITY").ok().or_else(|| self.config.signer_identity.clone())
    }

    pub fn get_keyring_path(&self) -> Result<PathBuf, AppError> {
        let path = env::var("SIGMATE_KEYRING_PATH").map(PathBuf::from).ok().or(self.config.keyring_path.clone());
        
        match path {
            Some(p) => {
                 fs::create_dir_all(&p).map_err(|e| AppError::Io {
                    path: p.clone(),
                    source: e,
                })?;
                Ok(p)
            }
            None => Err(AppError::Config("Keyring path not configured and default could not be determined.".into()))
        }
    }
    
    pub fn set_private_key_path(&mut self, path: PathBuf) {
        self.config.private_key_path = Some(path);
    }

    pub fn set_signer_identity(&mut self, identity: String) {
        self.config.signer_identity = Some(identity);
    }
    
    pub fn set_keyring_path(&mut self, path: PathBuf) {
        self.config.keyring_path = Some(path);
    }

    pub fn get_config_path(&self) -> &PathBuf {
        &self.config_path
    }
}