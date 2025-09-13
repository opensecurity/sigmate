use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Filesystem IO error for path '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 encoding/decoding error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Cryptography error: {0}")]
    Crypto(String),

    #[error("Key is encrypted but no password was provided or it was incorrect.")]
    KeyPasswordRequired,

    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Idempotency check failed: one or more files have been modified since they were last signed.")]
    IdempotencyCheckFailed(Vec<String>),

    #[error("Verification failed for '{path}': {reason}")]
    VerificationFailure { path: PathBuf, reason: String },

    #[error("Existing signature for '{0}' is invalid for the current file content. Use --force to overwrite.")]
    ExistingSignatureInvalid(PathBuf),

    #[error("Trust store error: {0}")]
    TrustStore(String),

    #[error("Checksum error: {0}")]
    Checksum(String),

    #[error("Could not find a valid git repository at or above '{path}'.")]
    GitRepositoryNotFound { path: PathBuf },

    #[error("Git operation failed: {0}")]
    Git(#[from] git2::Error),

    #[error("An unexpected error occurred: {0}")]
    Anyhow(#[from] anyhow::Error),
}