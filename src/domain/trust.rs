use crate::error::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Pending,
    Verified,
    Revoked,
    Compromised,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct TrustedKey {
    pub fingerprint: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    pub added_by: String,
    pub added_at: DateTime<Utc>,
    pub algo: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_verified_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_by: Option<String>,
    pub verification_status: VerificationStatus,
    #[serde(default)]
    pub notes: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct TrustStore {
    pub trusted_keys: Vec<TrustedKey>,
}

impl FromStr for VerificationStatus {
    type Err = AppError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "verified" => Ok(Self::Verified),
            "revoked" => Ok(Self::Revoked),
            "compromised" => Ok(Self::Compromised),
            _ => Err(AppError::InvalidInput(format!(
                "Invalid verification status '{}'",
                s
            ))),
        }
    }
}

impl fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            VerificationStatus::Pending => "pending",
            VerificationStatus::Verified => "verified",
            VerificationStatus::Revoked => "revoked",
            VerificationStatus::Compromised => "compromised",
        };
        write!(f, "{}", s)
    }
}