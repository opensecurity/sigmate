use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ToolMetadata {
    pub name: String,
    pub version: String,
    pub language: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct SignatureMetadata {
    pub file: PathBuf,
    pub relpath: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abspath: Option<PathBuf>,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub tool: ToolMetadata,
    pub signer_identity: String,
    pub signer_host: String,
    pub signature_algorithm: String,
    pub hash_algorithm: String,
    pub file_hash: String,
    pub signature: String,
    pub signature_hash: String,
    pub key_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<HashMap<String, GitInfo>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct GitInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
}