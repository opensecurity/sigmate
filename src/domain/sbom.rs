use crate::domain::signature::GitInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;


#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")] // CycloneDX spec uses camelCase, must comply.
pub struct CycloneDxSbom {
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: SbomMetadata,
    pub components: Vec<SbomComponent>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")] // CycloneDX spec uses camelCase, must comply.
pub struct SbomMetadata {
    pub timestamp: String,
    pub tools: Vec<SbomTool>,
    pub authors: Vec<SbomAuthor>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")] // CycloneDX spec uses camelCase, must comply.
pub struct ExternalReference {
    pub url: String,
    pub r#type: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")] // CycloneDX spec uses camelCase, must comply.
pub struct SbomTool {
    pub vendor: String,
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_references: Option<Vec<ExternalReference>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")] // CycloneDX spec uses camelCase, must comply.
pub struct SbomAuthor {
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")] // CycloneDX spec uses camelCase, must comply.
pub struct SbomComponent {
    pub r#type: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<HashMap<String, GitInfo>>,
    pub hashes: Vec<SbomHash>,
    pub signatures: Vec<SbomSignature>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<SbomProperty>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")] // CycloneDX spec uses camelCase, must comply.
pub struct SbomHash {
    pub alg: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")] // CycloneDX spec uses camelCase, must comply.
pub struct SbomSignature {
    pub algorithm: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")] // CycloneDX spec uses camelCase, must comply.
pub struct SbomProperty {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}
