use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PackageKind {
    Model,
    Agent,
    Tool,
    Dataset,
    Benchmark,
    Workflow,
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum LicenseType {
    Open,
    Commercial,
    Private,
    TokenGated,
    Subscription,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LicenseInfo {
    #[serde(rename = "type")]
    pub license_type: LicenseType,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Publisher {
    pub address: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "publisherProfileRef", default)]
    pub publisher_profile_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactMinimum {
    #[serde(rename = "memoryMB", default)]
    pub memory_mb: Option<u64>,
    #[serde(default)]
    pub webgpu: Option<bool>,
    #[serde(rename = "diskMB", default)]
    pub disk_mb: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactGroup {
    pub id: String,
    pub target: String,
    pub engine: String,
    pub format: String,
    pub paths: Vec<String>,
    #[serde(rename = "totalBytes")]
    pub total_bytes: u64,
    pub sha256: String,
    pub minimum: ArtifactMinimum,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PermissionRequest {
    pub name: String,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default = "empty_limits")]
    pub limits: Value,
}

fn empty_limits() -> Value {
    json!({})
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PackageManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub kind: PackageKind,
    pub name: String,
    pub version: String,
    pub publisher: Publisher,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(rename = "artifactGroups")]
    pub artifact_groups: Vec<ArtifactGroup>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(rename = "outputSchema")]
    pub output_schema: Value,
    #[serde(default)]
    pub permissions: Vec<PermissionRequest>,
    pub license: LicenseInfo,
}

pub fn manifest_supports_capability(manifest: &PackageManifestV1, capability: &str) -> bool {
    manifest
        .capabilities
        .iter()
        .any(|declared| declared == capability)
}
