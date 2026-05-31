use crate::access::{AccessGrantV1, AccessRevocationListV1};
use crate::errors::SwarmAiErrorV1;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionOptions {
    #[serde(default)]
    pub stream: bool,
    #[serde(rename = "deadlineMs", default)]
    pub deadline_ms: Option<u64>,
    #[serde(default)]
    pub deterministic: Option<bool>,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        Self {
            stream: false,
            deadline_ms: Some(30_000),
            deterministic: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptMode {
    HashOnly,
    EncryptedEvidence,
    PublicEvidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionPrivacy {
    #[serde(rename = "receiptMode")]
    pub receipt_mode: ReceiptMode,
}

impl Default for ExecutionPrivacy {
    fn default() -> Self {
        Self {
            receipt_mode: ReceiptMode::HashOnly,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "preferredArtifactGroup", default)]
    pub preferred_artifact_group: Option<String>,
    pub task: String,
    pub input: Value,
    #[serde(default)]
    pub options: ExecutionOptions,
    #[serde(default)]
    pub privacy: ExecutionPrivacy,
    #[serde(rename = "accessGrant", default)]
    pub access_grant: Option<AccessGrantV1>,
    #[serde(rename = "accessRevocationList", default)]
    pub access_revocation_list: Option<AccessRevocationListV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionStatus {
    Succeeded,
    Failed,
    Cancelled,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct ExecutionMetrics {
    #[serde(rename = "queueMs", default)]
    pub queue_ms: u64,
    #[serde(rename = "loadMs", default)]
    pub load_ms: u64,
    #[serde(rename = "computeMs", default)]
    pub compute_ms: u64,
    #[serde(rename = "totalMs", default)]
    pub total_ms: u64,
    #[serde(rename = "inputTokens", default)]
    pub input_tokens: Option<u64>,
    #[serde(rename = "outputTokens", default)]
    pub output_tokens: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionResponseV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub status: ExecutionStatus,
    pub output: Value,
    pub metrics: ExecutionMetrics,
    #[serde(rename = "receiptRef", default)]
    pub receipt_ref: Option<String>,
    pub error: Option<SwarmAiErrorV1>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

fn empty_metadata() -> Value {
    json!({})
}

impl ExecutionResponseV1 {
    pub fn succeeded(
        request_id: impl Into<String>,
        output: Value,
        metrics: ExecutionMetrics,
    ) -> Self {
        Self {
            schema_version: "swarm-ai.execution.response.v1".to_string(),
            request_id: request_id.into(),
            status: ExecutionStatus::Succeeded,
            output,
            metrics,
            receipt_ref: None,
            error: None,
            metadata: json!({}),
        }
    }

    pub fn failed(
        request_id: impl Into<String>,
        error: SwarmAiErrorV1,
        metrics: ExecutionMetrics,
    ) -> Self {
        Self {
            schema_version: "swarm-ai.execution.response.v1".to_string(),
            request_id: request_id.into(),
            status: ExecutionStatus::Failed,
            output: json!({}),
            metrics,
            receipt_ref: None,
            error: Some(error),
            metadata: json!({}),
        }
    }
}
