use crate::canonical::{canonicalize_json, hash_canonical_json};
use crate::errors::{ErrorCode, StandardErrorCodeV1, SwarmAiErrorV1};
use crate::execution::{
    ExecutionMetrics, ExecutionOptions, ExecutionPrivacy, ExecutionRequestV1, ExecutionResponseV1,
    ExecutionStatus, ReceiptMode,
};
use crate::job::{ApiSurface, PriceV1, StreamingEventType};
use crate::manifest::{AssetDescriptorV1, AssetRoleV1, UniversalCapabilityV1};
use crate::trust::{DataRetentionRule, IntegrityTier, LoggingRule, PrivacyTier};
use crate::validation::ValidationIssue;
use chrono::{SecondsFormat, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEV_AI_REQUEST_SIGNATURE_PREFIX: &str = "dev-ai-request-signature-v1";
const DEV_AI_RESPONSE_SIGNATURE_PREFIX: &str = "dev-ai-response-signature-v1";
const DEV_AI_WORKLOAD_SIGNATURE_PREFIX: &str = "dev-ai-workload-signature-v1";
const DEV_TASK_ENVELOPE_SIGNATURE_PREFIX: &str = "dev-task-envelope-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiInputPartType {
    Text,
    ImageRef,
    ImageInline,
    AudioRef,
    AudioChunk,
    DocumentRef,
    VectorQuery,
    FileRef,
    ToolResult,
    VideoRef,
    TrainingDataRef,
    EvaluationDataRef,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiInputPartV1 {
    #[serde(rename = "type")]
    pub part_type: AiInputPartType,
    #[serde(default)]
    pub content: Value,
    #[serde(
        rename = "contentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_ref: Option<String>,
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

impl AiInputPartV1 {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            part_type: AiInputPartType::Text,
            content: json!(text.into()),
            content_ref: None,
            mime_type: Some("text/plain".to_string()),
            hash: None,
            metadata: json!({}),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct AiPackageSelectorV1 {
    #[serde(rename = "packageId", default, skip_serializing_if = "Option::is_none")]
    pub package_id: Option<String>,
    #[serde(
        rename = "packageRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_ref: Option<String>,
    #[serde(
        rename = "serviceRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub service_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct AiSamplingOptionsV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(rename = "topP", default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    #[serde(
        rename = "maxOutputTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(default)]
    pub stop: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct AiRequestConstraintsV1 {
    #[serde(rename = "maxPrice", default, skip_serializing_if = "Option::is_none")]
    pub max_price: Option<PriceV1>,
    #[serde(
        rename = "maxLatencyMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_latency_ms: Option<u64>,
    #[serde(
        rename = "deadlineMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deadline_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deterministic: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiRequestPrivacyV1 {
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "receiptMode")]
    pub receipt_mode: ReceiptMode,
    #[serde(
        rename = "dataRetentionRule",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub data_retention_rule: Option<DataRetentionRule>,
    #[serde(
        rename = "loggingRule",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub logging_rule: Option<LoggingRule>,
}

impl Default for AiRequestPrivacyV1 {
    fn default() -> Self {
        Self {
            privacy_tier: PrivacyTier::Standard,
            receipt_mode: ReceiptMode::HashOnly,
            data_retention_rule: None,
            logging_rule: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiRequestValidationV1 {
    #[serde(rename = "requiredVerificationTier")]
    pub required_verification_tier: IntegrityTier,
    #[serde(rename = "validationRequired")]
    pub validation_required: bool,
    #[serde(default)]
    pub strategies: Vec<String>,
}

impl Default for AiRequestValidationV1 {
    fn default() -> Self {
        Self {
            required_verification_tier: IntegrityTier::ReceiptOnly,
            validation_required: false,
            strategies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub requester: String,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    #[serde(rename = "packageSelector")]
    pub package_selector: AiPackageSelectorV1,
    #[serde(default)]
    pub inputs: Vec<AiInputPartV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Value>>,
    #[serde(
        rename = "responseFormat",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub response_format: Option<Value>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sampling: Option<AiSamplingOptionsV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<String>,
    #[serde(default)]
    pub constraints: AiRequestConstraintsV1,
    #[serde(default)]
    pub privacy: AiRequestPrivacyV1,
    #[serde(default)]
    pub validation: AiRequestValidationV1,
    #[serde(default)]
    pub signatures: Vec<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

impl AiRequestV1 {
    pub fn text(
        request_id: impl Into<String>,
        requester: impl Into<String>,
        api_surface: ApiSurface,
        package_selector: AiPackageSelectorV1,
        text: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: "hivemind.request.v1".to_string(),
            request_id: request_id.into(),
            requester: requester.into(),
            api_surface,
            package_selector,
            inputs: vec![AiInputPartV1::text(text)],
            messages: None,
            tools: None,
            response_format: None,
            stream: false,
            sampling: None,
            task: None,
            constraints: AiRequestConstraintsV1::default(),
            privacy: AiRequestPrivacyV1::default(),
            validation: AiRequestValidationV1::default(),
            signatures: Vec::new(),
            metadata: json!({}),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiWorkloadExecutionRequirementsV1 {
    #[serde(rename = "runtimeClasses", default)]
    pub runtime_classes: Vec<String>,
    #[serde(rename = "requiredApiSurface")]
    pub required_api_surface: ApiSurface,
    #[serde(
        rename = "maxLatencyMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_latency_ms: Option<u64>,
    #[serde(rename = "maxCost", default, skip_serializing_if = "Option::is_none")]
    pub max_cost: Option<PriceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deterministic: Option<bool>,
    #[serde(default)]
    pub stream: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiWorkloadStoragePlanV1 {
    #[serde(rename = "inputStrategy")]
    pub input_strategy: String,
    #[serde(rename = "outputStrategy")]
    pub output_strategy: String,
    #[serde(rename = "allowedProviders", default)]
    pub allowed_providers: Vec<String>,
    #[serde(rename = "requiredStorageReceipts")]
    pub required_storage_receipts: bool,
    #[serde(rename = "encryptInputs")]
    pub encrypt_inputs: bool,
    #[serde(
        rename = "outputAssetClass",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_asset_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiWorkloadPrivacyRequirementV1 {
    pub tier: PrivacyTier,
    #[serde(rename = "allowPlaintextMiner")]
    pub allow_plaintext_miner: bool,
    #[serde(
        rename = "dataRetentionRule",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub data_retention_rule: Option<DataRetentionRule>,
    #[serde(
        rename = "loggingRule",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub logging_rule: Option<LoggingRule>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiWorkloadValidationRequirementV1 {
    pub tier: IntegrityTier,
    #[serde(rename = "validationRequired")]
    pub validation_required: bool,
    #[serde(rename = "methodHints", default)]
    pub method_hints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiWorkloadSettlementRequirementV1 {
    #[serde(rename = "paymentMode")]
    pub payment_mode: String,
    #[serde(rename = "releaseCondition")]
    pub release_condition: String,
    #[serde(rename = "maxPrice", default, skip_serializing_if = "Option::is_none")]
    pub max_price: Option<PriceV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiWorkloadTraceRequirementV1 {
    #[serde(rename = "receiptRequired")]
    pub receipt_required: bool,
    #[serde(rename = "routeTraceRequired")]
    pub route_trace_required: bool,
    #[serde(rename = "storageReceiptsRequired")]
    pub storage_receipts_required: bool,
    #[serde(rename = "validationRefsRequired")]
    pub validation_refs_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AIWorkloadV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "workloadId")]
    pub workload_id: String,
    pub requester: String,
    #[serde(rename = "selectedCapability")]
    pub selected_capability: String,
    #[serde(
        rename = "packageSelector",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_selector: Option<AiPackageSelectorV1>,
    #[serde(
        rename = "serviceSelector",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub service_selector: Option<String>,
    #[serde(rename = "inputAssets", default)]
    pub input_assets: Vec<AssetDescriptorV1>,
    #[serde(rename = "inlineInputs", default)]
    pub inline_inputs: Vec<AiInputPartV1>,
    #[serde(rename = "outputContract")]
    pub output_contract: Value,
    #[serde(rename = "executionRequirements")]
    pub execution_requirements: AiWorkloadExecutionRequirementsV1,
    #[serde(rename = "storagePlan")]
    pub storage_plan: AiWorkloadStoragePlanV1,
    #[serde(rename = "privacyRequirement")]
    pub privacy_requirement: AiWorkloadPrivacyRequirementV1,
    #[serde(rename = "validationRequirement")]
    pub validation_requirement: AiWorkloadValidationRequirementV1,
    #[serde(rename = "settlementRequirement")]
    pub settlement_requirement: AiWorkloadSettlementRequirementV1,
    #[serde(rename = "traceRequirement")]
    pub trace_requirement: AiWorkloadTraceRequirementV1,
    #[serde(
        rename = "deadlineMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deadline_ms: Option<u64>,
    #[serde(default)]
    pub signatures: Vec<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AIWorkloadVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "workloadId")]
    pub workload_id: String,
    #[serde(rename = "expectedWorkloadId")]
    pub expected_workload_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AssetOrInlineInputV1 {
    #[serde(rename = "inputId")]
    pub input_id: String,
    #[serde(rename = "inputKind")]
    pub input_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(
        rename = "contentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_ref: Option<String>,
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExpectedOutputDescriptorV1 {
    #[serde(rename = "outputId")]
    pub output_id: String,
    #[serde(rename = "outputKind")]
    pub output_kind: String,
    #[serde(
        rename = "contentType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type: Option<String>,
    #[serde(
        rename = "outputSchemaRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_schema_ref: Option<String>,
    #[serde(rename = "targetRef", default, skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobPolicyV1 {
    #[serde(rename = "policyId", default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(
        rename = "accessGrantRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub access_grant_ref: Option<String>,
    #[serde(rename = "licensePolicy", default = "empty_metadata")]
    pub license_policy: Value,
    #[serde(rename = "safetyPolicy", default = "empty_metadata")]
    pub safety_policy: Value,
    #[serde(rename = "settlementMethod")]
    pub settlement_method: String,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PrivacyRequirementV1 {
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "allowPlaintextMiner")]
    pub allow_plaintext_miner: bool,
    #[serde(rename = "encryptedStorageRequired")]
    pub encrypted_storage_required: bool,
    #[serde(rename = "localOnly")]
    pub local_only: bool,
    #[serde(
        rename = "dataRetentionRule",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub data_retention_rule: Option<DataRetentionRule>,
    #[serde(
        rename = "loggingRule",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub logging_rule: Option<LoggingRule>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct VerificationRequirementV1 {
    #[serde(rename = "verificationTier")]
    pub verification_tier: IntegrityTier,
    #[serde(rename = "validationRequired")]
    pub validation_required: bool,
    #[serde(rename = "methodHints", default)]
    pub method_hints: Vec<String>,
    #[serde(rename = "redundantExecutionRequired")]
    pub redundant_execution_required: bool,
    #[serde(rename = "deterministicReplayRequired")]
    pub deterministic_replay_required: bool,
    #[serde(rename = "teeAttestationRequired")]
    pub tee_attestation_required: bool,
    #[serde(rename = "zkProofPreferred")]
    pub zk_proof_preferred: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BudgetV1 {
    #[serde(rename = "maxPrice", default, skip_serializing_if = "Option::is_none")]
    pub max_price: Option<PriceV1>,
    #[serde(
        rename = "maxLatencyMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_latency_ms: Option<u64>,
    #[serde(
        rename = "deadlineMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deadline_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RuntimePreferencesV1 {
    #[serde(rename = "runtimeClasses", default)]
    pub runtime_classes: Vec<String>,
    #[serde(rename = "preferredRunnerTypes", default)]
    pub preferred_runner_types: Vec<String>,
    #[serde(
        rename = "preferredArtifactGroup",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub preferred_artifact_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(rename = "hardwareHints", default = "empty_metadata")]
    pub hardware_hints: Value,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TaskStreamingV1 {
    pub enabled: bool,
    #[serde(rename = "eventTypes", default)]
    pub event_types: Vec<StreamingEventType>,
    #[serde(rename = "partialReceipts")]
    pub partial_receipts: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TaskEnvelopeV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "taskId")]
    pub task_id: String,
    #[serde(rename = "requestedApi")]
    pub requested_api: ApiSurface,
    pub capability: UniversalCapabilityV1,
    #[serde(
        rename = "packageRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_ref: Option<String>,
    #[serde(default)]
    pub inputs: Vec<AssetOrInlineInputV1>,
    #[serde(rename = "expectedOutputs", default)]
    pub expected_outputs: Vec<ExpectedOutputDescriptorV1>,
    pub policy: JobPolicyV1,
    pub privacy: PrivacyRequirementV1,
    pub verification: VerificationRequirementV1,
    pub budget: BudgetV1,
    #[serde(rename = "runtimePreferences")]
    pub runtime_preferences: RuntimePreferencesV1,
    pub streaming: TaskStreamingV1,
    pub requester: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TaskEnvelopeVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "taskId")]
    pub task_id: String,
    #[serde(rename = "expectedTaskId")]
    pub expected_task_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiRequestVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "expectedRequestId")]
    pub expected_request_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiResponseStatusV1 {
    Completed,
    Partial,
    Failed,
    Cancelled,
    PolicyBlocked,
    ValidationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AiOutputPartType {
    Text,
    Json,
    Embedding,
    ImageRef,
    AudioRef,
    FileRef,
    ToolResult,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiOutputPartV1 {
    #[serde(rename = "type")]
    pub part_type: AiOutputPartType,
    pub content: Value,
    #[serde(
        rename = "contentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_ref: Option<String>,
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct AiUsageV1 {
    #[serde(
        rename = "inputTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub input_tokens: Option<u64>,
    #[serde(
        rename = "outputTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_tokens: Option<u64>,
    #[serde(rename = "queueMs", default)]
    pub queue_ms: u64,
    #[serde(rename = "computeMs", default)]
    pub compute_ms: u64,
    #[serde(rename = "totalMs", default)]
    pub total_ms: u64,
}

impl From<&ExecutionMetrics> for AiUsageV1 {
    fn from(metrics: &ExecutionMetrics) -> Self {
        Self {
            input_tokens: metrics.input_tokens,
            output_tokens: metrics.output_tokens,
            queue_ms: metrics.queue_ms,
            compute_ms: metrics.compute_ms,
            total_ms: metrics.total_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiResponseErrorV1 {
    pub code: ErrorCode,
    #[serde(
        rename = "standardCode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub standard_code: Option<StandardErrorCodeV1>,
    pub message: String,
    #[serde(default = "empty_metadata")]
    pub details: Value,
}

impl From<&SwarmAiErrorV1> for AiResponseErrorV1 {
    fn from(error: &SwarmAiErrorV1) -> Self {
        Self {
            code: error.code,
            standard_code: Some(error.standard_code()),
            message: error.message.clone(),
            details: error.details.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiResponseV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "responseId")]
    pub response_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub status: AiResponseStatusV1,
    #[serde(default)]
    pub outputs: Vec<AiOutputPartV1>,
    pub usage: AiUsageV1,
    #[serde(
        rename = "receiptRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub receipt_ref: Option<String>,
    #[serde(rename = "traceRef", default, skip_serializing_if = "Option::is_none")]
    pub trace_ref: Option<String>,
    #[serde(default)]
    pub errors: Vec<AiResponseErrorV1>,
    #[serde(default)]
    pub signatures: Vec<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AiResponseVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "responseId")]
    pub response_id: String,
    #[serde(rename = "expectedResponseId")]
    pub expected_response_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

impl AiResponseV1 {
    pub fn failed(request_id: impl Into<String>, error: SwarmAiErrorV1) -> Self {
        let mut response = Self {
            schema_version: "hivemind.response.v1".to_string(),
            response_id: String::new(),
            request_id: request_id.into(),
            status: response_status_from_error(&error),
            outputs: Vec::new(),
            usage: AiUsageV1::default(),
            receipt_ref: None,
            trace_ref: None,
            errors: vec![AiResponseErrorV1::from(&error)],
            signatures: Vec::new(),
            metadata: json!({}),
        };
        response.response_id =
            canonical_ai_response_id(&response).expect("AI response should serialize for id");
        response
    }
}

pub fn execution_request_from_ai_request(
    request: &AiRequestV1,
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
) -> Result<ExecutionRequestV1, SwarmAiErrorV1> {
    if request.schema_version != "hivemind.request.v1" {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "AI request schemaVersion is not supported",
        ));
    }
    if request.request_id.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "AI request requestId is required",
        ));
    }

    let package_ref = package_ref.into();
    let package_id = package_id.into();
    let package_version = package_version.into();
    if package_ref.trim().is_empty() || package_id.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "AI request must resolve to a packageRef and packageId",
        ));
    }

    Ok(ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: request.request_id.clone(),
        package_ref,
        package_id,
        package_version,
        preferred_artifact_group: request
            .metadata
            .get("preferredArtifactGroup")
            .and_then(Value::as_str)
            .map(str::to_string),
        task: task_for_ai_request(request),
        input: execution_input_for_ai_request(request),
        options: ExecutionOptions {
            stream: request.stream,
            deadline_ms: request.constraints.deadline_ms,
            deterministic: request.constraints.deterministic,
        },
        privacy: ExecutionPrivacy {
            receipt_mode: request.privacy.receipt_mode.clone(),
        },
        access_grant: None,
        access_revocation_list: None,
    })
}

pub fn ai_request_from_execution_request(
    request: &ExecutionRequestV1,
    requester: impl Into<String>,
    api_surface: ApiSurface,
) -> AiRequestV1 {
    AiRequestV1 {
        schema_version: "hivemind.request.v1".to_string(),
        request_id: request.request_id.clone(),
        requester: requester.into(),
        api_surface,
        package_selector: AiPackageSelectorV1 {
            package_id: Some(request.package_id.clone()),
            package_ref: Some(request.package_ref.clone()),
            service_ref: None,
            model: Some(request.package_id.clone()),
            channel: None,
        },
        inputs: vec![AiInputPartV1 {
            part_type: AiInputPartType::Text,
            content: request.input.get("text").cloned().unwrap_or_else(|| {
                request
                    .input
                    .get("input")
                    .cloned()
                    .unwrap_or_else(|| request.input.clone())
            }),
            content_ref: None,
            mime_type: Some("application/json".to_string()),
            hash: None,
            metadata: json!({ "source": "execution-request" }),
        }],
        messages: request
            .input
            .get("messages")
            .and_then(Value::as_array)
            .cloned(),
        tools: request
            .input
            .get("tools")
            .and_then(Value::as_array)
            .cloned(),
        response_format: request.input.get("responseFormat").cloned(),
        stream: request.options.stream,
        sampling: None,
        task: Some(request.task.clone()),
        constraints: AiRequestConstraintsV1 {
            max_price: None,
            max_latency_ms: request.options.deadline_ms,
            deadline_ms: request.options.deadline_ms,
            deterministic: request.options.deterministic,
        },
        privacy: AiRequestPrivacyV1 {
            privacy_tier: PrivacyTier::Standard,
            receipt_mode: request.privacy.receipt_mode.clone(),
            data_retention_rule: None,
            logging_rule: None,
        },
        validation: AiRequestValidationV1::default(),
        signatures: Vec::new(),
        metadata: json!({
            "executionRequest": request,
        }),
    }
}

pub fn ai_workload_from_ai_request(request: &AiRequestV1) -> AIWorkloadV1 {
    let input_assets = input_assets_for_workload(request);
    let inline_inputs = request
        .inputs
        .iter()
        .filter(|input| input.content_ref.is_none())
        .cloned()
        .collect::<Vec<_>>();
    let requires_storage_receipts =
        !input_assets.is_empty() || request.metadata.get("browserStorageSessionRef").is_some();
    let encrypt_inputs = request_requires_input_encryption(request);
    let selected_capability = request
        .task
        .clone()
        .filter(|task| task.contains('.'))
        .unwrap_or_else(|| capability_for_ai_request(request));
    let mut workload = AIWorkloadV1 {
        schema_version: "hivemind.workload.v1".to_string(),
        workload_id: String::new(),
        requester: request.requester.clone(),
        selected_capability,
        package_selector: Some(request.package_selector.clone()),
        service_selector: request.package_selector.service_ref.clone(),
        input_assets,
        inline_inputs,
        output_contract: output_contract_for_ai_request(request),
        execution_requirements: AiWorkloadExecutionRequirementsV1 {
            runtime_classes: runtime_classes_for_ai_request(request),
            required_api_surface: request.api_surface.clone(),
            max_latency_ms: request.constraints.max_latency_ms,
            max_cost: request.constraints.max_price.clone(),
            deterministic: request.constraints.deterministic,
            stream: request.stream,
        },
        storage_plan: AiWorkloadStoragePlanV1 {
            input_strategy: input_strategy_for_ai_request(request),
            output_strategy: output_strategy_for_ai_request(request),
            allowed_providers: allowed_storage_providers_for_ai_request(request),
            required_storage_receipts: requires_storage_receipts,
            encrypt_inputs,
            output_asset_class: output_asset_class_for_ai_request(request),
        },
        privacy_requirement: AiWorkloadPrivacyRequirementV1 {
            tier: request.privacy.privacy_tier.clone(),
            allow_plaintext_miner: allows_plaintext_miner(&request.privacy.privacy_tier),
            data_retention_rule: request.privacy.data_retention_rule.clone(),
            logging_rule: request.privacy.logging_rule.clone(),
        },
        validation_requirement: AiWorkloadValidationRequirementV1 {
            tier: request.validation.required_verification_tier.clone(),
            validation_required: request.validation.validation_required,
            method_hints: request.validation.strategies.clone(),
        },
        settlement_requirement: AiWorkloadSettlementRequirementV1 {
            payment_mode: if request.constraints.max_price.is_some() {
                "quote_or_escrow".to_string()
            } else {
                "none_or_free_tier".to_string()
            },
            release_condition: if request.validation.validation_required {
                "receipt_plus_validation".to_string()
            } else {
                "signed_receipt".to_string()
            },
            max_price: request.constraints.max_price.clone(),
        },
        trace_requirement: AiWorkloadTraceRequirementV1 {
            receipt_required: true,
            route_trace_required: true,
            storage_receipts_required: requires_storage_receipts,
            validation_refs_required: request.validation.validation_required,
        },
        deadline_ms: request.constraints.deadline_ms,
        signatures: Vec::new(),
        metadata: json!({
            "sourceRequestId": request.request_id,
            "sourceSchemaVersion": request.schema_version,
            "sourceApiSurface": request.api_surface,
            "sourceMetadata": request.metadata
        }),
    };
    workload.workload_id =
        canonical_ai_workload_id(&workload).expect("AI workload should serialize for id");
    workload
}

pub fn task_envelope_from_ai_request(request: &AiRequestV1) -> TaskEnvelopeV1 {
    let capability_id = request
        .task
        .clone()
        .filter(|task| task.contains('.'))
        .unwrap_or_else(|| capability_for_ai_request(request));
    let package_ref = request
        .package_selector
        .package_ref
        .clone()
        .or_else(|| request.package_selector.service_ref.clone())
        .or_else(|| {
            request
                .package_selector
                .model
                .as_ref()
                .map(|model| format!("model://{model}"))
        })
        .or_else(|| {
            request
                .package_selector
                .package_id
                .as_ref()
                .map(|package_id| format!("package://{package_id}"))
        });
    let mut envelope = TaskEnvelopeV1 {
        schema_version: "hivemind.task_envelope.v1".to_string(),
        object_kind: "task_envelope".to_string(),
        task_id: String::new(),
        requested_api: request.api_surface.clone(),
        capability: universal_capability_for_ai_request(request, capability_id),
        package_ref,
        inputs: task_envelope_inputs_from_ai_request(request),
        expected_outputs: expected_outputs_for_ai_request(request),
        policy: JobPolicyV1 {
            policy_id: request
                .metadata
                .get("policyId")
                .and_then(Value::as_str)
                .map(str::to_string),
            access_grant_ref: request
                .metadata
                .get("accessGrantRef")
                .and_then(Value::as_str)
                .map(str::to_string),
            license_policy: request
                .metadata
                .get("licensePolicy")
                .cloned()
                .unwrap_or_else(|| json!({ "source": "package-or-service" })),
            safety_policy: request
                .metadata
                .get("safetyPolicy")
                .cloned()
                .unwrap_or_else(|| json!({ "source": "request-or-package-default" })),
            settlement_method: if request.constraints.max_price.is_some() {
                "quote_or_escrow".to_string()
            } else {
                "none_or_free_tier".to_string()
            },
            metadata: request
                .metadata
                .get("policyMetadata")
                .cloned()
                .unwrap_or_else(|| json!({})),
        },
        privacy: PrivacyRequirementV1 {
            privacy_tier: request.privacy.privacy_tier.clone(),
            allow_plaintext_miner: allows_plaintext_miner(&request.privacy.privacy_tier),
            encrypted_storage_required: request_requires_input_encryption(request),
            local_only: matches!(request.privacy.privacy_tier, PrivacyTier::LocalOnly),
            data_retention_rule: request.privacy.data_retention_rule.clone(),
            logging_rule: request.privacy.logging_rule.clone(),
            limitations: privacy_limitations_for_tier(&request.privacy.privacy_tier),
        },
        verification: VerificationRequirementV1 {
            verification_tier: request.validation.required_verification_tier.clone(),
            validation_required: request.validation.validation_required,
            method_hints: request.validation.strategies.clone(),
            redundant_execution_required: matches!(
                request.validation.required_verification_tier,
                IntegrityTier::RedundantExecution
            ),
            deterministic_replay_required: matches!(
                request.validation.required_verification_tier,
                IntegrityTier::DeterministicReplay
            ),
            tee_attestation_required: matches!(
                request.validation.required_verification_tier,
                IntegrityTier::TeeAttested
            ),
            zk_proof_preferred: matches!(
                request.validation.required_verification_tier,
                IntegrityTier::ZkProofWhenSupported
            ),
        },
        budget: BudgetV1 {
            max_price: request.constraints.max_price.clone(),
            max_latency_ms: request.constraints.max_latency_ms,
            deadline_ms: request.constraints.deadline_ms,
        },
        runtime_preferences: RuntimePreferencesV1 {
            runtime_classes: runtime_classes_for_ai_request(request),
            preferred_runner_types: preferred_runner_types_for_ai_request(request),
            preferred_artifact_group: request
                .metadata
                .get("preferredArtifactGroup")
                .and_then(Value::as_str)
                .map(str::to_string),
            region: request
                .metadata
                .get("region")
                .and_then(Value::as_str)
                .map(str::to_string),
            hardware_hints: request
                .metadata
                .get("hardwareHints")
                .cloned()
                .unwrap_or_else(|| json!({})),
            metadata: request
                .metadata
                .get("runtimeMetadata")
                .cloned()
                .unwrap_or_else(|| json!({})),
        },
        streaming: TaskStreamingV1 {
            enabled: request.stream,
            event_types: streaming_events_for_ai_request(request),
            partial_receipts: request.stream,
        },
        requester: request.requester.clone(),
        signature: None,
        metadata: json!({
            "sourceRequestId": request.request_id,
            "sourceSchemaVersion": request.schema_version,
            "packageSelector": request.package_selector,
            "sourceMetadata": request.metadata
        }),
    };
    envelope.task_id =
        canonical_task_envelope_id(&envelope).expect("task envelope should serialize for id");
    envelope
}

pub fn ai_response_from_execution_response(response: &ExecutionResponseV1) -> AiResponseV1 {
    let mut ai_response = AiResponseV1 {
        schema_version: "hivemind.response.v1".to_string(),
        response_id: String::new(),
        request_id: response.request_id.clone(),
        status: ai_status_from_execution_status(&response.status, response.error.as_ref()),
        outputs: ai_outputs_from_execution(response),
        usage: AiUsageV1::from(&response.metrics),
        receipt_ref: response.receipt_ref.clone().or_else(|| {
            response
                .metadata
                .get("receiptStore")
                .and_then(|store| store.get("receiptRef"))
                .and_then(Value::as_str)
                .map(str::to_string)
        }),
        trace_ref: response
            .metadata
            .get("routeExecution")
            .and_then(|trace| trace.get("selectedRouteId"))
            .and_then(Value::as_str)
            .map(|route_id| format!("local://route/{route_id}")),
        errors: response
            .error
            .as_ref()
            .map(|error| vec![AiResponseErrorV1::from(error)])
            .unwrap_or_default(),
        signatures: Vec::new(),
        metadata: json!({
            "execution": {
                "schemaVersion": response.schema_version,
                "metadata": response.metadata,
            }
        }),
    };
    ai_response.response_id =
        canonical_ai_response_id(&ai_response).expect("AI response should serialize for id");
    ai_response
}

pub fn canonical_ai_request_id(request: &AiRequestV1) -> serde_json::Result<String> {
    Ok(format!(
        "aireq-{}",
        &hash_canonical_json(&canonicalize_json(&ai_request_signing_value(request)?))[..24]
    ))
}

pub fn canonical_ai_response_id(response: &AiResponseV1) -> serde_json::Result<String> {
    Ok(format!(
        "airesp-{}",
        &hash_canonical_json(&canonicalize_json(&ai_response_signing_value(response)?))[..24]
    ))
}

pub fn canonical_ai_workload_id(workload: &AIWorkloadV1) -> serde_json::Result<String> {
    Ok(format!(
        "workload-{}",
        &hash_canonical_json(&canonicalize_json(&ai_workload_signing_value(workload)?))[..24]
    ))
}

pub fn canonical_task_envelope_id(envelope: &TaskEnvelopeV1) -> serde_json::Result<String> {
    Ok(format!(
        "task-{}",
        &hash_canonical_json(&canonicalize_json(&task_envelope_signing_value(envelope)?))[..24]
    ))
}

pub fn expected_ai_request_signature(request: &AiRequestV1) -> serde_json::Result<String> {
    Ok(format!(
        "{DEV_AI_REQUEST_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&ai_request_signing_value(request)?))
    ))
}

pub fn expected_ai_response_signature(response: &AiResponseV1) -> serde_json::Result<String> {
    Ok(format!(
        "{DEV_AI_RESPONSE_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&ai_response_signing_value(response)?))
    ))
}

pub fn expected_ai_workload_signature(workload: &AIWorkloadV1) -> serde_json::Result<String> {
    Ok(format!(
        "{DEV_AI_WORKLOAD_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&ai_workload_signing_value(workload)?))
    ))
}

pub fn expected_task_envelope_signature(envelope: &TaskEnvelopeV1) -> serde_json::Result<String> {
    Ok(format!(
        "{DEV_TASK_ENVELOPE_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&task_envelope_signing_value(envelope)?))
    ))
}

pub fn sign_ai_request(request: &mut AiRequestV1) -> serde_json::Result<String> {
    let signature = expected_ai_request_signature(request)?;
    request
        .signatures
        .retain(|value| !value.starts_with(DEV_AI_REQUEST_SIGNATURE_PREFIX));
    request.signatures.push(signature.clone());
    request.request_id = canonical_ai_request_id(request)?;
    Ok(signature)
}

pub fn sign_ai_response(response: &mut AiResponseV1) -> serde_json::Result<String> {
    let signature = expected_ai_response_signature(response)?;
    response
        .signatures
        .retain(|value| !value.starts_with(DEV_AI_RESPONSE_SIGNATURE_PREFIX));
    response.signatures.push(signature.clone());
    response.response_id = canonical_ai_response_id(response)?;
    Ok(signature)
}

pub fn sign_ai_workload(workload: &mut AIWorkloadV1) -> serde_json::Result<String> {
    let signature = expected_ai_workload_signature(workload)?;
    workload
        .signatures
        .retain(|value| !value.starts_with(DEV_AI_WORKLOAD_SIGNATURE_PREFIX));
    workload.signatures.push(signature.clone());
    workload.workload_id = canonical_ai_workload_id(workload)?;
    Ok(signature)
}

pub fn sign_task_envelope(envelope: &mut TaskEnvelopeV1) -> serde_json::Result<String> {
    let signature = expected_task_envelope_signature(envelope)?;
    envelope.signature = Some(signature.clone());
    envelope.task_id = canonical_task_envelope_id(envelope)?;
    Ok(signature)
}

pub fn verify_ai_request(request: &AiRequestV1) -> AiRequestVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_request_id =
        canonical_ai_request_id(request).unwrap_or_else(|_| "aireq-invalid".to_string());
    let expected_signature = expected_ai_request_signature(request)
        .unwrap_or_else(|_| format!("{DEV_AI_REQUEST_SIGNATURE_PREFIX}:invalid"));

    if request.schema_version != "hivemind.request.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.request.v1",
        ));
    }
    require_non_empty(&mut issues, "$.requestId", &request.request_id);
    if !request.request_id.is_empty() && request.request_id != expected_request_id {
        issues.push(issue(
            "$.requestId",
            "AI request id does not match canonical request content",
        ));
    }
    require_non_empty(&mut issues, "$.requester", &request.requester);
    validate_package_selector(&request.package_selector, &mut issues);
    validate_ai_inputs(&request.inputs, &mut issues, &mut warnings);
    if request.inputs.is_empty()
        && request
            .messages
            .as_ref()
            .map(|messages| messages.is_empty())
            .unwrap_or(true)
    {
        if ai_request_allows_empty_input(request) {
            warnings.push(issue(
                "$.inputs",
                "Realtime AI request has no initial inputs or messages; input is expected to arrive over the session transport",
            ));
        } else {
            issues.push(issue(
                "$.inputs",
                "AI request must include inputs or messages",
            ));
        }
    }
    if let Some(messages) = &request.messages {
        for (index, message) in messages.iter().enumerate() {
            if !message.is_object() {
                warnings.push(issue(
                    format!("$.messages[{index}]"),
                    "AI request messages are usually expected to be objects",
                ));
            }
        }
    }
    if let Some(sampling) = &request.sampling {
        validate_sampling_options(sampling, &mut issues);
    }
    validate_request_constraints(&request.constraints, &mut issues);
    if request.validation.validation_required && request.validation.strategies.is_empty() {
        warnings.push(issue(
            "$.validation.strategies",
            "Validation is required but no validation strategies are declared",
        ));
    }
    if !request.metadata.is_object() {
        warnings.push(issue(
            "$.metadata",
            "AI request metadata is usually expected to be an object",
        ));
    }
    verify_signature_list(
        &request.signatures,
        &expected_signature,
        DEV_AI_REQUEST_SIGNATURE_PREFIX,
        "$.signatures",
        "AI request",
        &mut issues,
        &mut warnings,
    );

    AiRequestVerificationV1 {
        schema_version: "hivemind.ai_request_verification.v1".to_string(),
        request_id: request.request_id.clone(),
        expected_request_id,
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn verify_ai_workload(workload: &AIWorkloadV1) -> AIWorkloadVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_workload_id =
        canonical_ai_workload_id(workload).unwrap_or_else(|_| "workload-invalid".to_string());
    let expected_signature = expected_ai_workload_signature(workload)
        .unwrap_or_else(|_| format!("{DEV_AI_WORKLOAD_SIGNATURE_PREFIX}:invalid"));

    if workload.schema_version != "hivemind.workload.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.workload.v1",
        ));
    }
    require_non_empty(&mut issues, "$.workloadId", &workload.workload_id);
    if !workload.workload_id.is_empty() && workload.workload_id != expected_workload_id {
        issues.push(issue(
            "$.workloadId",
            "AI workload id does not match canonical workload content",
        ));
    }
    require_non_empty(&mut issues, "$.requester", &workload.requester);
    require_non_empty(
        &mut issues,
        "$.selectedCapability",
        &workload.selected_capability,
    );
    if workload.package_selector.is_none() && workload.service_selector.is_none() {
        issues.push(issue(
            "$.packageSelector",
            "AI workload requires a packageSelector or serviceSelector",
        ));
    }
    for (index, asset) in workload.input_assets.iter().enumerate() {
        require_non_empty(
            &mut issues,
            format!("$.inputAssets[{index}].assetId"),
            &asset.asset_id,
        );
        require_non_empty(
            &mut issues,
            format!("$.inputAssets[{index}].assetClass"),
            &asset.asset_class,
        );
        if asset.storage_refs.is_empty() {
            issues.push(issue(
                format!("$.inputAssets[{index}].storageRefs"),
                "Referenced input assets must include at least one storage ref",
            ));
        }
    }
    if workload.input_assets.is_empty() && workload.inline_inputs.is_empty() {
        warnings.push(issue(
            "$.inlineInputs",
            "AI workload has no input assets or inline inputs",
        ));
    }
    if workload.execution_requirements.runtime_classes.is_empty() {
        warnings.push(issue(
            "$.executionRequirements.runtimeClasses",
            "AI workload has no runtime classes; routing will need defaults",
        ));
    }
    require_non_empty(
        &mut issues,
        "$.storagePlan.inputStrategy",
        &workload.storage_plan.input_strategy,
    );
    require_non_empty(
        &mut issues,
        "$.storagePlan.outputStrategy",
        &workload.storage_plan.output_strategy,
    );
    if workload.storage_plan.required_storage_receipts
        && workload.storage_plan.allowed_providers.is_empty()
    {
        issues.push(issue(
            "$.storagePlan.allowedProviders",
            "Storage receipts are required but no storage providers are allowed",
        ));
    }
    if workload.validation_requirement.validation_required
        && workload.validation_requirement.method_hints.is_empty()
    {
        warnings.push(issue(
            "$.validationRequirement.methodHints",
            "Validation is required but no task-specific validation methods are declared",
        ));
    }
    if !workload.metadata.is_object() {
        warnings.push(issue(
            "$.metadata",
            "AI workload metadata is usually expected to be an object",
        ));
    }
    verify_signature_list(
        &workload.signatures,
        &expected_signature,
        DEV_AI_WORKLOAD_SIGNATURE_PREFIX,
        "$.signatures",
        "AI workload",
        &mut issues,
        &mut warnings,
    );

    AIWorkloadVerificationV1 {
        schema_version: "hivemind.ai_workload_verification.v1".to_string(),
        workload_id: workload.workload_id.clone(),
        expected_workload_id,
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn verify_task_envelope(envelope: &TaskEnvelopeV1) -> TaskEnvelopeVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_task_id =
        canonical_task_envelope_id(envelope).unwrap_or_else(|_| "task-invalid".to_string());
    let expected_signature = expected_task_envelope_signature(envelope)
        .unwrap_or_else(|_| format!("{DEV_TASK_ENVELOPE_SIGNATURE_PREFIX}:invalid"));

    if envelope.schema_version != "hivemind.task_envelope.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.task_envelope.v1",
        ));
    }
    if envelope.object_kind != "task_envelope" {
        issues.push(issue(
            "$.objectKind",
            "Expected objectKind to be task_envelope",
        ));
    }
    require_non_empty(&mut issues, "$.taskId", &envelope.task_id);
    if !envelope.task_id.is_empty() && envelope.task_id != expected_task_id {
        issues.push(issue(
            "$.taskId",
            "Task envelope id does not match canonical envelope content",
        ));
    }
    require_non_empty(&mut issues, "$.requester", &envelope.requester);
    require_non_empty(
        &mut issues,
        "$.capability.capabilityId",
        &envelope.capability.capability_id,
    );
    require_non_empty(
        &mut issues,
        "$.capability.operation",
        &envelope.capability.operation,
    );
    if envelope.package_ref.is_none() {
        warnings.push(issue(
            "$.packageRef",
            "Task envelope has no packageRef; routing must resolve a service, model, or package selector from metadata",
        ));
    }
    if envelope.inputs.is_empty() {
        warnings.push(issue(
            "$.inputs",
            "Task envelope has no initial inputs; realtime or delayed-input work must document the transport in metadata",
        ));
    }
    for (index, input) in envelope.inputs.iter().enumerate() {
        let path = format!("$.inputs[{index}]");
        require_non_empty(&mut issues, format!("{path}.inputId"), &input.input_id);
        require_non_empty(&mut issues, format!("{path}.inputKind"), &input.input_kind);
        if input.content.is_none() && input.content_ref.is_none() {
            issues.push(issue(
                format!("{path}.content"),
                "Envelope input must include content or contentRef",
            ));
        }
        if let Some(reference) = &input.content_ref {
            require_optional_reference(
                &mut issues,
                &mut warnings,
                &format!("{path}.contentRef"),
                Some(reference),
                "Envelope input reference",
            );
        }
        if let Some(metadata) = input.metadata.as_object() {
            if metadata.contains_key("byteSize")
                && metadata.get("byteSize").and_then(Value::as_u64).is_none()
            {
                issues.push(issue(
                    format!("{path}.metadata.byteSize"),
                    "byteSize metadata must be an unsigned integer",
                ));
            }
        } else {
            warnings.push(issue(
                format!("{path}.metadata"),
                "Envelope input metadata is usually expected to be an object",
            ));
        }
    }
    if envelope.expected_outputs.is_empty() {
        issues.push(issue(
            "$.expectedOutputs",
            "Task envelope must declare at least one expected output",
        ));
    }
    for (index, output) in envelope.expected_outputs.iter().enumerate() {
        let path = format!("$.expectedOutputs[{index}]");
        require_non_empty(&mut issues, format!("{path}.outputId"), &output.output_id);
        require_non_empty(
            &mut issues,
            format!("{path}.outputKind"),
            &output.output_kind,
        );
        if let Some(reference) = &output.target_ref {
            require_optional_reference(
                &mut issues,
                &mut warnings,
                &format!("{path}.targetRef"),
                Some(reference),
                "Expected output target reference",
            );
        }
    }
    if envelope.privacy.local_only
        != matches!(envelope.privacy.privacy_tier, PrivacyTier::LocalOnly)
    {
        issues.push(issue(
            "$.privacy.localOnly",
            "localOnly must match the local-only privacy tier",
        ));
    }
    if !allows_plaintext_miner(&envelope.privacy.privacy_tier)
        && envelope.privacy.allow_plaintext_miner
    {
        issues.push(issue(
            "$.privacy.allowPlaintextMiner",
            "This privacy tier cannot allow plaintext miner execution",
        ));
    }
    if matches!(
        envelope.privacy.privacy_tier,
        PrivacyTier::RedactedInput
            | PrivacyTier::LocalOnly
            | PrivacyTier::TeeConfidential
            | PrivacyTier::FheEncrypted
            | PrivacyTier::MpcExperimental
    ) && !envelope.privacy.encrypted_storage_required
    {
        warnings.push(issue(
            "$.privacy.encryptedStorageRequired",
            "Sensitive privacy tiers usually require encrypted storage or local-only handling",
        ));
    }
    if envelope.verification.validation_required && envelope.verification.method_hints.is_empty() {
        warnings.push(issue(
            "$.verification.methodHints",
            "Validation is required but no validation method hints are declared",
        ));
    }
    if envelope.verification.redundant_execution_required
        != matches!(
            envelope.verification.verification_tier,
            IntegrityTier::RedundantExecution
        )
    {
        warnings.push(issue(
            "$.verification.redundantExecutionRequired",
            "Redundant execution flag does not match the selected verification tier",
        ));
    }
    if envelope.runtime_preferences.runtime_classes.is_empty() {
        warnings.push(issue(
            "$.runtimePreferences.runtimeClasses",
            "Task envelope has no runtime class preferences; routing will need defaults",
        ));
    }
    validate_budget(&envelope.budget, &mut issues);
    verify_task_envelope_signature(
        envelope.signature.as_deref(),
        &expected_signature,
        &mut issues,
        &mut warnings,
    );

    TaskEnvelopeVerificationV1 {
        schema_version: "hivemind.task_envelope_verification.v1".to_string(),
        task_id: envelope.task_id.clone(),
        expected_task_id,
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn verify_ai_response(response: &AiResponseV1) -> AiResponseVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_response_id =
        canonical_ai_response_id(response).unwrap_or_else(|_| "airesp-invalid".to_string());
    let expected_signature = expected_ai_response_signature(response)
        .unwrap_or_else(|_| format!("{DEV_AI_RESPONSE_SIGNATURE_PREFIX}:invalid"));

    if response.schema_version != "hivemind.response.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.response.v1",
        ));
    }
    require_non_empty(&mut issues, "$.responseId", &response.response_id);
    require_non_empty(&mut issues, "$.requestId", &response.request_id);
    if !response.response_id.is_empty() && response.response_id != expected_response_id {
        issues.push(issue(
            "$.responseId",
            "AI response id does not match canonical response content",
        ));
    }
    validate_ai_outputs(&response.outputs, &mut issues, &mut warnings);
    match response.status {
        AiResponseStatusV1::Completed | AiResponseStatusV1::Partial => {
            if response.outputs.is_empty() {
                warnings.push(issue(
                    "$.outputs",
                    "Completed or partial AI responses usually include at least one output",
                ));
            }
            if !response.errors.is_empty() {
                warnings.push(issue(
                    "$.errors",
                    "Completed or partial AI response includes errors",
                ));
            }
        }
        AiResponseStatusV1::Failed
        | AiResponseStatusV1::Cancelled
        | AiResponseStatusV1::PolicyBlocked
        | AiResponseStatusV1::ValidationFailed => {
            if response.errors.is_empty() {
                issues.push(issue(
                    "$.errors",
                    "Terminal non-success AI responses must include at least one standard error",
                ));
            }
        }
    }
    validate_ai_response_errors(&response.errors, &mut issues);
    if !response.metadata.is_object() {
        warnings.push(issue(
            "$.metadata",
            "AI response metadata is usually expected to be an object",
        ));
    }
    verify_signature_list(
        &response.signatures,
        &expected_signature,
        DEV_AI_RESPONSE_SIGNATURE_PREFIX,
        "$.signatures",
        "AI response",
        &mut issues,
        &mut warnings,
    );

    AiResponseVerificationV1 {
        schema_version: "hivemind.ai_response_verification.v1".to_string(),
        response_id: response.response_id.clone(),
        expected_response_id,
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

fn task_envelope_inputs_from_ai_request(request: &AiRequestV1) -> Vec<AssetOrInlineInputV1> {
    let mut inputs = request
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| AssetOrInlineInputV1 {
            input_id: input
                .metadata
                .get("inputId")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("input-{index}")),
            input_kind: if input.content_ref.is_some() {
                "asset_ref".to_string()
            } else {
                "inline".to_string()
            },
            content: if input.content_ref.is_some() {
                None
            } else {
                Some(input.content.clone())
            },
            content_ref: input.content_ref.clone(),
            mime_type: input.mime_type.clone(),
            hash: input.hash.clone(),
            metadata: json!({
                "partType": input.part_type,
                "sourceMetadata": input.metadata,
                "modality": modality_for_input_part(input),
                "assetClass": asset_class_for_input_part(input)
            }),
        })
        .collect::<Vec<_>>();

    if let Some(messages) = &request.messages {
        inputs.push(AssetOrInlineInputV1 {
            input_id: "messages".to_string(),
            input_kind: "message_bundle".to_string(),
            content: Some(json!(messages)),
            content_ref: None,
            mime_type: Some("application/json".to_string()),
            hash: None,
            metadata: json!({
                "messageCount": messages.len(),
                "source": "aiRequest.messages"
            }),
        });
    }

    if let Some(tools) = &request.tools {
        inputs.push(AssetOrInlineInputV1 {
            input_id: "tools".to_string(),
            input_kind: "tool_contracts".to_string(),
            content: Some(json!(tools)),
            content_ref: None,
            mime_type: Some("application/json".to_string()),
            hash: None,
            metadata: json!({
                "toolCount": tools.len(),
                "source": "aiRequest.tools"
            }),
        });
    }

    inputs
}

fn expected_outputs_for_ai_request(request: &AiRequestV1) -> Vec<ExpectedOutputDescriptorV1> {
    vec![ExpectedOutputDescriptorV1 {
        output_id: "primary".to_string(),
        output_kind: output_kind_for_ai_request(request).to_string(),
        content_type: output_content_type_for_ai_request(request).map(str::to_string),
        output_schema_ref: request
            .metadata
            .get("outputSchemaRef")
            .and_then(Value::as_str)
            .map(str::to_string),
        target_ref: request
            .metadata
            .get("outputRef")
            .and_then(Value::as_str)
            .map(str::to_string),
        required: true,
        metadata: json!({
            "responseFormat": request.response_format,
            "delivery": if request.stream { "stream_or_swarm_ref" } else { "inline_small_or_swarm_ref" },
            "receiptRequired": true
        }),
    }]
}

fn universal_capability_for_ai_request(
    request: &AiRequestV1,
    capability_id: String,
) -> UniversalCapabilityV1 {
    UniversalCapabilityV1 {
        capability_id,
        modalities: modalities_for_ai_request(request),
        operation: request
            .task
            .clone()
            .unwrap_or_else(|| operation_for_api_surface(&request.api_surface).to_string()),
        input_contract_ref: request
            .metadata
            .get("inputSchemaRef")
            .and_then(Value::as_str)
            .map(str::to_string),
        output_contract_ref: request
            .metadata
            .get("outputSchemaRef")
            .and_then(Value::as_str)
            .map(str::to_string),
        supported_api_surfaces: vec![api_surface_wire_name(&request.api_surface)],
        supported_streaming_events: streaming_events_for_ai_request(request)
            .iter()
            .map(streaming_event_wire_name)
            .collect(),
        runtime_classes: runtime_classes_for_ai_request(request),
        privacy_classes: vec![privacy_tier_wire_name(&request.privacy.privacy_tier)],
        validation_classes: vec![integrity_tier_wire_name(
            &request.validation.required_verification_tier,
        )],
        cost_hints: request
            .constraints
            .max_price
            .as_ref()
            .map(|price| json!({ "maxPrice": price }))
            .unwrap_or_else(|| json!({})),
        latency_hints: json!({
            "maxLatencyMs": request.constraints.max_latency_ms,
            "deadlineMs": request.constraints.deadline_ms
        }),
    }
}

fn modalities_for_ai_request(request: &AiRequestV1) -> Vec<String> {
    let mut modalities = request
        .inputs
        .iter()
        .map(modality_for_input_part)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let api_modality = match request.api_surface {
        ApiSurface::OpenAiEmbeddings => "embedding",
        ApiSurface::OpenAiImages | ApiSurface::ImageGeneration => "image",
        ApiSurface::OpenAiAudio | ApiSurface::SpeechToText | ApiSurface::TextToSpeech => "audio",
        ApiSurface::OpenAiVectorStores | ApiSurface::VectorSearch => "vector_search",
        ApiSurface::OpenAiFineTuning | ApiSurface::FineTune => "training_data",
        ApiSurface::OpenAiEvals | ApiSurface::EvalRun => "evaluation_data",
        ApiSurface::Moderation => "safety",
        _ => "text",
    };
    push_unique_string(&mut modalities, api_modality);
    if request.messages.is_some() {
        push_unique_string(&mut modalities, "chat");
    }
    modalities
}

fn preferred_runner_types_for_ai_request(request: &AiRequestV1) -> Vec<String> {
    if let Some(values) = request
        .metadata
        .get("preferredRunnerTypes")
        .and_then(Value::as_array)
    {
        let runners = values
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if !runners.is_empty() {
            return runners;
        }
    }

    match request.privacy.privacy_tier {
        PrivacyTier::LocalOnly => vec!["browser".to_string(), "local".to_string()],
        PrivacyTier::TeeConfidential => vec!["confidential".to_string()],
        PrivacyTier::FheEncrypted | PrivacyTier::MpcExperimental => {
            vec!["cryptographic".to_string()]
        }
        _ => match request.api_surface {
            ApiSurface::OpenAiBatches
            | ApiSurface::Batch
            | ApiSurface::OpenAiFineTuning
            | ApiSurface::FineTune => vec!["batch".to_string(), "ai-miner".to_string()],
            ApiSurface::OpenAiRealtime | ApiSurface::RealtimeSession | ApiSurface::GeminiLive => {
                vec!["realtime".to_string(), "local".to_string()]
            }
            _ => vec![
                "browser".to_string(),
                "local".to_string(),
                "remote-gpu".to_string(),
                "ai-miner".to_string(),
            ],
        },
    }
}

fn streaming_events_for_ai_request(request: &AiRequestV1) -> Vec<StreamingEventType> {
    if !request.stream {
        return Vec::new();
    }
    match request.api_surface {
        ApiSurface::OpenAiAudio | ApiSurface::TextToSpeech | ApiSurface::SpeechToText => vec![
            StreamingEventType::Started,
            StreamingEventType::AudioChunk,
            StreamingEventType::PartialReceipt,
            StreamingEventType::Completed,
        ],
        ApiSurface::OpenAiImages | ApiSurface::ImageGeneration => vec![
            StreamingEventType::Started,
            StreamingEventType::ImageProgress,
            StreamingEventType::PartialReceipt,
            StreamingEventType::Completed,
        ],
        ApiSurface::OpenAiVectorStores | ApiSurface::VectorSearch | ApiSurface::RagQuery => vec![
            StreamingEventType::Started,
            StreamingEventType::RetrievalEvent,
            StreamingEventType::TextDelta,
            StreamingEventType::PartialReceipt,
            StreamingEventType::Completed,
        ],
        _ => vec![
            StreamingEventType::Started,
            StreamingEventType::TextDelta,
            StreamingEventType::ToolCallRequested,
            StreamingEventType::ToolCallResult,
            StreamingEventType::PartialReceipt,
            StreamingEventType::Completed,
        ],
    }
}

fn privacy_limitations_for_tier(tier: &PrivacyTier) -> Vec<String> {
    crate::trust::privacy_tier_profile(tier).limitations
}

fn validate_budget(budget: &BudgetV1, issues: &mut Vec<ValidationIssue>) {
    if let Some(price) = &budget.max_price {
        if !price.amount.is_finite() || price.amount < 0.0 {
            issues.push(issue(
                "$.budget.maxPrice.amount",
                "Maximum price must be a finite non-negative number",
            ));
        }
        require_non_empty(issues, "$.budget.maxPrice.currency", &price.currency);
    }
    if matches!(budget.max_latency_ms, Some(0)) {
        issues.push(issue(
            "$.budget.maxLatencyMs",
            "Maximum latency must be greater than zero milliseconds",
        ));
    }
    if matches!(budget.deadline_ms, Some(0)) {
        issues.push(issue(
            "$.budget.deadlineMs",
            "Deadline must be greater than zero milliseconds",
        ));
    }
}

fn verify_task_envelope_signature(
    signature: Option<&str>,
    expected_signature: &str,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    match signature {
        None => warnings.push(issue(
            "$.signature",
            "Task envelope is unsigned; signed interface objects are required for production trust",
        )),
        Some(signature) if signature.trim().is_empty() => {
            issues.push(issue("$.signature", "Signature must not be empty"));
        }
        Some(signature) if signature == expected_signature => {}
        Some(signature) if signature.starts_with(DEV_TASK_ENVELOPE_SIGNATURE_PREFIX) => {
            issues.push(issue(
                "$.signature",
                "Task envelope dev signature does not match canonical content",
            ));
        }
        Some(_) => warnings.push(issue(
            "$.signature",
            "Task envelope signature is not a local-dev signature and was not verified here",
        )),
    }
}

fn execution_input_for_ai_request(request: &AiRequestV1) -> Value {
    let text = text_for_ai_request(request);
    let mut input = json!({
        "apiSurface": request.api_surface,
        "inputs": request.inputs,
        "metadata": request.metadata,
    });
    if let Some(task) = &request.task {
        input["task"] = json!(task);
    }
    if let Some(text) = text {
        input["text"] = json!(text);
    }
    if let Some(messages) = &request.messages {
        input["messages"] = json!(messages);
    }
    if let Some(tools) = &request.tools {
        input["tools"] = json!(tools);
    }
    if let Some(response_format) = &request.response_format {
        input["responseFormat"] = response_format.clone();
    }
    if let Some(sampling) = &request.sampling {
        input["sampling"] = json!(sampling);
    }
    input
}

fn text_for_ai_request(request: &AiRequestV1) -> Option<String> {
    let mut parts = Vec::new();
    for input in &request.inputs {
        if input.part_type != AiInputPartType::Text {
            continue;
        }
        if let Some(text) = input.content.as_str() {
            parts.push(text.to_string());
        } else if let Some(text) = input.content.get("text").and_then(Value::as_str) {
            parts.push(text.to_string());
        } else if !input.content.is_null() {
            parts.push(input.content.to_string());
        }
    }
    if parts.is_empty() {
        if let Some(messages) = &request.messages {
            parts.extend(messages.iter().filter_map(message_text));
        }
    }
    (!parts.is_empty()).then(|| parts.join("\n"))
}

fn message_text(message: &Value) -> Option<String> {
    if let Some(text) = message.get("content").and_then(Value::as_str) {
        return Some(text.to_string());
    }
    let content = message.get("content")?.as_array()?;
    let parts: Vec<_> = content
        .iter()
        .filter_map(|part| {
            part.get("text")
                .and_then(Value::as_str)
                .or_else(|| part.get("content").and_then(Value::as_str))
                .map(str::to_string)
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("\n"))
}

fn task_for_ai_request(request: &AiRequestV1) -> String {
    if let Some(task) = request
        .task
        .as_deref()
        .filter(|task| !task.trim().is_empty())
    {
        return task.to_string();
    }
    if let Some(task) = request.metadata.get("task").and_then(Value::as_str) {
        return task.to_string();
    }
    match request.api_surface {
        ApiSurface::OpenAiEmbeddings | ApiSurface::VectorSearch | ApiSurface::RagQuery => {
            "embedding".to_string()
        }
        ApiSurface::OpenAiRealtime | ApiSurface::GeminiLive | ApiSurface::RealtimeSession => {
            "realtime".to_string()
        }
        ApiSurface::Moderation => "classification".to_string(),
        _ => "chat".to_string(),
    }
}

fn ai_outputs_from_execution(response: &ExecutionResponseV1) -> Vec<AiOutputPartV1> {
    if response.status == ExecutionStatus::Failed || response.status == ExecutionStatus::Cancelled {
        return Vec::new();
    }
    let part_type = if response.output.get("embedding").is_some() {
        AiOutputPartType::Embedding
    } else if response.output.get("message").is_some() {
        AiOutputPartType::Text
    } else {
        AiOutputPartType::Json
    };
    let content = response
        .output
        .get("message")
        .and_then(|message| message.get("content"))
        .cloned()
        .unwrap_or_else(|| response.output.clone());
    vec![AiOutputPartV1 {
        part_type,
        content,
        content_ref: None,
        mime_type: None,
        metadata: json!({}),
    }]
}

fn ai_status_from_execution_status(
    status: &ExecutionStatus,
    error: Option<&SwarmAiErrorV1>,
) -> AiResponseStatusV1 {
    match status {
        ExecutionStatus::Succeeded => AiResponseStatusV1::Completed,
        ExecutionStatus::Partial => AiResponseStatusV1::Partial,
        ExecutionStatus::Cancelled => AiResponseStatusV1::Cancelled,
        ExecutionStatus::Failed => error
            .map(response_status_from_error)
            .unwrap_or(AiResponseStatusV1::Failed),
    }
}

fn response_status_from_error(error: &SwarmAiErrorV1) -> AiResponseStatusV1 {
    match error.code {
        ErrorCode::AccessDenied => AiResponseStatusV1::PolicyBlocked,
        ErrorCode::ValidationFailed => AiResponseStatusV1::ValidationFailed,
        _ => AiResponseStatusV1::Failed,
    }
}

fn input_assets_for_workload(request: &AiRequestV1) -> Vec<AssetDescriptorV1> {
    request
        .inputs
        .iter()
        .enumerate()
        .filter_map(|(index, input)| {
            let content_ref = input.content_ref.as_ref()?;
            Some(AssetDescriptorV1 {
                asset_id: input
                    .metadata
                    .get("assetId")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("input-asset-{index}")),
                role: Some(asset_role_for_input_part(input)),
                asset_class: asset_class_for_input_part(input).to_string(),
                path: None,
                reference: Some(content_ref.clone()),
                storage_refs: vec![content_ref.clone()],
                byte_size: input
                    .metadata
                    .get("byteSize")
                    .and_then(Value::as_u64)
                    .or_else(|| input.metadata.get("sizeBytes").and_then(Value::as_u64)),
                content_type: input.mime_type.clone(),
                hash: input.hash.clone(),
                content_hash: input.hash.clone(),
                mime_type: input.mime_type.clone(),
                modality: Some(modality_for_input_part(input).to_string()),
                media_metadata: input
                    .metadata
                    .get("mediaMetadata")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
                encryption: input
                    .metadata
                    .get("encryption")
                    .cloned()
                    .unwrap_or_else(|| json!({ "mode": "unspecified" })),
                sensitivity: input
                    .metadata
                    .get("sensitivity")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                license: None,
                access_policy: input
                    .metadata
                    .get("accessPolicy")
                    .cloned()
                    .unwrap_or_else(|| json!({ "source": "request" })),
                access_policy_ref: input
                    .metadata
                    .get("accessPolicyRef")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                cache_policy: input
                    .metadata
                    .get("cachePolicy")
                    .cloned()
                    .unwrap_or_else(|| json!({ "mode": "content-addressed" })),
                retention_policy: input
                    .metadata
                    .get("retentionPolicy")
                    .cloned()
                    .unwrap_or_else(|| json!({ "mode": "workload-scoped" })),
                sensitivity_label: input
                    .metadata
                    .get("sensitivityLabel")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                created_by: Some(request.requester.clone()),
                created_at: request
                    .metadata
                    .get("createdAt")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                signatures: Vec::new(),
            })
        })
        .collect()
}

fn asset_role_for_input_part(input: &AiInputPartV1) -> AssetRoleV1 {
    match input.part_type {
        AiInputPartType::Text => AssetRoleV1::Prompt,
        AiInputPartType::ImageRef
        | AiInputPartType::ImageInline
        | AiInputPartType::AudioRef
        | AiInputPartType::AudioChunk
        | AiInputPartType::VideoRef => AssetRoleV1::Media,
        AiInputPartType::DocumentRef | AiInputPartType::FileRef => AssetRoleV1::Document,
        AiInputPartType::VectorQuery => AssetRoleV1::VectorIndex,
        AiInputPartType::ToolResult => AssetRoleV1::Tool,
        AiInputPartType::TrainingDataRef => AssetRoleV1::Dataset,
        AiInputPartType::EvaluationDataRef => AssetRoleV1::Benchmark,
    }
}

fn modality_for_input_part(input: &AiInputPartV1) -> &'static str {
    match input.part_type {
        AiInputPartType::Text => "text",
        AiInputPartType::ImageRef | AiInputPartType::ImageInline => "image",
        AiInputPartType::AudioRef | AiInputPartType::AudioChunk => "audio",
        AiInputPartType::DocumentRef => "document",
        AiInputPartType::VectorQuery => "vector_search",
        AiInputPartType::FileRef => "file",
        AiInputPartType::ToolResult => "tool_call",
        AiInputPartType::VideoRef => "video",
        AiInputPartType::TrainingDataRef => "training_data",
        AiInputPartType::EvaluationDataRef => "evaluation_data",
    }
}

fn asset_class_for_input_part(input: &AiInputPartV1) -> &'static str {
    match input.part_type {
        AiInputPartType::Text => "prompt",
        AiInputPartType::ImageRef | AiInputPartType::ImageInline => "image",
        AiInputPartType::AudioRef | AiInputPartType::AudioChunk => "audio",
        AiInputPartType::DocumentRef => "document_collection",
        AiInputPartType::VectorQuery => "vector_index",
        AiInputPartType::FileRef => "file",
        AiInputPartType::ToolResult => "tool_result",
        AiInputPartType::VideoRef => "video",
        AiInputPartType::TrainingDataRef => "dataset",
        AiInputPartType::EvaluationDataRef => "evaluation_set",
    }
}

fn capability_for_ai_request(request: &AiRequestV1) -> String {
    match request.api_surface {
        ApiSurface::OpenAiEmbeddings => "text.embedding.general",
        ApiSurface::OpenAiVectorStores | ApiSurface::VectorSearch => "vector.retrieve.general",
        ApiSurface::RagQuery => "document.answer.retrieval_augmented",
        ApiSurface::OpenAiImages | ApiSurface::ImageGeneration => "image.generate.general",
        ApiSurface::ImageUnderstanding => "vision.understand.general",
        ApiSurface::OpenAiAudio | ApiSurface::SpeechToText => "audio.transcribe.general",
        ApiSurface::TextToSpeech => "audio.synthesize.general",
        ApiSurface::OpenAiBatches | ApiSurface::Batch => "batch.execute.general",
        ApiSurface::OpenAiFineTuning | ApiSurface::FineTune => "model.fine_tune.general",
        ApiSurface::OpenAiEvals | ApiSurface::EvalRun => "model.evaluate.general",
        ApiSurface::OpenAiRealtime | ApiSurface::GeminiLive | ApiSurface::RealtimeSession => {
            "realtime.session.general"
        }
        ApiSurface::Moderation => "safety.moderate.general",
        ApiSurface::HuggingFaceInference => "model.infer.general",
        ApiSurface::AnthropicMessages
        | ApiSurface::GeminiGenerateContent
        | ApiSurface::OpenAiChatCompletions
        | ApiSurface::OpenAiResponses
        | ApiSurface::HivemindNative => "text.chat.general",
    }
    .to_string()
}

fn runtime_classes_for_ai_request(request: &AiRequestV1) -> Vec<String> {
    if let Some(values) = request
        .metadata
        .get("runtimeClasses")
        .and_then(Value::as_array)
    {
        let classes = values
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if !classes.is_empty() {
            return classes;
        }
    }

    match request.privacy.privacy_tier {
        PrivacyTier::LocalOnly => vec!["browser".to_string(), "local".to_string()],
        PrivacyTier::TeeConfidential => vec!["confidential_runner".to_string()],
        PrivacyTier::FheEncrypted | PrivacyTier::MpcExperimental => {
            vec!["cryptographic_runtime".to_string()]
        }
        _ => match request.api_surface {
            ApiSurface::OpenAiFineTuning
            | ApiSurface::FineTune
            | ApiSurface::OpenAiBatches
            | ApiSurface::Batch
            | ApiSurface::OpenAiImages
            | ApiSurface::ImageGeneration
            | ApiSurface::OpenAiAudio
            | ApiSurface::SpeechToText
            | ApiSurface::TextToSpeech => vec!["remote_gpu".to_string(), "miner".to_string()],
            ApiSurface::OpenAiEmbeddings
            | ApiSurface::OpenAiVectorStores
            | ApiSurface::VectorSearch => {
                vec![
                    "browser".to_string(),
                    "local".to_string(),
                    "remote_gpu".to_string(),
                    "miner".to_string(),
                ]
            }
            _ => vec![
                "browser".to_string(),
                "local".to_string(),
                "remote_gpu".to_string(),
                "miner".to_string(),
            ],
        },
    }
}

fn output_contract_for_ai_request(request: &AiRequestV1) -> Value {
    if let Some(response_format) = &request.response_format {
        return json!({
            "format": "explicit_response_format",
            "schema": response_format,
            "delivery": if request.stream { "stream_or_swarm_ref" } else { "inline_small_or_swarm_ref" }
        });
    }
    json!({
        "format": match request.api_surface {
            ApiSurface::OpenAiEmbeddings => "embedding_vector",
            ApiSurface::OpenAiImages | ApiSurface::ImageGeneration => "image_ref",
            ApiSurface::OpenAiAudio | ApiSurface::SpeechToText => "transcript_or_audio_ref",
            ApiSurface::TextToSpeech => "audio_ref",
            ApiSurface::OpenAiVectorStores | ApiSurface::VectorSearch | ApiSurface::RagQuery => "retrieval_results",
            ApiSurface::Moderation => "safety_classification",
            _ => "text_or_json"
        },
        "delivery": if request.stream { "stream_or_swarm_ref" } else { "inline_small_or_swarm_ref" },
        "receiptRequired": true
    })
}

fn input_strategy_for_ai_request(request: &AiRequestV1) -> String {
    if let Some(strategy) = request
        .metadata
        .get("storagePlan")
        .and_then(|plan| plan.get("inputStrategy"))
        .and_then(Value::as_str)
    {
        return strategy.to_string();
    }
    if request
        .inputs
        .iter()
        .any(|input| input.content_ref.is_some())
    {
        "use_referenced_assets".to_string()
    } else if request.metadata.get("browserStorageSessionRef").is_some() {
        "browser_upload".to_string()
    } else {
        "inline_small".to_string()
    }
}

fn output_strategy_for_ai_request(request: &AiRequestV1) -> String {
    if let Some(strategy) = request
        .metadata
        .get("storagePlan")
        .and_then(|plan| plan.get("outputStrategy"))
        .and_then(Value::as_str)
    {
        return strategy.to_string();
    }
    if request.stream {
        "stream_then_receipt".to_string()
    } else {
        "inline_small_or_upload_output_to_swarm".to_string()
    }
}

fn allowed_storage_providers_for_ai_request(request: &AiRequestV1) -> Vec<String> {
    if let Some(values) = request
        .metadata
        .get("storagePlan")
        .and_then(|plan| plan.get("allowedProviders"))
        .and_then(Value::as_array)
    {
        let providers = values
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        if !providers.is_empty() {
            return providers;
        }
    }
    vec![
        "local_dev".to_string(),
        "bee_http".to_string(),
        "bee_js_gateway".to_string(),
        "weeb3_npm".to_string(),
    ]
}

fn request_requires_input_encryption(request: &AiRequestV1) -> bool {
    match request.privacy.privacy_tier {
        PrivacyTier::Public | PrivacyTier::Standard | PrivacyTier::StandardRemote => {
            request.inputs.iter().any(|input| {
                input
                    .metadata
                    .get("sensitivityLabel")
                    .and_then(Value::as_str)
                    .map(|label| label.contains("private") || label.contains("secret"))
                    .unwrap_or(false)
            })
        }
        PrivacyTier::NoLog
        | PrivacyTier::NoLogRemote
        | PrivacyTier::RedactedInput
        | PrivacyTier::LocalOnly
        | PrivacyTier::BrowserOnly
        | PrivacyTier::EncryptedStorage
        | PrivacyTier::TeeConfidential
        | PrivacyTier::FheEncrypted
        | PrivacyTier::FheEncryptedInference
        | PrivacyTier::SplitTrustRedundant
        | PrivacyTier::ZkVerifiedInference
        | PrivacyTier::MpcExperimental => true,
    }
}

fn output_asset_class_for_ai_request(request: &AiRequestV1) -> Option<String> {
    let class = match request.api_surface {
        ApiSurface::OpenAiImages | ApiSurface::ImageGeneration => "image",
        ApiSurface::OpenAiAudio | ApiSurface::TextToSpeech => "audio",
        ApiSurface::OpenAiEmbeddings => "vector_index",
        ApiSurface::OpenAiBatches | ApiSurface::Batch => "generated_output",
        ApiSurface::OpenAiFineTuning | ApiSurface::FineTune => "model_weight",
        ApiSurface::OpenAiEvals | ApiSurface::EvalRun => "report",
        _ => return None,
    };
    Some(class.to_string())
}

fn output_kind_for_ai_request(request: &AiRequestV1) -> &'static str {
    match request.api_surface {
        ApiSurface::OpenAiEmbeddings => "embedding",
        ApiSurface::OpenAiImages | ApiSurface::ImageGeneration => "image",
        ApiSurface::OpenAiAudio | ApiSurface::SpeechToText => "transcript",
        ApiSurface::TextToSpeech => "audio",
        ApiSurface::OpenAiVectorStores | ApiSurface::VectorSearch => "vector_search_results",
        ApiSurface::RagQuery => "answer_with_citations",
        ApiSurface::OpenAiBatches | ApiSurface::Batch => "batch_result_manifest",
        ApiSurface::OpenAiFineTuning | ApiSurface::FineTune => "trained_adapter_or_model",
        ApiSurface::OpenAiEvals | ApiSurface::EvalRun => "evaluation_report",
        ApiSurface::Moderation => "moderation_classification",
        ApiSurface::OpenAiRealtime | ApiSurface::RealtimeSession | ApiSurface::GeminiLive => {
            "realtime_events"
        }
        _ => "text_or_json",
    }
}

fn output_content_type_for_ai_request(request: &AiRequestV1) -> Option<&'static str> {
    match request.api_surface {
        ApiSurface::OpenAiImages | ApiSurface::ImageGeneration => Some("image/*"),
        ApiSurface::OpenAiAudio | ApiSurface::TextToSpeech | ApiSurface::SpeechToText => {
            Some("audio/*")
        }
        ApiSurface::OpenAiEmbeddings
        | ApiSurface::OpenAiVectorStores
        | ApiSurface::VectorSearch
        | ApiSurface::RagQuery
        | ApiSurface::OpenAiBatches
        | ApiSurface::Batch
        | ApiSurface::OpenAiFineTuning
        | ApiSurface::FineTune
        | ApiSurface::OpenAiEvals
        | ApiSurface::EvalRun
        | ApiSurface::Moderation => Some("application/json"),
        _ => Some("text/plain"),
    }
}

fn operation_for_api_surface(api_surface: &ApiSurface) -> &'static str {
    match api_surface {
        ApiSurface::OpenAiEmbeddings => "embedding",
        ApiSurface::OpenAiVectorStores | ApiSurface::VectorSearch => "vector_search",
        ApiSurface::RagQuery => "rag_query",
        ApiSurface::OpenAiImages | ApiSurface::ImageGeneration => "image_generation",
        ApiSurface::ImageUnderstanding => "image_understanding",
        ApiSurface::OpenAiAudio | ApiSurface::SpeechToText => "speech_to_text",
        ApiSurface::TextToSpeech => "text_to_speech",
        ApiSurface::OpenAiBatches | ApiSurface::Batch => "batch",
        ApiSurface::OpenAiFineTuning | ApiSurface::FineTune => "fine_tune",
        ApiSurface::OpenAiEvals | ApiSurface::EvalRun => "eval_run",
        ApiSurface::OpenAiRealtime | ApiSurface::GeminiLive | ApiSurface::RealtimeSession => {
            "realtime_session"
        }
        ApiSurface::Moderation => "moderation",
        ApiSurface::HuggingFaceInference => "inference",
        ApiSurface::AnthropicMessages
        | ApiSurface::GeminiGenerateContent
        | ApiSurface::OpenAiChatCompletions
        | ApiSurface::OpenAiResponses
        | ApiSurface::HivemindNative => "chat",
    }
}

fn api_surface_wire_name(api_surface: &ApiSurface) -> String {
    json_wire_name(api_surface)
}

fn privacy_tier_wire_name(tier: &PrivacyTier) -> String {
    json_wire_name(tier)
}

fn integrity_tier_wire_name(tier: &IntegrityTier) -> String {
    json_wire_name(tier)
}

fn streaming_event_wire_name(event: &StreamingEventType) -> String {
    json_wire_name(event)
}

fn json_wire_name(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn push_unique_string(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn allows_plaintext_miner(tier: &PrivacyTier) -> bool {
    matches!(tier, PrivacyTier::Standard | PrivacyTier::NoLog)
}

fn ai_request_signing_value(request: &AiRequestV1) -> serde_json::Result<Value> {
    let mut value = serde_json::to_value(request)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("requestId");
        object.remove("signatures");
    }
    Ok(value)
}

fn ai_response_signing_value(response: &AiResponseV1) -> serde_json::Result<Value> {
    let mut value = serde_json::to_value(response)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("responseId");
        object.remove("signatures");
    }
    Ok(value)
}

fn ai_workload_signing_value(workload: &AIWorkloadV1) -> serde_json::Result<Value> {
    let mut value = serde_json::to_value(workload)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("workloadId");
        object.remove("signatures");
    }
    Ok(value)
}

fn task_envelope_signing_value(envelope: &TaskEnvelopeV1) -> serde_json::Result<Value> {
    let mut value = serde_json::to_value(envelope)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("taskId");
        object.remove("signature");
    }
    Ok(value)
}

fn validate_package_selector(selector: &AiPackageSelectorV1, issues: &mut Vec<ValidationIssue>) {
    let candidates = [
        (
            "$.packageSelector.packageId",
            selector.package_id.as_deref(),
        ),
        (
            "$.packageSelector.packageRef",
            selector.package_ref.as_deref(),
        ),
        (
            "$.packageSelector.serviceRef",
            selector.service_ref.as_deref(),
        ),
        ("$.packageSelector.model", selector.model.as_deref()),
        ("$.packageSelector.channel", selector.channel.as_deref()),
    ];
    let mut has_selector = false;
    for (path, value) in candidates {
        if let Some(value) = value {
            if value.trim().is_empty() {
                issues.push(issue(path, "Package selector value must not be empty"));
            } else {
                has_selector = true;
            }
        }
    }
    if !has_selector {
        issues.push(issue(
            "$.packageSelector",
            "AI request packageSelector must include a packageId, packageRef, serviceRef, model, or channel",
        ));
    }
}

fn validate_ai_inputs(
    inputs: &[AiInputPartV1],
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    for (index, input) in inputs.iter().enumerate() {
        let path = format!("$.inputs[{index}]");
        match input.part_type {
            AiInputPartType::Text => {
                if input.content.is_null()
                    && input
                        .content_ref
                        .as_deref()
                        .map(|reference| reference.trim().is_empty())
                        .unwrap_or(true)
                {
                    issues.push(issue(
                        format!("{path}.content"),
                        "Text input must include content or contentRef",
                    ));
                }
            }
            AiInputPartType::ImageRef
            | AiInputPartType::AudioRef
            | AiInputPartType::DocumentRef
            | AiInputPartType::FileRef
            | AiInputPartType::VideoRef
            | AiInputPartType::TrainingDataRef
            | AiInputPartType::EvaluationDataRef => {
                require_optional_reference(
                    issues,
                    warnings,
                    &format!("{path}.contentRef"),
                    input.content_ref.as_deref(),
                    "Reference input",
                );
            }
            AiInputPartType::ImageInline | AiInputPartType::AudioChunk => {
                if input.content.is_null() {
                    issues.push(issue(
                        format!("{path}.content"),
                        "Inline media input must include content",
                    ));
                } else if input.hash.is_none() {
                    warnings.push(issue(
                        format!("{path}.hash"),
                        "Inline media input should include a hash for reproducibility",
                    ));
                }
            }
            AiInputPartType::VectorQuery | AiInputPartType::ToolResult => {
                if input.content.is_null() {
                    issues.push(issue(
                        format!("{path}.content"),
                        "Structured input part must include content",
                    ));
                }
            }
        }
        if let Some(reference) = &input.content_ref {
            require_optional_reference(
                issues,
                warnings,
                &format!("{path}.contentRef"),
                Some(reference),
                "Input contentRef",
            );
        }
        if let Some(hash) = &input.hash {
            require_non_empty(issues, format!("{path}.hash"), hash);
        }
        if !input.metadata.is_object() {
            warnings.push(issue(
                format!("{path}.metadata"),
                "Input metadata is usually expected to be an object",
            ));
        }
    }
}

fn ai_request_allows_empty_input(request: &AiRequestV1) -> bool {
    matches!(
        request.api_surface,
        ApiSurface::OpenAiRealtime | ApiSurface::GeminiLive | ApiSurface::RealtimeSession
    ) || request.task.as_deref() == Some("realtime")
}

fn validate_ai_outputs(
    outputs: &[AiOutputPartV1],
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    for (index, output) in outputs.iter().enumerate() {
        let path = format!("$.outputs[{index}]");
        match output.part_type {
            AiOutputPartType::ImageRef | AiOutputPartType::AudioRef | AiOutputPartType::FileRef => {
                require_optional_reference(
                    issues,
                    warnings,
                    &format!("{path}.contentRef"),
                    output.content_ref.as_deref(),
                    "Reference output",
                );
            }
            AiOutputPartType::Text
            | AiOutputPartType::Json
            | AiOutputPartType::Embedding
            | AiOutputPartType::ToolResult => {
                if output.content.is_null() && output.content_ref.is_none() {
                    issues.push(issue(
                        format!("{path}.content"),
                        "AI output must include content or contentRef",
                    ));
                }
            }
        }
        if !output.metadata.is_object() {
            warnings.push(issue(
                format!("{path}.metadata"),
                "Output metadata is usually expected to be an object",
            ));
        }
    }
}

fn validate_sampling_options(sampling: &AiSamplingOptionsV1, issues: &mut Vec<ValidationIssue>) {
    if let Some(temperature) = sampling.temperature {
        if !temperature.is_finite() || temperature < 0.0 {
            issues.push(issue(
                "$.sampling.temperature",
                "Temperature must be a non-negative finite number",
            ));
        }
    }
    if let Some(top_p) = sampling.top_p {
        if !(0.0..=1.0).contains(&top_p) || !top_p.is_finite() {
            issues.push(issue(
                "$.sampling.topP",
                "topP must be a finite number between 0 and 1",
            ));
        }
    }
    if matches!(sampling.max_output_tokens, Some(0)) {
        issues.push(issue(
            "$.sampling.maxOutputTokens",
            "maxOutputTokens must be greater than zero when present",
        ));
    }
    for (index, stop) in sampling.stop.iter().enumerate() {
        require_non_empty(issues, format!("$.sampling.stop[{index}]"), stop);
    }
}

fn validate_request_constraints(
    constraints: &AiRequestConstraintsV1,
    issues: &mut Vec<ValidationIssue>,
) {
    if let Some(price) = &constraints.max_price {
        if !price.amount.is_finite() || price.amount < 0.0 {
            issues.push(issue(
                "$.constraints.maxPrice.amount",
                "Maximum price must be a finite non-negative number",
            ));
        }
        require_non_empty(issues, "$.constraints.maxPrice.currency", &price.currency);
    }
    if matches!(constraints.max_latency_ms, Some(0)) {
        issues.push(issue(
            "$.constraints.maxLatencyMs",
            "Maximum latency must be greater than zero milliseconds",
        ));
    }
    if matches!(constraints.deadline_ms, Some(0)) {
        issues.push(issue(
            "$.constraints.deadlineMs",
            "Deadline must be greater than zero milliseconds",
        ));
    }
}

fn validate_ai_response_errors(errors: &[AiResponseErrorV1], issues: &mut Vec<ValidationIssue>) {
    for (index, error) in errors.iter().enumerate() {
        if error.standard_code.is_none() {
            issues.push(issue(
                format!("$.errors[{index}].standardCode"),
                "AI response errors must include a standard error code",
            ));
        }
        require_non_empty(issues, format!("$.errors[{index}].message"), &error.message);
        if !error.details.is_object() {
            issues.push(issue(
                format!("$.errors[{index}].details"),
                "AI response error details must be an object",
            ));
        }
    }
}

fn require_optional_reference(
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
    path: &str,
    value: Option<&str>,
    label: &str,
) {
    match value {
        Some(reference) if reference.trim().is_empty() => {
            issues.push(issue(path, format!("{label} must not be empty")));
        }
        Some(reference) if !looks_like_reference(reference) && !looks_like_hash_ref(reference) => {
            warnings.push(issue(
                path,
                format!("{label} is not a recognized content, local, web, file, selector, or hash reference"),
            ));
        }
        Some(_) => {}
        None => issues.push(issue(path, format!("{label} is required"))),
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_signature_list(
    signatures: &[String],
    expected_signature: &str,
    dev_signature_prefix: &str,
    path: &str,
    label: &str,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if signatures.is_empty() {
        warnings.push(issue(
            path,
            format!(
                "{label} is unsigned; signed interface objects are required for production trust"
            ),
        ));
        return;
    }
    let mut matched = false;
    for (index, signature) in signatures.iter().enumerate() {
        let signature_path = format!("{path}[{index}]");
        if signature.trim().is_empty() {
            issues.push(issue(signature_path, "Signature must not be empty"));
        } else if signature == expected_signature {
            matched = true;
        } else if signature.starts_with(dev_signature_prefix) {
            issues.push(issue(
                signature_path,
                format!("{label} dev signature does not match canonical content"),
            ));
        } else {
            warnings.push(issue(
                signature_path,
                format!("{label} signature is not a local-dev signature and was not verified here"),
            ));
        }
    }
    if !matched
        && !signatures
            .iter()
            .any(|signature| signature.starts_with(dev_signature_prefix))
    {
        warnings.push(issue(
            path,
            format!("{label} does not include a locally verifiable development signature"),
        ));
    }
}

fn require_non_empty(issues: &mut Vec<ValidationIssue>, path: impl Into<String>, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value must not be empty"));
    }
}

fn looks_like_hash_ref(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("sha256:")
        || value.starts_with("sha256://")
        || (value.len() == 64 && value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()))
}

fn looks_like_reference(value: &str) -> bool {
    value.starts_with("bzz://")
        || value.starts_with("local://")
        || value.starts_with("ipfs://")
        || value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("file:")
        || value.starts_with("package://")
        || value.starts_with("package-kind://")
        || value.starts_with("model://")
        || value.starts_with("dataset://")
        || value.starts_with("benchmark://")
        || value.starts_with("eval://")
        || value.starts_with("receipt://")
        || value.starts_with("vector://")
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn empty_metadata() -> Value {
    json!({})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_request_maps_text_to_execution_request() {
        let request = AiRequestV1::text(
            "ai-request-1",
            "alice",
            ApiSurface::HivemindNative,
            AiPackageSelectorV1 {
                package_id: Some("hivemind/hello-chat".to_string()),
                package_ref: Some("bzz://hello-chat".to_string()),
                ..Default::default()
            },
            "hello interface",
        );

        let execution = execution_request_from_ai_request(
            &request,
            "bzz://hello-chat",
            "hivemind/hello-chat",
            "0.1.0",
        )
        .unwrap();

        assert_eq!(execution.schema_version, "swarm-ai.execution.request.v1");
        assert_eq!(execution.task, "chat");
        assert_eq!(execution.input["text"], json!("hello interface"));
        assert_eq!(execution.input["inputs"][0]["type"], json!("text"));
    }

    #[test]
    fn ai_response_wraps_execution_metadata_and_receipt() {
        let mut execution = ExecutionResponseV1::succeeded(
            "ai-request-1",
            json!({ "message": { "role": "assistant", "content": "done" } }),
            ExecutionMetrics {
                queue_ms: 1,
                compute_ms: 2,
                total_ms: 3,
                input_tokens: Some(4),
                output_tokens: Some(5),
                load_ms: 0,
            },
        );
        execution.receipt_ref = Some("local://receipt/1".to_string());
        execution.metadata = json!({
            "routeExecution": {
                "selectedRouteId": "route-local"
            }
        });

        let response = ai_response_from_execution_response(&execution);

        assert_eq!(response.schema_version, "hivemind.response.v1");
        assert_eq!(response.status, AiResponseStatusV1::Completed);
        assert_eq!(response.receipt_ref.as_deref(), Some("local://receipt/1"));
        assert_eq!(
            response.trace_ref.as_deref(),
            Some("local://route/route-local")
        );
        assert_eq!(response.outputs[0].content, json!("done"));
        assert!(response.response_id.starts_with("airesp-"));
    }

    #[test]
    fn signed_ai_request_verifies_and_detects_tampering() {
        let mut request = AiRequestV1::text(
            "temporary-id",
            "alice",
            ApiSurface::HivemindNative,
            AiPackageSelectorV1 {
                package_id: Some("hivemind/hello-chat".to_string()),
                package_ref: Some("bzz://hello-chat".to_string()),
                ..Default::default()
            },
            "hello interface",
        );

        let signature = sign_ai_request(&mut request).unwrap();
        let verification = verify_ai_request(&request);

        assert!(request.request_id.starts_with("aireq-"));
        assert_eq!(request.signatures, vec![signature]);
        assert!(verification.valid, "{verification:#?}");
        assert_eq!(verification.expected_request_id, request.request_id);

        request.inputs[0].content = json!("tampered");
        let tampered = verify_ai_request(&request);
        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path == "$.requestId" || issue.path.starts_with("$.signatures"))
        );
    }

    #[test]
    fn ai_workload_projects_referenced_assets_storage_privacy_and_signatures() {
        let request = AiRequestV1 {
            schema_version: "hivemind.request.v1".to_string(),
            request_id: "rag-request-1".to_string(),
            requester: "enterprise-user".to_string(),
            api_surface: ApiSurface::RagQuery,
            package_selector: AiPackageSelectorV1 {
                package_id: Some("hivemind/private-rag".to_string()),
                package_ref: Some("bzz://private-rag".to_string()),
                ..Default::default()
            },
            inputs: vec![
                AiInputPartV1 {
                    part_type: AiInputPartType::DocumentRef,
                    content: json!({}),
                    content_ref: Some("bzz://encrypted-docs".to_string()),
                    mime_type: Some("application/pdf".to_string()),
                    hash: Some("sha256:abc".to_string()),
                    metadata: json!({
                        "assetId": "invoice-corpus",
                        "byteSize": 2048,
                        "sensitivityLabel": "private_enterprise"
                    }),
                },
                AiInputPartV1::text("summarize invoice risk"),
            ],
            messages: None,
            tools: None,
            response_format: Some(json!({
                "type": "json_schema",
                "jsonSchema": {
                    "name": "invoice_risk",
                    "schema": { "type": "object" }
                }
            })),
            stream: true,
            sampling: None,
            task: None,
            constraints: AiRequestConstraintsV1 {
                max_price: Some(PriceV1 {
                    amount: 1.0,
                    currency: "USD".to_string(),
                }),
                max_latency_ms: Some(30_000),
                deadline_ms: Some(60_000),
                deterministic: Some(true),
            },
            privacy: AiRequestPrivacyV1 {
                privacy_tier: PrivacyTier::TeeConfidential,
                receipt_mode: ReceiptMode::HashOnly,
                data_retention_rule: Some(DataRetentionRule::NoRetention),
                logging_rule: Some(LoggingRule::HashOnlyAuditLogs),
            },
            validation: AiRequestValidationV1 {
                required_verification_tier: IntegrityTier::ValidatorSpotCheck,
                validation_required: true,
                strategies: vec!["schema_check".to_string()],
            },
            signatures: Vec::new(),
            metadata: json!({
                "browserStorageSessionRef": "local://storage-session/session-1"
            }),
        };

        let mut workload = ai_workload_from_ai_request(&request);
        let signature = sign_ai_workload(&mut workload).unwrap();
        let verification = verify_ai_workload(&workload);

        assert_eq!(
            workload.selected_capability,
            "document.answer.retrieval_augmented"
        );
        assert_eq!(workload.input_assets.len(), 1);
        assert_eq!(workload.input_assets[0].asset_id, "invoice-corpus");
        assert_eq!(
            workload.input_assets[0].storage_refs,
            vec!["bzz://encrypted-docs"]
        );
        assert_eq!(workload.inline_inputs.len(), 1);
        assert_eq!(
            workload.execution_requirements.runtime_classes,
            vec!["confidential_runner"]
        );
        assert_eq!(
            workload.privacy_requirement.tier,
            PrivacyTier::TeeConfidential
        );
        assert!(!workload.privacy_requirement.allow_plaintext_miner);
        assert!(workload.storage_plan.required_storage_receipts);
        assert!(workload.storage_plan.encrypt_inputs);
        assert_eq!(
            workload.settlement_requirement.payment_mode,
            "quote_or_escrow"
        );
        assert_eq!(workload.signatures, vec![signature]);
        assert!(verification.valid, "{verification:#?}");

        workload.selected_capability = "tampered.capability".to_string();
        let tampered = verify_ai_workload(&workload);
        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path == "$.workloadId" || issue.path.starts_with("$.signatures"))
        );
    }

    #[test]
    fn task_envelope_projects_review4_job_contract_and_detects_tampering() {
        let request = AiRequestV1 {
            schema_version: "hivemind.request.v1".to_string(),
            request_id: "rag-request-1".to_string(),
            requester: "enterprise-user".to_string(),
            api_surface: ApiSurface::RagQuery,
            package_selector: AiPackageSelectorV1 {
                package_id: Some("hivemind/private-rag".to_string()),
                package_ref: Some("bzz://private-rag".to_string()),
                ..Default::default()
            },
            inputs: vec![
                AiInputPartV1 {
                    part_type: AiInputPartType::DocumentRef,
                    content: json!({}),
                    content_ref: Some("bzz://encrypted-docs".to_string()),
                    mime_type: Some("application/pdf".to_string()),
                    hash: Some("sha256:abc".to_string()),
                    metadata: json!({
                        "inputId": "invoice-corpus",
                        "byteSize": 2048,
                        "sensitivityLabel": "private_enterprise"
                    }),
                },
                AiInputPartV1::text("summarize invoice risk"),
            ],
            messages: Some(vec![json!({
                "role": "user",
                "content": "Which invoices need manual review?"
            })]),
            tools: Some(vec![json!({
                "type": "function",
                "name": "lookup_customer_policy"
            })]),
            response_format: Some(json!({
                "type": "json_schema",
                "jsonSchema": {
                    "name": "invoice_risk",
                    "schema": { "type": "object" }
                }
            })),
            stream: true,
            sampling: None,
            task: Some("document.answer.retrieval_augmented".to_string()),
            constraints: AiRequestConstraintsV1 {
                max_price: Some(PriceV1 {
                    amount: 1.0,
                    currency: "USD".to_string(),
                }),
                max_latency_ms: Some(30_000),
                deadline_ms: Some(60_000),
                deterministic: Some(true),
            },
            privacy: AiRequestPrivacyV1 {
                privacy_tier: PrivacyTier::TeeConfidential,
                receipt_mode: ReceiptMode::HashOnly,
                data_retention_rule: Some(DataRetentionRule::NoRetention),
                logging_rule: Some(LoggingRule::HashOnlyAuditLogs),
            },
            validation: AiRequestValidationV1 {
                required_verification_tier: IntegrityTier::ValidatorSpotCheck,
                validation_required: true,
                strategies: vec!["schema_check".to_string()],
            },
            signatures: Vec::new(),
            metadata: json!({
                "outputRef": "bzz://risk-output",
                "inputSchemaRef": "bzz://schemas/rag-input",
                "outputSchemaRef": "bzz://schemas/rag-output",
                "preferredRunnerTypes": ["confidential"]
            }),
        };

        let mut envelope = task_envelope_from_ai_request(&request);
        let signature = sign_task_envelope(&mut envelope).unwrap();
        let verification = verify_task_envelope(&envelope);

        assert_eq!(envelope.schema_version, "hivemind.task_envelope.v1");
        assert_eq!(envelope.object_kind, "task_envelope");
        assert_eq!(envelope.requested_api, ApiSurface::RagQuery);
        assert_eq!(
            envelope.capability.capability_id,
            "document.answer.retrieval_augmented"
        );
        assert_eq!(envelope.package_ref.as_deref(), Some("bzz://private-rag"));
        assert_eq!(envelope.inputs.len(), 4);
        assert_eq!(envelope.inputs[0].input_kind, "asset_ref");
        assert_eq!(envelope.inputs[1].input_kind, "inline");
        assert_eq!(
            envelope.expected_outputs[0].target_ref.as_deref(),
            Some("bzz://risk-output")
        );
        assert_eq!(envelope.privacy.privacy_tier, PrivacyTier::TeeConfidential);
        assert!(!envelope.privacy.allow_plaintext_miner);
        assert_eq!(
            envelope.verification.verification_tier,
            IntegrityTier::ValidatorSpotCheck
        );
        assert!(envelope.streaming.enabled);
        assert_eq!(envelope.signature.as_deref(), Some(signature.as_str()));
        assert!(verification.valid, "{verification:#?}");

        envelope.budget.max_price.as_mut().unwrap().amount = -1.0;
        let tampered = verify_task_envelope(&envelope);
        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path == "$.taskId" || issue.path == "$.budget.maxPrice.amount")
        );
    }

    #[test]
    fn realtime_ai_request_allows_empty_initial_input_after_signing() {
        let mut request = AiRequestV1 {
            schema_version: "hivemind.request.v1".to_string(),
            request_id: "temporary-id".to_string(),
            requester: "alice".to_string(),
            api_surface: ApiSurface::GeminiLive,
            package_selector: AiPackageSelectorV1 {
                model: Some("hivemind/realtime".to_string()),
                ..Default::default()
            },
            inputs: Vec::new(),
            messages: None,
            tools: None,
            response_format: Some(json!({
                "inputModalities": ["audio", "text"],
                "responseModalities": ["audio", "text"]
            })),
            stream: true,
            sampling: None,
            task: Some("realtime".to_string()),
            constraints: AiRequestConstraintsV1::default(),
            privacy: AiRequestPrivacyV1::default(),
            validation: AiRequestValidationV1::default(),
            signatures: Vec::new(),
            metadata: json!({}),
        };

        sign_ai_request(&mut request).unwrap();
        let verification = verify_ai_request(&request);

        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.inputs")
        );
    }

    #[test]
    fn ai_request_verifier_requires_selectors_and_reference_inputs() {
        let request = AiRequestV1 {
            schema_version: "hivemind.request.v1".to_string(),
            request_id: "manual-id".to_string(),
            requester: "alice".to_string(),
            api_surface: ApiSurface::HivemindNative,
            package_selector: AiPackageSelectorV1::default(),
            inputs: vec![AiInputPartV1 {
                part_type: AiInputPartType::DocumentRef,
                content: json!({}),
                content_ref: None,
                mime_type: Some("application/pdf".to_string()),
                hash: None,
                metadata: json!({}),
            }],
            messages: None,
            tools: None,
            response_format: None,
            stream: false,
            sampling: Some(AiSamplingOptionsV1 {
                temperature: Some(-1.0),
                top_p: Some(2.0),
                max_output_tokens: Some(0),
                seed: None,
                stop: vec!["".to_string()],
            }),
            task: Some("chat".to_string()),
            constraints: AiRequestConstraintsV1 {
                max_price: Some(PriceV1 {
                    amount: -1.0,
                    currency: String::new(),
                }),
                max_latency_ms: Some(0),
                deadline_ms: Some(0),
                deterministic: None,
            },
            privacy: AiRequestPrivacyV1::default(),
            validation: AiRequestValidationV1::default(),
            signatures: Vec::new(),
            metadata: json!({}),
        };

        let verification = verify_ai_request(&request);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.packageSelector")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.inputs[0].contentRef")
        );
        assert!(
            verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signatures")
        );
    }

    #[test]
    fn signed_ai_response_verifies_and_requires_standard_errors() {
        let mut response = AiResponseV1::failed(
            "ai-request-1",
            SwarmAiErrorV1::new(ErrorCode::AccessDenied, "blocked"),
        );
        let signature = sign_ai_response(&mut response).unwrap();
        let verification = verify_ai_response(&response);

        assert_eq!(response.signatures, vec![signature]);
        assert!(verification.valid, "{verification:#?}");

        response.errors[0].standard_code = None;
        let missing_standard = verify_ai_response(&response);
        assert!(!missing_standard.valid);
        assert!(
            missing_standard
                .issues
                .iter()
                .any(|issue| issue.path == "$.errors[0].standardCode")
        );
    }
}
