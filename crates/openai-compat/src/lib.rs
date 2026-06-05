use hivemind_batch::{
    BatchJobInitOptionsV1, BatchJobV1, BatchPartialResultPolicy, batch_execution_plan,
    create_batch_job, verify_batch_job,
};
use hivemind_core::{
    AiInputPartType, AiInputPartV1, AiPackageSelectorV1, AiRequestConstraintsV1,
    AiRequestPrivacyV1, AiRequestV1, AiRequestValidationV1, AiSamplingOptionsV1, ApiSurface,
    ExecutionOptions, ExecutionPrivacy, ExecutionRequestV1, ExecutionResponseV1, ExecutionStatus,
    IntegrityTier, Modality, PriceV1, PrivacyTier, RegistryEntryV1, TaskEnvelopeV1,
    canonicalize_json, hash_canonical_json, task_envelope_from_ai_request,
};
use hivemind_evals::{
    EvalKind, EvalManifestInitOptionsV1, EvalManifestV1, EvalRunInitOptionsV1, EvalRunPlanV1,
    EvalRunV1, create_eval_manifest, create_eval_run, eval_run_plan, verify_eval_manifest,
    verify_eval_run,
};
use hivemind_fine_tune::{
    FineTuneJobInitOptionsV1, FineTuneJobV1, FineTuneOutputArtifactKind, FineTuneOutputVisibility,
    create_fine_tune_job, fine_tune_execution_plan, verify_fine_tune_job,
};
use hivemind_media::{
    MediaExecutionPlanV1, MediaJobInitOptionsV1, MediaJobV1, MediaTask, create_media_job,
    media_execution_plan, verify_media_job,
};
use hivemind_realtime::{
    RealtimeConnectionPlanV1, RealtimeSessionInitOptionsV1, RealtimeSessionV1, RealtimeTransport,
    create_realtime_session, realtime_connection_plan, verify_realtime_session,
};
use hivemind_vector::{
    VectorMetric, VectorSearchPlanV1, VectorSearchRequestV1, VectorStorageRefV1, VectorStorageRole,
    VectorStoreInitOptionsV1, VectorStoreManifestV1, create_vector_store_manifest,
    verify_vector_store_manifest,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChatCompletionRequestV1 {
    pub model: String,
    pub messages: Vec<ChatMessageV1>,
    #[serde(default)]
    pub stream: bool,
    #[serde(rename = "max_tokens", default)]
    pub max_tokens: Option<u64>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChatMessageV1 {
    pub role: String,
    #[serde(default)]
    pub content: Value,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChatCompletionResponseV1 {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatCompletionChoiceV1>,
    pub usage: OpenAiUsageV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChatCompletionChoiceV1 {
    pub index: u32,
    pub message: ChatMessageV1,
    #[serde(rename = "finish_reason")]
    pub finish_reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChatCompletionStreamEventV1 {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatCompletionStreamChoiceV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChatCompletionStreamChoiceV1 {
    pub index: u32,
    pub delta: ChatCompletionDeltaV1,
    #[serde(rename = "finish_reason")]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChatCompletionDeltaV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiResponsesRequestV1 {
    pub model: String,
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub instructions: Option<String>,
    #[serde(default)]
    pub stream: bool,
    #[serde(rename = "max_output_tokens", default)]
    pub max_output_tokens: Option<u64>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiResponsesResponseV1 {
    pub id: String,
    pub object: String,
    #[serde(rename = "created_at")]
    pub created_at: u64,
    pub status: String,
    pub model: String,
    pub output: Vec<OpenAiResponseOutputV1>,
    #[serde(rename = "output_text")]
    pub output_text: String,
    pub usage: OpenAiUsageV1,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiResponsesStreamEventV1 {
    #[serde(rename = "type")]
    pub event_type: String,
    pub sequence_number: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<OpenAiResponsesResponseV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiResponseOutputV1 {
    pub id: String,
    #[serde(rename = "type")]
    pub output_type: String,
    pub status: String,
    pub role: String,
    pub content: Vec<OpenAiResponseContentV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiResponseContentV1 {
    #[serde(rename = "type")]
    pub content_type: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EmbeddingRequestV1 {
    pub model: String,
    pub input: Value,
    #[serde(rename = "encoding_format", default)]
    pub encoding_format: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EmbeddingResponseV1 {
    pub object: String,
    pub data: Vec<EmbeddingDataV1>,
    pub model: String,
    pub usage: OpenAiUsageV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EmbeddingDataV1 {
    pub object: String,
    pub index: u32,
    pub embedding: Vec<f32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiModerationRequestV1 {
    pub model: String,
    pub input: Value,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiModerationResponseV1 {
    pub id: String,
    pub model: String,
    pub results: Vec<OpenAiModerationResultV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiModerationResultV1 {
    pub flagged: bool,
    pub categories: BTreeMap<String, bool>,
    #[serde(rename = "category_scores")]
    pub category_scores: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiModelV1 {
    pub id: String,
    pub object: String,
    pub created: u64,
    #[serde(rename = "owned_by")]
    pub owned_by: String,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiModelListV1 {
    pub object: String,
    pub data: Vec<OpenAiModelV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiFileCreateRequestV1 {
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
    #[serde(rename = "ref", default)]
    pub reference: Option<String>,
    #[serde(rename = "storage_ref", default)]
    pub storage_ref: Option<String>,
    #[serde(default)]
    pub bytes: Option<u64>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiFileV1 {
    pub id: String,
    pub object: String,
    pub bytes: u64,
    #[serde(rename = "created_at")]
    pub created_at: u64,
    pub filename: String,
    pub purpose: String,
    pub status: String,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiVectorStoreStorageRefV1 {
    pub role: String,
    pub reference: String,
    #[serde(rename = "content_type", default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(rename = "size_bytes", default)]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiVectorStoreCreateRequestV1 {
    pub name: String,
    #[serde(rename = "file_ids", default)]
    pub file_ids: Vec<String>,
    #[serde(rename = "document_refs", default)]
    pub document_refs: Vec<String>,
    #[serde(rename = "storage_refs", default)]
    pub storage_refs: Vec<OpenAiVectorStoreStorageRefV1>,
    #[serde(rename = "embedding_model", default)]
    pub embedding_model: Option<String>,
    #[serde(default)]
    pub dimensions: Option<u32>,
    #[serde(default)]
    pub metric: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(rename = "chunking_strategy", default)]
    pub chunking_strategy: Option<Value>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiVectorStoreFileCountsV1 {
    #[serde(rename = "in_progress")]
    pub in_progress: u64,
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiVectorStoreV1 {
    pub id: String,
    pub object: String,
    #[serde(rename = "created_at")]
    pub created_at: u64,
    pub name: String,
    pub status: String,
    #[serde(rename = "file_counts")]
    pub file_counts: OpenAiVectorStoreFileCountsV1,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiVectorStoreSearchRequestV1 {
    #[serde(default)]
    pub query: Value,
    #[serde(rename = "max_num_results", default)]
    pub max_num_results: Option<u32>,
    #[serde(default)]
    pub filters: Option<Value>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiVectorStoreSearchResultV1 {
    #[serde(rename = "file_id")]
    pub file_id: String,
    pub filename: String,
    pub score: f64,
    pub text: String,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiVectorStoreSearchResponseV1 {
    pub object: String,
    #[serde(rename = "search_query")]
    pub search_query: Value,
    pub data: Vec<OpenAiVectorStoreSearchResultV1>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiBatchCreateRequestV1 {
    #[serde(rename = "input_file_id")]
    pub input_file_id: String,
    pub endpoint: String,
    #[serde(rename = "completion_window")]
    pub completion_window: String,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(rename = "package_ref", default)]
    pub package_ref: Option<String>,
    #[serde(rename = "package_id", default)]
    pub package_id: Option<String>,
    #[serde(rename = "package_version", default)]
    pub package_version: Option<String>,
    #[serde(default)]
    pub task: Option<String>,
    #[serde(rename = "max_concurrency", default)]
    pub max_concurrency: Option<u32>,
    #[serde(rename = "privacy_tier", default)]
    pub privacy_tier: Option<String>,
    #[serde(rename = "integrity_tier", default)]
    pub integrity_tier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiBatchRequestCountsV1 {
    pub total: u64,
    pub completed: u64,
    pub failed: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiBatchV1 {
    pub id: String,
    pub object: String,
    pub endpoint: String,
    pub errors: Option<Value>,
    #[serde(rename = "input_file_id")]
    pub input_file_id: String,
    #[serde(rename = "completion_window")]
    pub completion_window: String,
    pub status: String,
    #[serde(rename = "output_file_id", default)]
    pub output_file_id: Option<String>,
    #[serde(rename = "error_file_id", default)]
    pub error_file_id: Option<String>,
    #[serde(rename = "created_at")]
    pub created_at: u64,
    #[serde(rename = "in_progress_at", default)]
    pub in_progress_at: Option<u64>,
    #[serde(rename = "expires_at", default)]
    pub expires_at: Option<u64>,
    #[serde(rename = "finalizing_at", default)]
    pub finalizing_at: Option<u64>,
    #[serde(rename = "completed_at", default)]
    pub completed_at: Option<u64>,
    #[serde(rename = "failed_at", default)]
    pub failed_at: Option<u64>,
    #[serde(rename = "expired_at", default)]
    pub expired_at: Option<u64>,
    #[serde(rename = "cancelling_at", default)]
    pub cancelling_at: Option<u64>,
    #[serde(rename = "cancelled_at", default)]
    pub cancelled_at: Option<u64>,
    #[serde(rename = "request_counts")]
    pub request_counts: OpenAiBatchRequestCountsV1,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiFineTuningCreateRequestV1 {
    pub model: String,
    #[serde(rename = "training_file")]
    pub training_file: String,
    #[serde(rename = "validation_file", default)]
    pub validation_file: Option<String>,
    #[serde(default)]
    pub hyperparameters: Option<Value>,
    #[serde(default)]
    pub suffix: Option<String>,
    #[serde(default)]
    pub integrations: Vec<Value>,
    #[serde(default)]
    pub seed: Option<u64>,
    #[serde(default)]
    pub method: Option<Value>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(rename = "recipe_ref", default)]
    pub recipe_ref: Option<String>,
    #[serde(rename = "output_ref", default)]
    pub output_ref: Option<String>,
    #[serde(rename = "privacy_tier", default)]
    pub privacy_tier: Option<String>,
    #[serde(rename = "integrity_tier", default)]
    pub integrity_tier: Option<String>,
    #[serde(rename = "max_cost", default)]
    pub max_cost: Option<PriceV1>,
    #[serde(rename = "validation_required", default)]
    pub validation_required: Option<bool>,
    #[serde(rename = "artifact_kind", default)]
    pub artifact_kind: Option<String>,
    #[serde(rename = "output_visibility", default)]
    pub output_visibility: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiFineTuningJobV1 {
    pub id: String,
    pub object: String,
    #[serde(rename = "created_at")]
    pub created_at: u64,
    #[serde(rename = "finished_at", default)]
    pub finished_at: Option<u64>,
    pub model: String,
    #[serde(rename = "fine_tuned_model", default)]
    pub fine_tuned_model: Option<String>,
    #[serde(rename = "organization_id", default)]
    pub organization_id: Option<String>,
    #[serde(rename = "result_files", default)]
    pub result_files: Vec<String>,
    pub status: String,
    #[serde(rename = "validation_file", default)]
    pub validation_file: Option<String>,
    #[serde(rename = "training_file")]
    pub training_file: String,
    #[serde(default)]
    pub hyperparameters: Value,
    #[serde(rename = "trained_tokens", default)]
    pub trained_tokens: Option<u64>,
    pub error: Option<Value>,
    #[serde(default)]
    pub integrations: Vec<Value>,
    #[serde(default)]
    pub seed: Option<u64>,
    #[serde(default)]
    pub method: Option<Value>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiRealtimeSessionCreateRequestV1 {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub modalities: Vec<String>,
    #[serde(rename = "modalities_in", default)]
    pub modalities_in: Vec<String>,
    #[serde(rename = "modalities_out", default)]
    pub modalities_out: Vec<String>,
    #[serde(default)]
    pub instructions: Option<String>,
    #[serde(default)]
    pub voice: Option<String>,
    #[serde(rename = "input_audio_format", default)]
    pub input_audio_format: Option<String>,
    #[serde(rename = "output_audio_format", default)]
    pub output_audio_format: Option<String>,
    #[serde(rename = "input_audio_transcription", default)]
    pub input_audio_transcription: Option<Value>,
    #[serde(rename = "turn_detection", default)]
    pub turn_detection: Option<Value>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(rename = "tool_choice", default)]
    pub tool_choice: Option<Value>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(rename = "max_response_output_tokens", default)]
    pub max_response_output_tokens: Option<Value>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(rename = "package_ref", default)]
    pub package_ref: Option<String>,
    #[serde(rename = "package_id", default)]
    pub package_id: Option<String>,
    #[serde(rename = "package_version", default)]
    pub package_version: Option<String>,
    #[serde(rename = "service_ref", default)]
    pub service_ref: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(rename = "latency_target_ms", default)]
    pub latency_target_ms: Option<u32>,
    #[serde(rename = "interruptions_allowed", default)]
    pub interruptions_allowed: Option<bool>,
    #[serde(rename = "privacy_tier", default)]
    pub privacy_tier: Option<String>,
    #[serde(rename = "settlement_method", default)]
    pub settlement_method: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiRealtimeClientSecretV1 {
    pub value: String,
    #[serde(rename = "expires_at")]
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiRealtimeSessionV1 {
    pub id: String,
    pub object: String,
    pub model: String,
    pub modalities: Vec<String>,
    #[serde(default)]
    pub instructions: Option<String>,
    #[serde(default)]
    pub voice: Option<String>,
    #[serde(rename = "input_audio_format", default)]
    pub input_audio_format: Option<String>,
    #[serde(rename = "output_audio_format", default)]
    pub output_audio_format: Option<String>,
    #[serde(rename = "input_audio_transcription", default)]
    pub input_audio_transcription: Option<Value>,
    #[serde(rename = "turn_detection", default)]
    pub turn_detection: Option<Value>,
    #[serde(default)]
    pub tools: Vec<Value>,
    #[serde(rename = "tool_choice", default)]
    pub tool_choice: Option<Value>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(rename = "max_response_output_tokens", default)]
    pub max_response_output_tokens: Option<Value>,
    pub status: String,
    #[serde(rename = "client_secret", default)]
    pub client_secret: Option<OpenAiRealtimeClientSecretV1>,
    #[serde(rename = "expires_at", default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiRealtimeSessionRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub request: OpenAiRealtimeSessionCreateRequestV1,
    pub session: RealtimeSessionV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiEvalCreateRequestV1 {
    pub name: String,
    #[serde(rename = "data_source", default)]
    pub data_source: Option<Value>,
    #[serde(rename = "testing_criteria", default)]
    pub testing_criteria: Vec<Value>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(rename = "dataset_refs", default)]
    pub dataset_refs: Vec<String>,
    #[serde(rename = "scoring_rule_refs", default)]
    pub scoring_rule_refs: Vec<String>,
    #[serde(rename = "target_refs", default)]
    pub target_refs: Vec<String>,
    #[serde(rename = "grader_model", default)]
    pub grader_model: Option<String>,
    #[serde(rename = "output_schema_ref", default)]
    pub output_schema_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiEvalV1 {
    pub id: String,
    pub object: String,
    pub name: String,
    #[serde(rename = "created_at")]
    pub created_at: u64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiEvalRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub request: OpenAiEvalCreateRequestV1,
    pub manifest: EvalManifestV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiEvalRunCreateRequestV1 {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(rename = "target_ref", default)]
    pub target_ref: Option<String>,
    #[serde(rename = "input_refs", default)]
    pub input_refs: Vec<String>,
    #[serde(rename = "data_source", default)]
    pub data_source: Option<Value>,
    #[serde(rename = "sample_count", default)]
    pub sample_count: Option<u32>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(rename = "privacy_tier", default)]
    pub privacy_tier: Option<String>,
    #[serde(rename = "integrity_tier", default)]
    pub integrity_tier: Option<String>,
    #[serde(rename = "settlement_method", default)]
    pub settlement_method: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiEvalRunV1 {
    pub id: String,
    pub object: String,
    #[serde(rename = "eval_id")]
    pub eval_id: String,
    pub status: String,
    #[serde(rename = "created_at")]
    pub created_at: u64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiEvalRunRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evalId")]
    pub eval_id: String,
    pub request: OpenAiEvalRunCreateRequestV1,
    pub run: EvalRunV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiImageGenerationRequestV1 {
    #[serde(default)]
    pub model: Option<String>,
    pub prompt: String,
    #[serde(default)]
    pub n: Option<u32>,
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub quality: Option<String>,
    #[serde(default)]
    pub style: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(rename = "response_format", default)]
    pub response_format: Option<String>,
    #[serde(default)]
    pub background: Option<String>,
    #[serde(rename = "output_format", default)]
    pub output_format: Option<String>,
    #[serde(rename = "output_ref", default)]
    pub output_ref: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(rename = "package_ref", default)]
    pub package_ref: Option<String>,
    #[serde(rename = "package_id", default)]
    pub package_id: Option<String>,
    #[serde(rename = "package_version", default)]
    pub package_version: Option<String>,
    #[serde(rename = "service_ref", default)]
    pub service_ref: Option<String>,
    #[serde(rename = "privacy_tier", default)]
    pub privacy_tier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiImageEditRequestV1 {
    #[serde(default)]
    pub model: Option<String>,
    pub image: String,
    #[serde(rename = "image_ref", default)]
    pub image_ref: Option<String>,
    pub prompt: String,
    #[serde(default)]
    pub mask: Option<String>,
    #[serde(rename = "mask_ref", default)]
    pub mask_ref: Option<String>,
    #[serde(default)]
    pub n: Option<u32>,
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(rename = "response_format", default)]
    pub response_format: Option<String>,
    #[serde(rename = "output_format", default)]
    pub output_format: Option<String>,
    #[serde(rename = "output_ref", default)]
    pub output_ref: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(rename = "package_ref", default)]
    pub package_ref: Option<String>,
    #[serde(rename = "package_id", default)]
    pub package_id: Option<String>,
    #[serde(rename = "package_version", default)]
    pub package_version: Option<String>,
    #[serde(rename = "service_ref", default)]
    pub service_ref: Option<String>,
    #[serde(rename = "privacy_tier", default)]
    pub privacy_tier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiImageDataV1 {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(rename = "b64_json", default)]
    pub b64_json: Option<String>,
    #[serde(rename = "revised_prompt", default)]
    pub revised_prompt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiImageGenerationResponseV1 {
    pub created: u64,
    pub data: Vec<OpenAiImageDataV1>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiAudioTranscriptionRequestV1 {
    pub model: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(rename = "file_ref", default)]
    pub file_ref: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(rename = "response_format", default)]
    pub response_format: Option<String>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(rename = "timestamp_granularities", default)]
    pub timestamp_granularities: Vec<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(rename = "package_ref", default)]
    pub package_ref: Option<String>,
    #[serde(rename = "package_id", default)]
    pub package_id: Option<String>,
    #[serde(rename = "package_version", default)]
    pub package_version: Option<String>,
    #[serde(rename = "service_ref", default)]
    pub service_ref: Option<String>,
    #[serde(rename = "privacy_tier", default)]
    pub privacy_tier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiAudioTranscriptionResponseV1 {
    pub text: String,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiAudioSpeechRequestV1 {
    pub model: String,
    pub input: String,
    pub voice: String,
    #[serde(rename = "response_format", default)]
    pub response_format: Option<String>,
    #[serde(default)]
    pub speed: Option<f64>,
    #[serde(rename = "output_ref", default)]
    pub output_ref: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(rename = "package_ref", default)]
    pub package_ref: Option<String>,
    #[serde(rename = "package_id", default)]
    pub package_id: Option<String>,
    #[serde(rename = "package_version", default)]
    pub package_version: Option<String>,
    #[serde(rename = "service_ref", default)]
    pub service_ref: Option<String>,
    #[serde(rename = "privacy_tier", default)]
    pub privacy_tier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiAudioSpeechResponseV1 {
    pub object: String,
    #[serde(rename = "audio_ref")]
    pub audio_ref: String,
    pub format: String,
    pub voice: String,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct OpenAiUsageV1 {
    #[serde(rename = "prompt_tokens")]
    pub prompt_tokens: u64,
    #[serde(rename = "completion_tokens")]
    pub completion_tokens: u64,
    #[serde(rename = "total_tokens")]
    pub total_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiErrorResponseV1 {
    pub error: OpenAiErrorDetailV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OpenAiErrorDetailV1 {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: String,
    #[serde(default)]
    pub param: Option<String>,
    pub code: String,
}

pub fn chat_request_to_execution(
    request: &ChatCompletionRequestV1,
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    request_id: impl Into<String>,
) -> ExecutionRequestV1 {
    ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: request_id.into(),
        package_ref: package_ref.into(),
        package_id: package_id.into(),
        package_version: package_version.into(),
        preferred_artifact_group: None,
        task: "chat".to_string(),
        input: json!({
            "messages": request.messages,
            "text": latest_message_text(&request.messages),
            "model": request.model,
            "maxOutputTokens": request.max_tokens,
            "temperature": request.temperature,
            "user": request.user,
            "metadata": request.metadata,
        }),
        options: ExecutionOptions {
            stream: request.stream,
            ..ExecutionOptions::default()
        },
        privacy: ExecutionPrivacy::default(),
        access_grant: None,
        access_revocation_list: None,
    }
}

pub fn chat_request_to_ai_request(
    request: &ChatCompletionRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> AiRequestV1 {
    let messages = request
        .messages
        .iter()
        .map(|message| json!(message))
        .collect::<Vec<_>>();
    let text = latest_message_text(&request.messages);
    AiRequestV1 {
        schema_version: "hivemind.request.v1".to_string(),
        request_id: request_id.into(),
        requester: openai_requester(
            &request.metadata,
            request.user.as_deref(),
            default_requester,
        ),
        api_surface: ApiSurface::OpenAiChatCompletions,
        package_selector: ai_package_selector_from_model(&request.model),
        inputs: ai_text_parts_from_text(text),
        messages: Some(messages),
        tools: None,
        response_format: None,
        stream: request.stream,
        sampling: ai_sampling_options(request.temperature, None, request.max_tokens),
        task: Some("chat".to_string()),
        constraints: AiRequestConstraintsV1::default(),
        privacy: AiRequestPrivacyV1::default(),
        validation: AiRequestValidationV1::default(),
        signatures: Vec::new(),
        metadata: metadata_with_openai_payload(
            request.metadata.clone(),
            json!({
                "compatTask": "chat_completions",
                "model": request.model,
                "user": request.user,
            }),
        ),
    }
}

pub fn chat_request_to_task_envelope(
    request: &ChatCompletionRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> TaskEnvelopeV1 {
    let ai_request = chat_request_to_ai_request(request, request_id, default_requester);
    task_envelope_from_ai_request(&ai_request)
}

pub fn chat_completion_from_execution(
    request: &ChatCompletionRequestV1,
    response: &ExecutionResponseV1,
    id: impl Into<String>,
    created: u64,
) -> ChatCompletionResponseV1 {
    let content = response_message_content(response);
    let completion_tokens = response
        .metrics
        .output_tokens
        .unwrap_or_else(|| count_tokens(&content));
    let prompt_tokens = response.metrics.input_tokens.unwrap_or_else(|| {
        request
            .messages
            .iter()
            .map(|message| count_tokens(&message_text(message)))
            .sum()
    });
    ChatCompletionResponseV1 {
        id: id.into(),
        object: "chat.completion".to_string(),
        created,
        model: request.model.clone(),
        choices: vec![ChatCompletionChoiceV1 {
            index: 0,
            message: ChatMessageV1 {
                role: "assistant".to_string(),
                content: Value::String(content),
                name: None,
            },
            finish_reason: "stop".to_string(),
        }],
        usage: OpenAiUsageV1 {
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens + completion_tokens,
        },
    }
}

pub fn chat_completion_stream_events_from_execution(
    request: &ChatCompletionRequestV1,
    response: &ExecutionResponseV1,
    id: impl Into<String>,
    created: u64,
) -> Vec<ChatCompletionStreamEventV1> {
    let id = id.into();
    let content = response_message_content(response);
    let mut events = vec![ChatCompletionStreamEventV1 {
        id: id.clone(),
        object: "chat.completion.chunk".to_string(),
        created,
        model: request.model.clone(),
        choices: vec![ChatCompletionStreamChoiceV1 {
            index: 0,
            delta: ChatCompletionDeltaV1 {
                role: Some("assistant".to_string()),
                content: None,
            },
            finish_reason: None,
        }],
    }];

    if !content.is_empty() {
        events.push(ChatCompletionStreamEventV1 {
            id: id.clone(),
            object: "chat.completion.chunk".to_string(),
            created,
            model: request.model.clone(),
            choices: vec![ChatCompletionStreamChoiceV1 {
                index: 0,
                delta: ChatCompletionDeltaV1 {
                    role: None,
                    content: Some(content),
                },
                finish_reason: None,
            }],
        });
    }

    events.push(ChatCompletionStreamEventV1 {
        id,
        object: "chat.completion.chunk".to_string(),
        created,
        model: request.model.clone(),
        choices: vec![ChatCompletionStreamChoiceV1 {
            index: 0,
            delta: ChatCompletionDeltaV1 {
                role: None,
                content: None,
            },
            finish_reason: Some("stop".to_string()),
        }],
    });
    events
}

pub fn chat_completion_stream_body_from_execution(
    request: &ChatCompletionRequestV1,
    response: &ExecutionResponseV1,
    id: impl Into<String>,
    created: u64,
) -> String {
    let mut body = String::new();
    for event in chat_completion_stream_events_from_execution(request, response, id, created) {
        body.push_str("data: ");
        body.push_str(
            &serde_json::to_string(&event)
                .expect("chat completion stream event should serialize to JSON"),
        );
        body.push_str("\n\n");
    }
    body.push_str("data: [DONE]\n\n");
    body
}

pub fn responses_request_to_execution(
    request: &OpenAiResponsesRequestV1,
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    request_id: impl Into<String>,
) -> ExecutionRequestV1 {
    let messages = responses_input_messages(request);
    ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: request_id.into(),
        package_ref: package_ref.into(),
        package_id: package_id.into(),
        package_version: package_version.into(),
        preferred_artifact_group: None,
        task: "chat".to_string(),
        input: json!({
            "messages": messages,
            "text": latest_message_text(&messages),
            "instructions": request.instructions,
            "model": request.model,
            "maxOutputTokens": request.max_output_tokens,
            "temperature": request.temperature,
            "user": request.user,
            "metadata": request.metadata,
            "compatTask": "responses",
        }),
        options: ExecutionOptions {
            stream: request.stream,
            ..ExecutionOptions::default()
        },
        privacy: ExecutionPrivacy::default(),
        access_grant: None,
        access_revocation_list: None,
    }
}

pub fn responses_request_to_ai_request(
    request: &OpenAiResponsesRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> AiRequestV1 {
    let messages = responses_input_messages(request);
    let text = latest_message_text(&messages);
    AiRequestV1 {
        schema_version: "hivemind.request.v1".to_string(),
        request_id: request_id.into(),
        requester: openai_requester(
            &request.metadata,
            request.user.as_deref(),
            default_requester,
        ),
        api_surface: ApiSurface::OpenAiResponses,
        package_selector: ai_package_selector_from_model(&request.model),
        inputs: ai_text_parts_from_text(text),
        messages: Some(messages.into_iter().map(|message| json!(message)).collect()),
        tools: None,
        response_format: None,
        stream: request.stream,
        sampling: ai_sampling_options(request.temperature, None, request.max_output_tokens),
        task: Some("chat".to_string()),
        constraints: AiRequestConstraintsV1::default(),
        privacy: AiRequestPrivacyV1::default(),
        validation: AiRequestValidationV1::default(),
        signatures: Vec::new(),
        metadata: metadata_with_openai_payload(
            request.metadata.clone(),
            json!({
                "compatTask": "responses",
                "instructions": request.instructions,
                "input": request.input,
                "model": request.model,
                "user": request.user,
            }),
        ),
    }
}

pub fn responses_request_to_task_envelope(
    request: &OpenAiResponsesRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> TaskEnvelopeV1 {
    let ai_request = responses_request_to_ai_request(request, request_id, default_requester);
    task_envelope_from_ai_request(&ai_request)
}

pub fn responses_response_from_execution(
    request: &OpenAiResponsesRequestV1,
    response: &ExecutionResponseV1,
    id: impl Into<String>,
    created_at: u64,
) -> OpenAiResponsesResponseV1 {
    let id = id.into();
    let output_text = response_message_content(response);
    let completion_tokens = response
        .metrics
        .output_tokens
        .unwrap_or_else(|| count_tokens(&output_text));
    let prompt_text = responses_input_messages(request)
        .iter()
        .map(message_text)
        .collect::<Vec<_>>()
        .join(" ");
    let prompt_tokens = response
        .metrics
        .input_tokens
        .unwrap_or_else(|| count_tokens(&prompt_text));
    let status = response_status(&response.status).to_string();
    OpenAiResponsesResponseV1 {
        id: id.clone(),
        object: "response".to_string(),
        created_at,
        status: status.clone(),
        model: request.model.clone(),
        output: vec![OpenAiResponseOutputV1 {
            id: format!("msg-{id}"),
            output_type: "message".to_string(),
            status,
            role: "assistant".to_string(),
            content: vec![OpenAiResponseContentV1 {
                content_type: "output_text".to_string(),
                text: output_text.clone(),
            }],
        }],
        output_text,
        usage: OpenAiUsageV1 {
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens + completion_tokens,
        },
        metadata: json!({
            "hivemind": {
                "receiptRef": response.receipt_ref,
                "executionMetadata": response.metadata,
            }
        }),
    }
}

pub fn responses_stream_events_from_execution(
    request: &OpenAiResponsesRequestV1,
    response: &ExecutionResponseV1,
    id: impl Into<String>,
    created_at: u64,
) -> Vec<OpenAiResponsesStreamEventV1> {
    let id = id.into();
    let completed = responses_response_from_execution(request, response, id.clone(), created_at);
    let output_text = completed.output_text.clone();
    let item_id = completed
        .output
        .first()
        .map(|output| output.id.clone())
        .unwrap_or_else(|| format!("msg-{id}"));
    let mut created = completed.clone();
    created.status = "in_progress".to_string();
    created.output_text.clear();
    created.usage = OpenAiUsageV1::default();
    for output in &mut created.output {
        output.status = "in_progress".to_string();
        for content in &mut output.content {
            content.text.clear();
        }
    }

    let mut sequence_number = 0;
    let mut events = vec![OpenAiResponsesStreamEventV1 {
        event_type: "response.created".to_string(),
        sequence_number,
        response: Some(created),
        item_id: None,
        output_index: None,
        content_index: None,
        delta: None,
        text: None,
    }];
    sequence_number += 1;

    if !output_text.is_empty() {
        events.push(OpenAiResponsesStreamEventV1 {
            event_type: "response.output_text.delta".to_string(),
            sequence_number,
            response: None,
            item_id: Some(item_id.clone()),
            output_index: Some(0),
            content_index: Some(0),
            delta: Some(output_text.clone()),
            text: None,
        });
        sequence_number += 1;
    }

    events.push(OpenAiResponsesStreamEventV1 {
        event_type: "response.output_text.done".to_string(),
        sequence_number,
        response: None,
        item_id: Some(item_id),
        output_index: Some(0),
        content_index: Some(0),
        delta: None,
        text: Some(output_text),
    });
    sequence_number += 1;

    events.push(OpenAiResponsesStreamEventV1 {
        event_type: "response.completed".to_string(),
        sequence_number,
        response: Some(completed),
        item_id: None,
        output_index: None,
        content_index: None,
        delta: None,
        text: None,
    });
    events
}

pub fn responses_stream_body_from_execution(
    request: &OpenAiResponsesRequestV1,
    response: &ExecutionResponseV1,
    id: impl Into<String>,
    created_at: u64,
) -> String {
    let mut body = String::new();
    for event in responses_stream_events_from_execution(request, response, id, created_at) {
        body.push_str("event: ");
        body.push_str(&event.event_type);
        body.push('\n');
        body.push_str("data: ");
        body.push_str(
            &serde_json::to_string(&event)
                .expect("responses stream event should serialize to JSON"),
        );
        body.push_str("\n\n");
    }
    body
}

pub fn embedding_requests_to_executions(
    request: &EmbeddingRequestV1,
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    request_id_prefix: impl Into<String>,
) -> Vec<ExecutionRequestV1> {
    let package_ref = package_ref.into();
    let package_id = package_id.into();
    let package_version = package_version.into();
    let request_id_prefix = request_id_prefix.into();
    embedding_inputs(&request.input)
        .into_iter()
        .enumerate()
        .map(|(index, input)| ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: if index == 0 {
                request_id_prefix.clone()
            } else {
                format!("{request_id_prefix}-{index}")
            },
            package_ref: package_ref.clone(),
            package_id: package_id.clone(),
            package_version: package_version.clone(),
            preferred_artifact_group: None,
            task: "embedding".to_string(),
            input,
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        })
        .collect()
}

pub fn embedding_request_to_ai_request(
    request: &EmbeddingRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> AiRequestV1 {
    AiRequestV1 {
        schema_version: "hivemind.request.v1".to_string(),
        request_id: request_id.into(),
        requester: openai_requester(
            &request.metadata,
            request.user.as_deref(),
            default_requester,
        ),
        api_surface: ApiSurface::OpenAiEmbeddings,
        package_selector: ai_package_selector_from_model(&request.model),
        inputs: embedding_inputs(&request.input)
            .into_iter()
            .map(ai_text_part_from_value)
            .collect(),
        messages: None,
        tools: None,
        response_format: request
            .encoding_format
            .as_ref()
            .map(|encoding_format| json!({ "encodingFormat": encoding_format })),
        stream: false,
        sampling: None,
        task: Some("embedding".to_string()),
        constraints: AiRequestConstraintsV1::default(),
        privacy: AiRequestPrivacyV1::default(),
        validation: AiRequestValidationV1::default(),
        signatures: Vec::new(),
        metadata: metadata_with_openai_payload(
            request.metadata.clone(),
            json!({
                "compatTask": "embeddings",
                "model": request.model,
                "user": request.user,
            }),
        ),
    }
}

pub fn embedding_request_to_task_envelope(
    request: &EmbeddingRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> TaskEnvelopeV1 {
    let ai_request = embedding_request_to_ai_request(request, request_id, default_requester);
    task_envelope_from_ai_request(&ai_request)
}

pub fn embedding_response_from_executions(
    request: &EmbeddingRequestV1,
    responses: &[ExecutionResponseV1],
) -> EmbeddingResponseV1 {
    let prompt_tokens = responses
        .iter()
        .map(|response| response.metrics.input_tokens.unwrap_or(0))
        .sum();
    EmbeddingResponseV1 {
        object: "list".to_string(),
        data: responses
            .iter()
            .enumerate()
            .map(|(index, response)| EmbeddingDataV1 {
                object: "embedding".to_string(),
                index: index as u32,
                embedding: response_embedding(response),
            })
            .collect(),
        model: request.model.clone(),
        usage: OpenAiUsageV1 {
            prompt_tokens,
            completion_tokens: 0,
            total_tokens: prompt_tokens,
        },
    }
}

pub fn moderation_requests_to_executions(
    request: &OpenAiModerationRequestV1,
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    request_id_prefix: impl Into<String>,
) -> Vec<ExecutionRequestV1> {
    let package_ref = package_ref.into();
    let package_id = package_id.into();
    let package_version = package_version.into();
    let request_id_prefix = request_id_prefix.into();
    moderation_inputs(&request.input)
        .into_iter()
        .enumerate()
        .map(|(index, input)| {
            let text = moderation_input_text(&input);
            ExecutionRequestV1 {
                schema_version: "swarm-ai.execution.request.v1".to_string(),
                request_id: if index == 0 {
                    request_id_prefix.clone()
                } else {
                    format!("{request_id_prefix}-{index}")
                },
                package_ref: package_ref.clone(),
                package_id: package_id.clone(),
                package_version: package_version.clone(),
                preferred_artifact_group: None,
                task: "classification".to_string(),
                input: json!({
                    "text": text,
                    "input": input,
                    "model": request.model,
                    "user": request.user,
                    "metadata": request.metadata,
                    "compatTask": "moderation",
                }),
                options: ExecutionOptions::default(),
                privacy: ExecutionPrivacy::default(),
                access_grant: None,
                access_revocation_list: None,
            }
        })
        .collect()
}

pub fn moderation_request_to_ai_request(
    request: &OpenAiModerationRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> AiRequestV1 {
    AiRequestV1 {
        schema_version: "hivemind.request.v1".to_string(),
        request_id: request_id.into(),
        requester: openai_requester(
            &request.metadata,
            request.user.as_deref(),
            default_requester,
        ),
        api_surface: ApiSurface::Moderation,
        package_selector: ai_package_selector_from_model(&request.model),
        inputs: moderation_inputs(&request.input)
            .into_iter()
            .map(ai_text_part_from_value)
            .collect(),
        messages: None,
        tools: None,
        response_format: Some(json!({ "type": "moderation" })),
        stream: false,
        sampling: None,
        task: Some("classification".to_string()),
        constraints: AiRequestConstraintsV1::default(),
        privacy: AiRequestPrivacyV1::default(),
        validation: AiRequestValidationV1::default(),
        signatures: Vec::new(),
        metadata: metadata_with_openai_payload(
            request.metadata.clone(),
            json!({
                "compatTask": "moderations",
                "model": request.model,
                "user": request.user,
            }),
        ),
    }
}

pub fn moderation_request_to_task_envelope(
    request: &OpenAiModerationRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> TaskEnvelopeV1 {
    let ai_request = moderation_request_to_ai_request(request, request_id, default_requester);
    task_envelope_from_ai_request(&ai_request)
}

pub fn moderation_response_from_executions(
    request: &OpenAiModerationRequestV1,
    responses: &[ExecutionResponseV1],
    id: impl Into<String>,
) -> OpenAiModerationResponseV1 {
    OpenAiModerationResponseV1 {
        id: id.into(),
        model: request.model.clone(),
        results: responses.iter().map(moderation_result).collect(),
    }
}

pub fn model_from_registry_entry(entry: &RegistryEntryV1) -> OpenAiModelV1 {
    OpenAiModelV1 {
        id: entry.package_id.clone(),
        object: "model".to_string(),
        created: 0,
        owned_by: if entry.publisher.display_name.trim().is_empty() {
            entry.publisher.address.clone()
        } else {
            entry.publisher.display_name.clone()
        },
        metadata: json!({
            "hivemind": {
                "packageId": entry.package_id,
                "name": entry.name,
                "kind": entry.kind,
                "latestVersion": entry.latest_version,
                "stableVersion": entry.stable_version,
                "packageRefs": entry.package_refs,
                "publisher": entry.publisher,
                "capabilities": entry.capabilities,
                "targets": entry.targets,
                "engines": entry.engines,
                "license": entry.license,
                "trust": entry.trust,
                "policySummary": entry.policy_summary,
                "benchmarkScores": entry.benchmark_scores,
                "approxArtifactBytes": entry.approx_artifact_bytes,
            }
        }),
    }
}

pub fn model_list_from_registry_entries<'a>(
    entries: impl IntoIterator<Item = &'a RegistryEntryV1>,
) -> OpenAiModelListV1 {
    let mut data: Vec<_> = entries.into_iter().map(model_from_registry_entry).collect();
    data.sort_by(|left, right| left.id.cmp(&right.id));
    OpenAiModelListV1 {
        object: "list".to_string(),
        data,
    }
}

pub fn openai_file_id_from_create_request(request: &OpenAiFileCreateRequestV1) -> String {
    stable_openai_id("file", request)
}

pub fn openai_file_storage_ref(id: &str, request: &OpenAiFileCreateRequestV1) -> String {
    request
        .storage_ref
        .as_deref()
        .or(request.reference.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("local://openai/files/{id}"))
}

pub fn openai_file_from_create_request(
    request: &OpenAiFileCreateRequestV1,
    id: impl Into<String>,
    created_at: u64,
) -> OpenAiFileV1 {
    let id = id.into();
    let storage_ref = openai_file_storage_ref(&id, request);
    OpenAiFileV1 {
        id: id.clone(),
        object: "file".to_string(),
        bytes: request.bytes.unwrap_or(0),
        created_at,
        filename: request
            .filename
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(&id)
            .to_string(),
        purpose: request
            .purpose
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("assistants")
            .to_string(),
        status: "processed".to_string(),
        metadata: metadata_with_hivemind(
            request.metadata.clone(),
            json!({
                "storageRef": storage_ref,
                "sha256": request.sha256,
                "compatibilityMode": "json-reference",
            }),
        ),
    }
}

pub fn vector_store_manifest_from_openai_request(
    request: &OpenAiVectorStoreCreateRequestV1,
    default_owner: impl Into<String>,
) -> VectorStoreManifestV1 {
    let owner = request
        .owner
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| default_owner.into());
    let mut document_collection_refs = request.document_refs.clone();
    document_collection_refs.extend(
        request
            .file_ids
            .iter()
            .map(|file_id| format!("local://openai/files/{file_id}")),
    );
    if document_collection_refs.is_empty() {
        document_collection_refs.push(format!(
            "local://openai/vector-stores/{}/documents",
            stable_openai_id("vector-docs", &request.name)
        ));
    }

    let mut storage_refs: Vec<_> = request
        .storage_refs
        .iter()
        .map(vector_storage_ref_from_openai)
        .collect();
    storage_refs.extend(request.file_ids.iter().map(|file_id| VectorStorageRefV1 {
        role: VectorStorageRole::Documents,
        reference: format!("local://openai/files/{file_id}"),
        content_type: Some("application/json".to_string()),
        sha256: None,
        size_bytes: None,
    }));
    if storage_refs.is_empty() {
        storage_refs.push(VectorStorageRefV1 {
            role: VectorStorageRole::Documents,
            reference: document_collection_refs[0].clone(),
            content_type: Some("application/json".to_string()),
            sha256: None,
            size_bytes: None,
        });
    }

    create_vector_store_manifest(VectorStoreInitOptionsV1 {
        name: request.name.clone(),
        owner,
        embedding_model_ref: request
            .embedding_model
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("local://embedding/default")
            .to_string(),
        document_collection_refs,
        index_format: Some("hnsw".to_string()),
        dimensions: request.dimensions.unwrap_or(1536),
        metric: request.metric.as_deref().map(openai_vector_metric),
        chunking_strategy_ref: Some(chunking_strategy_ref(&request.chunking_strategy)),
        storage_refs,
        access_policy: Some(hivemind_vector::VectorAccessPolicyV1 {
            privacy_tier: privacy_tier_from_metadata(&request.metadata),
            ..hivemind_vector::VectorAccessPolicyV1::default()
        }),
    })
}

pub fn openai_vector_store_from_manifest(
    manifest: &VectorStoreManifestV1,
    created_at: u64,
    request_metadata: Option<Value>,
) -> OpenAiVectorStoreV1 {
    let verification = verify_vector_store_manifest(manifest);
    let total = manifest.document_collection_refs.len() as u64;
    OpenAiVectorStoreV1 {
        id: manifest.vector_store_id.clone(),
        object: "vector_store".to_string(),
        created_at,
        name: manifest.name.clone(),
        status: if verification.valid {
            "completed".to_string()
        } else {
            "failed".to_string()
        },
        file_counts: OpenAiVectorStoreFileCountsV1 {
            in_progress: 0,
            completed: if verification.valid { total } else { 0 },
            failed: if verification.valid { 0 } else { total },
            cancelled: 0,
            total,
        },
        metadata: metadata_with_hivemind(
            request_metadata,
            json!({
                "manifest": manifest,
                "verification": verification,
                "compatibilityMode": "manifest-backed",
            }),
        ),
    }
}

pub fn vector_search_request_from_openai(
    manifest: &VectorStoreManifestV1,
    request: &OpenAiVectorStoreSearchRequestV1,
    requester: impl Into<String>,
) -> VectorSearchRequestV1 {
    let mut search_request = hivemind_vector::vector_search_request(
        format!("local://openai/vector-stores/{}", manifest.vector_store_id),
        manifest.vector_store_id.clone(),
        requester,
        normalized_search_query(&request.query),
    );
    search_request.top_k = request.max_num_results.unwrap_or(5).clamp(1, 100);
    search_request.filters = request.filters.clone().unwrap_or_else(|| json!({}));
    search_request.privacy_tier = manifest.access_policy.privacy_tier.clone();
    search_request
}

pub fn openai_vector_search_response_from_plan(
    request: &OpenAiVectorStoreSearchRequestV1,
    plan: &VectorSearchPlanV1,
) -> OpenAiVectorStoreSearchResponseV1 {
    let refs: Vec<_> = plan
        .immutable_refs
        .iter()
        .chain(plan.mutable_refs.iter())
        .take(plan.top_k as usize)
        .cloned()
        .collect();
    let data = refs
        .iter()
        .enumerate()
        .map(|(index, reference)| OpenAiVectorStoreSearchResultV1 {
            file_id: stable_openai_id("file", reference),
            filename: reference
                .rsplit(['/', ':'])
                .next()
                .filter(|value| !value.is_empty())
                .unwrap_or(reference)
                .to_string(),
            score: 1.0_f64 - (index as f64 * 0.01),
            text: format!("Planned retrieval reference: {reference}"),
            metadata: json!({
                "hivemind": {
                    "reference": reference,
                    "searchMode": "plan-only",
                }
            }),
        })
        .collect();

    OpenAiVectorStoreSearchResponseV1 {
        object: "vector_store.search_results".to_string(),
        search_query: normalized_search_query(&request.query),
        data,
        metadata: metadata_with_hivemind(
            request.metadata.clone(),
            json!({
                "plan": plan,
                "searchMode": "plan-only",
                "compatibilityMode": "vector-search-planning",
            }),
        ),
    }
}

pub fn batch_job_from_openai_request(
    request: &OpenAiBatchCreateRequestV1,
    default_requester: impl Into<String>,
) -> BatchJobV1 {
    let task = request
        .task
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| batch_task_from_endpoint(&request.endpoint));
    let package_ref = request
        .package_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            request
                .model
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|model| format!("local://openai/models/{model}"))
        })
        .unwrap_or_else(|| format!("local://openai/batches/{}/package", request.input_file_id));
    let package_id = request
        .package_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| request.model.clone())
        .unwrap_or_else(|| format!("openai{}", request.endpoint.replace('/', ".")));

    create_batch_job(BatchJobInitOptionsV1 {
        requester: request
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata
                    .get("requester")
                    .or_else(|| metadata.get("user"))
                    .and_then(Value::as_str)
            })
            .map(str::to_string)
            .unwrap_or_else(|| default_requester.into()),
        package_ref,
        package_id,
        package_version: request
            .package_version
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("0.1.0")
            .to_string(),
        task,
        api_surface: Some(ApiSurface::OpenAiBatches),
        items: vec![json!({
            "inputFileId": request.input_file_id,
            "inputRef": format!("local://openai/files/{}", request.input_file_id),
            "endpoint": request.endpoint,
            "completionWindow": request.completion_window,
            "metadata": request.metadata,
        })],
        max_concurrency: request.max_concurrency.unwrap_or(4).max(1),
        checkpoint_every_items: Some(1),
        partial_result_policy: Some(BatchPartialResultPolicy::OnItemCompletion),
        settlement_method: Some(
            request
                .metadata
                .as_ref()
                .and_then(|metadata| {
                    metadata
                        .get("settlement_method")
                        .or_else(|| metadata.get("settlementMethod"))
                        .and_then(Value::as_str)
                })
                .unwrap_or("free-local-dev")
                .to_string(),
        ),
        privacy_tier: Some(openai_privacy_tier(
            request.privacy_tier.as_deref(),
            &request.metadata,
        )),
        integrity_tier: Some(openai_integrity_tier(
            request.integrity_tier.as_deref(),
            &request.metadata,
        )),
    })
}

pub fn openai_batch_from_job(job: &BatchJobV1, created_at: u64) -> OpenAiBatchV1 {
    let verification = verify_batch_job(job);
    let plan = batch_execution_plan(job);
    let first_input = job
        .items
        .first()
        .map(|item| &item.input)
        .unwrap_or(&Value::Null);
    let input_file_id = first_input
        .get("inputFileId")
        .and_then(Value::as_str)
        .unwrap_or("file-unknown")
        .to_string();
    let endpoint = first_input
        .get("endpoint")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| endpoint_from_batch_task(&job.job_template.task));
    let completion_window = first_input
        .get("completionWindow")
        .and_then(Value::as_str)
        .unwrap_or("24h")
        .to_string();
    let total = plan.item_count as u64;
    let valid = verification.valid && plan.valid;

    OpenAiBatchV1 {
        id: job.batch_id.clone(),
        object: "batch".to_string(),
        endpoint,
        errors: (!valid).then(|| {
            json!({
                "object": "list",
                "data": plan.issues,
            })
        }),
        input_file_id,
        completion_window,
        status: if valid {
            "validating".to_string()
        } else {
            "failed".to_string()
        },
        output_file_id: None,
        error_file_id: None,
        created_at,
        in_progress_at: None,
        expires_at: None,
        finalizing_at: None,
        completed_at: None,
        failed_at: (!valid).then_some(created_at),
        expired_at: None,
        cancelling_at: None,
        cancelled_at: None,
        request_counts: OpenAiBatchRequestCountsV1 {
            total,
            completed: 0,
            failed: 0,
        },
        metadata: metadata_with_hivemind(
            first_input.get("metadata").cloned(),
            json!({
                "job": job,
                "verification": verification,
                "plan": plan,
                "compatibilityMode": "contract-only",
            }),
        ),
    }
}

pub fn fine_tune_job_from_openai_request(
    request: &OpenAiFineTuningCreateRequestV1,
    default_requester: impl Into<String>,
) -> FineTuneJobV1 {
    create_fine_tune_job(FineTuneJobInitOptionsV1 {
        requester: requester_from_metadata(&request.metadata)
            .unwrap_or_else(|| default_requester.into()),
        base_model_ref: model_ref_from_openai_model(&request.model),
        training_dataset_refs: vec![file_ref_from_openai_file_id(&request.training_file)],
        validation_dataset_refs: request
            .validation_file
            .as_deref()
            .map(file_ref_from_openai_file_id)
            .into_iter()
            .collect(),
        recipe_ref: request
            .recipe_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        hyperparameters: Some(openai_fine_tune_hyperparameters(request)),
        output_ref: request
            .output_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        artifact_kind: request
            .artifact_kind
            .as_deref()
            .and_then(fine_tune_artifact_kind_from_str),
        output_visibility: request
            .output_visibility
            .as_deref()
            .and_then(fine_tune_output_visibility_from_str),
        privacy_tier: Some(openai_privacy_tier(
            request.privacy_tier.as_deref(),
            &request.metadata,
        )),
        integrity_tier: Some(openai_integrity_tier(
            request.integrity_tier.as_deref(),
            &request.metadata,
        )),
        max_cost: request.max_cost.clone(),
        validation_required: request
            .validation_required
            .or_else(|| bool_from_metadata(&request.metadata, "validation_required"))
            .or_else(|| bool_from_metadata(&request.metadata, "validationRequired")),
    })
}

pub fn openai_fine_tuning_job_from_job(
    job: &FineTuneJobV1,
    created_at: u64,
) -> OpenAiFineTuningJobV1 {
    let verification = verify_fine_tune_job(job);
    let plan = fine_tune_execution_plan(job);
    let valid = verification.valid && plan.valid;
    let sidecar = job.hyperparameters.get("_openai").cloned();
    let model = sidecar
        .as_ref()
        .and_then(|value| value.get("model"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| openai_model_from_ref(&job.base_model_ref));
    let training_file = sidecar
        .as_ref()
        .and_then(|value| value.get("trainingFile"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            job.training_dataset_refs
                .first()
                .map(|reference| openai_file_id_from_ref(reference))
                .unwrap_or_else(|| "file-unknown".to_string())
        });
    let validation_file = sidecar
        .as_ref()
        .and_then(|value| value.get("validationFile"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            job.validation_dataset_refs
                .first()
                .map(|reference| openai_file_id_from_ref(reference))
        });
    let integrations = sidecar
        .as_ref()
        .and_then(|value| value.get("integrations"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let seed = sidecar
        .as_ref()
        .and_then(|value| value.get("seed"))
        .and_then(Value::as_u64);
    let method = sidecar
        .as_ref()
        .and_then(|value| value.get("method"))
        .cloned();
    let metadata = sidecar
        .as_ref()
        .and_then(|value| value.get("metadata"))
        .cloned();
    let organization_id = metadata
        .as_ref()
        .and_then(|metadata| {
            metadata
                .get("organization_id")
                .or_else(|| metadata.get("organizationId"))
                .or_else(|| metadata.get("organization"))
                .or_else(|| metadata.get("org"))
        })
        .and_then(Value::as_str)
        .map(str::to_string);

    OpenAiFineTuningJobV1 {
        id: job.fine_tune_job_id.clone(),
        object: "fine_tuning.job".to_string(),
        created_at,
        finished_at: None,
        model,
        fine_tuned_model: None,
        organization_id,
        result_files: Vec::new(),
        status: if valid {
            "validating".to_string()
        } else {
            "failed".to_string()
        },
        validation_file,
        training_file,
        hyperparameters: public_openai_fine_tune_hyperparameters(&job.hyperparameters),
        trained_tokens: None,
        error: (!valid).then(|| {
            json!({
                "code": "fine_tune_job_invalid",
                "message": validation_issue_messages(&plan.issues),
                "param": null,
            })
        }),
        integrations,
        seed,
        method,
        metadata: metadata_with_hivemind(
            metadata,
            json!({
                "job": job,
                "verification": verification,
                "plan": plan,
                "compatibilityMode": "contract-only",
            }),
        ),
    }
}

pub fn realtime_session_record_from_openai_request(
    request: &OpenAiRealtimeSessionCreateRequestV1,
    default_requester: impl Into<String>,
) -> OpenAiRealtimeSessionRecordV1 {
    OpenAiRealtimeSessionRecordV1 {
        schema_version: "swarm-ai.openai-realtime-session-record.v1".to_string(),
        request: request.clone(),
        session: realtime_session_from_openai_request(request, default_requester),
    }
}

pub fn realtime_session_from_openai_request(
    request: &OpenAiRealtimeSessionCreateRequestV1,
    default_requester: impl Into<String>,
) -> RealtimeSessionV1 {
    let model = request
        .model
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let package_ref = request
        .package_ref
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            model
                .filter(|value| looks_like_storage_ref(value))
                .map(ToOwned::to_owned)
        });
    let package_id = request
        .package_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            model
                .filter(|value| !looks_like_storage_ref(value))
                .map(ToOwned::to_owned)
        });
    let model_alias = model
        .filter(|value| !looks_like_storage_ref(value))
        .map(ToOwned::to_owned)
        .or_else(|| {
            (package_ref.is_none() && package_id.is_none() && request.service_ref.is_none())
                .then(|| "hivemind/realtime".to_string())
        });

    create_realtime_session(RealtimeSessionInitOptionsV1 {
        requester: requester_from_metadata(&request.metadata)
            .unwrap_or_else(|| default_requester.into()),
        package_ref,
        package_id,
        package_version: request
            .package_version
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        service_ref: request
            .service_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned),
        model_alias,
        modalities_in: openai_realtime_modalities(
            &request.modalities_in,
            &request.modalities,
            &[Modality::Audio, Modality::Text],
        ),
        modalities_out: openai_realtime_modalities(
            &request.modalities_out,
            &request.modalities,
            &[Modality::Audio, Modality::Text],
        ),
        transport: request
            .transport
            .as_deref()
            .and_then(realtime_transport_from_str),
        latency_target_ms: request.latency_target_ms,
        interruptions_allowed: request.interruptions_allowed,
        tool_refs: request.tools.iter().map(openai_realtime_tool_ref).collect(),
        privacy_tier: Some(openai_privacy_tier(
            request.privacy_tier.as_deref(),
            &request.metadata,
        )),
        settlement_method: request
            .settlement_method
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| {
                request
                    .metadata
                    .as_ref()
                    .and_then(|metadata| {
                        metadata
                            .get("settlement_method")
                            .or_else(|| metadata.get("settlementMethod"))
                    })
                    .and_then(Value::as_str)
                    .map(str::to_string)
            }),
    })
}

pub fn openai_realtime_session_from_record(
    record: &OpenAiRealtimeSessionRecordV1,
    created_at: u64,
) -> OpenAiRealtimeSessionV1 {
    let verification = verify_realtime_session(&record.session);
    let plan = realtime_connection_plan(&record.session);
    openai_realtime_session_from_parts(
        &record.request,
        &record.session,
        &plan,
        created_at,
        verification.valid && plan.valid,
    )
}

pub fn openai_realtime_session_from_parts(
    request: &OpenAiRealtimeSessionCreateRequestV1,
    session: &RealtimeSessionV1,
    plan: &RealtimeConnectionPlanV1,
    created_at: u64,
    valid: bool,
) -> OpenAiRealtimeSessionV1 {
    let model = request
        .model
        .clone()
        .or_else(|| session.package_selector.model_alias.clone())
        .or_else(|| session.package_selector.package_id.clone())
        .or_else(|| session.package_selector.package_ref.clone())
        .or_else(|| session.package_selector.service_ref.clone())
        .unwrap_or_else(|| "hivemind/realtime".to_string());
    let modalities = if request.modalities.is_empty() {
        session
            .modalities_out
            .iter()
            .map(openai_modality_name)
            .collect()
    } else {
        request.modalities.clone()
    };
    let expires_at = created_at + 3_600;

    OpenAiRealtimeSessionV1 {
        id: session.session_id.clone(),
        object: "realtime.session".to_string(),
        model,
        modalities,
        instructions: request.instructions.clone(),
        voice: request.voice.clone(),
        input_audio_format: request.input_audio_format.clone(),
        output_audio_format: request.output_audio_format.clone(),
        input_audio_transcription: request.input_audio_transcription.clone(),
        turn_detection: request.turn_detection.clone(),
        tools: request.tools.clone(),
        tool_choice: request.tool_choice.clone(),
        temperature: request.temperature,
        max_response_output_tokens: request.max_response_output_tokens.clone(),
        status: if valid {
            "created".to_string()
        } else {
            "failed".to_string()
        },
        client_secret: valid.then(|| OpenAiRealtimeClientSecretV1 {
            value: format!("rt-local-secret-{}", session.session_id),
            expires_at,
        }),
        expires_at: Some(expires_at),
        metadata: metadata_with_hivemind(
            request.metadata.clone(),
            json!({
                "session": session,
                "verification": verify_realtime_session(session),
                "plan": plan,
                "compatibilityMode": "contract-only",
                "transportMode": "plan-only",
            }),
        ),
    }
}

pub fn eval_manifest_record_from_openai_request(
    request: &OpenAiEvalCreateRequestV1,
    default_owner: impl Into<String>,
) -> OpenAiEvalRecordV1 {
    let owner = request
        .owner
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| requester_from_metadata(&request.metadata))
        .unwrap_or_else(|| default_owner.into());
    let mut dataset_refs = request
        .dataset_refs
        .iter()
        .map(|reference| eval_ref_from_openai_ref(reference))
        .collect::<Vec<_>>();
    dataset_refs.extend(data_source_refs_from_openai(
        &request.data_source,
        &request.name,
    ));
    dedup_strings(&mut dataset_refs);
    let mut scoring_rule_refs = request
        .scoring_rule_refs
        .iter()
        .map(|reference| eval_ref_from_openai_ref(reference))
        .collect::<Vec<_>>();
    scoring_rule_refs.extend(testing_criteria_refs_from_openai(
        &request.testing_criteria,
        &request.name,
    ));
    dedup_strings(&mut scoring_rule_refs);
    let mut target_refs = request
        .target_refs
        .iter()
        .map(|reference| eval_ref_from_openai_ref(reference))
        .collect::<Vec<_>>();
    if let Some(model) = trim_optional_string(&request.model) {
        target_refs.push(model_ref_from_openai_model(&model));
    }
    dedup_strings(&mut target_refs);
    let grader_model_ref = request
        .grader_model
        .as_deref()
        .and_then(trim_str)
        .map(model_ref_from_openai_model)
        .or_else(|| grader_model_ref_from_testing_criteria(&request.testing_criteria));

    let manifest = create_eval_manifest(EvalManifestInitOptionsV1 {
        name: request.name.clone(),
        owner,
        kind: Some(eval_kind_from_openai(request)),
        dataset_refs,
        scoring_rule_refs,
        target_refs,
        grader_model_ref,
        output_schema_ref: trim_optional_string(&request.output_schema_ref),
        metadata: Some(metadata_with_openai_payload(
            request.metadata.clone(),
            json!({
                "dataSource": request.data_source,
                "testingCriteria": request.testing_criteria,
                "model": request.model,
            }),
        )),
    });

    OpenAiEvalRecordV1 {
        schema_version: "swarm-ai.openai-eval-record.v1".to_string(),
        request: request.clone(),
        manifest,
    }
}

pub fn openai_eval_from_record(record: &OpenAiEvalRecordV1, created_at: u64) -> OpenAiEvalV1 {
    let verification = verify_eval_manifest(&record.manifest);
    OpenAiEvalV1 {
        id: record.manifest.eval_id.clone(),
        object: "eval".to_string(),
        name: record.manifest.name.clone(),
        created_at,
        metadata: metadata_with_hivemind(
            record.request.metadata.clone(),
            json!({
                "manifest": record.manifest,
                "verification": verification,
                "compatibilityMode": "manifest-backed",
            }),
        ),
    }
}

pub fn eval_run_record_from_openai_request(
    eval_id: impl Into<String>,
    request: &OpenAiEvalRunCreateRequestV1,
    default_requester: impl Into<String>,
) -> OpenAiEvalRunRecordV1 {
    let eval_id = eval_id.into();
    let requester =
        requester_from_metadata(&request.metadata).unwrap_or_else(|| default_requester.into());
    let target_ref = request
        .target_ref
        .as_deref()
        .and_then(trim_str)
        .map(eval_ref_from_openai_ref)
        .or_else(|| {
            request
                .model
                .as_deref()
                .and_then(trim_str)
                .map(model_ref_from_openai_model)
        })
        .unwrap_or_else(|| format!("local://openai/evals/{eval_id}/target"));
    let mut input_refs = request
        .input_refs
        .iter()
        .map(|reference| eval_ref_from_openai_ref(reference))
        .collect::<Vec<_>>();
    input_refs.extend(data_source_refs_from_openai(&request.data_source, &eval_id));
    if input_refs.is_empty() {
        input_refs.push(format!("local://openai/evals/{eval_id}/inputs"));
    }
    dedup_strings(&mut input_refs);
    let sample_count = request
        .sample_count
        .or_else(|| Some(input_refs.len().max(1) as u32));

    let run = create_eval_run(EvalRunInitOptionsV1 {
        eval_id: eval_id.clone(),
        requester,
        target_ref,
        input_refs,
        sample_count,
        privacy_tier: Some(openai_privacy_tier(
            request.privacy_tier.as_deref(),
            &request.metadata,
        )),
        integrity_tier: Some(openai_integrity_tier(
            request.integrity_tier.as_deref(),
            &request.metadata,
        )),
        settlement_method: request
            .settlement_method
            .clone()
            .or_else(|| settlement_method_from_metadata(&request.metadata)),
        report_ref: request
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata
                    .get("report_ref")
                    .or_else(|| metadata.get("reportRef"))
            })
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string),
        metadata: Some(metadata_with_openai_payload(
            request.metadata.clone(),
            json!({
                "name": request.name,
                "model": request.model,
                "dataSource": request.data_source,
            }),
        )),
    });

    OpenAiEvalRunRecordV1 {
        schema_version: "swarm-ai.openai-eval-run-record.v1".to_string(),
        eval_id,
        request: request.clone(),
        run,
    }
}

pub fn openai_eval_run_from_record(
    record: &OpenAiEvalRunRecordV1,
    manifest: Option<&EvalManifestV1>,
    created_at: u64,
) -> OpenAiEvalRunV1 {
    let verification = verify_eval_run(&record.run);
    let plan = manifest.map(|manifest| eval_run_plan(manifest, &record.run));
    let valid = verification.valid && plan.as_ref().map(|plan| plan.valid).unwrap_or(true);
    OpenAiEvalRunV1 {
        id: record.run.eval_run_id.clone(),
        object: "eval.run".to_string(),
        eval_id: record.eval_id.clone(),
        status: if valid {
            "queued".to_string()
        } else {
            "failed".to_string()
        },
        created_at,
        metadata: openai_eval_run_metadata(
            record.request.metadata.clone(),
            &record.run,
            &verification,
            plan.as_ref(),
        ),
    }
}

pub fn media_job_from_openai_image_generation(
    request: &OpenAiImageGenerationRequestV1,
    default_requester: impl Into<String>,
) -> MediaJobV1 {
    create_media_job(MediaJobInitOptionsV1 {
        requester: requester_from_metadata(&request.metadata)
            .or_else(|| request.user.clone())
            .unwrap_or_else(|| default_requester.into()),
        task: MediaTask::ImageGeneration,
        package_ref: package_ref_from_compat_selector(
            &request.package_ref,
            request.model.as_deref(),
        ),
        package_id: package_id_from_compat_selector(&request.package_id, request.model.as_deref()),
        package_version: trim_optional_string(&request.package_version),
        service_ref: trim_optional_string(&request.service_ref),
        model_alias: model_alias_from_compat_selector(
            request.model.as_deref(),
            "hivemind/image-generation",
        ),
        prompt: Some(request.prompt.clone()),
        text: None,
        input_ref: None,
        mask_ref: None,
        parameters: Some(json!({
            "model": request.model,
            "background": request.background,
            "outputFormat": request.output_format,
            "metadata": request.metadata,
        })),
        response_format: Some(
            request
                .response_format
                .clone()
                .unwrap_or_else(|| "url".to_string()),
        ),
        output_ref: trim_optional_string(&request.output_ref),
        count: Some(request.n.unwrap_or(1).clamp(1, 16)),
        size: request.size.clone(),
        quality: request.quality.clone(),
        style: request.style.clone(),
        voice: None,
        audio_format: None,
        privacy_tier: Some(openai_privacy_tier(
            request.privacy_tier.as_deref(),
            &request.metadata,
        )),
        integrity_tier: Some(openai_integrity_tier(None, &request.metadata)),
        settlement_method: settlement_method_from_metadata(&request.metadata),
    })
}

pub fn openai_image_generation_from_media_job(
    request: &OpenAiImageGenerationRequestV1,
    job: &MediaJobV1,
    created_at: u64,
) -> OpenAiImageGenerationResponseV1 {
    let plan = media_execution_plan(job);
    let response_format = request
        .response_format
        .as_deref()
        .unwrap_or(&job.output_policy.response_format);
    let data = (0..job.output_policy.count)
        .map(|index| {
            let output_ref = job.output_policy.output_ref.clone().unwrap_or_else(|| {
                format!("local://openai/images/{}/outputs/{index}", job.media_job_id)
            });
            if normalize_wire_name(response_format) == "b64_json" {
                OpenAiImageDataV1 {
                    url: None,
                    b64_json: Some("cGxhbi1vbmx5".to_string()),
                    revised_prompt: Some(request.prompt.clone()),
                }
            } else {
                OpenAiImageDataV1 {
                    url: Some(if job.output_policy.count == 1 {
                        output_ref
                    } else {
                        format!("{output_ref}/{index}")
                    }),
                    b64_json: None,
                    revised_prompt: Some(request.prompt.clone()),
                }
            }
        })
        .collect();

    OpenAiImageGenerationResponseV1 {
        created: created_at,
        data,
        metadata: openai_media_metadata(request.metadata.clone(), job, &plan),
    }
}

pub fn media_job_from_openai_image_edit(
    request: &OpenAiImageEditRequestV1,
    default_requester: impl Into<String>,
) -> MediaJobV1 {
    let input_ref = request
        .image_ref
        .as_deref()
        .and_then(trim_str)
        .or_else(|| trim_str(&request.image))
        .map(file_ref_from_openai_file_id);
    let mask_ref = request
        .mask_ref
        .as_deref()
        .and_then(trim_str)
        .or_else(|| request.mask.as_deref().and_then(trim_str))
        .map(file_ref_from_openai_file_id);
    create_media_job(MediaJobInitOptionsV1 {
        requester: requester_from_metadata(&request.metadata)
            .or_else(|| request.user.clone())
            .unwrap_or_else(|| default_requester.into()),
        task: MediaTask::ImageEdit,
        package_ref: package_ref_from_compat_selector(
            &request.package_ref,
            request.model.as_deref(),
        ),
        package_id: package_id_from_compat_selector(&request.package_id, request.model.as_deref()),
        package_version: trim_optional_string(&request.package_version),
        service_ref: trim_optional_string(&request.service_ref),
        model_alias: model_alias_from_compat_selector(
            request.model.as_deref(),
            "hivemind/image-edit",
        ),
        prompt: Some(request.prompt.clone()),
        text: None,
        input_ref,
        mask_ref,
        parameters: Some(json!({
            "model": request.model,
            "outputFormat": request.output_format,
            "metadata": request.metadata,
        })),
        response_format: Some(
            request
                .response_format
                .clone()
                .unwrap_or_else(|| "url".to_string()),
        ),
        output_ref: trim_optional_string(&request.output_ref),
        count: Some(request.n.unwrap_or(1).clamp(1, 16)),
        size: request.size.clone(),
        quality: None,
        style: None,
        voice: None,
        audio_format: None,
        privacy_tier: Some(openai_privacy_tier(
            request.privacy_tier.as_deref(),
            &request.metadata,
        )),
        integrity_tier: Some(openai_integrity_tier(None, &request.metadata)),
        settlement_method: settlement_method_from_metadata(&request.metadata),
    })
}

pub fn openai_image_edit_from_media_job(
    request: &OpenAiImageEditRequestV1,
    job: &MediaJobV1,
    created_at: u64,
) -> OpenAiImageGenerationResponseV1 {
    let plan = media_execution_plan(job);
    let response_format = request
        .response_format
        .as_deref()
        .unwrap_or(&job.output_policy.response_format);
    let data = (0..job.output_policy.count)
        .map(|index| {
            let output_ref = job.output_policy.output_ref.clone().unwrap_or_else(|| {
                format!(
                    "local://openai/images/edits/{}/outputs/{index}",
                    job.media_job_id
                )
            });
            if normalize_wire_name(response_format) == "b64_json" {
                OpenAiImageDataV1 {
                    url: None,
                    b64_json: Some("cGxhbi1vbmx5".to_string()),
                    revised_prompt: Some(request.prompt.clone()),
                }
            } else {
                OpenAiImageDataV1 {
                    url: Some(if job.output_policy.count == 1 {
                        output_ref
                    } else {
                        format!("{output_ref}/{index}")
                    }),
                    b64_json: None,
                    revised_prompt: Some(request.prompt.clone()),
                }
            }
        })
        .collect();

    OpenAiImageGenerationResponseV1 {
        created: created_at,
        data,
        metadata: openai_media_metadata(request.metadata.clone(), job, &plan),
    }
}

pub fn media_job_from_openai_audio_transcription(
    request: &OpenAiAudioTranscriptionRequestV1,
    default_requester: impl Into<String>,
) -> MediaJobV1 {
    let input_ref = request
        .file_ref
        .as_deref()
        .or(request.file.as_deref())
        .map(file_ref_from_openai_file_id);
    create_media_job(MediaJobInitOptionsV1 {
        requester: requester_from_metadata(&request.metadata)
            .unwrap_or_else(|| default_requester.into()),
        task: MediaTask::AudioTranscription,
        package_ref: package_ref_from_compat_selector(&request.package_ref, Some(&request.model)),
        package_id: package_id_from_compat_selector(&request.package_id, Some(&request.model)),
        package_version: trim_optional_string(&request.package_version),
        service_ref: trim_optional_string(&request.service_ref),
        model_alias: model_alias_from_compat_selector(
            Some(&request.model),
            "hivemind/audio-transcription",
        ),
        prompt: request.prompt.clone(),
        text: None,
        input_ref,
        mask_ref: None,
        parameters: Some(json!({
            "language": request.language,
            "temperature": request.temperature,
            "timestampGranularities": request.timestamp_granularities,
            "metadata": request.metadata,
        })),
        response_format: Some(
            request
                .response_format
                .clone()
                .unwrap_or_else(|| "json".to_string()),
        ),
        output_ref: None,
        count: Some(1),
        size: None,
        quality: None,
        style: None,
        voice: None,
        audio_format: None,
        privacy_tier: Some(openai_privacy_tier(
            request.privacy_tier.as_deref(),
            &request.metadata,
        )),
        integrity_tier: Some(openai_integrity_tier(None, &request.metadata)),
        settlement_method: settlement_method_from_metadata(&request.metadata),
    })
}

pub fn openai_audio_transcription_from_media_job(
    request: &OpenAiAudioTranscriptionRequestV1,
    job: &MediaJobV1,
) -> OpenAiAudioTranscriptionResponseV1 {
    let plan = media_execution_plan(job);
    let input_ref = job
        .input
        .input_ref
        .as_deref()
        .unwrap_or("local://openai/audio/unknown");

    OpenAiAudioTranscriptionResponseV1 {
        text: format!("Planned transcription for {input_ref}"),
        metadata: openai_media_metadata(request.metadata.clone(), job, &plan),
    }
}

pub fn media_job_from_openai_audio_speech(
    request: &OpenAiAudioSpeechRequestV1,
    default_requester: impl Into<String>,
) -> MediaJobV1 {
    create_media_job(MediaJobInitOptionsV1 {
        requester: requester_from_metadata(&request.metadata)
            .unwrap_or_else(|| default_requester.into()),
        task: MediaTask::TextToSpeech,
        package_ref: package_ref_from_compat_selector(&request.package_ref, Some(&request.model)),
        package_id: package_id_from_compat_selector(&request.package_id, Some(&request.model)),
        package_version: trim_optional_string(&request.package_version),
        service_ref: trim_optional_string(&request.service_ref),
        model_alias: model_alias_from_compat_selector(
            Some(&request.model),
            "hivemind/text-to-speech",
        ),
        prompt: None,
        text: Some(request.input.clone()),
        input_ref: None,
        mask_ref: None,
        parameters: Some(json!({
            "speed": request.speed,
            "metadata": request.metadata,
        })),
        response_format: Some(
            request
                .response_format
                .clone()
                .unwrap_or_else(|| "mp3".to_string()),
        ),
        output_ref: trim_optional_string(&request.output_ref),
        count: Some(1),
        size: None,
        quality: None,
        style: None,
        voice: Some(request.voice.clone()),
        audio_format: request.response_format.clone(),
        privacy_tier: Some(openai_privacy_tier(
            request.privacy_tier.as_deref(),
            &request.metadata,
        )),
        integrity_tier: Some(openai_integrity_tier(None, &request.metadata)),
        settlement_method: settlement_method_from_metadata(&request.metadata),
    })
}

pub fn openai_audio_speech_from_media_job(
    request: &OpenAiAudioSpeechRequestV1,
    job: &MediaJobV1,
) -> OpenAiAudioSpeechResponseV1 {
    let plan = media_execution_plan(job);
    OpenAiAudioSpeechResponseV1 {
        object: "audio.speech".to_string(),
        audio_ref: job
            .output_policy
            .output_ref
            .clone()
            .unwrap_or_else(|| format!("local://openai/audio/speech/{}", job.media_job_id)),
        format: request
            .response_format
            .clone()
            .unwrap_or_else(|| "mp3".to_string()),
        voice: request.voice.clone(),
        metadata: openai_media_metadata(request.metadata.clone(), job, &plan),
    }
}

pub fn error_response(
    code: impl Into<String>,
    message: impl Into<String>,
) -> OpenAiErrorResponseV1 {
    OpenAiErrorResponseV1 {
        error: OpenAiErrorDetailV1 {
            message: message.into(),
            error_type: "hivemind_compat_error".to_string(),
            param: None,
            code: code.into(),
        },
    }
}

fn stable_openai_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("OpenAI compatibility value should serialize");
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

fn metadata_with_hivemind(metadata: Option<Value>, hivemind: Value) -> Value {
    let mut metadata = metadata.unwrap_or_else(|| json!({}));
    if !metadata.is_object() {
        metadata = json!({ "value": metadata });
    }
    metadata["hivemind"] = hivemind;
    metadata
}

fn metadata_with_openai_payload(metadata: Option<Value>, openai: Value) -> Value {
    let mut metadata = metadata.unwrap_or_else(|| json!({}));
    if !metadata.is_object() {
        metadata = json!({ "value": metadata });
    }
    metadata["openai"] = openai;
    metadata
}

fn ai_package_selector_from_model(model: &str) -> AiPackageSelectorV1 {
    let model = model.trim().to_string();
    if looks_like_storage_ref(&model) {
        AiPackageSelectorV1 {
            package_ref: Some(model),
            ..AiPackageSelectorV1::default()
        }
    } else {
        AiPackageSelectorV1 {
            model: Some(model),
            ..AiPackageSelectorV1::default()
        }
    }
}

fn openai_requester(
    metadata: &Option<Value>,
    user: Option<&str>,
    default_requester: impl Into<String>,
) -> String {
    requester_from_metadata(metadata)
        .or_else(|| {
            user.map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| default_requester.into())
}

fn ai_sampling_options(
    temperature: Option<f64>,
    top_p: Option<f64>,
    max_output_tokens: Option<u64>,
) -> Option<AiSamplingOptionsV1> {
    if temperature.is_none() && top_p.is_none() && max_output_tokens.is_none() {
        return None;
    }
    Some(AiSamplingOptionsV1 {
        temperature,
        top_p,
        max_output_tokens,
        seed: None,
        stop: Vec::new(),
    })
}

fn ai_text_part_from_value(value: Value) -> AiInputPartV1 {
    AiInputPartV1 {
        part_type: AiInputPartType::Text,
        content: value,
        content_ref: None,
        mime_type: Some("text/plain".to_string()),
        hash: None,
        metadata: json!({}),
    }
}

fn ai_text_parts_from_text(text: String) -> Vec<AiInputPartV1> {
    if text.trim().is_empty() {
        Vec::new()
    } else {
        vec![AiInputPartV1::text(text)]
    }
}

fn requester_from_metadata(metadata: &Option<Value>) -> Option<String> {
    metadata
        .as_ref()
        .and_then(|metadata| {
            metadata
                .get("requester")
                .or_else(|| metadata.get("user"))
                .or_else(|| metadata.get("owner"))
        })
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn bool_from_metadata(metadata: &Option<Value>, key: &str) -> Option<bool> {
    metadata
        .as_ref()
        .and_then(|metadata| metadata.get(key))
        .and_then(Value::as_bool)
}

fn trim_optional_string(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn trim_str(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() { None } else { Some(value) }
}

fn package_ref_from_compat_selector(
    explicit: &Option<String>,
    model: Option<&str>,
) -> Option<String> {
    trim_optional_string(explicit).or_else(|| {
        model
            .map(str::trim)
            .filter(|value| looks_like_storage_ref(value))
            .map(str::to_string)
    })
}

fn package_id_from_compat_selector(
    explicit: &Option<String>,
    model: Option<&str>,
) -> Option<String> {
    trim_optional_string(explicit).or_else(|| {
        model
            .map(str::trim)
            .filter(|value| !value.is_empty() && !looks_like_storage_ref(value))
            .map(str::to_string)
    })
}

fn model_alias_from_compat_selector(model: Option<&str>, fallback: &str) -> Option<String> {
    model
        .map(str::trim)
        .filter(|value| !value.is_empty() && !looks_like_storage_ref(value))
        .map(str::to_string)
        .or_else(|| Some(fallback.to_string()))
}

fn settlement_method_from_metadata(metadata: &Option<Value>) -> Option<String> {
    metadata
        .as_ref()
        .and_then(|metadata| {
            metadata
                .get("settlement_method")
                .or_else(|| metadata.get("settlementMethod"))
        })
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn openai_media_metadata(
    metadata: Option<Value>,
    job: &MediaJobV1,
    plan: &MediaExecutionPlanV1,
) -> Value {
    metadata_with_hivemind(
        metadata,
        json!({
            "job": job,
            "verification": verify_media_job(job),
            "plan": plan,
            "compatibilityMode": "contract-only",
            "executionMode": "media-planning",
        }),
    )
}

fn openai_eval_run_metadata(
    metadata: Option<Value>,
    run: &EvalRunV1,
    verification: &hivemind_evals::EvalRunVerificationV1,
    plan: Option<&EvalRunPlanV1>,
) -> Value {
    metadata_with_hivemind(
        metadata,
        json!({
            "run": run,
            "verification": verification,
            "plan": plan,
            "compatibilityMode": "contract-only",
            "executionMode": "eval-planning",
        }),
    )
}

fn eval_kind_from_openai(request: &OpenAiEvalCreateRequestV1) -> EvalKind {
    if let Some(kind) = request.kind.as_deref().and_then(trim_str) {
        return eval_kind_from_str(kind);
    }
    if request
        .testing_criteria
        .iter()
        .any(|criterion| openai_value_type_name(criterion).contains("safety"))
    {
        return EvalKind::Safety;
    }
    if request
        .testing_criteria
        .iter()
        .any(|criterion| openai_value_type_name(criterion).contains("human"))
    {
        return EvalKind::HumanReview;
    }
    if request.grader_model.is_some()
        || request
            .testing_criteria
            .iter()
            .any(|criterion| openai_value_type_name(criterion).contains("model"))
    {
        return EvalKind::ModelGraded;
    }
    EvalKind::Dataset
}

fn eval_kind_from_str(value: &str) -> EvalKind {
    match normalize_wire_name(value).as_str() {
        "model_graded" | "model_grader" => EvalKind::ModelGraded,
        "human_review" | "human" => EvalKind::HumanReview,
        "regression" => EvalKind::Regression,
        "safety" => EvalKind::Safety,
        "retrieval" => EvalKind::Retrieval,
        "agent_tooling" | "agent" | "tooling" => EvalKind::AgentTooling,
        "rag" => EvalKind::Rag,
        _ => EvalKind::Dataset,
    }
}

fn openai_value_type_name(value: &Value) -> String {
    value
        .get("type")
        .or_else(|| value.get("kind"))
        .and_then(Value::as_str)
        .map(normalize_wire_name)
        .unwrap_or_default()
}

fn data_source_refs_from_openai(data_source: &Option<Value>, fallback_seed: &str) -> Vec<String> {
    let Some(data_source) = data_source else {
        return Vec::new();
    };
    let mut refs = Vec::new();
    collect_openai_refs(data_source, &mut refs);
    if refs.is_empty() {
        refs.push(format!(
            "local://openai/evals/{}/data-source",
            stable_openai_id("eval-data", data_source)
        ));
    }
    if refs.is_empty() {
        refs.push(format!("local://openai/evals/{fallback_seed}/data-source"));
    }
    dedup_strings(&mut refs);
    refs
}

fn testing_criteria_refs_from_openai(criteria: &[Value], fallback_seed: &str) -> Vec<String> {
    if criteria.is_empty() {
        return vec![format!(
            "local://openai/evals/{}/testing-criteria",
            stable_openai_id("eval-criteria", &fallback_seed)
        )];
    }
    let mut refs = Vec::new();
    for criterion in criteria {
        let before = refs.len();
        collect_openai_refs(criterion, &mut refs);
        if refs.len() == before {
            refs.push(format!(
                "local://openai/evals/{}/testing-criteria",
                stable_openai_id("eval-criteria", criterion)
            ));
        }
    }
    dedup_strings(&mut refs);
    refs
}

fn grader_model_ref_from_testing_criteria(criteria: &[Value]) -> Option<String> {
    criteria.iter().find_map(|criterion| {
        criterion
            .get("model")
            .or_else(|| criterion.get("grader_model"))
            .or_else(|| criterion.get("graderModel"))
            .and_then(Value::as_str)
            .and_then(trim_str)
            .map(model_ref_from_openai_model)
    })
}

fn collect_openai_refs(value: &Value, refs: &mut Vec<String>) {
    match value {
        Value::String(value) => {
            if looks_like_storage_ref(value) || value.starts_with("file-") {
                refs.push(eval_ref_from_openai_ref(value));
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_openai_refs(value, refs);
            }
        }
        Value::Object(object) => {
            for key in [
                "ref",
                "reference",
                "dataset_ref",
                "datasetRef",
                "input_ref",
                "inputRef",
                "scoring_rule_ref",
                "scoringRuleRef",
            ] {
                if let Some(value) = object.get(key).and_then(Value::as_str).and_then(trim_str) {
                    refs.push(eval_ref_from_openai_ref(value));
                }
            }
            for key in ["file_id", "fileId"] {
                if let Some(value) = object.get(key).and_then(Value::as_str).and_then(trim_str) {
                    refs.push(file_ref_from_openai_file_id(value));
                }
            }
            for key in [
                "file_ids",
                "fileIds",
                "dataset_refs",
                "datasetRefs",
                "input_refs",
                "inputRefs",
                "scoring_rule_refs",
                "scoringRuleRefs",
            ] {
                if let Some(values) = object.get(key).and_then(Value::as_array) {
                    for value in values {
                        collect_openai_refs(value, refs);
                    }
                }
            }
        }
        _ => {}
    }
}

fn eval_ref_from_openai_ref(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "local://openai/evals/ref-unknown".to_string()
    } else if looks_like_storage_ref(value) {
        value.to_string()
    } else if value.starts_with("file-") {
        file_ref_from_openai_file_id(value)
    } else {
        format!("local://openai/evals/{value}")
    }
}

fn dedup_strings(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn file_ref_from_openai_file_id(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "local://openai/files/file-unknown".to_string()
    } else if looks_like_storage_ref(value) {
        value.to_string()
    } else {
        format!("local://openai/files/{value}")
    }
}

fn model_ref_from_openai_model(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "local://openai/models/model-unknown".to_string()
    } else if looks_like_storage_ref(value) {
        value.to_string()
    } else {
        format!("local://openai/models/{value}")
    }
}

fn openai_file_id_from_ref(value: &str) -> String {
    value
        .strip_prefix("local://openai/files/")
        .unwrap_or(value)
        .to_string()
}

fn openai_model_from_ref(value: &str) -> String {
    value
        .strip_prefix("local://openai/models/")
        .unwrap_or(value)
        .to_string()
}

fn looks_like_storage_ref(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("bzz://")
        || value.starts_with("local://")
        || value.starts_with("ipfs://")
        || value.starts_with("sha256://")
        || value.starts_with("https://")
        || value.starts_with("swarm://")
}

fn openai_fine_tune_hyperparameters(request: &OpenAiFineTuningCreateRequestV1) -> Value {
    let mut parameters = match request.hyperparameters.clone() {
        Some(Value::Object(object)) => Value::Object(object),
        Some(value) => json!({ "value": value }),
        None => json!({ "n_epochs": "auto" }),
    };

    if let Value::Object(object) = &mut parameters {
        let mut sidecar = serde_json::Map::new();
        sidecar.insert("model".to_string(), Value::String(request.model.clone()));
        sidecar.insert(
            "trainingFile".to_string(),
            Value::String(request.training_file.clone()),
        );
        if let Some(validation_file) = &request.validation_file {
            sidecar.insert(
                "validationFile".to_string(),
                Value::String(validation_file.clone()),
            );
        }
        if let Some(suffix) = &request.suffix {
            sidecar.insert("suffix".to_string(), Value::String(suffix.clone()));
        }
        if !request.integrations.is_empty() {
            sidecar.insert(
                "integrations".to_string(),
                Value::Array(request.integrations.clone()),
            );
        }
        if let Some(seed) = request.seed {
            sidecar.insert("seed".to_string(), json!(seed));
        }
        if let Some(method) = &request.method {
            sidecar.insert("method".to_string(), method.clone());
        }
        if let Some(metadata) = &request.metadata {
            sidecar.insert("metadata".to_string(), metadata.clone());
        }
        object.insert("_openai".to_string(), Value::Object(sidecar));
    }

    parameters
}

fn public_openai_fine_tune_hyperparameters(parameters: &Value) -> Value {
    match parameters {
        Value::Object(object) => {
            let mut public = object.clone();
            public.remove("_openai");
            if public.is_empty() {
                json!({ "n_epochs": "auto" })
            } else {
                Value::Object(public)
            }
        }
        other => other.clone(),
    }
}

fn fine_tune_artifact_kind_from_str(value: &str) -> Option<FineTuneOutputArtifactKind> {
    match normalize_wire_name(value).as_str() {
        "adapter_or_lora" | "lora" | "adapter" => Some(FineTuneOutputArtifactKind::AdapterOrLora),
        "full_model" => Some(FineTuneOutputArtifactKind::FullModel),
        "merged_model" => Some(FineTuneOutputArtifactKind::MergedModel),
        "checkpoint_set" | "checkpoints" => Some(FineTuneOutputArtifactKind::CheckpointSet),
        _ => None,
    }
}

fn fine_tune_output_visibility_from_str(value: &str) -> Option<FineTuneOutputVisibility> {
    match normalize_wire_name(value).as_str() {
        "private" => Some(FineTuneOutputVisibility::Private),
        "organization" | "org" => Some(FineTuneOutputVisibility::Organization),
        "public" => Some(FineTuneOutputVisibility::Public),
        "token_gated" | "token_gated_public" => Some(FineTuneOutputVisibility::TokenGated),
        _ => None,
    }
}

fn validation_issue_messages(issues: &[hivemind_core::ValidationIssue]) -> Vec<String> {
    issues
        .iter()
        .map(|issue| format!("{}: {}", issue.path, issue.message))
        .collect()
}

fn openai_realtime_modalities(
    primary: &[String],
    fallback: &[String],
    default: &[Modality],
) -> Vec<Modality> {
    let source = if primary.is_empty() {
        fallback
    } else {
        primary
    };
    let mut modalities: Vec<Modality> = source
        .iter()
        .filter_map(|value| modality_from_openai_name(value))
        .collect();
    if modalities.is_empty() {
        modalities = default.to_vec();
    }
    dedup_modalities(&mut modalities);
    modalities
}

fn modality_from_openai_name(value: &str) -> Option<Modality> {
    match normalize_wire_name(value).as_str() {
        "text" => Some(Modality::Text),
        "chat" | "message" | "messages" => Some(Modality::Chat),
        "audio" | "voice" => Some(Modality::Audio),
        "image" | "vision" => Some(Modality::Image),
        "video" => Some(Modality::Video),
        "document" => Some(Modality::Document),
        "file" => Some(Modality::File),
        "tool" | "tool_call" | "function" | "function_call" => Some(Modality::ToolCall),
        "structured_output" | "json" => Some(Modality::StructuredOutput),
        _ => None,
    }
}

fn openai_modality_name(modality: &Modality) -> String {
    match modality {
        Modality::Text => "text",
        Modality::Chat => "chat",
        Modality::StructuredOutput => "structured_output",
        Modality::Embedding => "embedding",
        Modality::Image => "image",
        Modality::Audio => "audio",
        Modality::Video => "video",
        Modality::Document => "document",
        Modality::File => "file",
        Modality::ToolCall => "tool_call",
        Modality::BrowserAction => "browser_action",
        Modality::VectorSearch => "vector_search",
        Modality::TrainingData => "training_data",
        Modality::EvaluationData => "evaluation_data",
    }
    .to_string()
}

fn realtime_transport_from_str(value: &str) -> Option<RealtimeTransport> {
    match normalize_wire_name(value).as_str() {
        "websocket" | "ws" => Some(RealtimeTransport::Websocket),
        "webrtc" => Some(RealtimeTransport::Webrtc),
        "http_stream" | "http" | "sse" | "server_event_stream" => {
            Some(RealtimeTransport::HttpStream)
        }
        "local" | "loopback" => Some(RealtimeTransport::Local),
        _ => None,
    }
}

fn openai_realtime_tool_ref(tool: &Value) -> String {
    match tool {
        Value::String(value) => local_or_external_tool_ref(value),
        Value::Object(object) => object
            .get("tool_ref")
            .or_else(|| object.get("toolRef"))
            .or_else(|| object.get("ref"))
            .or_else(|| object.get("$ref"))
            .or_else(|| object.get("name"))
            .or_else(|| object.get("type"))
            .and_then(Value::as_str)
            .map(local_or_external_tool_ref)
            .unwrap_or_else(|| {
                format!(
                    "local://openai/realtime/tools/{}",
                    stable_openai_id("tool", tool)
                )
            }),
        _ => format!(
            "local://openai/realtime/tools/{}",
            stable_openai_id("tool", tool)
        ),
    }
}

fn local_or_external_tool_ref(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "local://openai/realtime/tools/unknown".to_string()
    } else if looks_like_storage_ref(value) {
        value.to_string()
    } else {
        format!(
            "local://openai/realtime/tools/{}",
            normalize_wire_name(value)
        )
    }
}

fn dedup_modalities(values: &mut Vec<Modality>) {
    let mut seen = Vec::new();
    values.retain(|value| {
        if seen.iter().any(|seen_value| seen_value == value) {
            false
        } else {
            seen.push(value.clone());
            true
        }
    });
}

fn vector_storage_ref_from_openai(reference: &OpenAiVectorStoreStorageRefV1) -> VectorStorageRefV1 {
    VectorStorageRefV1 {
        role: openai_vector_storage_role(&reference.role),
        reference: reference.reference.clone(),
        content_type: reference.content_type.clone(),
        sha256: reference.sha256.clone(),
        size_bytes: reference.size_bytes,
    }
}

fn openai_vector_storage_role(role: &str) -> VectorStorageRole {
    match normalize_wire_name(role).as_str() {
        "index" => VectorStorageRole::Index,
        "metadata" => VectorStorageRole::Metadata,
        "chunks" => VectorStorageRole::Chunks,
        "embedding_cache" => VectorStorageRole::EmbeddingCache,
        "manifest" => VectorStorageRole::Manifest,
        _ => VectorStorageRole::Documents,
    }
}

fn openai_vector_metric(metric: &str) -> VectorMetric {
    match normalize_wire_name(metric).as_str() {
        "dot_product" => VectorMetric::DotProduct,
        "euclidean" => VectorMetric::Euclidean,
        _ => VectorMetric::Cosine,
    }
}

fn chunking_strategy_ref(strategy: &Option<Value>) -> String {
    let Some(strategy) = strategy else {
        return "local://chunking/default".to_string();
    };
    if let Some(reference) = strategy
        .get("ref")
        .or_else(|| strategy.get("reference"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return reference.to_string();
    }
    format!(
        "local://chunking/{}",
        stable_openai_id("strategy", strategy)
    )
}

fn privacy_tier_from_metadata(metadata: &Option<Value>) -> PrivacyTier {
    let Some(value) = metadata.as_ref() else {
        return PrivacyTier::Standard;
    };
    let Some(privacy) = value
        .get("privacy_tier")
        .or_else(|| value.get("privacyTier"))
        .and_then(Value::as_str)
    else {
        return PrivacyTier::Standard;
    };
    match normalize_wire_name(privacy).as_str() {
        "local_only" => PrivacyTier::LocalOnly,
        "redacted_input" => PrivacyTier::RedactedInput,
        "no_log" => PrivacyTier::NoLog,
        "tee_confidential" => PrivacyTier::TeeConfidential,
        "fhe_encrypted" => PrivacyTier::FheEncrypted,
        "mpc_experimental" => PrivacyTier::MpcExperimental,
        _ => PrivacyTier::Standard,
    }
}

fn openai_privacy_tier(value: Option<&str>, metadata: &Option<Value>) -> PrivacyTier {
    value
        .or_else(|| {
            metadata
                .as_ref()
                .and_then(|metadata| {
                    metadata
                        .get("privacy_tier")
                        .or_else(|| metadata.get("privacyTier"))
                })
                .and_then(Value::as_str)
        })
        .map(privacy_tier_from_str)
        .unwrap_or(PrivacyTier::Standard)
}

fn privacy_tier_from_str(value: &str) -> PrivacyTier {
    match normalize_wire_name(value).as_str() {
        "local_only" => PrivacyTier::LocalOnly,
        "redacted_input" => PrivacyTier::RedactedInput,
        "no_log" => PrivacyTier::NoLog,
        "tee_confidential" => PrivacyTier::TeeConfidential,
        "fhe_encrypted" => PrivacyTier::FheEncrypted,
        "mpc_experimental" => PrivacyTier::MpcExperimental,
        _ => PrivacyTier::Standard,
    }
}

fn openai_integrity_tier(value: Option<&str>, metadata: &Option<Value>) -> IntegrityTier {
    value
        .or_else(|| {
            metadata
                .as_ref()
                .and_then(|metadata| {
                    metadata
                        .get("integrity_tier")
                        .or_else(|| metadata.get("integrityTier"))
                        .or_else(|| metadata.get("verification_mode"))
                        .or_else(|| metadata.get("verificationMode"))
                })
                .and_then(Value::as_str)
        })
        .map(integrity_tier_from_str)
        .unwrap_or(IntegrityTier::ReceiptOnly)
}

fn integrity_tier_from_str(value: &str) -> IntegrityTier {
    match normalize_wire_name(value).as_str() {
        "validator_spot_check" | "validator_checked" => IntegrityTier::ValidatorSpotCheck,
        "redundant_execution" => IntegrityTier::RedundantExecution,
        "deterministic_replay" | "deterministic_where_possible" => {
            IntegrityTier::DeterministicReplay
        }
        "tee_attested" | "tee_attestation" => IntegrityTier::TeeAttested,
        "zk_proof_when_supported" | "zk_proof" => IntegrityTier::ZkProofWhenSupported,
        _ => IntegrityTier::ReceiptOnly,
    }
}

fn batch_task_from_endpoint(endpoint: &str) -> String {
    match normalize_endpoint(endpoint).as_str() {
        "/v1/chat/completions" => "chat".to_string(),
        "/v1/responses" => "responses".to_string(),
        "/v1/embeddings" => "embedding".to_string(),
        "/v1/moderations" => "classification".to_string(),
        "/v1/vector_stores/search" | "/v1/vector-stores/search" => "vector-search".to_string(),
        other if other.contains("image") => "image-generation".to_string(),
        other if other.contains("audio") => "audio".to_string(),
        _ => "batch".to_string(),
    }
}

fn endpoint_from_batch_task(task: &str) -> String {
    match normalize_wire_name(task).as_str() {
        "chat" => "/v1/chat/completions".to_string(),
        "responses" => "/v1/responses".to_string(),
        "embedding" | "embeddings" => "/v1/embeddings".to_string(),
        "classification" | "moderation" => "/v1/moderations".to_string(),
        "vector_search" => "/v1/vector_stores/search".to_string(),
        "image_generation" => "/v1/images/generations".to_string(),
        "audio" => "/v1/audio/transcriptions".to_string(),
        _ => "/v1/batches".to_string(),
    }
}

fn normalize_endpoint(value: &str) -> String {
    let trimmed = value.trim().to_ascii_lowercase();
    if trimmed.starts_with('/') {
        trimmed
    } else {
        format!("/{trimmed}")
    }
}

fn normalized_search_query(query: &Value) -> Value {
    if query.is_null() {
        json!("")
    } else {
        query.clone()
    }
}

fn normalize_wire_name(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(' ', "_")
}

fn embedding_inputs(input: &Value) -> Vec<Value> {
    match input {
        Value::String(text) => vec![json!({ "text": text })],
        Value::Array(values) if values.iter().all(Value::is_string) => values
            .iter()
            .filter_map(Value::as_str)
            .map(|text| json!({ "text": text }))
            .collect(),
        Value::Array(values) if values.iter().all(Value::is_number) => {
            vec![json!({ "tokens": values })]
        }
        other => vec![json!({ "input": other })],
    }
}

fn moderation_inputs(input: &Value) -> Vec<Value> {
    match input {
        Value::String(text) => vec![Value::String(text.clone())],
        Value::Array(values) if values.iter().all(Value::is_string) => values
            .iter()
            .filter_map(Value::as_str)
            .map(|text| Value::String(text.to_string()))
            .collect(),
        Value::Array(values) => values.clone(),
        other => vec![other.clone()],
    }
}

fn responses_input_messages(request: &OpenAiResponsesRequestV1) -> Vec<ChatMessageV1> {
    let mut messages = Vec::new();
    if let Some(instructions) = &request.instructions {
        if !instructions.trim().is_empty() {
            messages.push(ChatMessageV1 {
                role: "system".to_string(),
                content: Value::String(instructions.clone()),
                name: None,
            });
        }
    }

    match &request.input {
        Value::Null => {}
        Value::String(text) => messages.push(ChatMessageV1 {
            role: "user".to_string(),
            content: Value::String(text.clone()),
            name: None,
        }),
        Value::Array(values) => {
            for value in values {
                messages.push(response_input_message(value));
            }
        }
        Value::Object(object) => {
            if let Some(values) = object.get("messages").and_then(Value::as_array) {
                for value in values {
                    messages.push(response_input_message(value));
                }
            } else {
                messages.push(response_input_message(&request.input));
            }
        }
        other => messages.push(ChatMessageV1 {
            role: "user".to_string(),
            content: other.clone(),
            name: None,
        }),
    }

    if messages.is_empty() {
        messages.push(ChatMessageV1 {
            role: "user".to_string(),
            content: Value::String(String::new()),
            name: None,
        });
    }
    messages
}

fn response_input_message(value: &Value) -> ChatMessageV1 {
    let role = value
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("user")
        .to_string();
    let content = value
        .get("content")
        .cloned()
        .or_else(|| value.get("text").cloned())
        .unwrap_or_else(|| value.clone());
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string);
    ChatMessageV1 {
        role,
        content,
        name,
    }
}

fn moderation_input_text(input: &Value) -> String {
    match input {
        Value::String(text) => text.clone(),
        Value::Object(object) => object
            .get("text")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| input.to_string()),
        other => other.to_string(),
    }
}

fn latest_message_text(messages: &[ChatMessageV1]) -> String {
    messages
        .iter()
        .rev()
        .find(|message| message.role == "user")
        .or_else(|| messages.last())
        .map(message_text)
        .unwrap_or_default()
}

fn message_text(message: &ChatMessageV1) -> String {
    match &message.content {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| part.get("content").and_then(Value::as_str))
            })
            .collect::<Vec<_>>()
            .join(" "),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn response_message_content(response: &ExecutionResponseV1) -> String {
    response
        .output
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            response
                .output
                .get("text")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| response.output.to_string())
}

fn response_embedding(response: &ExecutionResponseV1) -> Vec<f32> {
    response
        .output
        .get("embedding")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_f64)
                .map(|value| value as f32)
                .collect()
        })
        .unwrap_or_default()
}

fn moderation_result(response: &ExecutionResponseV1) -> OpenAiModerationResultV1 {
    let label = response
        .output
        .get("label")
        .and_then(Value::as_str)
        .unwrap_or("general")
        .to_string();
    let score = response
        .output
        .get("score")
        .and_then(Value::as_f64)
        .unwrap_or(0.0)
        .clamp(0.0, 1.0);
    let mut category_scores = standard_moderation_categories()
        .into_iter()
        .map(|category| (category.to_string(), 0.0))
        .collect::<BTreeMap<_, _>>();
    if label != "general" {
        category_scores.insert(label.clone(), score);
    }
    if let Some(scores) = response
        .output
        .get("category_scores")
        .and_then(Value::as_object)
    {
        for (category, value) in scores {
            if let Some(score) = value.as_f64() {
                category_scores.insert(category.clone(), score.clamp(0.0, 1.0));
            }
        }
    }
    let categories = category_scores
        .iter()
        .map(|(category, score)| (category.clone(), *score >= 0.5))
        .collect::<BTreeMap<_, _>>();
    let flagged = categories.values().any(|value| *value);
    OpenAiModerationResultV1 {
        flagged,
        categories,
        category_scores,
    }
}

fn standard_moderation_categories() -> Vec<&'static str> {
    vec![
        "hate",
        "harassment",
        "self-harm",
        "sexual",
        "violence",
        "illicit",
        "privacy",
        "spam",
    ]
}

fn response_status(status: &ExecutionStatus) -> &'static str {
    match status {
        ExecutionStatus::Succeeded => "completed",
        ExecutionStatus::Partial => "in_progress",
        ExecutionStatus::Failed => "failed",
        ExecutionStatus::Cancelled => "cancelled",
    }
}

fn count_tokens(text: &str) -> u64 {
    text.split_whitespace().count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::ExecutionMetrics;

    #[test]
    fn maps_chat_request_and_response() {
        let request = ChatCompletionRequestV1 {
            model: "hivemind/hello-chat".to_string(),
            messages: vec![ChatMessageV1 {
                role: "user".to_string(),
                content: Value::String("hello there".to_string()),
                name: None,
            }],
            stream: true,
            max_tokens: Some(64),
            temperature: Some(0.2),
            user: None,
            metadata: None,
        };

        let execution =
            chat_request_to_execution(&request, "bzz://pkg", "hivemind/hello-chat", "0.1.0", "r1");

        assert_eq!(execution.task, "chat");
        assert!(execution.options.stream);
        assert_eq!(execution.input["text"], "hello there");

        let response = ExecutionResponseV1::succeeded(
            "r1",
            json!({ "message": { "role": "assistant", "content": "hi back" } }),
            ExecutionMetrics {
                input_tokens: Some(2),
                output_tokens: Some(2),
                ..ExecutionMetrics::default()
            },
        );
        let completion = chat_completion_from_execution(&request, &response, "chatcmpl-r1", 1);

        assert_eq!(completion.object, "chat.completion");
        assert_eq!(completion.choices[0].message.content, "hi back");
        assert_eq!(completion.usage.total_tokens, 4);

        let stream =
            chat_completion_stream_body_from_execution(&request, &response, "chatcmpl-r1", 1);

        assert!(stream.contains("\"object\":\"chat.completion.chunk\""));
        assert!(stream.contains("\"role\":\"assistant\""));
        assert!(stream.contains("\"content\":\"hi back\""));
        assert!(stream.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn projects_chat_request_to_native_ai_request() {
        let request = ChatCompletionRequestV1 {
            model: "hivemind/hello-chat".to_string(),
            messages: vec![ChatMessageV1 {
                role: "user".to_string(),
                content: Value::String("hello through ai request".to_string()),
                name: None,
            }],
            stream: true,
            max_tokens: Some(64),
            temperature: Some(0.2),
            user: Some("openai-user".to_string()),
            metadata: Some(json!({ "requester": "local-dev" })),
        };

        let ai = chat_request_to_ai_request(&request, "ai-openai-chat", "fallback");

        assert_eq!(ai.schema_version, "hivemind.request.v1");
        assert_eq!(ai.requester, "local-dev");
        assert_eq!(ai.api_surface, ApiSurface::OpenAiChatCompletions);
        assert_eq!(
            ai.package_selector.model.as_deref(),
            Some("hivemind/hello-chat")
        );
        assert_eq!(ai.inputs[0].content, "hello through ai request");
        assert_eq!(ai.messages.as_ref().unwrap()[0]["role"], "user");
        assert!(ai.stream);
        assert_eq!(ai.sampling.as_ref().unwrap().max_output_tokens, Some(64));
        assert_eq!(ai.metadata["openai"]["compatTask"], "chat_completions");
    }

    #[test]
    fn projects_openai_chat_to_task_envelope() {
        let request = ChatCompletionRequestV1 {
            model: "hivemind/hello-chat".to_string(),
            messages: vec![ChatMessageV1 {
                role: "user".to_string(),
                content: Value::String("hello through task envelope".to_string()),
                name: None,
            }],
            stream: true,
            max_tokens: Some(64),
            temperature: Some(0.2),
            user: Some("openai-user".to_string()),
            metadata: Some(json!({ "requester": "local-dev" })),
        };

        let envelope = chat_request_to_task_envelope(&request, "task-openai-chat", "fallback");
        let verification = hivemind_core::verify_task_envelope(&envelope);

        assert_eq!(envelope.schema_version, "hivemind.task_envelope.v1");
        assert_eq!(envelope.requester, "local-dev");
        assert_eq!(envelope.requested_api, ApiSurface::OpenAiChatCompletions);
        assert_eq!(envelope.capability.capability_id, "text.chat.general");
        assert_eq!(
            envelope.package_ref.as_deref(),
            Some("model://hivemind/hello-chat")
        );
        assert!(envelope.streaming.enabled);
        assert!(verification.valid, "{verification:#?}");
    }

    #[test]
    fn maps_batched_embedding_request() {
        let request = EmbeddingRequestV1 {
            model: "hivemind/hello-embedding".to_string(),
            input: json!(["alpha", "beta"]),
            encoding_format: None,
            user: None,
            metadata: None,
        };

        let executions = embedding_requests_to_executions(
            &request,
            "bzz://pkg",
            "hivemind/hello-embedding",
            "0.1.0",
            "embd-1",
        );

        assert_eq!(executions.len(), 2);
        assert_eq!(executions[1].request_id, "embd-1-1");

        let responses: Vec<_> = executions
            .iter()
            .enumerate()
            .map(|(index, execution)| {
                let mut response = ExecutionResponseV1::succeeded(
                    execution.request_id.clone(),
                    json!({ "embedding": [index as f64, 1.0] }),
                    ExecutionMetrics {
                        input_tokens: Some(1),
                        ..ExecutionMetrics::default()
                    },
                );
                response.status = ExecutionStatus::Succeeded;
                response
            })
            .collect();
        let embedding = embedding_response_from_executions(&request, &responses);

        assert_eq!(embedding.object, "list");
        assert_eq!(embedding.data.len(), 2);
        assert_eq!(embedding.data[1].embedding, vec![1.0, 1.0]);
        assert_eq!(embedding.usage.prompt_tokens, 2);
    }

    #[test]
    fn projects_embedding_request_to_native_ai_request() {
        let request = EmbeddingRequestV1 {
            model: "bzz://embedding-package".to_string(),
            input: json!(["alpha", "beta"]),
            encoding_format: Some("float".to_string()),
            user: None,
            metadata: Some(json!({ "requester": "embedder" })),
        };

        let ai = embedding_request_to_ai_request(&request, "ai-embed", "fallback");

        assert_eq!(ai.requester, "embedder");
        assert_eq!(ai.api_surface, ApiSurface::OpenAiEmbeddings);
        assert_eq!(
            ai.package_selector.package_ref.as_deref(),
            Some("bzz://embedding-package")
        );
        assert_eq!(ai.inputs.len(), 2);
        assert_eq!(ai.task.as_deref(), Some("embedding"));
        assert_eq!(
            ai.response_format.as_ref().unwrap()["encodingFormat"],
            "float"
        );
    }

    #[test]
    fn projects_openai_embedding_to_task_envelope() {
        let request = EmbeddingRequestV1 {
            model: "bzz://embedding-package".to_string(),
            input: json!(["alpha", "beta"]),
            encoding_format: Some("float".to_string()),
            user: None,
            metadata: Some(json!({ "requester": "embedder" })),
        };

        let envelope = embedding_request_to_task_envelope(&request, "task-embed", "fallback");
        let verification = hivemind_core::verify_task_envelope(&envelope);

        assert_eq!(envelope.requested_api, ApiSurface::OpenAiEmbeddings);
        assert_eq!(envelope.capability.capability_id, "text.embedding.general");
        assert_eq!(
            envelope.package_ref.as_deref(),
            Some("bzz://embedding-package")
        );
        assert_eq!(envelope.inputs.len(), 2);
        assert_eq!(envelope.expected_outputs[0].output_kind, "embedding");
        assert!(verification.valid, "{verification:#?}");
    }

    #[test]
    fn maps_responses_request_and_response() {
        let request = OpenAiResponsesRequestV1 {
            model: "hivemind/hello-chat".to_string(),
            input: Value::String("explain the package".to_string()),
            instructions: Some("Be concise".to_string()),
            stream: false,
            max_output_tokens: Some(128),
            temperature: Some(0.3),
            user: None,
            metadata: Some(json!({ "trace": true })),
        };

        let execution = responses_request_to_execution(
            &request,
            "bzz://pkg",
            "hivemind/hello-chat",
            "0.1.0",
            "resp-1",
        );

        assert_eq!(execution.task, "chat");
        assert_eq!(execution.input["text"], "explain the package");
        assert_eq!(execution.input["messages"][0]["role"], "system");
        assert_eq!(execution.input["messages"][1]["role"], "user");

        let execution_response = ExecutionResponseV1::succeeded(
            "resp-1",
            json!({ "message": { "role": "assistant", "content": "It is a signed package." } }),
            ExecutionMetrics {
                input_tokens: Some(5),
                output_tokens: Some(6),
                ..ExecutionMetrics::default()
            },
        );
        let response =
            responses_response_from_execution(&request, &execution_response, "resp-1", 1);

        assert_eq!(response.object, "response");
        assert_eq!(response.status, "completed");
        assert_eq!(response.output_text, "It is a signed package.");
        assert_eq!(response.output[0].content[0].content_type, "output_text");
        assert_eq!(response.usage.total_tokens, 11);

        let stream =
            responses_stream_body_from_execution(&request, &execution_response, "resp-1", 1);

        assert!(stream.contains("event: response.created"));
        assert!(stream.contains("event: response.output_text.delta"));
        assert!(stream.contains("event: response.completed"));
        assert!(stream.contains("\"sequence_number\":0"));
        assert!(stream.contains("\"delta\":\"It is a signed package.\""));
    }

    #[test]
    fn projects_responses_and_moderation_requests_to_native_ai_requests() {
        let responses = OpenAiResponsesRequestV1 {
            model: "hivemind/hello-chat".to_string(),
            input: Value::String("explain the package".to_string()),
            instructions: Some("Be concise".to_string()),
            stream: false,
            max_output_tokens: Some(128),
            temperature: Some(0.3),
            user: Some("user-1".to_string()),
            metadata: None,
        };
        let ai_response = responses_request_to_ai_request(&responses, "ai-resp", "fallback");

        assert_eq!(ai_response.requester, "user-1");
        assert_eq!(ai_response.api_surface, ApiSurface::OpenAiResponses);
        assert_eq!(ai_response.task.as_deref(), Some("chat"));
        assert_eq!(ai_response.messages.as_ref().unwrap()[0]["role"], "system");
        assert_eq!(ai_response.inputs[0].content, "explain the package");

        let moderation = OpenAiModerationRequestV1 {
            model: "hivemind/moderation".to_string(),
            input: json!(["please classify this"]),
            user: None,
            metadata: None,
        };
        let ai_moderation = moderation_request_to_ai_request(&moderation, "ai-mod", "fallback");

        assert_eq!(ai_moderation.requester, "fallback");
        assert_eq!(ai_moderation.api_surface, ApiSurface::Moderation);
        assert_eq!(ai_moderation.task.as_deref(), Some("classification"));
        assert_eq!(ai_moderation.inputs[0].content, "please classify this");
    }

    #[test]
    fn maps_moderation_request_and_classification_response() {
        let request = OpenAiModerationRequestV1 {
            model: "hivemind/moderation".to_string(),
            input: json!(["hello", "error happened"]),
            user: None,
            metadata: None,
        };

        let executions = moderation_requests_to_executions(
            &request,
            "bzz://pkg",
            "hivemind/moderation",
            "0.1.0",
            "modr-1",
        );

        assert_eq!(executions.len(), 2);
        assert_eq!(executions[0].task, "classification");
        assert_eq!(executions[1].request_id, "modr-1-1");

        let responses = vec![
            ExecutionResponseV1::succeeded(
                "modr-1",
                json!({ "label": "general", "score": 0.1 }),
                ExecutionMetrics::default(),
            ),
            ExecutionResponseV1::succeeded(
                "modr-1-1",
                json!({ "label": "harassment", "score": 0.76 }),
                ExecutionMetrics::default(),
            ),
        ];
        let moderation = moderation_response_from_executions(&request, &responses, "modr-1");

        assert_eq!(moderation.results.len(), 2);
        assert!(!moderation.results[0].flagged);
        assert!(moderation.results[1].flagged);
        assert_eq!(
            moderation.results[1].categories.get("harassment"),
            Some(&true)
        );
    }

    #[test]
    fn maps_registry_entry_to_openai_model() {
        let entry = RegistryEntryV1::from_manifest(
            &manifest(),
            "bzz://pkg",
            "0".repeat(64),
            "2026-06-02T00:00:00Z",
        );

        let model = model_from_registry_entry(&entry);
        let list = model_list_from_registry_entries([&entry]);

        assert_eq!(model.id, "hivemind/hello-chat");
        assert_eq!(model.object, "model");
        assert_eq!(model.owned_by, "Hivemind Labs");
        assert_eq!(
            model.metadata["hivemind"]["packageRefs"][0]["packageRef"],
            "bzz://pkg"
        );
        assert_eq!(list.object, "list");
        assert_eq!(list.data.len(), 1);
    }

    #[test]
    fn maps_json_file_reference_to_openai_file() {
        let request = OpenAiFileCreateRequestV1 {
            purpose: Some("assistants".to_string()),
            filename: Some("docs.jsonl".to_string()),
            reference: Some("bzz://docs".to_string()),
            storage_ref: None,
            bytes: Some(42),
            sha256: Some("a".repeat(64)),
            metadata: Some(json!({ "team": "research" })),
        };

        let id = openai_file_id_from_create_request(&request);
        let file = openai_file_from_create_request(&request, &id, 10);

        assert!(id.starts_with("file-"));
        assert_eq!(file.object, "file");
        assert_eq!(file.filename, "docs.jsonl");
        assert_eq!(file.bytes, 42);
        assert_eq!(file.metadata["team"], "research");
        assert_eq!(file.metadata["hivemind"]["storageRef"], "bzz://docs");
    }

    #[test]
    fn maps_vector_store_and_search_to_hivemind_plan() {
        let request = OpenAiVectorStoreCreateRequestV1 {
            name: "Company Docs".to_string(),
            file_ids: vec!["file-abc".to_string()],
            document_refs: vec!["bzz://docs".to_string()],
            storage_refs: vec![OpenAiVectorStoreStorageRefV1 {
                role: "index".to_string(),
                reference: "bzz://index".to_string(),
                content_type: Some("application/octet-stream".to_string()),
                sha256: None,
                size_bytes: Some(100),
            }],
            embedding_model: Some("hivemind/hello-embedding".to_string()),
            dimensions: Some(384),
            metric: Some("dot_product".to_string()),
            owner: Some("local-dev".to_string()),
            chunking_strategy: Some(json!({ "ref": "bzz://chunking" })),
            metadata: Some(json!({ "privacyTier": "no-log" })),
        };

        let manifest = vector_store_manifest_from_openai_request(&request, "fallback-owner");
        let verification = hivemind_vector::verify_vector_store_manifest(&manifest);
        let store = openai_vector_store_from_manifest(&manifest, 10, request.metadata.clone());

        assert!(verification.valid);
        assert_eq!(manifest.owner, "local-dev");
        assert_eq!(manifest.embedding_model_ref, "hivemind/hello-embedding");
        assert_eq!(manifest.dimensions, 384);
        assert_eq!(store.object, "vector_store");
        assert_eq!(store.status, "completed");
        assert_eq!(store.file_counts.total, 2);

        let search_request = OpenAiVectorStoreSearchRequestV1 {
            query: json!("security policy"),
            max_num_results: Some(2),
            filters: Some(json!({ "section": "policy" })),
            user: Some("tester".to_string()),
            metadata: None,
        };
        let native_request =
            vector_search_request_from_openai(&manifest, &search_request, "tester");
        let plan = hivemind_vector::vector_search_plan(&manifest, &native_request);
        let response = openai_vector_search_response_from_plan(&search_request, &plan);

        assert!(plan.valid);
        assert_eq!(plan.top_k, 2);
        assert_eq!(native_request.filters["section"], "policy");
        assert_eq!(response.object, "vector_store.search_results");
        assert_eq!(response.metadata["hivemind"]["searchMode"], "plan-only");
        assert!(!response.data.is_empty());
    }

    #[test]
    fn maps_openai_batch_to_signed_hivemind_batch_job() {
        let request = OpenAiBatchCreateRequestV1 {
            input_file_id: "file-input".to_string(),
            endpoint: "/v1/embeddings".to_string(),
            completion_window: "24h".to_string(),
            metadata: Some(json!({
                "requester": "local-dev",
                "privacyTier": "no-log",
                "integrityTier": "validator-spot-check"
            })),
            model: Some("hivemind/hello-embedding".to_string()),
            package_ref: Some("bzz://embedding-package".to_string()),
            package_id: None,
            package_version: Some("0.1.0".to_string()),
            task: None,
            max_concurrency: Some(8),
            privacy_tier: None,
            integrity_tier: None,
        };

        let job = batch_job_from_openai_request(&request, "fallback-requester");
        let verification = hivemind_batch::verify_batch_job(&job);
        let batch = openai_batch_from_job(&job, 10);

        assert!(verification.valid);
        assert_eq!(job.requester, "local-dev");
        assert_eq!(job.job_template.task, "embedding");
        assert_eq!(job.job_template.package_ref, "bzz://embedding-package");
        assert_eq!(job.max_concurrency, 8);
        assert_eq!(batch.object, "batch");
        assert_eq!(batch.status, "validating");
        assert_eq!(batch.input_file_id, "file-input");
        assert_eq!(batch.request_counts.total, 1);
        assert_eq!(batch.metadata["requester"], "local-dev");
        assert_eq!(
            batch.metadata["hivemind"]["compatibilityMode"],
            "contract-only"
        );
    }

    #[test]
    fn maps_openai_fine_tuning_to_signed_hivemind_job() {
        let request = OpenAiFineTuningCreateRequestV1 {
            model: "hivemind/hello-chat".to_string(),
            training_file: "file-train".to_string(),
            validation_file: Some("file-valid".to_string()),
            hyperparameters: Some(json!({
                "n_epochs": 2,
                "batch_size": "auto",
            })),
            suffix: Some("support-adapter".to_string()),
            integrations: vec![json!({ "type": "wandb" })],
            seed: Some(42),
            method: Some(json!({ "type": "supervised" })),
            metadata: Some(json!({
                "requester": "local-dev",
                "privacyTier": "tee-confidential",
                "integrityTier": "validator-spot-check",
                "organization_id": "org-local"
            })),
            recipe_ref: Some("bzz://fine-tune-recipe".to_string()),
            output_ref: Some("local://fine-tune/output".to_string()),
            privacy_tier: None,
            integrity_tier: None,
            max_cost: Some(PriceV1 {
                amount: 12.5,
                currency: "USD".to_string(),
            }),
            validation_required: Some(true),
            artifact_kind: Some("adapter-or-lora".to_string()),
            output_visibility: Some("private".to_string()),
        };

        let job = fine_tune_job_from_openai_request(&request, "fallback-requester");
        let verification = hivemind_fine_tune::verify_fine_tune_job(&job);
        let response = openai_fine_tuning_job_from_job(&job, 10);

        assert!(verification.valid);
        assert_eq!(job.requester, "local-dev");
        assert_eq!(
            job.base_model_ref,
            "local://openai/models/hivemind/hello-chat"
        );
        assert_eq!(
            job.training_dataset_refs[0],
            "local://openai/files/file-train"
        );
        assert_eq!(
            job.validation_dataset_refs[0],
            "local://openai/files/file-valid"
        );
        assert_eq!(job.recipe_ref, "bzz://fine-tune-recipe");
        assert_eq!(job.privacy.privacy_tier, PrivacyTier::TeeConfidential);
        assert_eq!(
            job.validation_policy.integrity_tier,
            IntegrityTier::ValidatorSpotCheck
        );
        assert!(job.validation_policy.required);
        assert_eq!(response.object, "fine_tuning.job");
        assert_eq!(response.status, "validating");
        assert_eq!(response.model, "hivemind/hello-chat");
        assert_eq!(response.training_file, "file-train");
        assert_eq!(response.validation_file.as_deref(), Some("file-valid"));
        assert_eq!(response.organization_id.as_deref(), Some("org-local"));
        assert!(response.hyperparameters.get("_openai").is_none());
        assert_eq!(
            response.metadata["hivemind"]["compatibilityMode"],
            "contract-only"
        );
    }

    #[test]
    fn maps_openai_realtime_session_to_signed_hivemind_session() {
        let request = OpenAiRealtimeSessionCreateRequestV1 {
            model: Some("hivemind/realtime-agent".to_string()),
            modalities: vec!["audio".to_string(), "text".to_string()],
            modalities_in: Vec::new(),
            modalities_out: Vec::new(),
            instructions: Some("Be concise.".to_string()),
            voice: Some("alloy".to_string()),
            input_audio_format: Some("pcm16".to_string()),
            output_audio_format: Some("pcm16".to_string()),
            input_audio_transcription: Some(json!({ "model": "hivemind/transcribe" })),
            turn_detection: Some(json!({ "type": "server_vad" })),
            tools: vec![json!({
                "type": "function",
                "name": "lookup_docs",
            })],
            tool_choice: Some(json!("auto")),
            temperature: Some(0.7),
            max_response_output_tokens: Some(json!(512)),
            metadata: Some(json!({
                "requester": "local-dev",
                "privacyTier": "no-log",
                "settlementMethod": "free-local-dev"
            })),
            package_ref: None,
            package_id: None,
            package_version: Some("0.1.0".to_string()),
            service_ref: None,
            transport: Some("websocket".to_string()),
            latency_target_ms: Some(200),
            interruptions_allowed: Some(true),
            privacy_tier: None,
            settlement_method: None,
        };

        let record = realtime_session_record_from_openai_request(&request, "fallback-requester");
        let verification = hivemind_realtime::verify_realtime_session(&record.session);
        let response = openai_realtime_session_from_record(&record, 10);

        assert!(verification.valid);
        assert_eq!(record.session.requester, "local-dev");
        assert_eq!(
            record.session.package_selector.package_id.as_deref(),
            Some("hivemind/realtime-agent")
        );
        assert_eq!(record.session.privacy.privacy_tier, PrivacyTier::NoLog);
        assert_eq!(record.session.latency_target_ms, 200);
        assert_eq!(record.session.tools.len(), 1);
        assert_eq!(response.object, "realtime.session");
        assert_eq!(response.status, "created");
        assert_eq!(response.model, "hivemind/realtime-agent");
        assert_eq!(response.voice.as_deref(), Some("alloy"));
        assert!(response.client_secret.is_some());
        assert_eq!(
            response.metadata["hivemind"]["compatibilityMode"],
            "contract-only"
        );
        assert_eq!(response.metadata["hivemind"]["transportMode"], "plan-only");
    }

    #[test]
    fn maps_openai_eval_and_run_to_signed_hivemind_contracts() {
        let request = OpenAiEvalCreateRequestV1 {
            name: "RAG answer quality".to_string(),
            data_source: Some(json!({
                "type": "jsonl",
                "file_id": "file-eval-dataset"
            })),
            testing_criteria: vec![json!({
                "type": "model_grader",
                "model": "hivemind/grader",
                "criteria": "answer correctness"
            })],
            metadata: Some(json!({ "requester": "local-dev" })),
            model: Some("hivemind/rag-agent".to_string()),
            owner: None,
            kind: Some("rag".to_string()),
            dataset_refs: Vec::new(),
            scoring_rule_refs: Vec::new(),
            target_refs: Vec::new(),
            grader_model: None,
            output_schema_ref: None,
        };
        let record = eval_manifest_record_from_openai_request(&request, "fallback-owner");
        let verification = hivemind_evals::verify_eval_manifest(&record.manifest);
        let response = openai_eval_from_record(&record, 10);

        assert!(verification.valid);
        assert_eq!(record.manifest.owner, "local-dev");
        assert_eq!(record.manifest.kind, EvalKind::Rag);
        assert_eq!(
            record.manifest.dataset_refs[0],
            "local://openai/files/file-eval-dataset"
        );
        assert_eq!(
            record.manifest.grader_model_ref.as_deref(),
            Some("local://openai/models/hivemind/grader")
        );
        assert_eq!(response.object, "eval");
        assert_eq!(
            response.metadata["hivemind"]["compatibilityMode"],
            "manifest-backed"
        );

        let run_request = OpenAiEvalRunCreateRequestV1 {
            name: Some("nightly".to_string()),
            model: Some("hivemind/rag-agent".to_string()),
            target_ref: None,
            input_refs: Vec::new(),
            data_source: Some(json!({ "file_ids": ["file-eval-dataset"] })),
            sample_count: Some(25),
            metadata: Some(json!({ "requester": "local-dev", "privacyTier": "no-log" })),
            privacy_tier: None,
            integrity_tier: Some("validator_spot_check".to_string()),
            settlement_method: None,
        };
        let run_record = eval_run_record_from_openai_request(
            &record.manifest.eval_id,
            &run_request,
            "fallback-requester",
        );
        let plan = hivemind_evals::eval_run_plan(&record.manifest, &run_record.run);
        let run_response = openai_eval_run_from_record(&run_record, Some(&record.manifest), 11);

        assert!(hivemind_evals::verify_eval_run(&run_record.run).valid);
        assert!(plan.valid);
        assert_eq!(run_record.run.sample_count, 25);
        assert_eq!(
            run_record.run.target_ref,
            "local://openai/models/hivemind/rag-agent"
        );
        assert_eq!(run_response.object, "eval.run");
        assert_eq!(run_response.status, "queued");
        assert_eq!(
            run_response.metadata["hivemind"]["executionMode"],
            "eval-planning"
        );
    }

    #[test]
    fn maps_openai_image_generation_to_media_job() {
        let request = OpenAiImageGenerationRequestV1 {
            model: Some("hivemind/image".to_string()),
            prompt: "a protocol workbench".to_string(),
            n: Some(2),
            size: Some("1024x1024".to_string()),
            quality: Some("standard".to_string()),
            style: Some("natural".to_string()),
            user: Some("local-dev".to_string()),
            response_format: Some("url".to_string()),
            background: None,
            output_format: None,
            output_ref: Some("local://media/output/image".to_string()),
            metadata: Some(json!({ "privacyTier": "no-log" })),
            package_ref: None,
            package_id: None,
            package_version: Some("0.1.0".to_string()),
            service_ref: None,
            privacy_tier: None,
        };

        let job = media_job_from_openai_image_generation(&request, "fallback-requester");
        let verification = hivemind_media::verify_media_job(&job);
        let response = openai_image_generation_from_media_job(&request, &job, 10);

        assert!(verification.valid);
        assert_eq!(job.task, hivemind_media::MediaTask::ImageGeneration);
        assert_eq!(job.requester, "local-dev");
        assert_eq!(
            job.package_selector.package_id.as_deref(),
            Some("hivemind/image")
        );
        assert_eq!(job.output_policy.count, 2);
        assert_eq!(response.data.len(), 2);
        assert_eq!(
            response.metadata["hivemind"]["compatibilityMode"],
            "contract-only"
        );
    }

    #[test]
    fn maps_openai_image_edit_to_media_job() {
        let request = OpenAiImageEditRequestV1 {
            model: Some("hivemind/image-edit".to_string()),
            image: "file-image".to_string(),
            image_ref: None,
            prompt: "replace the background with a clean workbench".to_string(),
            mask: Some("file-mask".to_string()),
            mask_ref: None,
            n: Some(1),
            size: Some("1024x1024".to_string()),
            user: Some("local-dev".to_string()),
            response_format: Some("url".to_string()),
            output_format: Some("png".to_string()),
            output_ref: Some("local://media/output/edit.png".to_string()),
            metadata: Some(json!({ "privacyTier": "no-log" })),
            package_ref: None,
            package_id: None,
            package_version: Some("0.1.0".to_string()),
            service_ref: None,
            privacy_tier: None,
        };

        let job = media_job_from_openai_image_edit(&request, "fallback-requester");
        let verification = hivemind_media::verify_media_job(&job);
        let response = openai_image_edit_from_media_job(&request, &job, 10);

        assert!(verification.valid);
        assert_eq!(job.task, hivemind_media::MediaTask::ImageEdit);
        assert_eq!(job.requester, "local-dev");
        assert_eq!(
            job.input.input_ref.as_deref(),
            Some("local://openai/files/file-image")
        );
        assert_eq!(
            job.input.mask_ref.as_deref(),
            Some("local://openai/files/file-mask")
        );
        assert_eq!(
            response.data[0].url.as_deref(),
            Some("local://media/output/edit.png")
        );
        assert_eq!(
            response.metadata["hivemind"]["executionMode"],
            "media-planning"
        );
    }

    #[test]
    fn maps_openai_audio_requests_to_media_jobs() {
        let transcription = OpenAiAudioTranscriptionRequestV1 {
            model: "hivemind/transcribe".to_string(),
            file: Some("file-audio".to_string()),
            file_ref: None,
            prompt: Some("Names may be technical.".to_string()),
            language: Some("en".to_string()),
            response_format: Some("json".to_string()),
            temperature: Some(0.0),
            timestamp_granularities: vec!["word".to_string()],
            metadata: Some(json!({ "requester": "local-dev" })),
            package_ref: None,
            package_id: None,
            package_version: None,
            service_ref: None,
            privacy_tier: None,
        };
        let transcription_job =
            media_job_from_openai_audio_transcription(&transcription, "fallback-requester");
        let transcription_response =
            openai_audio_transcription_from_media_job(&transcription, &transcription_job);

        assert!(hivemind_media::verify_media_job(&transcription_job).valid);
        assert_eq!(
            transcription_job.input.input_ref.as_deref(),
            Some("local://openai/files/file-audio")
        );
        assert!(transcription_response.text.contains("file-audio"));

        let speech = OpenAiAudioSpeechRequestV1 {
            model: "hivemind/speech".to_string(),
            input: "hello".to_string(),
            voice: "alloy".to_string(),
            response_format: Some("mp3".to_string()),
            speed: Some(1.0),
            output_ref: Some("local://media/output/speech.mp3".to_string()),
            metadata: Some(json!({ "requester": "local-dev" })),
            package_ref: None,
            package_id: None,
            package_version: None,
            service_ref: None,
            privacy_tier: None,
        };
        let speech_job = media_job_from_openai_audio_speech(&speech, "fallback-requester");
        let speech_response = openai_audio_speech_from_media_job(&speech, &speech_job);

        assert!(hivemind_media::verify_media_job(&speech_job).valid);
        assert_eq!(speech_job.task, hivemind_media::MediaTask::TextToSpeech);
        assert_eq!(speech_response.audio_ref, "local://media/output/speech.mp3");
        assert_eq!(
            speech_response.metadata["hivemind"]["executionMode"],
            "media-planning"
        );
    }

    fn manifest() -> hivemind_core::PackageManifestV1 {
        hivemind_core::PackageManifestV1 {
            schema_version: "swarm-ai.package.v1".to_string(),
            package_id: "hivemind/hello-chat".to_string(),
            kind: hivemind_core::PackageKind::Model,
            name: "Hello Chat".to_string(),
            version: "0.1.0".to_string(),
            publisher: hivemind_core::Publisher {
                address: "0xPublisher".to_string(),
                display_name: "Hivemind Labs".to_string(),
                publisher_profile_ref: None,
            },
            capabilities: vec!["chat".to_string()],
            artifact_groups: vec![hivemind_core::ArtifactGroup {
                id: "local".to_string(),
                target: "local".to_string(),
                engine: "mock".to_string(),
                format: "json".to_string(),
                paths: vec!["model/config.json".to_string()],
                total_bytes: 1,
                sha256: "0".repeat(64),
                minimum: hivemind_core::ArtifactMinimum {
                    memory_mb: Some(1),
                    webgpu: Some(false),
                    disk_mb: None,
                },
            }],
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            permissions: Vec::new(),
            license: hivemind_core::LicenseInfo {
                license_type: hivemind_core::LicenseType::Open,
                name: Some("Apache-2.0".to_string()),
                url: None,
            },
        }
    }
}
