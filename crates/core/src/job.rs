use crate::access::AccessGrantV1;
use crate::canonical::{canonicalize_json, hash_canonical_json};
use crate::errors::{ErrorCode, SwarmAiErrorV1};
use crate::execution::{ExecutionOptions, ExecutionPrivacy, ExecutionRequestV1, ReceiptMode};
use crate::runner::{RunnerCapabilityV1, RunnerPriceEntryV1};
use crate::trust::{DataRetentionRule, IntegrityTier, LoggingRule, PrivacyTier};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const JOB_ORDER_SCHEMA_VERSION: &str = "hivemind.job_order.v1";
pub const JOB_QUOTE_SCHEMA_VERSION: &str = "hivemind.quote.v1";
pub const EXECUTION_LEASE_SCHEMA_VERSION: &str = "hivemind.execution_lease.v1";
pub const EXECUTION_LEASE_REQUEST_SCHEMA_VERSION: &str = "hivemind.execution_lease_request.v1";
pub const STREAMING_EVENT_SCHEMA_VERSION: &str = "hivemind.stream_event.v1";
pub const LEGACY_JOB_ORDER_SCHEMA_VERSION: &str = "swarm-ai.job-order.v1";
pub const LEGACY_JOB_QUOTE_SCHEMA_VERSION: &str = "swarm-ai.job-quote.v1";
pub const LEGACY_EXECUTION_LEASE_SCHEMA_VERSION: &str = "swarm-ai.execution-lease.v1";
pub const LEGACY_EXECUTION_LEASE_REQUEST_SCHEMA_VERSION: &str =
    "swarm-ai.execution-lease-request.v1";
pub const LEGACY_STREAMING_EVENT_SCHEMA_VERSION: &str = "swarm-ai.streaming-event.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApiSurface {
    HivemindNative,
    #[serde(rename = "openai_chat_completions")]
    OpenAiChatCompletions,
    #[serde(rename = "openai_responses")]
    OpenAiResponses,
    #[serde(rename = "openai_embeddings")]
    OpenAiEmbeddings,
    #[serde(rename = "openai_vector_stores")]
    OpenAiVectorStores,
    #[serde(rename = "openai_images")]
    OpenAiImages,
    #[serde(rename = "openai_audio")]
    OpenAiAudio,
    #[serde(rename = "openai_batches")]
    OpenAiBatches,
    #[serde(rename = "openai_fine_tuning")]
    OpenAiFineTuning,
    #[serde(rename = "openai_evals")]
    OpenAiEvals,
    #[serde(rename = "openai_realtime")]
    OpenAiRealtime,
    AnthropicMessages,
    GeminiGenerateContent,
    GeminiLive,
    #[serde(rename = "huggingface_inference")]
    HuggingFaceInference,
    RagQuery,
    VectorSearch,
    ImageGeneration,
    ImageUnderstanding,
    SpeechToText,
    TextToSpeech,
    RealtimeSession,
    Batch,
    FineTune,
    EvalRun,
    Moderation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    Text,
    Chat,
    StructuredOutput,
    Embedding,
    Image,
    Audio,
    Video,
    Document,
    File,
    ToolCall,
    BrowserAction,
    VectorSearch,
    TrainingData,
    EvaluationData,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PriceV1 {
    pub amount: f64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PriceModel {
    Fixed,
    PerToken,
    PerSecond,
    PerImage,
    PerAudioMinute,
    PerEmbedding,
    PerBatchItem,
    Auction,
    Subscription,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionConstraintsV1 {
    #[serde(default)]
    pub stream: bool,
    #[serde(rename = "deadlineMs", default)]
    pub deadline_ms: Option<u64>,
    #[serde(rename = "maxLatencyMs", default)]
    pub max_latency_ms: Option<u64>,
    #[serde(default)]
    pub deterministic: Option<bool>,
}

impl From<&ExecutionOptions> for ExecutionConstraintsV1 {
    fn from(options: &ExecutionOptions) -> Self {
        Self {
            stream: options.stream,
            deadline_ms: options.deadline_ms,
            max_latency_ms: options.deadline_ms,
            deterministic: options.deterministic,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OutputContractV1 {
    pub task: String,
    #[serde(rename = "outputSchemaRef", default)]
    pub output_schema_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RetryPolicyV1 {
    #[serde(rename = "maxAttempts")]
    pub max_attempts: u32,
    #[serde(rename = "retryableErrorCodes")]
    pub retryable_error_codes: Vec<ErrorCode>,
}

impl Default for RetryPolicyV1 {
    fn default() -> Self {
        Self {
            max_attempts: 1,
            retryable_error_codes: vec![
                ErrorCode::RunnerOverloaded,
                ErrorCode::DeadlineExceeded,
                ErrorCode::ExecutionFailed,
                ErrorCode::UnsupportedTarget,
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobPrivacyV1 {
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

impl From<&ExecutionPrivacy> for JobPrivacyV1 {
    fn from(privacy: &ExecutionPrivacy) -> Self {
        Self {
            privacy_tier: match privacy.receipt_mode {
                ReceiptMode::HashOnly => PrivacyTier::NoLog,
                ReceiptMode::EncryptedEvidence => PrivacyTier::RedactedInput,
                ReceiptMode::PublicEvidence => PrivacyTier::Standard,
            },
            receipt_mode: privacy.receipt_mode.clone(),
            data_retention_rule: None,
            logging_rule: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobOrderV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub requester: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    pub modalities: Vec<Modality>,
    pub task: String,
    #[serde(rename = "inputHash")]
    pub input_hash: String,
    #[serde(rename = "preferredArtifactGroup", default)]
    pub preferred_artifact_group: Option<String>,
    #[serde(rename = "outputContract")]
    pub output_contract: OutputContractV1,
    pub constraints: ExecutionConstraintsV1,
    pub privacy: JobPrivacyV1,
    #[serde(rename = "requiredVerificationTier")]
    pub required_verification_tier: IntegrityTier,
    #[serde(rename = "accessGrantRef", default)]
    pub access_grant_ref: Option<String>,
    #[serde(rename = "maxPrice", default)]
    pub max_price: Option<PriceV1>,
    #[serde(rename = "validationRequired")]
    pub validation_required: bool,
    #[serde(rename = "settlementMethod")]
    pub settlement_method: String,
    #[serde(rename = "retryPolicy")]
    pub retry_policy: RetryPolicyV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JobQuoteV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "routeId", default)]
    pub route_id: Option<String>,
    pub price: PriceV1,
    #[serde(rename = "priceModel")]
    pub price_model: PriceModel,
    #[serde(rename = "privacyMode")]
    pub privacy_mode: PrivacyTier,
    #[serde(rename = "verificationMode")]
    pub verification_mode: IntegrityTier,
    #[serde(rename = "estimatedStartDelayMs")]
    pub estimated_start_delay_ms: u64,
    #[serde(rename = "estimatedTimeToFirstOutputMs", default)]
    pub estimated_time_to_first_output_ms: Option<u64>,
    #[serde(rename = "estimatedCompletionMs", default)]
    pub estimated_completion_ms: Option<u64>,
    #[serde(rename = "cacheHitClaim")]
    pub cache_hit_claim: bool,
    #[serde(rename = "validationSupport")]
    pub validation_support: Vec<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(default = "empty_terms")]
    pub terms: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionLeaseRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobOrder")]
    pub job_order: JobOrderV1,
    pub quote: JobQuoteV1,
    pub requester: String,
    #[serde(rename = "settlementRef")]
    pub settlement_ref: String,
    #[serde(
        rename = "startAfter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub start_after: Option<String>,
    pub deadline: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionLeaseV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "leaseId")]
    pub lease_id: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub requester: String,
    #[serde(
        rename = "allowedInputRefs",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allowed_input_refs: Vec<String>,
    #[serde(
        rename = "allowedInputHashes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub allowed_input_hashes: Vec<String>,
    #[serde(rename = "allowedPackageRefs")]
    pub allowed_package_refs: Vec<String>,
    #[serde(rename = "maxCost")]
    pub max_cost: PriceV1,
    #[serde(
        rename = "startAfter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub start_after: Option<String>,
    pub deadline: String,
    #[serde(rename = "cancellationRules", default = "empty_terms")]
    pub cancellation_rules: Value,
    #[serde(rename = "settlementRef")]
    pub settlement_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StreamingEventType {
    Started,
    Heartbeat,
    TextDelta,
    TokenDelta,
    AudioChunk,
    ImageProgress,
    VideoFrame,
    EmbeddingProgress,
    ToolCallRequested,
    ToolCallResult,
    RetrievalEvent,
    SafetyEvent,
    LogEvent,
    PartialReceipt,
    Completed,
    Error,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StreamingEventV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "eventId")]
    pub event_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "jobId", default)]
    pub job_id: Option<String>,
    pub sequence: u64,
    #[serde(rename = "type")]
    pub event_type: StreamingEventType,
    pub timestamp: String,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

pub fn job_order_from_execution_request(
    request: &ExecutionRequestV1,
    requester: impl Into<String>,
    api_surface: ApiSurface,
) -> JobOrderV1 {
    let mut order = JobOrderV1 {
        schema_version: JOB_ORDER_SCHEMA_VERSION.to_string(),
        job_id: String::new(),
        request_id: request.request_id.clone(),
        requester: requester.into(),
        package_ref: request.package_ref.clone(),
        package_id: request.package_id.clone(),
        package_version: request.package_version.clone(),
        api_surface,
        modalities: modalities_for_task(&request.task),
        task: request.task.clone(),
        input_hash: execution_request_input_hash(request),
        preferred_artifact_group: request.preferred_artifact_group.clone(),
        output_contract: OutputContractV1 {
            task: request.task.clone(),
            output_schema_ref: None,
        },
        constraints: ExecutionConstraintsV1::from(&request.options),
        privacy: JobPrivacyV1::from(&request.privacy),
        required_verification_tier: IntegrityTier::ReceiptOnly,
        access_grant_ref: request.access_grant.as_ref().map(access_grant_ref),
        max_price: None,
        validation_required: false,
        settlement_method: "free-local-dev".to_string(),
        retry_policy: RetryPolicyV1::default(),
        signature: None,
    };
    order.job_id = canonical_job_order_id(&order).expect("job order should serialize for id");
    order
}

pub fn execution_lease_from_quote(
    order: &JobOrderV1,
    quote: &JobQuoteV1,
    requester: impl Into<String>,
    settlement_ref: impl Into<String>,
    deadline: impl Into<String>,
) -> Result<ExecutionLeaseV1, SwarmAiErrorV1> {
    execution_lease_from_quote_with_start_after(
        order,
        quote,
        requester,
        settlement_ref,
        None,
        deadline,
    )
}

fn execution_lease_from_quote_with_start_after(
    order: &JobOrderV1,
    quote: &JobQuoteV1,
    requester: impl Into<String>,
    settlement_ref: impl Into<String>,
    start_after: Option<String>,
    deadline: impl Into<String>,
) -> Result<ExecutionLeaseV1, SwarmAiErrorV1> {
    let requester = requester.into();
    let settlement_ref = settlement_ref.into();
    let deadline = deadline.into();
    validate_execution_lease_inputs(
        order,
        quote,
        &requester,
        &settlement_ref,
        start_after.as_deref(),
        &deadline,
    )?;
    let mut lease = ExecutionLeaseV1 {
        schema_version: EXECUTION_LEASE_SCHEMA_VERSION.to_string(),
        lease_id: String::new(),
        job_id: order.job_id.clone(),
        quote_id: quote.quote_id.clone(),
        runner_id: quote.runner_id.clone(),
        requester,
        allowed_input_refs: execution_lease_allowed_input_refs(order),
        allowed_input_hashes: vec![order.input_hash.clone()],
        allowed_package_refs: vec![order.package_ref.clone()],
        max_cost: quote.price.clone(),
        start_after,
        deadline,
        cancellation_rules: json!({
            "runnerTimeoutMs": order.constraints.deadline_ms.unwrap_or(30_000),
            "allowRequesterCancel": true
        }),
        settlement_ref,
        signature: None,
    };
    lease.lease_id =
        canonical_execution_lease_id(&lease).expect("execution lease should serialize for id");
    Ok(lease)
}

pub fn execution_lease_from_request(
    request: &ExecutionLeaseRequestV1,
) -> Result<ExecutionLeaseV1, SwarmAiErrorV1> {
    if !matches!(
        request.schema_version.as_str(),
        EXECUTION_LEASE_REQUEST_SCHEMA_VERSION | LEGACY_EXECUTION_LEASE_REQUEST_SCHEMA_VERSION
    ) {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "execution lease request schemaVersion is not supported",
        ));
    }
    execution_lease_from_quote_with_start_after(
        &request.job_order,
        &request.quote,
        request.requester.clone(),
        request.settlement_ref.clone(),
        request.start_after.clone(),
        request.deadline.clone(),
    )
}

fn validate_execution_lease_inputs(
    order: &JobOrderV1,
    quote: &JobQuoteV1,
    requester: &str,
    settlement_ref: &str,
    start_after: Option<&str>,
    deadline: &str,
) -> Result<(), SwarmAiErrorV1> {
    if !matches!(
        order.schema_version.as_str(),
        JOB_ORDER_SCHEMA_VERSION | LEGACY_JOB_ORDER_SCHEMA_VERSION
    ) {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "job order schemaVersion is not supported",
        ));
    }
    if !matches!(
        quote.schema_version.as_str(),
        JOB_QUOTE_SCHEMA_VERSION | LEGACY_JOB_QUOTE_SCHEMA_VERSION
    ) {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "job quote schemaVersion is not supported",
        ));
    }
    if order.job_id.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "job order jobId is required",
        ));
    }
    let expected_job_id = canonical_job_order_id(order).map_err(|error| {
        SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            format!("job order could not be canonicalized: {error}"),
        )
    })?;
    if order.job_id != expected_job_id {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "job order jobId does not match canonical signed content",
        ));
    }
    if quote.quote_id.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "quote quoteId is required",
        ));
    }
    let expected_quote_id = canonical_job_quote_id(quote).map_err(|error| {
        SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            format!("quote could not be canonicalized: {error}"),
        )
    })?;
    if quote.quote_id != expected_quote_id {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "quote quoteId does not match canonical signed content",
        ));
    }
    if quote.job_id != order.job_id {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "quote jobId does not match job order",
        ));
    }
    if order.input_hash.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "job order inputHash is required for lease input authorization",
        ));
    }
    if order.package_ref.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "job order packageRef is required for lease package authorization",
        ));
    }
    if quote.runner_id.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "quote runnerId is required",
        ));
    }
    if requester.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "lease requester is required",
        ));
    }
    if requester != order.requester {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::AccessDenied,
            "lease requester does not match job order requester",
        ));
    }
    if settlement_ref.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "settlementRef is required",
        ));
    }
    if deadline.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "lease deadline is required",
        ));
    }
    let start_after = if let Some(start_after) = start_after {
        let start_after = start_after.trim();
        if start_after.is_empty() {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "startAfter must not be empty when present",
            ));
        }
        Some(DateTime::parse_from_rfc3339(start_after).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                format!("startAfter must be RFC3339: {error}"),
            )
        })?)
    } else {
        None
    };
    let quote_expires_at = DateTime::parse_from_rfc3339(&quote.expires_at).map_err(|error| {
        SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            format!("quote expiresAt must be RFC3339: {error}"),
        )
    })?;
    if quote_expires_at.with_timezone(&Utc) <= Utc::now() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::DeadlineExceeded,
            "quote has expired",
        ));
    }
    let lease_deadline = DateTime::parse_from_rfc3339(deadline).map_err(|error| {
        SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            format!("lease deadline must be RFC3339: {error}"),
        )
    })?;
    if lease_deadline.with_timezone(&Utc) <= Utc::now() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::DeadlineExceeded,
            "lease deadline has already passed",
        ));
    }
    if let Some(start_after) = start_after
        && start_after >= lease_deadline
    {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "startAfter must be before lease deadline",
        ));
    }
    if quote.price.amount < 0.0 {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "quote price must not be negative",
        ));
    }
    if quote.price.currency.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "quote price currency is required",
        ));
    }
    if let Some(max_price) = &order.max_price {
        if max_price.currency != quote.price.currency {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "quote currency does not match job maxPrice currency",
            ));
        }
        if quote.price.amount > max_price.amount {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::AccessDenied,
                "quote price exceeds job maxPrice",
            ));
        }
    }
    if !crate::trust::privacy_tier_satisfies(&quote.privacy_mode, &order.privacy.privacy_tier) {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::AccessDenied,
            "quote privacyMode does not satisfy job privacy tier",
        ));
    }
    if !integrity_tier_satisfies(&quote.verification_mode, &order.required_verification_tier) {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::AccessDenied,
            "quote verificationMode does not satisfy job required verification tier",
        ));
    }
    if quote.estimated_completion_ms.is_some()
        && quote.estimated_time_to_first_output_ms.is_some()
        && quote.estimated_completion_ms < quote.estimated_time_to_first_output_ms
    {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "quote estimatedCompletionMs is earlier than estimatedTimeToFirstOutputMs",
        ));
    }
    if order.validation_required && quote.validation_support.is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "job requires validation but quote declares no validation support",
        ));
    }
    Ok(())
}

pub fn job_quote_from_runner_capability(
    order: &JobOrderV1,
    capability: &RunnerCapabilityV1,
    route_id: Option<String>,
    expires_at: impl Into<String>,
) -> Result<JobQuoteV1, SwarmAiErrorV1> {
    if !capability.supported_apis.contains(&order.api_surface) {
        return Err(quote_rejection(
            "runner does not support the requested API surface",
        ));
    }
    for modality in &order.modalities {
        if !capability.supported_modalities.contains(modality) {
            return Err(quote_rejection(format!(
                "runner does not support requested modality {modality:?}"
            )));
        }
    }
    let Some(privacy_mode) =
        select_privacy_tier(&capability.privacy_tiers, &order.privacy.privacy_tier)
    else {
        return Err(quote_rejection(
            "runner does not satisfy the requested privacy tier",
        ));
    };
    let Some(verification_mode) = select_integrity_tier(
        &capability.verification_tiers,
        &order.required_verification_tier,
    ) else {
        return Err(quote_rejection(
            "runner does not satisfy the requested verification tier",
        ));
    };
    let price_entry = quote_price_entry(capability);
    if let Some(max_price) = &order.max_price {
        if max_price.currency != price_entry.price.currency {
            return Err(quote_rejection(
                "runner quote currency does not match job maxPrice currency",
            ));
        }
        if price_entry.price.amount > max_price.amount {
            return Err(quote_rejection("runner quote exceeds job maxPrice"));
        }
    }

    let cache_hit_claim = capability
        .cache_claims
        .iter()
        .any(|claim| claim.warmed && claim.package_ref == order.package_ref);
    let estimated_start_delay_ms = if cache_hit_claim { 0 } else { 250 };
    let mut quote = JobQuoteV1 {
        schema_version: JOB_QUOTE_SCHEMA_VERSION.to_string(),
        quote_id: String::new(),
        job_id: order.job_id.clone(),
        runner_id: capability.runner_id.clone(),
        route_id,
        price: price_entry.price.clone(),
        price_model: price_entry.price_model.clone(),
        privacy_mode,
        verification_mode,
        estimated_start_delay_ms,
        estimated_time_to_first_output_ms: if order.constraints.stream {
            Some(estimated_start_delay_ms + 100)
        } else {
            None
        },
        estimated_completion_ms: order.constraints.max_latency_ms.or(Some(1_000)),
        cache_hit_claim,
        validation_support: capability
            .verification_tiers
            .iter()
            .map(tier_wire_name)
            .collect(),
        expires_at: expires_at.into(),
        terms: json!({
            "unit": price_entry.unit,
            "apiSurface": tier_wire_name(&order.api_surface),
            "quoteInput": "metadata-only",
            "runnerCapabilitySchema": capability.schema_version
        }),
        signature: None,
    };
    quote.quote_id = canonical_job_quote_id(&quote).expect("job quote should serialize for id");
    Ok(quote)
}

pub fn streaming_event(
    request_id: impl Into<String>,
    job_id: Option<String>,
    sequence: u64,
    event_type: StreamingEventType,
    timestamp: impl Into<String>,
    payload: Value,
) -> StreamingEventV1 {
    let mut event = StreamingEventV1 {
        schema_version: STREAMING_EVENT_SCHEMA_VERSION.to_string(),
        event_id: String::new(),
        request_id: request_id.into(),
        job_id,
        sequence,
        event_type,
        timestamp: timestamp.into(),
        payload,
        signature: None,
    };
    event.event_id =
        canonical_streaming_event_id(&event).expect("streaming event should serialize for id");
    event
}

pub fn execution_request_input_hash(request: &ExecutionRequestV1) -> String {
    hash_canonical_json(&canonicalize_json(&request.input))
}

pub fn canonical_job_order_id(order: &JobOrderV1) -> serde_json::Result<String> {
    let mut unsigned = order.clone();
    unsigned.job_id.clear();
    unsigned.signature = None;
    stable_contract_id("job", &unsigned)
}

pub fn canonical_job_quote_id(quote: &JobQuoteV1) -> serde_json::Result<String> {
    let mut unsigned = quote.clone();
    unsigned.quote_id.clear();
    unsigned.signature = None;
    stable_contract_id("quote", &unsigned)
}

pub fn canonical_execution_lease_id(lease: &ExecutionLeaseV1) -> serde_json::Result<String> {
    let mut unsigned = lease.clone();
    unsigned.lease_id.clear();
    unsigned.signature = None;
    stable_contract_id("lease", &unsigned)
}

pub fn canonical_streaming_event_id(event: &StreamingEventV1) -> serde_json::Result<String> {
    let mut unsigned = event.clone();
    unsigned.event_id.clear();
    unsigned.signature = None;
    stable_contract_id("stream", &unsigned)
}

fn execution_lease_allowed_input_refs(order: &JobOrderV1) -> Vec<String> {
    let input_hash = order.input_hash.trim();
    if input_hash.is_empty() {
        Vec::new()
    } else {
        vec![format!("sha256://{input_hash}")]
    }
}

fn modalities_for_task(task: &str) -> Vec<Modality> {
    match task {
        "chat" => vec![Modality::Chat, Modality::Text],
        "embedding" => vec![Modality::Embedding, Modality::Text],
        "ocr" => vec![Modality::Image, Modality::Text],
        "classification" => vec![Modality::Text, Modality::StructuredOutput],
        "vector-search" => vec![Modality::VectorSearch],
        _ => vec![Modality::Text],
    }
}

fn quote_price_entry(capability: &RunnerCapabilityV1) -> RunnerPriceEntryV1 {
    capability
        .price_table
        .first()
        .cloned()
        .unwrap_or(RunnerPriceEntryV1 {
            price_model: PriceModel::Fixed,
            unit: "request".to_string(),
            price: PriceV1 {
                amount: 0.0,
                currency: "none".to_string(),
            },
        })
}

fn select_privacy_tier(available: &[PrivacyTier], required: &PrivacyTier) -> Option<PrivacyTier> {
    available
        .iter()
        .find(|tier| crate::trust::privacy_tier_satisfies(tier, required))
        .cloned()
}

fn select_integrity_tier(
    available: &[IntegrityTier],
    required: &IntegrityTier,
) -> Option<IntegrityTier> {
    available
        .iter()
        .find(|tier| integrity_tier_satisfies(tier, required))
        .cloned()
}

fn integrity_tier_satisfies(available: &IntegrityTier, required: &IntegrityTier) -> bool {
    available == required || matches!(required, IntegrityTier::ReceiptOnly)
}

fn tier_wire_name(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn quote_rejection(message: impl Into<String>) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(ErrorCode::UnsupportedTarget, message)
}

fn access_grant_ref(grant: &AccessGrantV1) -> String {
    if grant.grant_id.trim().is_empty() {
        grant.signature.clone()
    } else {
        grant.grant_id.clone()
    }
}

fn stable_contract_id(prefix: &str, value: &impl Serialize) -> serde_json::Result<String> {
    let value = serde_json::to_value(value)?;
    Ok(format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    ))
}

fn empty_terms() -> Value {
    json!({})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::{ExecutionOptions, ReceiptMode};
    use crate::runner::{
        RunnerDescriptorV1, RunnerLimits, RunnerType, runner_capability_from_descriptor,
    };

    fn request_with_input(input: Value) -> ExecutionRequestV1 {
        ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: "hivemind/test".to_string(),
            package_version: "0.1.0".to_string(),
            preferred_artifact_group: Some("local-rust".to_string()),
            task: "embedding".to_string(),
            input,
            options: ExecutionOptions {
                stream: true,
                deadline_ms: Some(15_000),
                deterministic: Some(true),
            },
            privacy: ExecutionPrivacy {
                receipt_mode: ReceiptMode::HashOnly,
            },
            access_grant: None,
            access_revocation_list: None,
        }
    }

    fn quote_for_order(order: &JobOrderV1) -> JobQuoteV1 {
        let mut quote = JobQuoteV1 {
            schema_version: JOB_QUOTE_SCHEMA_VERSION.to_string(),
            quote_id: String::new(),
            job_id: order.job_id.clone(),
            runner_id: "runner-1".to_string(),
            route_id: Some("local-runner-1".to_string()),
            price: PriceV1 {
                amount: 0.0,
                currency: "none".to_string(),
            },
            price_model: PriceModel::Fixed,
            privacy_mode: PrivacyTier::NoLog,
            verification_mode: IntegrityTier::ReceiptOnly,
            estimated_start_delay_ms: 0,
            estimated_time_to_first_output_ms: Some(100),
            estimated_completion_ms: Some(500),
            cache_hit_claim: true,
            validation_support: vec!["receipt".to_string()],
            expires_at: "2030-05-31T00:00:00Z".to_string(),
            terms: json!({}),
            signature: None,
        };
        quote.quote_id = canonical_job_quote_id(&quote).unwrap();
        quote
    }

    #[test]
    fn job_order_hashes_inline_input_canonically() {
        let left = request_with_input(json!({ "b": 2, "a": 1 }));
        let right = request_with_input(json!({ "a": 1, "b": 2 }));

        let left_order =
            job_order_from_execution_request(&left, "local-dev", ApiSurface::HivemindNative);
        let right_order =
            job_order_from_execution_request(&right, "local-dev", ApiSurface::HivemindNative);

        assert_eq!(left_order.input_hash, right_order.input_hash);
        assert_eq!(left_order.job_id, right_order.job_id);
        assert_eq!(left_order.schema_version, JOB_ORDER_SCHEMA_VERSION);
        assert_eq!(
            left_order.modalities,
            vec![Modality::Embedding, Modality::Text]
        );
        assert_eq!(left_order.constraints.deadline_ms, Some(15_000));
        assert_eq!(left_order.privacy.privacy_tier, PrivacyTier::NoLog);
        assert_eq!(
            left_order.required_verification_tier,
            IntegrityTier::ReceiptOnly
        );
    }

    #[test]
    fn api_surface_wire_names_match_public_contract() {
        assert_eq!(
            serde_json::to_value(ApiSurface::OpenAiChatCompletions).unwrap(),
            json!("openai_chat_completions")
        );
        assert_eq!(
            serde_json::to_value(ApiSurface::OpenAiEmbeddings).unwrap(),
            json!("openai_embeddings")
        );
        assert_eq!(
            serde_json::to_value(ApiSurface::OpenAiVectorStores).unwrap(),
            json!("openai_vector_stores")
        );
        assert_eq!(
            serde_json::to_value(ApiSurface::OpenAiFineTuning).unwrap(),
            json!("openai_fine_tuning")
        );
        assert_eq!(
            serde_json::to_value(ApiSurface::HuggingFaceInference).unwrap(),
            json!("huggingface_inference")
        );
        assert_eq!(
            serde_json::to_value(ApiSurface::GeminiLive).unwrap(),
            json!("gemini_live")
        );
    }

    #[test]
    fn execution_lease_requires_matching_quote_job() {
        let request = request_with_input(json!({ "text": "hello" }));
        let order =
            job_order_from_execution_request(&request, "local-dev", ApiSurface::HivemindNative);
        let mut quote = JobQuoteV1 {
            schema_version: JOB_QUOTE_SCHEMA_VERSION.to_string(),
            quote_id: String::new(),
            job_id: order.job_id.clone(),
            runner_id: "runner-1".to_string(),
            route_id: Some("local-runner-1".to_string()),
            price: PriceV1 {
                amount: 0.0,
                currency: "none".to_string(),
            },
            price_model: PriceModel::Fixed,
            privacy_mode: PrivacyTier::NoLog,
            verification_mode: IntegrityTier::ReceiptOnly,
            estimated_start_delay_ms: 0,
            estimated_time_to_first_output_ms: Some(100),
            estimated_completion_ms: Some(500),
            cache_hit_claim: true,
            validation_support: vec!["receipt".to_string()],
            expires_at: "2030-05-31T00:00:00Z".to_string(),
            terms: json!({}),
            signature: None,
        };
        quote.quote_id = canonical_job_quote_id(&quote).unwrap();

        let lease = execution_lease_from_quote(
            &order,
            &quote,
            "local-dev",
            "local://settlement/free",
            "2030-05-31T00:05:00Z",
        )
        .unwrap();

        assert_eq!(lease.job_id, order.job_id);
        assert_eq!(lease.schema_version, EXECUTION_LEASE_SCHEMA_VERSION);
        assert_eq!(lease.quote_id, quote.quote_id);
        assert_eq!(
            lease.allowed_input_refs,
            vec![format!("sha256://{}", order.input_hash)]
        );
        assert_eq!(lease.allowed_input_hashes, vec![order.input_hash.clone()]);
        assert!(lease.lease_id.starts_with("lease-"));

        quote.job_id = "job-other".to_string();
        assert!(
            execution_lease_from_quote(
                &order,
                &quote,
                "local-dev",
                "local://settlement/free",
                "2030-05-31T00:05:00Z",
            )
            .is_err()
        );
    }

    #[test]
    fn execution_lease_rejects_tampered_quote_requester_and_budget_mismatch() {
        let request = request_with_input(json!({ "text": "hello" }));
        let mut order =
            job_order_from_execution_request(&request, "local-dev", ApiSurface::HivemindNative);
        let quote = quote_for_order(&order);

        let mut tampered_order = order.clone();
        tampered_order.package_version = "9.9.9".to_string();
        let order_error = execution_lease_from_quote(
            &tampered_order,
            &quote,
            "local-dev",
            "local://settlement/free",
            "2030-05-31T00:05:00Z",
        )
        .unwrap_err();
        assert_eq!(order_error.code, ErrorCode::InvalidRequest);
        assert!(order_error.message.contains("jobId"));

        let mut tampered_quote = quote.clone();
        tampered_quote.price.amount = 10.0;
        let tampered = execution_lease_from_quote(
            &order,
            &tampered_quote,
            "local-dev",
            "local://settlement/free",
            "2030-05-31T00:05:00Z",
        )
        .unwrap_err();
        assert_eq!(tampered.code, ErrorCode::InvalidRequest);
        assert!(tampered.message.contains("quoteId"));

        let wrong_requester = execution_lease_from_quote(
            &order,
            &quote,
            "other-requester",
            "local://settlement/free",
            "2030-05-31T00:05:00Z",
        )
        .unwrap_err();
        assert_eq!(wrong_requester.code, ErrorCode::AccessDenied);

        order.max_price = Some(PriceV1 {
            amount: 0.0,
            currency: "USD".to_string(),
        });
        order.job_id = canonical_job_order_id(&order).unwrap();
        let budget_quote = quote_for_order(&order);
        let budget_mismatch = execution_lease_from_quote(
            &order,
            &budget_quote,
            "local-dev",
            "local://settlement/free",
            "2030-05-31T00:05:00Z",
        )
        .unwrap_err();
        assert_eq!(budget_mismatch.code, ErrorCode::InvalidRequest);
        assert!(budget_mismatch.message.contains("currency"));
    }

    #[test]
    fn execution_lease_rejects_expired_quote_and_unsupported_modes() {
        let request = request_with_input(json!({ "text": "hello" }));
        let order =
            job_order_from_execution_request(&request, "local-dev", ApiSurface::HivemindNative);
        let mut expired_quote = quote_for_order(&order);
        expired_quote.expires_at = "2026-05-31T00:00:00Z".to_string();
        expired_quote.quote_id = canonical_job_quote_id(&expired_quote).unwrap();

        let expired = execution_lease_from_quote(
            &order,
            &expired_quote,
            "local-dev",
            "local://settlement/free",
            "2030-05-31T00:05:00Z",
        )
        .unwrap_err();
        assert_eq!(expired.code, ErrorCode::DeadlineExceeded);

        let mut unsupported_privacy = quote_for_order(&order);
        unsupported_privacy.privacy_mode = PrivacyTier::Standard;
        unsupported_privacy.quote_id = canonical_job_quote_id(&unsupported_privacy).unwrap();
        let privacy = execution_lease_from_quote(
            &order,
            &unsupported_privacy,
            "local-dev",
            "local://settlement/free",
            "2030-05-31T00:05:00Z",
        )
        .unwrap_err();
        assert_eq!(privacy.code, ErrorCode::AccessDenied);
        assert!(privacy.message.contains("privacyMode"));

        let bad_start = execution_lease_from_quote_with_start_after(
            &order,
            &quote_for_order(&order),
            "local-dev",
            "local://settlement/free",
            Some("2030-05-31T00:06:00Z".to_string()),
            "2030-05-31T00:05:00Z",
        )
        .unwrap_err();
        assert_eq!(bad_start.code, ErrorCode::InvalidRequest);
        assert!(bad_start.message.contains("startAfter"));
    }

    #[test]
    fn job_quote_from_runner_capability_enforces_metadata_constraints() {
        let request = request_with_input(json!({ "text": "hello" }));
        let mut order =
            job_order_from_execution_request(&request, "local-dev", ApiSurface::HivemindNative);
        let remote = runner_capability_from_descriptor(&RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: "remote-1".to_string(),
            runner_type: RunnerType::RemoteGpu,
            targets: vec!["cuda-vllm".to_string()],
            engines: vec!["vllm".to_string()],
            capabilities: vec!["embedding".to_string()],
            limits: RunnerLimits {
                max_memory_mb: 24 * 1024,
                max_input_bytes: 64 * 1024,
                max_concurrent_jobs: 4,
            },
            queue_depth: 0,
            warm_package_refs: vec!["bzz://pkg".to_string()],
        });

        let quote = job_quote_from_runner_capability(
            &order,
            &remote,
            Some("remote-route".to_string()),
            "2030-05-31T00:05:00Z",
        )
        .unwrap();

        assert_eq!(quote.job_id, order.job_id);
        assert_eq!(quote.schema_version, JOB_QUOTE_SCHEMA_VERSION);
        assert_eq!(quote.runner_id, "remote-1");
        assert_eq!(quote.privacy_mode, PrivacyTier::NoLog);
        assert_eq!(quote.verification_mode, IntegrityTier::ReceiptOnly);
        assert!(quote.cache_hit_claim);
        assert!(quote.quote_id.starts_with("quote-"));

        order.privacy.privacy_tier = PrivacyTier::LocalOnly;
        assert!(
            job_quote_from_runner_capability(&order, &remote, None, "2030-05-31T00:05:00Z")
                .is_err()
        );
    }

    #[test]
    fn local_runner_can_satisfy_no_log_privacy_with_stronger_local_mode() {
        let request = request_with_input(json!({ "text": "hello" }));
        let order =
            job_order_from_execution_request(&request, "local-dev", ApiSurface::HivemindNative);
        let local = runner_capability_from_descriptor(&RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: "local-1".to_string(),
            runner_type: RunnerType::Local,
            targets: vec!["local-mock".to_string()],
            engines: vec!["rust-mock".to_string()],
            capabilities: vec!["embedding".to_string()],
            limits: RunnerLimits {
                max_memory_mb: 1024,
                max_input_bytes: 1024,
                max_concurrent_jobs: 1,
            },
            queue_depth: 0,
            warm_package_refs: Vec::new(),
        });

        let quote =
            job_quote_from_runner_capability(&order, &local, None, "2030-05-31T00:05:00Z").unwrap();

        assert_eq!(quote.privacy_mode, PrivacyTier::LocalOnly);
        assert_eq!(quote.verification_mode, IntegrityTier::ReceiptOnly);
    }

    #[test]
    fn streaming_event_ids_include_sequence_and_payload() {
        let first = streaming_event(
            "request-1",
            Some("job-1".to_string()),
            1,
            StreamingEventType::TextDelta,
            "2026-05-31T00:00:00Z",
            json!({ "text": "hello" }),
        );
        let second = streaming_event(
            "request-1",
            Some("job-1".to_string()),
            2,
            StreamingEventType::TextDelta,
            "2026-05-31T00:00:00Z",
            json!({ "text": "hello" }),
        );

        assert_ne!(first.event_id, second.event_id);
        assert_eq!(first.schema_version, STREAMING_EVENT_SCHEMA_VERSION);
        assert!(first.event_id.starts_with("stream-"));
    }

    #[test]
    fn execution_lease_request_accepts_legacy_schema_version() {
        let request = request_with_input(json!({ "text": "hello" }));
        let order =
            job_order_from_execution_request(&request, "local-dev", ApiSurface::HivemindNative);
        let mut quote = JobQuoteV1 {
            schema_version: JOB_QUOTE_SCHEMA_VERSION.to_string(),
            quote_id: String::new(),
            job_id: order.job_id.clone(),
            runner_id: "runner-1".to_string(),
            route_id: None,
            price: PriceV1 {
                amount: 0.0,
                currency: "none".to_string(),
            },
            price_model: PriceModel::Fixed,
            privacy_mode: PrivacyTier::NoLog,
            verification_mode: IntegrityTier::ReceiptOnly,
            estimated_start_delay_ms: 0,
            estimated_time_to_first_output_ms: None,
            estimated_completion_ms: Some(500),
            cache_hit_claim: false,
            validation_support: vec!["receipt".to_string()],
            expires_at: "2030-05-31T00:00:00Z".to_string(),
            terms: json!({}),
            signature: None,
        };
        quote.quote_id = canonical_job_quote_id(&quote).unwrap();
        let request = ExecutionLeaseRequestV1 {
            schema_version: LEGACY_EXECUTION_LEASE_REQUEST_SCHEMA_VERSION.to_string(),
            job_order: order,
            quote,
            requester: "local-dev".to_string(),
            settlement_ref: "local://settlement/free".to_string(),
            start_after: Some("2030-05-31T00:00:00Z".to_string()),
            deadline: "2030-05-31T00:05:00Z".to_string(),
        };

        let lease = execution_lease_from_request(&request).unwrap();

        assert_eq!(lease.schema_version, EXECUTION_LEASE_SCHEMA_VERSION);
        assert_eq!(lease.start_after, request.start_after);
        assert!(lease.lease_id.starts_with("lease-"));
    }
}
