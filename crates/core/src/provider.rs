use crate::job::ApiSurface;
use crate::trust::{IntegrityTier, PrivacyTier};
use crate::validation::ValidationIssue;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const PROVIDER_IDENTITY_SCHEMA_VERSION: &str = "hivemind.provider.identity.v1";
pub const PROVIDER_MODEL_OFFER_SCHEMA_VERSION: &str = "hivemind.provider.model_offer.v1";
pub const PROVIDER_HEALTH_SCHEMA_VERSION: &str = "hivemind.provider.health.v1";
pub const MODEL_LIFECYCLE_STATE_SCHEMA_VERSION: &str = "hivemind.provider.model_lifecycle_state.v1";
pub const PROVIDER_MODEL_START_REQUEST_SCHEMA_VERSION: &str =
    "hivemind.provider.model_start_request.v1";
pub const PROVIDER_MODEL_STOP_REQUEST_SCHEMA_VERSION: &str =
    "hivemind.provider.model_stop_request.v1";
pub const PROVIDER_QUOTE_REQUEST_SCHEMA_VERSION: &str = "hivemind.provider.quote_request.v1";
pub const PROVIDER_QUOTE_SCHEMA_VERSION: &str = "hivemind.provider.quote.v1";
pub const PROVIDER_SESSION_OPEN_REQUEST_SCHEMA_VERSION: &str =
    "hivemind.provider.session_open_request.v1";
pub const PROVIDER_SESSION_CLOSE_REQUEST_SCHEMA_VERSION: &str =
    "hivemind.provider.session_close_request.v1";
pub const PROVIDER_SESSION_SCHEMA_VERSION: &str = "hivemind.provider.session.v1";
pub const PROVIDER_CHAT_REQUEST_SCHEMA_VERSION: &str = "hivemind.provider.chat_request.v1";
pub const PROVIDER_JOB_CANCEL_REQUEST_SCHEMA_VERSION: &str =
    "hivemind.provider.job_cancel_request.v1";
pub const PROVIDER_JOB_CANCEL_RESPONSE_SCHEMA_VERSION: &str =
    "hivemind.provider.job_cancel_response.v1";
pub const PROVIDER_STREAM_EVENT_SCHEMA_VERSION: &str = "hivemind.provider.stream_event.v1";
pub const PROVIDER_CHAT_RECEIPT_SCHEMA_VERSION: &str = "hivemind.provider.chat_receipt.v1";
pub const PSEUDO_PAYMENT_POLICY_SCHEMA_VERSION: &str = "hivemind.provider.pseudo_policy.v1";
pub const PSEUDO_PAYMENT_SESSION_SCHEMA_VERSION: &str = "hivemind.provider.pseudo_session.v1";
pub const PSEUDO_PAYMENT_STATE_SCHEMA_VERSION: &str = "hivemind.provider.pseudo_state.v1";
pub const PSEUDO_LEDGER_EVENT_SCHEMA_VERSION: &str = "hivemind.provider.pseudo_ledger_event.v1";
pub const PROVIDER_SESSION_SUMMARY_SCHEMA_VERSION: &str = "hivemind.provider.session_summary.v1";
pub const SIGNED_REQUEST_ENVELOPE_SCHEMA_VERSION: &str = "hivemind.provider.signed_request.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderReadinessLabel {
    Mock,
    Local,
    LanTest,
    Testnet,
    ProductionReserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSecurityMode {
    LocalDev,
    LanTest,
    Testnet,
    ProductionReserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAuthMode {
    None,
    BearerToken,
    SignedRequestEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Starting,
    Healthy,
    Degraded,
    Unavailable,
    Stopping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelBackendType {
    Mock,
    OpenAiCompatibleHttp,
    Ollama,
    Vllm,
    Sglang,
    LlamaCpp,
    CustomCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelBackendFeature {
    Chat,
    StreamingChat,
    Completions,
    Embeddings,
    FunctionCalling,
    StructuredOutput,
    JsonMode,
    VisionInput,
    AudioInput,
    ToolChoice,
    Logprobs,
    UsageMetrics,
    Cancellation,
    ModelPull,
    ModelUnload,
    Warmup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ModelLifecycleStateKind {
    Configured,
    Unavailable,
    AvailableCold,
    Starting,
    Warming,
    Ready,
    Busy,
    Stopping,
    Failed,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPaymentMode {
    Free,
    PseudopaymentDebtForgiveness,
    LocalDevAuthorization,
    ExternalSettlement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSessionStatus {
    Opening,
    Active,
    Paused,
    Closing,
    Closed,
    Expired,
    Disputed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStreamEventType {
    StreamStarted,
    ModelStarting,
    ModelReady,
    TokenDelta,
    UsageUpdate,
    ReceiptCreated,
    LedgerUpdated,
    StreamFinished,
    StreamCancelled,
    StreamError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderJobCancellationStatus {
    CancelRequested,
    JobNotActive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PseudoLedgerEventType {
    SessionOpened,
    CreditGranted,
    HoldCreated,
    HoldReleased,
    DebitApplied,
    ForgivenessApplied,
    CeilingExceeded,
    JobRefused,
    SessionPaused,
    SessionResumed,
    SessionClosed,
    DisputeOpened,
    DisputeResolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UsageConfidence {
    Measured,
    BackendReported,
    Estimated,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderIdentityV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "signingScheme")]
    pub signing_scheme: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(
        rename = "operatorContact",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub operator_contact: Option<String>,
    #[serde(rename = "readinessLabel")]
    pub readiness_label: ProviderReadinessLabel,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModelColdStartPolicyV1 {
    #[serde(rename = "allowConsumerTriggeredStart")]
    pub allow_consumer_triggered_start: bool,
    #[serde(rename = "requireSessionBeforeStart")]
    pub require_session_before_start: bool,
    #[serde(rename = "requirePaymentAuthorizationBeforeStart")]
    pub require_payment_authorization_before_start: bool,
    #[serde(rename = "maxStartsPerHour")]
    pub max_starts_per_hour: u32,
    #[serde(rename = "maxColdStartSeconds")]
    pub max_cold_start_seconds: u64,
    #[serde(
        rename = "idleUnloadSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub idle_unload_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderModelOfferV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "backendType")]
    pub backend_type: ModelBackendType,
    #[serde(rename = "backendModelId")]
    pub backend_model_id: String,
    #[serde(rename = "supportedApis", default)]
    pub supported_apis: Vec<ApiSurface>,
    #[serde(rename = "supportedFeatures", default)]
    pub supported_features: Vec<ModelBackendFeature>,
    #[serde(rename = "maxContextTokens")]
    pub max_context_tokens: u64,
    #[serde(rename = "maxOutputTokens")]
    pub max_output_tokens: u64,
    #[serde(rename = "maxConcurrentSessions")]
    pub max_concurrent_sessions: u32,
    #[serde(rename = "maxConcurrentJobs")]
    pub max_concurrent_jobs: u32,
    #[serde(rename = "coldStartPolicy")]
    pub cold_start_policy: ModelColdStartPolicyV1,
    #[serde(
        rename = "pricingPolicyRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pricing_policy_ref: Option<String>,
    #[serde(
        rename = "pseudopaymentPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pseudopayment_policy: Option<PseudoPaymentPolicyV1>,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "verificationTier")]
    pub verification_tier: IntegrityTier,
    #[serde(rename = "readinessLabel")]
    pub readiness_label: ProviderReadinessLabel,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderHealthV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    pub status: ProviderStatus,
    #[serde(rename = "uptimeSeconds")]
    pub uptime_seconds: u64,
    pub version: String,
    #[serde(rename = "securityMode")]
    pub security_mode: ProviderSecurityMode,
    #[serde(rename = "authModes", default)]
    pub auth_modes: Vec<ProviderAuthMode>,
    #[serde(rename = "activeSessions")]
    pub active_sessions: u32,
    #[serde(rename = "activeJobs")]
    pub active_jobs: u32,
    #[serde(rename = "modelStatuses", default)]
    pub model_statuses: Vec<ModelLifecycleStateV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModelLifecycleStateV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    pub state: ModelLifecycleStateKind,
    #[serde(rename = "backendType")]
    pub backend_type: ModelBackendType,
    #[serde(rename = "backendHealth")]
    pub backend_health: String,
    #[serde(rename = "currentConcurrency")]
    pub current_concurrency: u32,
    #[serde(rename = "maxConcurrency")]
    pub max_concurrency: u32,
    #[serde(
        rename = "lastStartedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_started_at: Option<DateTime<Utc>>,
    #[serde(
        rename = "lastWarmedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_warmed_at: Option<DateTime<Utc>>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(
        rename = "estimatedColdStartSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub estimated_cold_start_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderModelStartRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(
        rename = "requestEnvelope",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_envelope: Option<SignedRequestEnvelopeV1>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderModelStopRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(
        rename = "requestEnvelope",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_envelope: Option<SignedRequestEnvelopeV1>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderQuoteRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    pub task: String,
    #[serde(rename = "expectedMaxInputTokens")]
    pub expected_max_input_tokens: u64,
    #[serde(rename = "expectedMaxOutputTokens")]
    pub expected_max_output_tokens: u64,
    pub streaming: bool,
    #[serde(rename = "requestedPrivacyTier")]
    pub requested_privacy_tier: PrivacyTier,
    #[serde(rename = "requestedVerificationTier")]
    pub requested_verification_tier: IntegrityTier,
    #[serde(rename = "paymentMode")]
    pub payment_mode: ProviderPaymentMode,
    #[serde(
        rename = "requestEnvelope",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_envelope: Option<SignedRequestEnvelopeV1>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderPriceTermsV1 {
    #[serde(rename = "currencyUnit")]
    pub currency_unit: String,
    #[serde(rename = "pricePerInputToken")]
    pub price_per_input_token: f64,
    #[serde(rename = "pricePerOutputToken")]
    pub price_per_output_token: f64,
    #[serde(rename = "pricePerModelSecond")]
    pub price_per_model_second: f64,
    #[serde(
        rename = "pricePerRequest",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub price_per_request: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderSessionLimitsV1 {
    #[serde(rename = "maxSessionDurationSeconds")]
    pub max_session_duration_seconds: u64,
    #[serde(rename = "maxJobsPerMinute")]
    pub max_jobs_per_minute: u32,
    #[serde(rename = "maxConcurrentJobs")]
    pub max_concurrent_jobs: u32,
    #[serde(rename = "maxInputTokens")]
    pub max_input_tokens: u64,
    #[serde(rename = "maxOutputTokens")]
    pub max_output_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderQuoteV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    #[serde(rename = "priceTerms")]
    pub price_terms: ProviderPriceTermsV1,
    #[serde(rename = "pseudopaymentPolicy")]
    pub pseudopayment_policy: PseudoPaymentPolicyV1,
    #[serde(rename = "coldStartPolicy")]
    pub cold_start_policy: ModelColdStartPolicyV1,
    pub limits: ProviderSessionLimitsV1,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PseudoPaymentPolicyV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "policyId")]
    pub policy_id: String,
    #[serde(rename = "currencyUnit")]
    pub currency_unit: String,
    #[serde(rename = "maxDebt")]
    pub max_debt: f64,
    #[serde(rename = "forgivenessPerSecond")]
    pub forgiveness_per_second: f64,
    #[serde(rename = "forgivenessStartsAt")]
    pub forgiveness_starts_at: DateTime<Utc>,
    #[serde(rename = "pricePerInputToken")]
    pub price_per_input_token: f64,
    #[serde(rename = "pricePerOutputToken")]
    pub price_per_output_token: f64,
    #[serde(rename = "pricePerModelSecond")]
    pub price_per_model_second: f64,
    #[serde(
        rename = "pricePerRequest",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub price_per_request: Option<f64>,
    #[serde(rename = "maxSessionDurationSeconds")]
    pub max_session_duration_seconds: u64,
    #[serde(rename = "maxJobsPerMinute")]
    pub max_jobs_per_minute: u32,
    #[serde(rename = "maxConcurrentJobs")]
    pub max_concurrent_jobs: u32,
    #[serde(rename = "stopWhenDebtAboveMax")]
    pub stop_when_debt_above_max: bool,
    #[serde(rename = "allowProviderPolicyUpdate")]
    pub allow_provider_policy_update: bool,
    #[serde(rename = "disputeWindowSeconds")]
    pub dispute_window_seconds: u64,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderSessionOpenRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "acceptedPolicyHash")]
    pub accepted_policy_hash: String,
    #[serde(rename = "spendingCap")]
    pub spending_cap: f64,
    #[serde(rename = "requestedExpiresAt")]
    pub requested_expires_at: DateTime<Utc>,
    #[serde(rename = "authProof", default, skip_serializing_if = "Option::is_none")]
    pub auth_proof: Option<String>,
    #[serde(
        rename = "requestEnvelope",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_envelope: Option<SignedRequestEnvelopeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderSessionCloseRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(
        rename = "requestEnvelope",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_envelope: Option<SignedRequestEnvelopeV1>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderSessionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    pub status: ProviderSessionStatus,
    #[serde(rename = "paymentMode")]
    pub payment_mode: ProviderPaymentMode,
    #[serde(rename = "policyHash")]
    pub policy_hash: String,
    #[serde(rename = "openedAt")]
    pub opened_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "currentLedgerState")]
    pub current_ledger_state: PseudoPaymentStateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PseudoPaymentSessionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "policyHash")]
    pub policy_hash: String,
    #[serde(rename = "currentDebt")]
    pub current_debt: f64,
    #[serde(rename = "lastForgivenessAt")]
    pub last_forgiveness_at: DateTime<Utc>,
    #[serde(rename = "nextSequence")]
    pub next_sequence: u64,
    pub status: ProviderSessionStatus,
    #[serde(rename = "openedAt")]
    pub opened_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderChatRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    #[serde(default)]
    pub messages: Vec<Value>,
    pub stream: bool,
    #[serde(rename = "maxOutputTokens")]
    pub max_output_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(
        rename = "toolPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tool_policy: Option<Value>,
    #[serde(
        rename = "requestEnvelope",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_envelope: Option<SignedRequestEnvelopeV1>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderJobCancelRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(
        rename = "requestEnvelope",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_envelope: Option<SignedRequestEnvelopeV1>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderJobCancelResponseV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "cancellationId")]
    pub cancellation_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    pub accepted: bool,
    pub status: ProviderJobCancellationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(
        rename = "streamEvent",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub stream_event: Option<ProviderStreamEventV1>,
    #[serde(
        rename = "ledgerState",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ledger_state: Option<PseudoPaymentStateV1>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderStreamEventV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "eventId")]
    pub event_id: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub sequence: u64,
    #[serde(rename = "eventType")]
    pub event_type: ProviderStreamEventType,
    #[serde(default)]
    pub payload: Value,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderUsageV1 {
    #[serde(rename = "inputTokens")]
    pub input_tokens: u64,
    #[serde(rename = "outputTokens")]
    pub output_tokens: u64,
    #[serde(rename = "totalTokens")]
    pub total_tokens: u64,
    #[serde(rename = "modelSeconds")]
    pub model_seconds: f64,
    #[serde(rename = "queueSeconds")]
    pub queue_seconds: f64,
    #[serde(
        rename = "firstTokenMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub first_token_ms: Option<u64>,
    #[serde(
        rename = "tokensPerSecond",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tokens_per_second: Option<f64>,
    #[serde(rename = "usageConfidence")]
    pub usage_confidence: UsageConfidence,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderChatReceiptV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    #[serde(rename = "backendType")]
    pub backend_type: ModelBackendType,
    #[serde(rename = "inputHash")]
    pub input_hash: String,
    #[serde(rename = "outputHash")]
    pub output_hash: String,
    pub usage: ProviderUsageV1,
    pub cost: f64,
    #[serde(rename = "startedAt")]
    pub started_at: DateTime<Utc>,
    #[serde(rename = "finishedAt")]
    pub finished_at: DateTime<Utc>,
    #[serde(rename = "streamSummary", default)]
    pub stream_summary: Value,
    #[serde(rename = "ledgerEventIds", default)]
    pub ledger_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PseudoLedgerEventV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "eventId")]
    pub event_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub sequence: u64,
    #[serde(rename = "eventType")]
    pub event_type: PseudoLedgerEventType,
    pub amount: f64,
    #[serde(rename = "debtBefore")]
    pub debt_before: f64,
    #[serde(rename = "debtAfter")]
    pub debt_after: f64,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "receiptId", default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    pub reason: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    pub signer: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PseudoPaymentStateV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "currentDebt")]
    pub current_debt: f64,
    #[serde(rename = "maxDebt")]
    pub max_debt: f64,
    #[serde(rename = "remainingCapacity")]
    pub remaining_capacity: f64,
    #[serde(rename = "forgivenessPerSecond")]
    pub forgiveness_per_second: f64,
    #[serde(rename = "estimatedSecondsToZero")]
    pub estimated_seconds_to_zero: f64,
    pub status: ProviderSessionStatus,
    #[serde(rename = "lastEventSequence")]
    pub last_event_sequence: u64,
    #[serde(rename = "canSubmitNextJob")]
    pub can_submit_next_job: bool,
    #[serde(
        rename = "refusalReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub refusal_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderSessionSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "summaryId")]
    pub summary_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    #[serde(rename = "modelId")]
    pub model_id: String,
    #[serde(rename = "totalJobs")]
    pub total_jobs: u64,
    #[serde(rename = "totalInputTokens")]
    pub total_input_tokens: u64,
    #[serde(rename = "totalOutputTokens")]
    pub total_output_tokens: u64,
    #[serde(rename = "totalCost")]
    pub total_cost: f64,
    #[serde(rename = "totalForgiven")]
    pub total_forgiven: f64,
    #[serde(rename = "finalDebt")]
    pub final_debt: f64,
    #[serde(rename = "receiptIds", default)]
    pub receipt_ids: Vec<String>,
    #[serde(rename = "ledgerEventCount")]
    pub ledger_event_count: u64,
    #[serde(rename = "closedAt")]
    pub closed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SignedRequestEnvelopeV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "envelopeId")]
    pub envelope_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "consumerId")]
    pub consumer_id: String,
    pub method: String,
    pub path: String,
    #[serde(rename = "bodyHash")]
    pub body_hash: String,
    pub nonce: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "quoteId", default, skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<String>,
    #[serde(rename = "signatureScheme")]
    pub signature_scheme: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum ProviderSecurityError {
    #[error("local-dev provider mode may only bind loopback hosts")]
    LocalDevRequiresLoopback,
    #[error("non-loopback provider serving requires bearer token or signed request auth")]
    ExternalServingRequiresAuth,
    #[error(
        "production provider mode is reserved until the production readiness gate is implemented"
    )]
    ProductionReserved,
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum PseudoPaymentError {
    #[error("pseudopayment policy is invalid: {0}")]
    InvalidPolicy(String),
    #[error("pseudopayment session is not active")]
    SessionNotActive,
    #[error("pseudopayment session has expired")]
    SessionExpired,
    #[error("debit amount must be non-negative and finite")]
    InvalidDebitAmount,
    #[error("debt ceiling would be exceeded")]
    DebtCeilingExceeded,
}

pub fn provider_security_mode_allows_bind(
    host: &str,
    mode: &ProviderSecurityMode,
    auth_modes: &[ProviderAuthMode],
) -> Result<(), ProviderSecurityError> {
    match mode {
        ProviderSecurityMode::LocalDev if !is_loopback_bind_host(host) => {
            Err(ProviderSecurityError::LocalDevRequiresLoopback)
        }
        ProviderSecurityMode::LocalDev => Ok(()),
        ProviderSecurityMode::LanTest | ProviderSecurityMode::Testnet
            if !has_external_provider_auth(auth_modes) =>
        {
            Err(ProviderSecurityError::ExternalServingRequiresAuth)
        }
        ProviderSecurityMode::LanTest | ProviderSecurityMode::Testnet => Ok(()),
        ProviderSecurityMode::ProductionReserved => Err(ProviderSecurityError::ProductionReserved),
    }
}

pub fn is_loopback_bind_host(host: &str) -> bool {
    let host = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    matches!(host.as_str(), "127.0.0.1" | "::1" | "localhost")
}

pub fn has_external_provider_auth(auth_modes: &[ProviderAuthMode]) -> bool {
    auth_modes.iter().any(|mode| {
        matches!(
            mode,
            ProviderAuthMode::BearerToken | ProviderAuthMode::SignedRequestEnvelope
        )
    })
}

pub fn provider_chat_usage_cost(policy: &PseudoPaymentPolicyV1, usage: &ProviderUsageV1) -> f64 {
    policy.price_per_request.unwrap_or(0.0)
        + usage.input_tokens as f64 * policy.price_per_input_token
        + usage.output_tokens as f64 * policy.price_per_output_token
        + usage.model_seconds * policy.price_per_model_second
}

pub fn validate_pseudo_payment_policy(policy: &PseudoPaymentPolicyV1) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    require_schema_version(
        &mut issues,
        "$.schemaVersion",
        &policy.schema_version,
        PSEUDO_PAYMENT_POLICY_SCHEMA_VERSION,
    );
    require_id(&mut issues, "$.policyId", &policy.policy_id);
    require_non_empty(&mut issues, "$.currencyUnit", &policy.currency_unit);
    require_non_negative_finite(&mut issues, "$.maxDebt", policy.max_debt);
    require_non_negative_finite(
        &mut issues,
        "$.forgivenessPerSecond",
        policy.forgiveness_per_second,
    );
    require_non_negative_finite(
        &mut issues,
        "$.pricePerInputToken",
        policy.price_per_input_token,
    );
    require_non_negative_finite(
        &mut issues,
        "$.pricePerOutputToken",
        policy.price_per_output_token,
    );
    require_non_negative_finite(
        &mut issues,
        "$.pricePerModelSecond",
        policy.price_per_model_second,
    );
    if let Some(price) = policy.price_per_request {
        require_non_negative_finite(&mut issues, "$.pricePerRequest", price);
    }
    if policy.max_session_duration_seconds == 0 {
        issues.push(issue(
            "$.maxSessionDurationSeconds",
            "Session duration limit must be greater than zero",
        ));
    }
    if policy.max_jobs_per_minute == 0 {
        issues.push(issue(
            "$.maxJobsPerMinute",
            "Job rate limit must be greater than zero",
        ));
    }
    if policy.max_concurrent_jobs == 0 {
        issues.push(issue(
            "$.maxConcurrentJobs",
            "Concurrent job limit must be greater than zero",
        ));
    }
    if policy.expires_at <= policy.created_at {
        issues.push(issue(
            "$.expiresAt",
            "Policy expiry must be later than createdAt",
        ));
    }
    issues
}

pub fn validate_provider_model_offer(
    offer: &ProviderModelOfferV1,
    now: DateTime<Utc>,
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    require_schema_version(
        &mut issues,
        "$.schemaVersion",
        &offer.schema_version,
        PROVIDER_MODEL_OFFER_SCHEMA_VERSION,
    );
    require_id(&mut issues, "$.offerId", &offer.offer_id);
    require_id(&mut issues, "$.providerId", &offer.provider_id);
    require_id(&mut issues, "$.modelId", &offer.model_id);
    require_non_empty(&mut issues, "$.displayName", &offer.display_name);
    require_non_empty(&mut issues, "$.backendModelId", &offer.backend_model_id);
    if offer.supported_apis.is_empty() {
        issues.push(issue(
            "$.supportedApis",
            "At least one API surface must be advertised",
        ));
    }
    if offer.supported_features.is_empty() {
        issues.push(issue(
            "$.supportedFeatures",
            "At least one backend feature must be advertised",
        ));
    }
    if offer.max_context_tokens == 0 {
        issues.push(issue(
            "$.maxContextTokens",
            "Context token limit must be greater than zero",
        ));
    }
    if offer.max_output_tokens == 0 {
        issues.push(issue(
            "$.maxOutputTokens",
            "Output token limit must be greater than zero",
        ));
    }
    if offer.max_concurrent_sessions == 0 {
        issues.push(issue(
            "$.maxConcurrentSessions",
            "Concurrent session limit must be greater than zero",
        ));
    }
    if offer.max_concurrent_jobs == 0 {
        issues.push(issue(
            "$.maxConcurrentJobs",
            "Concurrent job limit must be greater than zero",
        ));
    }
    if offer.expires_at <= now {
        issues.push(issue("$.expiresAt", "Provider model offer has expired"));
    }
    if let Some(policy) = &offer.pseudopayment_policy {
        issues.extend(validate_pseudo_payment_policy(policy));
    }
    issues
}

pub fn validate_provider_quote(
    quote: &ProviderQuoteV1,
    now: DateTime<Utc>,
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    require_schema_version(
        &mut issues,
        "$.schemaVersion",
        &quote.schema_version,
        PROVIDER_QUOTE_SCHEMA_VERSION,
    );
    require_id(&mut issues, "$.quoteId", &quote.quote_id);
    require_id(&mut issues, "$.requestId", &quote.request_id);
    require_id(&mut issues, "$.providerId", &quote.provider_id);
    require_id(&mut issues, "$.consumerId", &quote.consumer_id);
    require_id(&mut issues, "$.modelId", &quote.model_id);
    if quote.expires_at <= now {
        issues.push(issue("$.expiresAt", "Provider quote has expired"));
    }
    issues.extend(validate_pseudo_payment_policy(&quote.pseudopayment_policy));
    issues
}

pub fn validate_signed_request_envelope(
    envelope: &SignedRequestEnvelopeV1,
    expected_method: &str,
    expected_path: &str,
    now: DateTime<Utc>,
) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    require_schema_version(
        &mut issues,
        "$.schemaVersion",
        &envelope.schema_version,
        SIGNED_REQUEST_ENVELOPE_SCHEMA_VERSION,
    );
    require_id(&mut issues, "$.envelopeId", &envelope.envelope_id);
    require_id(&mut issues, "$.providerId", &envelope.provider_id);
    require_id(&mut issues, "$.consumerId", &envelope.consumer_id);
    require_non_empty(&mut issues, "$.bodyHash", &envelope.body_hash);
    require_non_empty(&mut issues, "$.nonce", &envelope.nonce);
    require_non_empty(&mut issues, "$.signatureScheme", &envelope.signature_scheme);
    require_non_empty(&mut issues, "$.signature", &envelope.signature);
    if envelope.method != expected_method {
        issues.push(issue("$.method", "Signed request method does not match"));
    }
    if envelope.path != expected_path {
        issues.push(issue("$.path", "Signed request path does not match"));
    }
    if envelope.expires_at <= now {
        issues.push(issue("$.expiresAt", "Signed request envelope has expired"));
    }
    if envelope.issued_at > now + chrono::Duration::minutes(5) {
        issues.push(issue(
            "$.issuedAt",
            "Signed request envelope is issued too far in the future",
        ));
    }
    issues
}

pub fn pseudo_payment_state(
    session: &PseudoPaymentSessionV1,
    policy: &PseudoPaymentPolicyV1,
    now: DateTime<Utc>,
) -> Result<PseudoPaymentStateV1, PseudoPaymentError> {
    ensure_policy_valid(policy)?;
    let forgiven_debt = debt_after_forgiveness(
        session.current_debt,
        session.last_forgiveness_at,
        now,
        policy,
    );
    let remaining_capacity = (policy.max_debt - forgiven_debt).max(0.0);
    let can_submit = session.status == ProviderSessionStatus::Active
        && session.expires_at > now
        && (!policy.stop_when_debt_above_max || forgiven_debt < policy.max_debt);
    let refusal_reason = if session.status != ProviderSessionStatus::Active {
        Some("session is not active".to_string())
    } else if session.expires_at <= now {
        Some("session has expired".to_string())
    } else if policy.stop_when_debt_above_max && forgiven_debt >= policy.max_debt {
        Some("debt ceiling has been reached".to_string())
    } else {
        None
    };

    Ok(PseudoPaymentStateV1 {
        schema_version: PSEUDO_PAYMENT_STATE_SCHEMA_VERSION.to_string(),
        session_id: session.session_id.clone(),
        current_debt: forgiven_debt,
        max_debt: policy.max_debt,
        remaining_capacity,
        forgiveness_per_second: policy.forgiveness_per_second,
        estimated_seconds_to_zero: seconds_to_zero(forgiven_debt, policy.forgiveness_per_second),
        status: session.status.clone(),
        last_event_sequence: session.next_sequence.saturating_sub(1),
        can_submit_next_job: can_submit,
        refusal_reason,
    })
}

pub fn apply_pseudo_payment_forgiveness(
    session: &mut PseudoPaymentSessionV1,
    policy: &PseudoPaymentPolicyV1,
    now: DateTime<Utc>,
    signer: impl Into<String>,
) -> Result<Option<PseudoLedgerEventV1>, PseudoPaymentError> {
    ensure_session_can_update(session, now)?;
    ensure_policy_valid(policy)?;

    let debt_before = session.current_debt;
    let debt_after = debt_after_forgiveness(debt_before, session.last_forgiveness_at, now, policy);
    session.last_forgiveness_at = now;
    if (debt_before - debt_after).abs() < f64::EPSILON {
        return Ok(None);
    }

    session.current_debt = debt_after;
    let event = ledger_event(
        session,
        PseudoLedgerEventType::ForgivenessApplied,
        debt_before - debt_after,
        debt_before,
        debt_after,
        None,
        None,
        "debt forgiven by policy rate",
        now,
        signer,
    );
    session.next_sequence += 1;
    Ok(Some(event))
}

pub fn apply_pseudo_payment_debit(
    session: &mut PseudoPaymentSessionV1,
    policy: &PseudoPaymentPolicyV1,
    amount: f64,
    job_id: Option<String>,
    receipt_id: Option<String>,
    now: DateTime<Utc>,
    signer: impl Into<String>,
) -> Result<PseudoLedgerEventV1, PseudoPaymentError> {
    ensure_session_can_update(session, now)?;
    ensure_policy_valid(policy)?;
    if !amount.is_finite() || amount < 0.0 {
        return Err(PseudoPaymentError::InvalidDebitAmount);
    }

    let debt_before = debt_after_forgiveness(
        session.current_debt,
        session.last_forgiveness_at,
        now,
        policy,
    );
    let debt_after = debt_before + amount;
    if policy.stop_when_debt_above_max && debt_after > policy.max_debt {
        return Err(PseudoPaymentError::DebtCeilingExceeded);
    }

    session.current_debt = debt_after;
    session.last_forgiveness_at = now;
    let event = ledger_event(
        session,
        PseudoLedgerEventType::DebitApplied,
        amount,
        debt_before,
        debt_after,
        job_id,
        receipt_id,
        "usage debited from provider receipt",
        now,
        signer,
    );
    session.next_sequence += 1;
    Ok(event)
}

pub fn apply_pseudo_payment_session_close(
    session: &mut PseudoPaymentSessionV1,
    policy: &PseudoPaymentPolicyV1,
    reason: Option<&str>,
    now: DateTime<Utc>,
    signer: impl Into<String>,
) -> Result<PseudoLedgerEventV1, PseudoPaymentError> {
    ensure_policy_valid(policy)?;
    if matches!(
        session.status,
        ProviderSessionStatus::Closed | ProviderSessionStatus::Closing
    ) {
        return Err(PseudoPaymentError::SessionNotActive);
    }

    let debt_before = session.current_debt;
    let debt_after = debt_after_forgiveness(debt_before, session.last_forgiveness_at, now, policy);
    session.current_debt = debt_after;
    session.last_forgiveness_at = now;
    session.status = ProviderSessionStatus::Closed;
    let event = ledger_event(
        session,
        PseudoLedgerEventType::SessionClosed,
        0.0,
        debt_before,
        debt_after,
        None,
        None,
        reason
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("pseudopayment session closed"),
        now,
        signer,
    );
    session.next_sequence += 1;
    Ok(event)
}

fn ledger_event(
    session: &PseudoPaymentSessionV1,
    event_type: PseudoLedgerEventType,
    amount: f64,
    debt_before: f64,
    debt_after: f64,
    job_id: Option<String>,
    receipt_id: Option<String>,
    reason: impl Into<String>,
    created_at: DateTime<Utc>,
    signer: impl Into<String>,
) -> PseudoLedgerEventV1 {
    let signer = signer.into();
    PseudoLedgerEventV1 {
        schema_version: PSEUDO_LEDGER_EVENT_SCHEMA_VERSION.to_string(),
        event_id: format!(
            "pseudo-ledger-{}-{}",
            session.session_id, session.next_sequence
        ),
        session_id: session.session_id.clone(),
        sequence: session.next_sequence,
        event_type,
        amount,
        debt_before,
        debt_after,
        job_id,
        receipt_id,
        reason: reason.into(),
        created_at,
        signer: signer.clone(),
        signature: format!(
            "dev-pseudo-ledger-signature-v1:{}:{}:{}",
            signer, session.session_id, session.next_sequence
        ),
    }
}

fn debt_after_forgiveness(
    current_debt: f64,
    last_forgiveness_at: DateTime<Utc>,
    now: DateTime<Utc>,
    policy: &PseudoPaymentPolicyV1,
) -> f64 {
    if current_debt <= 0.0 || policy.forgiveness_per_second <= 0.0 || now <= last_forgiveness_at {
        return current_debt.max(0.0);
    }
    let elapsed = now
        .signed_duration_since(last_forgiveness_at.max(policy.forgiveness_starts_at))
        .num_milliseconds()
        .max(0) as f64
        / 1000.0;
    (current_debt - elapsed * policy.forgiveness_per_second).max(0.0)
}

fn seconds_to_zero(current_debt: f64, forgiveness_per_second: f64) -> f64 {
    if current_debt <= 0.0 {
        0.0
    } else if forgiveness_per_second <= 0.0 {
        f64::INFINITY
    } else {
        current_debt / forgiveness_per_second
    }
}

fn ensure_session_can_update(
    session: &PseudoPaymentSessionV1,
    now: DateTime<Utc>,
) -> Result<(), PseudoPaymentError> {
    if session.status != ProviderSessionStatus::Active {
        return Err(PseudoPaymentError::SessionNotActive);
    }
    if session.expires_at <= now {
        return Err(PseudoPaymentError::SessionExpired);
    }
    Ok(())
}

fn ensure_policy_valid(policy: &PseudoPaymentPolicyV1) -> Result<(), PseudoPaymentError> {
    let issues = validate_pseudo_payment_policy(policy);
    if let Some(first) = issues.first() {
        return Err(PseudoPaymentError::InvalidPolicy(format!(
            "{}: {}",
            first.path, first.message
        )));
    }
    Ok(())
}

fn require_schema_version(
    issues: &mut Vec<ValidationIssue>,
    path: impl Into<String>,
    actual: &str,
    expected: &str,
) {
    if actual != expected {
        issues.push(issue(
            path,
            format!("Expected schemaVersion to be {expected}"),
        ));
    }
}

fn require_id(issues: &mut Vec<ValidationIssue>, path: impl Into<String>, value: &str) {
    if value.trim().is_empty()
        || value.contains('\\')
        || value.split('/').any(|part| part == ".." || part.is_empty())
    {
        issues.push(issue(
            path,
            "Identifier must be non-empty and must not contain path traversal",
        ));
    }
}

fn require_non_empty(issues: &mut Vec<ValidationIssue>, path: impl Into<String>, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value is required"));
    }
}

fn require_non_negative_finite(issues: &mut Vec<ValidationIssue>, path: &str, value: f64) {
    if !value.is_finite() || value < 0.0 {
        issues.push(issue(path, "Value must be non-negative and finite"));
    }
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn now() -> DateTime<Utc> {
        "2026-06-09T12:00:00Z".parse().unwrap()
    }

    fn policy() -> PseudoPaymentPolicyV1 {
        let now = now();
        PseudoPaymentPolicyV1 {
            schema_version: PSEUDO_PAYMENT_POLICY_SCHEMA_VERSION.to_string(),
            policy_id: "policy-local-dev".to_string(),
            currency_unit: "pseudo-credit".to_string(),
            max_debt: 100.0,
            forgiveness_per_second: 10.0,
            forgiveness_starts_at: now,
            price_per_input_token: 1.0,
            price_per_output_token: 2.0,
            price_per_model_second: 5.0,
            price_per_request: Some(3.0),
            max_session_duration_seconds: 3600,
            max_jobs_per_minute: 10,
            max_concurrent_jobs: 1,
            stop_when_debt_above_max: true,
            allow_provider_policy_update: false,
            dispute_window_seconds: 60,
            created_at: now,
            expires_at: now + Duration::hours(1),
        }
    }

    fn session() -> PseudoPaymentSessionV1 {
        let now = now();
        PseudoPaymentSessionV1 {
            schema_version: PSEUDO_PAYMENT_SESSION_SCHEMA_VERSION.to_string(),
            session_id: "session-1".to_string(),
            provider_id: "provider-1".to_string(),
            consumer_id: "consumer-1".to_string(),
            quote_id: "quote-1".to_string(),
            policy_hash: "sha256:policy".to_string(),
            current_debt: 0.0,
            last_forgiveness_at: now,
            next_sequence: 1,
            status: ProviderSessionStatus::Active,
            opened_at: now,
            expires_at: now + Duration::hours(1),
        }
    }

    #[test]
    fn provider_security_refuses_unsafe_external_local_dev_bind() {
        assert_eq!(
            provider_security_mode_allows_bind(
                "0.0.0.0",
                &ProviderSecurityMode::LocalDev,
                &[ProviderAuthMode::None]
            ),
            Err(ProviderSecurityError::LocalDevRequiresLoopback)
        );
        assert!(
            provider_security_mode_allows_bind(
                "127.0.0.1",
                &ProviderSecurityMode::LocalDev,
                &[ProviderAuthMode::None]
            )
            .is_ok()
        );
    }

    #[test]
    fn lan_test_requires_provider_auth() {
        assert_eq!(
            provider_security_mode_allows_bind(
                "192.168.1.20",
                &ProviderSecurityMode::LanTest,
                &[ProviderAuthMode::None]
            ),
            Err(ProviderSecurityError::ExternalServingRequiresAuth)
        );
        assert!(
            provider_security_mode_allows_bind(
                "192.168.1.20",
                &ProviderSecurityMode::LanTest,
                &[ProviderAuthMode::BearerToken]
            )
            .is_ok()
        );
    }

    #[test]
    fn usage_cost_combines_request_tokens_and_model_seconds() {
        let usage = ProviderUsageV1 {
            input_tokens: 7,
            output_tokens: 11,
            total_tokens: 18,
            model_seconds: 2.0,
            queue_seconds: 0.0,
            first_token_ms: Some(100),
            tokens_per_second: Some(5.5),
            usage_confidence: UsageConfidence::Measured,
        };

        assert_eq!(provider_chat_usage_cost(&policy(), &usage), 42.0);
    }

    #[test]
    fn forgiveness_caps_at_current_debt_and_advances_sequence() {
        let mut session = session();
        let policy = policy();
        let debit = apply_pseudo_payment_debit(
            &mut session,
            &policy,
            40.0,
            Some("job-1".to_string()),
            Some("receipt-1".to_string()),
            now(),
            "provider-1",
        )
        .unwrap();
        assert_eq!(debit.sequence, 1);
        assert_eq!(session.current_debt, 40.0);
        assert_eq!(session.next_sequence, 2);

        let event = apply_pseudo_payment_forgiveness(
            &mut session,
            &policy,
            now() + Duration::seconds(10),
            "provider-1",
        )
        .unwrap()
        .unwrap();
        assert_eq!(event.sequence, 2);
        assert_eq!(event.amount, 40.0);
        assert_eq!(event.debt_after, 0.0);
        assert_eq!(session.current_debt, 0.0);
        assert_eq!(session.next_sequence, 3);
    }

    #[test]
    fn debt_ceiling_blocks_until_enough_time_is_forgiven() {
        let mut session = session();
        let policy = policy();
        apply_pseudo_payment_debit(&mut session, &policy, 95.0, None, None, now(), "provider-1")
            .unwrap();
        assert_eq!(
            apply_pseudo_payment_debit(
                &mut session,
                &policy,
                20.0,
                None,
                None,
                now() + Duration::seconds(1),
                "provider-1"
            ),
            Err(PseudoPaymentError::DebtCeilingExceeded)
        );

        let event = apply_pseudo_payment_debit(
            &mut session,
            &policy,
            10.0,
            None,
            None,
            now() + Duration::seconds(2),
            "provider-1",
        )
        .unwrap();
        assert_eq!(event.debt_before, 75.0);
        assert_eq!(event.debt_after, 85.0);
    }

    #[test]
    fn session_close_records_final_debt_and_blocks_later_debits() {
        let mut session = session();
        let policy = policy();
        apply_pseudo_payment_debit(&mut session, &policy, 40.0, None, None, now(), "provider-1")
            .unwrap();

        let event = apply_pseudo_payment_session_close(
            &mut session,
            &policy,
            Some("consumer requested close"),
            now() + Duration::seconds(2),
            "provider-1",
        )
        .unwrap();

        assert_eq!(event.sequence, 2);
        assert_eq!(event.event_type, PseudoLedgerEventType::SessionClosed);
        assert_eq!(event.debt_before, 40.0);
        assert_eq!(event.debt_after, 20.0);
        assert_eq!(event.reason, "consumer requested close");
        assert_eq!(session.current_debt, 20.0);
        assert_eq!(session.status, ProviderSessionStatus::Closed);
        assert_eq!(session.next_sequence, 3);
        assert_eq!(
            apply_pseudo_payment_debit(
                &mut session,
                &policy,
                1.0,
                None,
                None,
                now() + Duration::seconds(3),
                "provider-1"
            ),
            Err(PseudoPaymentError::SessionNotActive)
        );
    }

    #[test]
    fn validation_rejects_expired_or_empty_provider_offer() {
        let mut offer = ProviderModelOfferV1 {
            schema_version: PROVIDER_MODEL_OFFER_SCHEMA_VERSION.to_string(),
            offer_id: "".to_string(),
            provider_id: "provider-1".to_string(),
            model_id: "model-1".to_string(),
            display_name: "Mock Model".to_string(),
            backend_type: ModelBackendType::Mock,
            backend_model_id: "mock".to_string(),
            supported_apis: vec![ApiSurface::OpenAiChatCompletions],
            supported_features: vec![ModelBackendFeature::Chat],
            max_context_tokens: 4096,
            max_output_tokens: 512,
            max_concurrent_sessions: 1,
            max_concurrent_jobs: 1,
            cold_start_policy: ModelColdStartPolicyV1 {
                allow_consumer_triggered_start: true,
                require_session_before_start: true,
                require_payment_authorization_before_start: true,
                max_starts_per_hour: 4,
                max_cold_start_seconds: 60,
                idle_unload_seconds: Some(300),
            },
            pricing_policy_ref: None,
            pseudopayment_policy: Some(policy()),
            privacy_tier: PrivacyTier::Standard,
            verification_tier: IntegrityTier::ReceiptOnly,
            readiness_label: ProviderReadinessLabel::LanTest,
            expires_at: now() - Duration::seconds(1),
            signature: None,
        };

        let issues = validate_provider_model_offer(&offer, now());
        assert!(issues.iter().any(|issue| issue.path == "$.offerId"));
        assert!(issues.iter().any(|issue| issue.path == "$.expiresAt"));

        offer.offer_id = "offer-1".to_string();
        offer.expires_at = now() + Duration::seconds(60);
        assert!(validate_provider_model_offer(&offer, now()).is_empty());
    }
}
