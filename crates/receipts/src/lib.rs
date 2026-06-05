pub use hivemind_core::{
    BillingInfo, ExecutionReceiptCostV2, ExecutionReceiptErrorV2, ExecutionReceiptTimingV2,
    ExecutionReceiptUsageV2, ExecutionReceiptV1, ExecutionReceiptV2, ExecutionReceiptV2Context,
    ReceiptDraft, canonical_receipt_id, create_signed_receipt, create_unsigned_receipt,
    execution_receipt_v2_from_v1, expected_receipt_signature, policy_decision_id,
    receipt_policy_evidence, sign_receipt,
};

use chrono::{DateTime, SecondsFormat, Utc};
use hivemind_core::{
    ApiSurface, ExecutionMetrics, ExecutionResponseV1, ExecutionStatus, IntegrityTier, PrivacyTier,
    StreamingEventType, StreamingEventV1, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use hivemind_storage::{StorageProvider, StorageTransferMetricsV1, UploadResponseV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const DEV_DISPUTE_SIGNATURE_PREFIX: &str = "dev-signature-v1";
const DEV_BATCH_RECEIPT_SIGNATURE_PREFIX: &str = "dev-signature-v1";
const DEV_PARTIAL_RECEIPT_SIGNATURE_PREFIX: &str = "dev-signature-v1";
const DEV_RECEIPT_REDACTION_SIGNATURE_PREFIX: &str = "dev-signature-v1";

pub const RECEIPT_CORRECTNESS_ASSESSMENT_REQUEST_SCHEMA_VERSION: &str =
    "hivemind.receipt_correctness_assessment_request.v1";
pub const RECEIPT_CORRECTNESS_ASSESSMENT_SCHEMA_VERSION: &str =
    "hivemind.receipt_correctness_assessment.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptVerificationIssueV1 {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    pub valid: bool,
    pub issues: Vec<ReceiptVerificationIssueV1>,
    pub warnings: Vec<ReceiptVerificationIssueV1>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionReceiptV2VerificationRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub receipt: ExecutionReceiptV2,
    #[serde(
        rename = "sourceReceipt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_receipt: Option<ExecutionReceiptV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionReceiptV2VerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    pub valid: bool,
    pub issues: Vec<ReceiptVerificationIssueV1>,
    pub warnings: Vec<ReceiptVerificationIssueV1>,
    #[serde(rename = "signatureVerified")]
    pub signature_verified: bool,
    #[serde(
        rename = "sourceReceiptValid",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_receipt_valid: Option<bool>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptCorrectnessEvidenceMethodV1 {
    ManifestCompatibility,
    ArtifactHashCheck,
    ValidatorSpotCheck,
    HiddenChallenge,
    RedundantExecution,
    DeterministicReplay,
    BenchmarkScore,
    LlmJudgeWithDisclosure,
    HumanReview,
    TeeAttestationCheck,
    ZkProofCheck,
    FheResultCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptCorrectnessEvidenceStatusV1 {
    Passed,
    Warning,
    Failed,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptCorrectnessEvidenceV1 {
    pub method: ReceiptCorrectnessEvidenceMethodV1,
    #[serde(rename = "evidenceRef")]
    pub evidence_ref: String,
    #[serde(
        rename = "validatorId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub validator_id: Option<String>,
    #[serde(rename = "receiptId", default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    pub status: ReceiptCorrectnessEvidenceStatusV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(default)]
    pub subjective: bool,
    #[serde(rename = "privateEvidence", default)]
    pub private_evidence: bool,
    #[serde(rename = "signatureVerified", default)]
    pub signature_verified: bool,
    #[serde(rename = "checkedAt", default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptCorrectnessAssessmentRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub receipt: ExecutionReceiptV2,
    #[serde(
        rename = "sourceReceipt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_receipt: Option<ExecutionReceiptV1>,
    #[serde(rename = "validationEvidence", default)]
    pub validation_evidence: Vec<ReceiptCorrectnessEvidenceV1>,
    #[serde(
        rename = "requiredIntegrityTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub required_integrity_tier: Option<IntegrityTier>,
    #[serde(rename = "requiredMethods", default)]
    pub required_methods: Vec<ReceiptCorrectnessEvidenceMethodV1>,
    #[serde(
        rename = "minimumConfidence",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_confidence: Option<f64>,
    #[serde(rename = "allowSubjectiveOnly", default)]
    pub allow_subjective_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptCorrectnessLevelV1 {
    Failed,
    Unverified,
    ReceiptOnly,
    ValidatorBacked,
    RedundantOrReplayBacked,
    Attested,
    CryptographicProof,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptCorrectnessAssessmentV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    pub valid: bool,
    #[serde(rename = "assessedIntegrityTier")]
    pub assessed_integrity_tier: IntegrityTier,
    #[serde(rename = "correctnessLevel")]
    pub correctness_level: ReceiptCorrectnessLevelV1,
    #[serde(rename = "receiptVerification")]
    pub receipt_verification: ExecutionReceiptV2VerificationV1,
    #[serde(rename = "evidenceCount")]
    pub evidence_count: usize,
    #[serde(rename = "acceptedEvidenceCount")]
    pub accepted_evidence_count: usize,
    #[serde(rename = "validationRefs")]
    pub validation_refs: Vec<String>,
    #[serde(rename = "satisfiedMethods")]
    pub satisfied_methods: Vec<ReceiptCorrectnessEvidenceMethodV1>,
    #[serde(rename = "missingMethods")]
    pub missing_methods: Vec<ReceiptCorrectnessEvidenceMethodV1>,
    #[serde(rename = "failedMethods")]
    pub failed_methods: Vec<ReceiptCorrectnessEvidenceMethodV1>,
    pub issues: Vec<ReceiptVerificationIssueV1>,
    pub warnings: Vec<ReceiptVerificationIssueV1>,
    #[serde(rename = "assessedAt")]
    pub assessed_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptSettlementStatusV1 {
    NotRequired,
    Pending,
    ReadyForSettlement,
    Authorized,
    Settled,
    PartiallySettled,
    Refunded,
    Disputed,
    DisputeRejected,
    Cancelled,
    Failed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptIndexEntryV1 {
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    #[serde(rename = "leaseId", default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(rename = "quoteId", default, skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<String>,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "routeId", default)]
    pub route_id: Option<String>,
    #[serde(rename = "privacyMode")]
    pub privacy_mode: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "finishedAt")]
    pub finished_at: String,
    #[serde(rename = "queueMs")]
    pub queue_ms: u64,
    #[serde(rename = "loadMs")]
    pub load_ms: u64,
    #[serde(rename = "computeMs")]
    pub compute_ms: u64,
    #[serde(rename = "totalMs")]
    pub total_ms: u64,
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
    #[serde(
        rename = "outputTokensPerSecond",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_tokens_per_second: Option<f64>,
    #[serde(rename = "estimatedCost")]
    pub estimated_cost: f64,
    pub currency: String,
    #[serde(rename = "licenseGrantId", default)]
    pub license_grant_id: Option<String>,
    #[serde(
        rename = "settlementRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub settlement_ref: Option<String>,
    #[serde(
        rename = "settlementStatus",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub settlement_status: Option<ReceiptSettlementStatusV1>,
    #[serde(rename = "receiptPath", default)]
    pub receipt_path: Option<String>,
    #[serde(rename = "verification")]
    pub verification: ReceiptVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "receiptCount")]
    pub receipt_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "withTimingMetricCount")]
    pub with_timing_metric_count: usize,
    #[serde(rename = "averageQueueMs")]
    pub average_queue_ms: Option<f64>,
    #[serde(rename = "maxQueueMs")]
    pub max_queue_ms: Option<u64>,
    #[serde(rename = "averageLoadMs")]
    pub average_load_ms: Option<f64>,
    #[serde(rename = "maxLoadMs")]
    pub max_load_ms: Option<u64>,
    #[serde(rename = "averageTotalMs")]
    pub average_total_ms: Option<f64>,
    #[serde(rename = "maxTotalMs")]
    pub max_total_ms: Option<u64>,
    #[serde(rename = "throughputSampleCount")]
    pub throughput_sample_count: usize,
    #[serde(rename = "averageOutputTokensPerSecond")]
    pub average_output_tokens_per_second: Option<f64>,
    #[serde(rename = "maxOutputTokensPerSecond")]
    pub max_output_tokens_per_second: Option<f64>,
    pub receipts: Vec<ReceiptIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptAuditSeverityV1 {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptAuditIssueV1 {
    pub severity: ReceiptAuditSeverityV1,
    #[serde(rename = "receiptId", default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptAuditGroupCountV1 {
    pub key: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptAuditCurrencyTotalV1 {
    pub currency: String,
    #[serde(rename = "estimatedCost")]
    pub estimated_cost: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptAuditIndexV1 {
    #[serde(rename = "byJobId")]
    pub by_job_id: Vec<ReceiptAuditGroupCountV1>,
    #[serde(rename = "byRunnerId")]
    pub by_runner_id: Vec<ReceiptAuditGroupCountV1>,
    #[serde(rename = "byRequester")]
    pub by_requester: Vec<ReceiptAuditGroupCountV1>,
    #[serde(rename = "byPackageRef")]
    pub by_package_ref: Vec<ReceiptAuditGroupCountV1>,
    #[serde(rename = "byPrivacyMode")]
    pub by_privacy_mode: Vec<ReceiptAuditGroupCountV1>,
    #[serde(rename = "bySettlementStatus")]
    pub by_settlement_status: Vec<ReceiptAuditGroupCountV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptAuditSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "auditedAt")]
    pub audited_at: String,
    #[serde(rename = "receiptCount")]
    pub receipt_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "hashOnlyCount")]
    pub hash_only_count: usize,
    #[serde(rename = "encryptedEvidenceCount")]
    pub encrypted_evidence_count: usize,
    #[serde(rename = "publicEvidenceCount")]
    pub public_evidence_count: usize,
    #[serde(rename = "missingJobContextCount")]
    pub missing_job_context_count: usize,
    #[serde(rename = "missingSettlementStatusCount")]
    pub missing_settlement_status_count: usize,
    #[serde(rename = "readyForSettlementCount")]
    pub ready_for_settlement_count: usize,
    #[serde(rename = "disputedCount")]
    pub disputed_count: usize,
    #[serde(rename = "redactionRecommendedCount")]
    pub redaction_recommended_count: usize,
    #[serde(rename = "currencyTotals")]
    pub currency_totals: Vec<ReceiptAuditCurrencyTotalV1>,
    pub index: ReceiptAuditIndexV1,
    pub issues: Vec<ReceiptAuditIssueV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptRedactionProfileV1 {
    PublicAudit,
    SettlementAudit,
    InternalAudit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptRedactionPolicyV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub profile: ReceiptRedactionProfileV1,
    #[serde(rename = "revealPackageRef")]
    pub reveal_package_ref: bool,
    #[serde(rename = "revealRunnerId")]
    pub reveal_runner_id: bool,
    #[serde(rename = "revealRouteId")]
    pub reveal_route_id: bool,
    #[serde(rename = "revealAccessGrantRefs")]
    pub reveal_access_grant_refs: bool,
    #[serde(rename = "revealPolicyRefs")]
    pub reveal_policy_refs: bool,
    #[serde(rename = "revealSignature")]
    pub reveal_signature: bool,
    #[serde(rename = "revealTiming")]
    pub reveal_timing: bool,
    #[serde(rename = "revealCost")]
    pub reveal_cost: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RedactedReceiptFieldsV1 {
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(
        rename = "packageRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_ref: Option<String>,
    #[serde(
        rename = "packageRefHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_ref_hash: Option<String>,
    #[serde(rename = "artifactGroup")]
    pub artifact_group: String,
    #[serde(rename = "packageManifestHash")]
    pub package_manifest_hash: String,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(
        rename = "runnerIdHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub runner_id_hash: Option<String>,
    #[serde(rename = "routeId", default, skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    #[serde(
        rename = "routeIdHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub route_id_hash: Option<String>,
    #[serde(rename = "inputHashes")]
    pub input_hashes: Vec<String>,
    #[serde(rename = "outputHashes")]
    pub output_hashes: Vec<String>,
    #[serde(rename = "privacyMode")]
    pub privacy_mode: String,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(
        rename = "finishedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub finished_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<ExecutionMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing: Option<BillingInfo>,
    #[serde(
        rename = "licenseGrantId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub license_grant_id: Option<String>,
    #[serde(
        rename = "licenseGrantIdHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub license_grant_id_hash: Option<String>,
    #[serde(
        rename = "policyDecisionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub policy_decision_id: Option<String>,
    #[serde(
        rename = "policyDecisionHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub policy_decision_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(
        rename = "signatureHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub signature_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RedactedReceiptV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "redactionId")]
    pub redaction_id: String,
    #[serde(rename = "originalReceiptId")]
    pub original_receipt_id: String,
    #[serde(rename = "originalReceiptHash")]
    pub original_receipt_hash: String,
    #[serde(rename = "redactionPolicy")]
    pub redaction_policy: ReceiptRedactionPolicyV1,
    #[serde(rename = "redactedAt")]
    pub redacted_at: String,
    pub fields: RedactedReceiptFieldsV1,
    #[serde(rename = "retainedFields")]
    pub retained_fields: Vec<String>,
    #[serde(rename = "redactedFields")]
    pub redacted_fields: Vec<String>,
    #[serde(rename = "sourceVerification")]
    pub source_verification: ReceiptVerificationV1,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RedactedReceiptVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "redactionId")]
    pub redaction_id: String,
    #[serde(rename = "originalReceiptId")]
    pub original_receipt_id: String,
    pub valid: bool,
    pub issues: Vec<ReceiptVerificationIssueV1>,
    pub warnings: Vec<ReceiptVerificationIssueV1>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BatchReceiptItemStatusV1 {
    Succeeded,
    Failed,
    Cancelled,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchReceiptItemV1 {
    #[serde(rename = "itemId")]
    pub item_id: String,
    #[serde(rename = "requestId", default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub status: BatchReceiptItemStatusV1,
    #[serde(rename = "inputHash")]
    pub input_hash: String,
    #[serde(
        rename = "outputHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ExecutionReceiptErrorV2>,
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    pub metrics: ExecutionMetrics,
    #[serde(rename = "receiptId", default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(
        rename = "receiptRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub receipt_ref: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchReceiptV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "batchReceiptId")]
    pub batch_receipt_id: String,
    #[serde(rename = "batchId")]
    pub batch_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(
        rename = "packageVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_version: Option<String>,
    #[serde(
        rename = "apiSurface",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub api_surface: Option<ApiSurface>,
    #[serde(
        rename = "privacyTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub privacy_tier: Option<PrivacyTier>,
    #[serde(rename = "privacyMode")]
    pub privacy_mode: String,
    #[serde(
        rename = "verificationMode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub verification_mode: Option<IntegrityTier>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    #[serde(rename = "itemCount")]
    pub item_count: u32,
    #[serde(rename = "succeededCount")]
    pub succeeded_count: u32,
    #[serde(rename = "failedCount")]
    pub failed_count: u32,
    #[serde(rename = "cancelledCount")]
    pub cancelled_count: u32,
    #[serde(rename = "skippedCount")]
    pub skipped_count: u32,
    #[serde(rename = "totalMetrics")]
    pub total_metrics: ExecutionMetrics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing: Option<BillingInfo>,
    pub items: Vec<BatchReceiptItemV1>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchReceiptVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "batchReceiptId")]
    pub batch_receipt_id: String,
    #[serde(rename = "batchId")]
    pub batch_id: String,
    pub valid: bool,
    pub issues: Vec<ReceiptVerificationIssueV1>,
    pub warnings: Vec<ReceiptVerificationIssueV1>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchReceiptIndexEntryV1 {
    #[serde(rename = "batchReceiptId")]
    pub batch_receipt_id: String,
    #[serde(rename = "batchId")]
    pub batch_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "privacyMode")]
    pub privacy_mode: String,
    #[serde(rename = "itemCount")]
    pub item_count: u32,
    #[serde(rename = "succeededCount")]
    pub succeeded_count: u32,
    #[serde(rename = "failedCount")]
    pub failed_count: u32,
    #[serde(rename = "cancelledCount")]
    pub cancelled_count: u32,
    #[serde(rename = "skippedCount")]
    pub skipped_count: u32,
    #[serde(rename = "totalMs")]
    pub total_ms: u64,
    #[serde(
        rename = "estimatedCost",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub estimated_cost: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    #[serde(rename = "batchReceiptPath", default)]
    pub batch_receipt_path: Option<String>,
    pub verification: BatchReceiptVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchReceiptStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "batchReceiptCount")]
    pub batch_receipt_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "totalItemCount")]
    pub total_item_count: u32,
    #[serde(rename = "succeededItemCount")]
    pub succeeded_item_count: u32,
    #[serde(rename = "failedItemCount")]
    pub failed_item_count: u32,
    #[serde(rename = "cancelledItemCount")]
    pub cancelled_item_count: u32,
    #[serde(rename = "skippedItemCount")]
    pub skipped_item_count: u32,
    #[serde(rename = "batchReceipts")]
    pub batch_receipts: Vec<BatchReceiptIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchReceiptAuditIndexV1 {
    #[serde(rename = "byBatchId")]
    pub by_batch_id: Vec<ReceiptAuditGroupCountV1>,
    #[serde(rename = "byJobId")]
    pub by_job_id: Vec<ReceiptAuditGroupCountV1>,
    #[serde(rename = "byRunnerId")]
    pub by_runner_id: Vec<ReceiptAuditGroupCountV1>,
    #[serde(rename = "byRequester")]
    pub by_requester: Vec<ReceiptAuditGroupCountV1>,
    #[serde(rename = "byPackageRef")]
    pub by_package_ref: Vec<ReceiptAuditGroupCountV1>,
    #[serde(rename = "byPrivacyMode")]
    pub by_privacy_mode: Vec<ReceiptAuditGroupCountV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchReceiptAuditIssueV1 {
    pub severity: ReceiptAuditSeverityV1,
    #[serde(
        rename = "batchReceiptId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub batch_receipt_id: Option<String>,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchReceiptAuditSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "auditedAt")]
    pub audited_at: String,
    #[serde(rename = "batchReceiptCount")]
    pub batch_receipt_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "totalItemCount")]
    pub total_item_count: u32,
    #[serde(rename = "succeededItemCount")]
    pub succeeded_item_count: u32,
    #[serde(rename = "failedItemCount")]
    pub failed_item_count: u32,
    #[serde(rename = "cancelledItemCount")]
    pub cancelled_item_count: u32,
    #[serde(rename = "skippedItemCount")]
    pub skipped_item_count: u32,
    #[serde(rename = "batchWithFailuresCount")]
    pub batch_with_failures_count: usize,
    #[serde(rename = "batchWithCancellationsCount")]
    pub batch_with_cancellations_count: usize,
    #[serde(rename = "partialSettlementCandidateCount")]
    pub partial_settlement_candidate_count: usize,
    #[serde(rename = "missingJobContextCount")]
    pub missing_job_context_count: usize,
    #[serde(rename = "publicEvidenceCount")]
    pub public_evidence_count: usize,
    #[serde(rename = "redactionRecommendedCount")]
    pub redaction_recommended_count: usize,
    pub index: BatchReceiptAuditIndexV1,
    pub issues: Vec<BatchReceiptAuditIssueV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchReceiptLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "batchReceiptId")]
    pub batch_receipt_id: String,
    #[serde(rename = "batchReceiptPath")]
    pub batch_receipt_path: String,
    #[serde(rename = "batchReceipt")]
    pub batch_receipt: BatchReceiptV1,
    pub verification: BatchReceiptVerificationV1,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BatchReceiptDraftV1 {
    pub batch_id: String,
    pub job_id: Option<String>,
    pub requester: Option<String>,
    pub runner_id: String,
    pub package_ref: String,
    pub package_id: String,
    pub package_version: Option<String>,
    pub api_surface: Option<ApiSurface>,
    pub privacy_tier: Option<PrivacyTier>,
    pub privacy_mode: String,
    pub verification_mode: Option<IntegrityTier>,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub billing: Option<BillingInfo>,
    pub items: Vec<BatchReceiptItemV1>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PartialReceiptV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "partialReceiptId")]
    pub partial_receipt_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "receiptId", default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(
        rename = "receiptRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub receipt_ref: Option<String>,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    pub sequence: u64,
    pub status: ExecutionStatus,
    #[serde(rename = "emittedAt")]
    pub emitted_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<f64>,
    #[serde(
        rename = "outputHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_hash: Option<String>,
    pub metrics: ExecutionMetrics,
    #[serde(
        rename = "verificationValid",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub verification_valid: Option<bool>,
    #[serde(
        rename = "issueCount",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub issue_count: Option<u64>,
    #[serde(
        rename = "warningCount",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub warning_count: Option<u64>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PartialReceiptVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "partialReceiptId")]
    pub partial_receipt_id: String,
    pub valid: bool,
    pub issues: Vec<ReceiptVerificationIssueV1>,
    pub warnings: Vec<ReceiptVerificationIssueV1>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PartialReceiptIndexEntryV1 {
    #[serde(rename = "partialReceiptId")]
    pub partial_receipt_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "receiptId", default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(
        rename = "receiptRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub receipt_ref: Option<String>,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    pub sequence: u64,
    #[serde(rename = "streamSequence")]
    pub stream_sequence: u64,
    #[serde(rename = "streamEventId")]
    pub stream_event_id: String,
    #[serde(rename = "streamEventTimestamp")]
    pub stream_event_timestamp: String,
    #[serde(rename = "emittedAt")]
    pub emitted_at: String,
    pub status: ExecutionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<f64>,
    #[serde(
        rename = "outputHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_hash: Option<String>,
    #[serde(
        rename = "verificationValid",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub verification_valid: Option<bool>,
    #[serde(
        rename = "issueCount",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub issue_count: Option<u64>,
    #[serde(
        rename = "warningCount",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub warning_count: Option<u64>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    pub verification: PartialReceiptVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PartialReceiptStreamSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub key: String,
    #[serde(rename = "eventCount")]
    pub event_count: usize,
    #[serde(rename = "partialEventCount")]
    pub partial_event_count: usize,
    #[serde(rename = "partialReceiptCount")]
    pub partial_receipt_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "malformedCount")]
    pub malformed_count: usize,
    #[serde(rename = "streamIssueCount")]
    pub stream_issue_count: usize,
    pub issues: Vec<ReceiptVerificationIssueV1>,
    #[serde(rename = "partialReceipts")]
    pub partial_receipts: Vec<PartialReceiptIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PartialReceiptDraftV1 {
    pub request_id: String,
    pub job_id: Option<String>,
    pub receipt_id: Option<String>,
    pub receipt_ref: Option<String>,
    pub runner_id: Option<String>,
    pub sequence: u64,
    pub status: ExecutionStatus,
    pub emitted_at: String,
    pub progress: Option<f64>,
    pub output_hash: Option<String>,
    pub metrics: ExecutionMetrics,
    pub verification_valid: Option<bool>,
    pub issue_count: Option<u64>,
    pub warning_count: Option<u64>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptCaptureResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receipt")]
    pub receipt: ExecutionReceiptV1,
    #[serde(rename = "verification")]
    pub verification: ReceiptVerificationV1,
    #[serde(rename = "receiptPath")]
    pub receipt_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptLookupResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "receiptPath")]
    pub receipt_path: String,
    pub receipt: ExecutionReceiptV1,
    pub verification: ReceiptVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptStorageObjectV1 {
    #[serde(rename = "receiptRef")]
    pub receipt_ref: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<StorageTransferMetricsV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptUploadResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "receiptRef")]
    pub receipt_ref: String,
    pub storage: ReceiptStorageObjectV1,
    pub upload: UploadResponseV1,
    pub verification: ReceiptVerificationV1,
    #[serde(rename = "uploadedAt")]
    pub uploaded_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReceiptDownloadResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptRef")]
    pub receipt_ref: String,
    pub storage: ReceiptStorageObjectV1,
    pub receipt: ExecutionReceiptV1,
    pub verification: ReceiptVerificationV1,
    #[serde(rename = "downloadedAt")]
    pub downloaded_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DisputeClaimKind {
    OutputMismatch,
    IncorrectBilling,
    AccessViolation,
    PolicyViolation,
    RunnerFailure,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisputeEvidenceV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "disputeId")]
    pub dispute_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub claimant: String,
    #[serde(rename = "claimKind")]
    pub claim_kind: DisputeClaimKind,
    pub summary: String,
    #[serde(rename = "privacyMode")]
    pub privacy_mode: String,
    #[serde(rename = "evidenceRefs")]
    pub evidence_refs: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub receipt: ExecutionReceiptV1,
    #[serde(rename = "receiptVerification")]
    pub receipt_verification: ReceiptVerificationV1,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisputeEvidenceVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "disputeId")]
    pub dispute_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    pub valid: bool,
    pub issues: Vec<ReceiptVerificationIssueV1>,
    pub warnings: Vec<ReceiptVerificationIssueV1>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisputeEvidenceIndexEntryV1 {
    #[serde(rename = "disputeId")]
    pub dispute_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub claimant: String,
    #[serde(rename = "claimKind")]
    pub claim_kind: DisputeClaimKind,
    #[serde(rename = "privacyMode")]
    pub privacy_mode: String,
    #[serde(rename = "evidenceRefCount")]
    pub evidence_ref_count: usize,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "disputePath")]
    pub dispute_path: String,
    pub verification: DisputeEvidenceVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisputeEvidenceStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "disputeCount")]
    pub dispute_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub disputes: Vec<DisputeEvidenceIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisputeEvidenceLookupResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "disputeId")]
    pub dispute_id: String,
    #[serde(rename = "disputePath")]
    pub dispute_path: String,
    pub evidence: DisputeEvidenceV1,
    pub verification: DisputeEvidenceVerificationV1,
}

pub fn receipt_from_response(response: &ExecutionResponseV1) -> Option<ExecutionReceiptV1> {
    serde_json::from_value(response.metadata.get("receipt")?.clone()).ok()
}

pub fn receipt_id_matches(receipt: &ExecutionReceiptV1) -> bool {
    canonical_receipt_id(receipt)
        .map(|id| id == receipt.receipt_id)
        .unwrap_or(false)
}

pub fn sign_receipt_with_identity(
    receipt: &mut ExecutionReceiptV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != receipt.runner_id {
        anyhow::bail!(
            "identity subject {} does not match receipt runner {}",
            identity.subject,
            receipt.runner_id
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "execution-receipt",
        &receipt_signing_value(receipt),
    )?;
    receipt.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    receipt.receipt_id = canonical_receipt_id(receipt)?;
    Ok(envelope)
}

pub fn verify_receipt(receipt: &ExecutionReceiptV1) -> ReceiptVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if receipt.schema_version != "swarm-ai.receipt.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.receipt.v1",
        ));
    }
    if receipt.receipt_id.trim().is_empty() {
        issues.push(issue("$.receiptId", "Receipt id is required"));
    } else if !receipt_id_matches(receipt) {
        issues.push(issue(
            "$.receiptId",
            "Receipt id does not match canonical receipt hash",
        ));
    }
    for (path, value, message) in [
        (
            "$.requestId",
            receipt.request_id.as_str(),
            "Request id is required",
        ),
        (
            "$.packageId",
            receipt.package_id.as_str(),
            "Package id is required",
        ),
        (
            "$.packageRef",
            receipt.package_ref.as_str(),
            "Package ref is required",
        ),
        (
            "$.artifactGroup",
            receipt.artifact_group.as_str(),
            "Artifact group is required",
        ),
        (
            "$.packageManifestHash",
            receipt.package_manifest_hash.as_str(),
            "Package manifest hash is required",
        ),
        (
            "$.runnerId",
            receipt.runner_id.as_str(),
            "Runner id is required",
        ),
        (
            "$.inputHash",
            receipt.input_hash.as_str(),
            "Input hash is required",
        ),
        (
            "$.outputHash",
            receipt.output_hash.as_str(),
            "Output hash is required",
        ),
        (
            "$.signature",
            receipt.signature.as_str(),
            "Signature is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }
    if !receipt.package_ref.starts_with("bzz://") {
        warnings.push(issue(
            "$.packageRef",
            "Receipt packageRef is not a Swarm bzz:// reference",
        ));
    }
    if !is_sha256_hex(&receipt.package_manifest_hash) {
        issues.push(issue(
            "$.packageManifestHash",
            "Package manifest hash must be a 64-character hex digest",
        ));
    }
    if !is_sha256_hex(&receipt.input_hash) {
        issues.push(issue(
            "$.inputHash",
            "Input hash must be a 64-character hex digest",
        ));
    }
    if !is_sha256_hex(&receipt.output_hash) {
        issues.push(issue(
            "$.outputHash",
            "Output hash must be a 64-character hex digest",
        ));
    }
    if !matches!(
        receipt.privacy_mode.as_str(),
        "hash-only" | "encrypted-evidence" | "public-evidence"
    ) {
        issues.push(issue(
            "$.privacyMode",
            "Privacy mode must be hash-only, encrypted-evidence, or public-evidence",
        ));
    }
    if receipt.privacy_mode == "hash-only" {
        warnings.push(issue(
            "$.privacyMode",
            "Hash-only receipt stores no raw private input or output",
        ));
    }
    if let Some(policy) = &receipt.policy {
        let expected_policy_id = policy_decision_id(&policy.policy_decision);
        if policy.policy_decision_id != expected_policy_id {
            issues.push(issue(
                "$.policy.policyDecisionId",
                "Policy decision id does not match canonical policy decision hash",
            ));
        }
        if policy.policy_decision.package_id != receipt.package_id {
            issues.push(issue(
                "$.policy.policyDecision.packageId",
                "Policy decision packageId must match receipt packageId",
            ));
        }
        if policy.policy_decision.package_ref != receipt.package_ref {
            issues.push(issue(
                "$.policy.policyDecision.packageRef",
                "Policy decision packageRef must match receipt packageRef",
            ));
        }
        if let Some(policy_runner) = &policy.policy_decision.runner_id
            && policy_runner != &receipt.runner_id
        {
            issues.push(issue(
                "$.policy.policyDecision.runnerId",
                "Policy decision runnerId must match receipt runnerId",
            ));
        }
        if DateTime::parse_from_rfc3339(&policy.enforced_at).is_err() {
            issues.push(issue(
                "$.policy.enforcedAt",
                "Policy enforcement timestamp must be RFC3339",
            ));
        }
    }
    if let (Ok(started), Ok(finished)) = (
        DateTime::parse_from_rfc3339(&receipt.started_at),
        DateTime::parse_from_rfc3339(&receipt.finished_at),
    ) {
        if finished < started {
            issues.push(issue(
                "$.finishedAt",
                "Finished timestamp must not be earlier than startedAt",
            ));
        }
    } else {
        issues.push(issue(
            "$.startedAt",
            "startedAt and finishedAt must be RFC3339 timestamps",
        ));
    }
    let mut expected_signature = expected_receipt_signature(receipt);
    if receipt
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &receipt.signature,
            "execution-receipt",
            &receipt_signing_value(receipt),
            Some(&receipt.runner_id),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if receipt.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Receipt signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production runner signing",
        ));
    }

    ReceiptVerificationV1 {
        schema_version: "swarm-ai.receipt-verification.v1".to_string(),
        receipt_id: receipt.receipt_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn verify_execution_receipt_v2_request(
    request: &ExecutionReceiptV2VerificationRequestV1,
) -> ExecutionReceiptV2VerificationV1 {
    let mut verification =
        verify_execution_receipt_v2(&request.receipt, request.source_receipt.as_ref());
    if request.schema_version != "hivemind.execution_receipt_v2_verification_request.v1" {
        verification.issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.execution_receipt_v2_verification_request.v1",
        ));
        verification.valid = false;
    }
    verification
}

pub fn verify_execution_receipt_v2(
    receipt: &ExecutionReceiptV2,
    source_receipt: Option<&ExecutionReceiptV1>,
) -> ExecutionReceiptV2VerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if receipt.schema_version != "hivemind.execution_receipt.v2" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.execution_receipt.v2",
        ));
    }
    for (path, value, message) in [
        (
            "$.receiptId",
            receipt.receipt_id.as_str(),
            "Receipt id is required",
        ),
        ("$.jobId", receipt.job_id.as_str(), "Job id is required"),
        (
            "$.requestId",
            receipt.request_id.as_str(),
            "Request id is required",
        ),
        (
            "$.runnerId",
            receipt.runner_id.as_str(),
            "Runner id is required",
        ),
        (
            "$.requester",
            receipt.requester.as_str(),
            "Requester is required",
        ),
        (
            "$.privacyMode",
            receipt.privacy_mode.as_str(),
            "Privacy mode is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }
    for (path, values, message) in [
        (
            "$.packageRefs",
            &receipt.package_refs,
            "Receipt must include at least one package ref",
        ),
        (
            "$.modelArtifactRefs",
            &receipt.model_artifact_refs,
            "Receipt must include at least one model artifact ref or manifest hash",
        ),
        (
            "$.artifactGroupIds",
            &receipt.artifact_group_ids,
            "Receipt must include at least one artifact group id",
        ),
        (
            "$.inputHashes",
            &receipt.input_hashes,
            "Receipt must include at least one input hash",
        ),
        (
            "$.outputHashes",
            &receipt.output_hashes,
            "Receipt must include at least one output hash",
        ),
        (
            "$.inputModalities",
            &receipt.input_modalities,
            "Receipt must include at least one input modality",
        ),
        (
            "$.outputModalities",
            &receipt.output_modalities,
            "Receipt must include at least one output modality",
        ),
        (
            "$.signatures",
            &receipt.signatures,
            "Receipt must include at least one signature",
        ),
    ] {
        if values.is_empty() {
            issues.push(issue(path, message));
        }
    }
    verify_receipt_v2_refs(receipt, &mut issues, &mut warnings);
    verify_receipt_v2_timing(receipt, &mut issues);
    verify_receipt_v2_status(receipt, &mut issues, &mut warnings);
    verify_receipt_v2_privacy_mode(receipt, &mut issues, &mut warnings);
    verify_receipt_v2_integrity_mode(receipt, &mut issues, &mut warnings);
    verify_receipt_v2_lease_context(receipt, &mut issues, &mut warnings);

    let mut source_receipt_valid = None;
    let mut expected_signature = None;
    let mut signature_verified = false;
    if let Some(source) = source_receipt {
        let source_verification = verify_receipt(source);
        source_receipt_valid = Some(source_verification.valid);
        expected_signature = Some(source_verification.expected_signature);
        if !source_verification.valid {
            issues.push(issue(
                "$.sourceReceipt",
                "Source ExecutionReceiptV1 is not valid",
            ));
        }
        compare_receipt_v2_source(receipt, source, &mut issues, &mut warnings);
        if receipt
            .signatures
            .iter()
            .any(|signature| signature == &source.signature)
        {
            signature_verified = source_verification.valid;
        } else {
            issues.push(issue(
                "$.signatures",
                "Receipt v2 signatures must include the source receipt signature",
            ));
        }
    } else {
        warnings.push(issue(
            "$.signatures",
            "Receipt v2 preserves source receipt signatures; provide sourceReceipt to verify the signature against the v1 evidence",
        ));
    }

    ExecutionReceiptV2VerificationV1 {
        schema_version: "hivemind.execution_receipt_v2_verification.v1".to_string(),
        receipt_id: receipt.receipt_id.clone(),
        valid: issues.is_empty() && signature_verified,
        issues,
        warnings,
        signature_verified,
        source_receipt_valid,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn assess_receipt_correctness(
    request: &ReceiptCorrectnessAssessmentRequestV1,
) -> ReceiptCorrectnessAssessmentV1 {
    let receipt_verification =
        verify_execution_receipt_v2(&request.receipt, request.source_receipt.as_ref());
    let assessed_integrity_tier = request
        .required_integrity_tier
        .clone()
        .unwrap_or_else(|| request.receipt.verification_mode.clone());
    let required_methods = if request.required_methods.is_empty() {
        default_correctness_methods_for_integrity_tier(&assessed_integrity_tier)
    } else {
        dedup_correctness_methods(request.required_methods.clone())
    };

    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut validation_refs = BTreeSet::new();
    let mut accepted_methods = BTreeSet::new();
    let mut failed_methods = BTreeSet::new();
    let mut accepted_evidence_count = 0usize;

    if request.schema_version != RECEIPT_CORRECTNESS_ASSESSMENT_REQUEST_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!(
                "Expected schemaVersion to be {RECEIPT_CORRECTNESS_ASSESSMENT_REQUEST_SCHEMA_VERSION}"
            ),
        ));
    }
    if !receipt_verification.valid {
        issues.push(issue(
            "$.receipt",
            "Receipt v2 must pass structure and source-signature verification before correctness evidence is trusted",
        ));
    }
    if let Some(minimum_confidence) = request.minimum_confidence
        && !(0.0..=1.0).contains(&minimum_confidence)
    {
        issues.push(issue(
            "$.minimumConfidence",
            "minimumConfidence must be between 0.0 and 1.0",
        ));
    }
    if let Some(required_tier) = &request.required_integrity_tier
        && required_tier != &request.receipt.verification_mode
    {
        warnings.push(issue(
            "$.requiredIntegrityTier",
            "Assessment tier differs from the receipt verificationMode; this is an external policy check",
        ));
    }

    for (index, evidence) in request.validation_evidence.iter().enumerate() {
        let path = format!("$.validationEvidence[{index}]");
        let mut evidence_accepted = true;
        if evidence.evidence_ref.trim().is_empty() {
            issues.push(issue(
                format!("{path}.evidenceRef"),
                "Validation evidence must include an evidenceRef",
            ));
            evidence_accepted = false;
        } else {
            validation_refs.insert(evidence.evidence_ref.clone());
            if !looks_like_evidence_ref(&evidence.evidence_ref)
                && !looks_like_hash_ref(&evidence.evidence_ref)
            {
                warnings.push(issue(
                    format!("{path}.evidenceRef"),
                    "Validation evidence ref is not a recognized content, local, web, file, or hash reference",
                ));
            }
        }
        if let Some(receipt_id) = &evidence.receipt_id {
            if receipt_id != &request.receipt.receipt_id {
                issues.push(issue(
                    format!("{path}.receiptId"),
                    "Validation evidence receiptId must match the assessed receipt",
                ));
                evidence_accepted = false;
            }
        } else {
            warnings.push(issue(
                format!("{path}.receiptId"),
                "Validation evidence is not directly scoped to this receiptId",
            ));
        }
        if !evidence.signature_verified {
            issues.push(issue(
                format!("{path}.signatureVerified"),
                "Correctness evidence must come from a verified signed report or integrity evidence object",
            ));
            evidence_accepted = false;
        }
        if let Some(confidence) = evidence.confidence {
            if !(0.0..=1.0).contains(&confidence) {
                issues.push(issue(
                    format!("{path}.confidence"),
                    "Validation evidence confidence must be between 0.0 and 1.0",
                ));
                evidence_accepted = false;
            } else if let Some(minimum_confidence) = request.minimum_confidence
                && confidence < minimum_confidence
            {
                warnings.push(issue(
                    format!("{path}.confidence"),
                    "Validation evidence confidence is below the requested minimum",
                ));
                evidence_accepted = false;
            }
        }
        if let Some(checked_at) = &evidence.checked_at
            && DateTime::parse_from_rfc3339(checked_at).is_err()
        {
            issues.push(issue(
                format!("{path}.checkedAt"),
                "Validation evidence checkedAt must be RFC3339",
            ));
            evidence_accepted = false;
        }
        if evidence.private_evidence
            && !looks_like_hash_ref(&evidence.evidence_ref)
            && !looks_like_evidence_ref(&evidence.evidence_ref)
        {
            warnings.push(issue(
                format!("{path}.privateEvidence"),
                "Private validation evidence should be represented by encrypted content refs or hashes",
            ));
        }
        match evidence.status {
            ReceiptCorrectnessEvidenceStatusV1::Passed if evidence_accepted => {
                accepted_methods.insert(evidence.method);
                accepted_evidence_count += 1;
            }
            ReceiptCorrectnessEvidenceStatusV1::Passed => {}
            ReceiptCorrectnessEvidenceStatusV1::Warning => warnings.push(issue(
                format!("{path}.status"),
                "Validation evidence reported warnings and does not satisfy correctness requirements",
            )),
            ReceiptCorrectnessEvidenceStatusV1::Failed => {
                failed_methods.insert(evidence.method);
                issues.push(issue(
                    format!("{path}.status"),
                    "Validation evidence reported failure",
                ));
            }
            ReceiptCorrectnessEvidenceStatusV1::Inconclusive => warnings.push(issue(
                format!("{path}.status"),
                "Validation evidence was inconclusive and does not satisfy correctness requirements",
            )),
        }
    }

    apply_receipt_embedded_correctness_evidence(&request.receipt, &mut accepted_methods);

    let mut satisfied_methods = Vec::new();
    let mut missing_methods = Vec::new();
    for required in &required_methods {
        if accepted_methods
            .iter()
            .any(|actual| correctness_method_satisfies(*required, *actual))
        {
            satisfied_methods.push(*required);
        } else {
            missing_methods.push(*required);
            issues.push(issue(
                "$.validationEvidence",
                format!(
                    "Missing required correctness evidence method {}",
                    correctness_method_name(required)
                ),
            ));
        }
    }

    let subjective_only = accepted_evidence_count > 0
        && request.validation_evidence.iter().any(|evidence| {
            evidence.status == ReceiptCorrectnessEvidenceStatusV1::Passed
                && evidence.signature_verified
                && evidence.subjective
        })
        && !request.validation_evidence.iter().any(|evidence| {
            evidence.status == ReceiptCorrectnessEvidenceStatusV1::Passed
                && evidence.signature_verified
                && !evidence.subjective
        });
    if subjective_only && !request.allow_subjective_only {
        warnings.push(issue(
            "$.validationEvidence",
            "Only subjective correctness evidence was supplied; disclose this before ranking it as objective proof",
        ));
    }
    if assessed_integrity_tier == IntegrityTier::ReceiptOnly && required_methods.is_empty() {
        warnings.push(issue(
            "$.assessedIntegrityTier",
            "Receipt-only assessment verifies audit structure, not output correctness",
        ));
    }

    let failed_methods = failed_methods.into_iter().collect::<Vec<_>>();
    let correctness_level = correctness_level_for_assessment(
        &assessed_integrity_tier,
        receipt_verification.valid,
        missing_methods.is_empty(),
        &failed_methods,
        accepted_evidence_count,
    );
    let valid = receipt_verification.valid && missing_methods.is_empty() && issues.is_empty();

    ReceiptCorrectnessAssessmentV1 {
        schema_version: RECEIPT_CORRECTNESS_ASSESSMENT_SCHEMA_VERSION.to_string(),
        receipt_id: request.receipt.receipt_id.clone(),
        valid,
        assessed_integrity_tier,
        correctness_level,
        receipt_verification,
        evidence_count: request.validation_evidence.len(),
        accepted_evidence_count,
        validation_refs: validation_refs.into_iter().collect(),
        satisfied_methods,
        missing_methods,
        failed_methods,
        issues,
        warnings,
        assessed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn receipt_redaction_policy(profile: ReceiptRedactionProfileV1) -> ReceiptRedactionPolicyV1 {
    match profile {
        ReceiptRedactionProfileV1::PublicAudit => ReceiptRedactionPolicyV1 {
            schema_version: "hivemind.receipt_redaction_policy.v1".to_string(),
            profile,
            reveal_package_ref: false,
            reveal_runner_id: false,
            reveal_route_id: false,
            reveal_access_grant_refs: false,
            reveal_policy_refs: false,
            reveal_signature: false,
            reveal_timing: true,
            reveal_cost: true,
            reason: Some(
                "Public audit view: retain hashes, timing, and cost while withholding route and identity refs."
                    .to_string(),
            ),
        },
        ReceiptRedactionProfileV1::SettlementAudit => ReceiptRedactionPolicyV1 {
            schema_version: "hivemind.receipt_redaction_policy.v1".to_string(),
            profile,
            reveal_package_ref: true,
            reveal_runner_id: true,
            reveal_route_id: true,
            reveal_access_grant_refs: true,
            reveal_policy_refs: true,
            reveal_signature: false,
            reveal_timing: true,
            reveal_cost: true,
            reason: Some(
                "Settlement audit view: retain routing, package, grant, timing, and cost refs without exposing the original signature body."
                    .to_string(),
            ),
        },
        ReceiptRedactionProfileV1::InternalAudit => ReceiptRedactionPolicyV1 {
            schema_version: "hivemind.receipt_redaction_policy.v1".to_string(),
            profile,
            reveal_package_ref: true,
            reveal_runner_id: true,
            reveal_route_id: true,
            reveal_access_grant_refs: true,
            reveal_policy_refs: true,
            reveal_signature: true,
            reveal_timing: true,
            reveal_cost: true,
            reason: Some(
                "Internal audit view: retain all receipt metadata; raw inputs and outputs are still represented only by hashes."
                    .to_string(),
            ),
        },
    }
}

pub fn redact_receipt(
    receipt: &ExecutionReceiptV1,
    policy: ReceiptRedactionPolicyV1,
) -> RedactedReceiptV1 {
    let source_verification = verify_receipt(receipt);
    let mut retained_fields = vec![
        "$.requestId".to_string(),
        "$.packageId".to_string(),
        "$.artifactGroup".to_string(),
        "$.packageManifestHash".to_string(),
        "$.inputHashes".to_string(),
        "$.outputHashes".to_string(),
        "$.privacyMode".to_string(),
    ];
    let mut redacted_fields = Vec::new();

    let (package_ref, package_ref_hash) = reveal_or_hash(
        &mut retained_fields,
        &mut redacted_fields,
        "$.packageRef",
        &receipt.package_ref,
        policy.reveal_package_ref,
    );
    let (runner_id, runner_id_hash) = reveal_or_hash(
        &mut retained_fields,
        &mut redacted_fields,
        "$.runnerId",
        &receipt.runner_id,
        policy.reveal_runner_id,
    );
    let (route_id, route_id_hash) = reveal_optional_or_hash(
        &mut retained_fields,
        &mut redacted_fields,
        "$.routeId",
        receipt.route_id.as_deref(),
        policy.reveal_route_id,
    );
    let (license_grant_id, license_grant_id_hash) = reveal_optional_or_hash(
        &mut retained_fields,
        &mut redacted_fields,
        "$.access.licenseGrantId",
        receipt.access.license_grant_id.as_deref(),
        policy.reveal_access_grant_refs,
    );
    let (policy_decision_id, policy_decision_hash) = if let Some(policy_evidence) = &receipt.policy
    {
        if policy.reveal_policy_refs {
            retained_fields.push("$.policy.policyDecisionId".to_string());
            (Some(policy_evidence.policy_decision_id.clone()), None)
        } else {
            redacted_fields.push("$.policy".to_string());
            (
                None,
                Some(format!(
                    "sha256://{}",
                    hash_canonical_json(
                        &serde_json::to_value(policy_evidence).unwrap_or_else(|_| json!(null))
                    )
                )),
            )
        }
    } else {
        (None, None)
    };
    let (signature, signature_hash) = reveal_or_hash(
        &mut retained_fields,
        &mut redacted_fields,
        "$.signature",
        &receipt.signature,
        policy.reveal_signature,
    );

    let (started_at, finished_at, metrics) = if policy.reveal_timing {
        retained_fields.push("$.startedAt".to_string());
        retained_fields.push("$.finishedAt".to_string());
        retained_fields.push("$.metrics".to_string());
        (
            Some(receipt.started_at.clone()),
            Some(receipt.finished_at.clone()),
            Some(receipt.metrics.clone()),
        )
    } else {
        redacted_fields.push("$.startedAt".to_string());
        redacted_fields.push("$.finishedAt".to_string());
        redacted_fields.push("$.metrics".to_string());
        (None, None, None)
    };
    let billing = if policy.reveal_cost {
        retained_fields.push("$.billing".to_string());
        Some(receipt.billing.clone())
    } else {
        redacted_fields.push("$.billing".to_string());
        None
    };

    retained_fields.sort();
    retained_fields.dedup();
    redacted_fields.sort();
    redacted_fields.dedup();

    let mut redacted = RedactedReceiptV1 {
        schema_version: "hivemind.receipt_redaction.v1".to_string(),
        redaction_id: String::new(),
        original_receipt_id: receipt.receipt_id.clone(),
        original_receipt_hash: receipt.receipt_id.clone(),
        redaction_policy: policy,
        redacted_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        fields: RedactedReceiptFieldsV1 {
            request_id: receipt.request_id.clone(),
            package_id: receipt.package_id.clone(),
            package_ref,
            package_ref_hash,
            artifact_group: receipt.artifact_group.clone(),
            package_manifest_hash: receipt.package_manifest_hash.clone(),
            runner_id,
            runner_id_hash,
            route_id,
            route_id_hash,
            input_hashes: vec![receipt.input_hash.clone()],
            output_hashes: vec![receipt.output_hash.clone()],
            privacy_mode: receipt.privacy_mode.clone(),
            started_at,
            finished_at,
            metrics,
            billing,
            license_grant_id,
            license_grant_id_hash,
            policy_decision_id,
            policy_decision_hash,
            signature,
            signature_hash,
        },
        retained_fields,
        redacted_fields,
        source_verification,
        signature: String::new(),
    };
    redacted.redaction_id =
        canonical_redacted_receipt_id(&redacted).expect("redacted receipt should serialize");
    sign_redacted_receipt(&mut redacted);
    redacted
}

pub fn sign_redacted_receipt(redacted: &mut RedactedReceiptV1) {
    redacted.signature = expected_redacted_receipt_signature(redacted);
}

pub fn canonical_redacted_receipt_id(redacted: &RedactedReceiptV1) -> serde_json::Result<String> {
    let mut unsigned = redacted.clone();
    unsigned.redaction_id.clear();
    unsigned.signature.clear();
    let value: Value = serde_json::to_value(unsigned)?;
    Ok(format!(
        "receipt-redaction-{}",
        hash_canonical_json(&value)
            .chars()
            .take(24)
            .collect::<String>()
    ))
}

pub fn expected_redacted_receipt_signature(redacted: &RedactedReceiptV1) -> String {
    let value = json!({
        "label": "receipt-redaction",
        "redactionId": redacted.redaction_id,
        "originalReceiptId": redacted.original_receipt_id,
        "payload": redacted_receipt_signing_value(redacted),
    });
    format!(
        "{DEV_RECEIPT_REDACTION_SIGNATURE_PREFIX}:receipt-redaction:{}",
        hash_canonical_json(&value)
    )
}

pub fn verify_redacted_receipt(redacted: &RedactedReceiptV1) -> RedactedReceiptVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if redacted.schema_version != "hivemind.receipt_redaction.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.receipt_redaction.v1",
        ));
    }
    if redacted.redaction_policy.schema_version != "hivemind.receipt_redaction_policy.v1" {
        issues.push(issue(
            "$.redactionPolicy.schemaVersion",
            "Expected redaction policy schemaVersion to be hivemind.receipt_redaction_policy.v1",
        ));
    }
    if redacted.redaction_id.trim().is_empty() {
        issues.push(issue("$.redactionId", "Redaction id is required"));
    } else {
        match canonical_redacted_receipt_id(redacted) {
            Ok(expected_id) if expected_id != redacted.redaction_id => issues.push(issue(
                "$.redactionId",
                "Redaction id does not match canonical redaction hash",
            )),
            Err(_) => issues.push(issue(
                "$.redactionId",
                "Redaction id could not be recomputed",
            )),
            _ => {}
        }
    }
    for (path, value, message) in [
        (
            "$.originalReceiptId",
            redacted.original_receipt_id.as_str(),
            "Original receipt id is required",
        ),
        (
            "$.originalReceiptHash",
            redacted.original_receipt_hash.as_str(),
            "Original receipt hash is required",
        ),
        (
            "$.fields.requestId",
            redacted.fields.request_id.as_str(),
            "Request id is required",
        ),
        (
            "$.fields.packageId",
            redacted.fields.package_id.as_str(),
            "Package id is required",
        ),
        (
            "$.fields.privacyMode",
            redacted.fields.privacy_mode.as_str(),
            "Privacy mode is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }
    if redacted.original_receipt_hash != redacted.original_receipt_id {
        warnings.push(issue(
            "$.originalReceiptHash",
            "Original receipt hash differs from originalReceiptId; this is only expected for non-canonical external receipt ids",
        ));
    }
    if redacted.source_verification.receipt_id != redacted.original_receipt_id {
        issues.push(issue(
            "$.sourceVerification.receiptId",
            "Source verification receiptId must match originalReceiptId",
        ));
    }
    if !redacted.source_verification.valid {
        issues.push(issue(
            "$.sourceVerification.valid",
            "Redacted receipt source verification must be valid",
        ));
    }
    if redacted.fields.input_hashes.is_empty() {
        issues.push(issue(
            "$.fields.inputHashes",
            "At least one input hash must be retained",
        ));
    }
    if redacted.fields.output_hashes.is_empty() {
        issues.push(issue(
            "$.fields.outputHashes",
            "At least one output hash must be retained",
        ));
    }
    enforce_redaction_policy(redacted, &mut issues);
    let expected_signature = expected_redacted_receipt_signature(redacted);
    if redacted.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Redacted receipt signature does not match canonical dev signature",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Redacted receipt uses deterministic local-dev signing",
        ));
    }

    RedactedReceiptVerificationV1 {
        schema_version: "hivemind.receipt_redaction_verification.v1".to_string(),
        redaction_id: redacted.redaction_id.clone(),
        original_receipt_id: redacted.original_receipt_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn index_entry(
    receipt: &ExecutionReceiptV1,
    receipt_path: Option<impl Into<String>>,
) -> ReceiptIndexEntryV1 {
    let verification = verify_receipt(receipt);
    ReceiptIndexEntryV1 {
        receipt_id: receipt.receipt_id.clone(),
        request_id: receipt.request_id.clone(),
        job_id: None,
        requester: None,
        lease_id: None,
        quote_id: None,
        package_id: receipt.package_id.clone(),
        package_ref: receipt.package_ref.clone(),
        runner_id: receipt.runner_id.clone(),
        route_id: receipt.route_id.clone(),
        privacy_mode: receipt.privacy_mode.clone(),
        started_at: receipt.started_at.clone(),
        finished_at: receipt.finished_at.clone(),
        queue_ms: receipt.metrics.queue_ms,
        load_ms: receipt.metrics.load_ms,
        compute_ms: receipt.metrics.compute_ms,
        total_ms: receipt.metrics.total_ms,
        input_tokens: receipt.metrics.input_tokens,
        output_tokens: receipt.metrics.output_tokens,
        output_tokens_per_second: receipt_output_tokens_per_second(&receipt.metrics),
        estimated_cost: receipt.billing.estimated_cost,
        currency: receipt.billing.currency.clone(),
        license_grant_id: receipt.access.license_grant_id.clone(),
        settlement_ref: None,
        settlement_status: None,
        receipt_path: receipt_path.map(Into::into),
        verification,
    }
}

pub fn batch_receipt_index_entry(
    receipt: &BatchReceiptV1,
    batch_receipt_path: Option<impl Into<String>>,
) -> BatchReceiptIndexEntryV1 {
    let verification = verify_batch_receipt(receipt);
    BatchReceiptIndexEntryV1 {
        batch_receipt_id: receipt.batch_receipt_id.clone(),
        batch_id: receipt.batch_id.clone(),
        job_id: receipt.job_id.clone(),
        requester: receipt.requester.clone(),
        runner_id: receipt.runner_id.clone(),
        package_ref: receipt.package_ref.clone(),
        package_id: receipt.package_id.clone(),
        privacy_mode: receipt.privacy_mode.clone(),
        item_count: receipt.item_count,
        succeeded_count: receipt.succeeded_count,
        failed_count: receipt.failed_count,
        cancelled_count: receipt.cancelled_count,
        skipped_count: receipt.skipped_count,
        total_ms: receipt.total_metrics.total_ms,
        estimated_cost: receipt
            .billing
            .as_ref()
            .map(|billing| billing.estimated_cost),
        currency: receipt
            .billing
            .as_ref()
            .map(|billing| billing.currency.clone()),
        created_at: receipt.created_at.clone(),
        completed_at: receipt.completed_at.clone(),
        batch_receipt_path: batch_receipt_path.map(Into::into),
        verification,
    }
}

#[derive(Debug, Clone, PartialEq)]
struct ReceiptTimingAggregates {
    sample_count: usize,
    average_queue_ms: Option<f64>,
    max_queue_ms: Option<u64>,
    average_load_ms: Option<f64>,
    max_load_ms: Option<u64>,
    average_total_ms: Option<f64>,
    max_total_ms: Option<u64>,
    throughput_sample_count: usize,
    average_output_tokens_per_second: Option<f64>,
    max_output_tokens_per_second: Option<f64>,
}

fn receipt_timing_aggregates(entries: &[ReceiptIndexEntryV1]) -> ReceiptTimingAggregates {
    let queue_values: Vec<u64> = entries.iter().map(|entry| entry.queue_ms).collect();
    let load_values: Vec<u64> = entries.iter().map(|entry| entry.load_ms).collect();
    let total_values: Vec<u64> = entries.iter().map(|entry| entry.total_ms).collect();
    let throughput_values: Vec<f64> = entries
        .iter()
        .filter_map(|entry| entry.output_tokens_per_second)
        .filter(|value| value.is_finite())
        .collect();

    ReceiptTimingAggregates {
        sample_count: entries.len(),
        average_queue_ms: average_u64(&queue_values),
        max_queue_ms: queue_values.iter().copied().max(),
        average_load_ms: average_u64(&load_values),
        max_load_ms: load_values.iter().copied().max(),
        average_total_ms: average_u64(&total_values),
        max_total_ms: total_values.iter().copied().max(),
        throughput_sample_count: throughput_values.len(),
        average_output_tokens_per_second: average_f64(&throughput_values),
        max_output_tokens_per_second: throughput_values.iter().copied().reduce(f64::max),
    }
}

fn receipt_output_tokens_per_second(metrics: &ExecutionMetrics) -> Option<f64> {
    let output_tokens = metrics.output_tokens?;
    if metrics.total_ms == 0 {
        return None;
    }
    Some(output_tokens as f64 * 1_000.0 / metrics.total_ms as f64)
}

fn average_u64(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    Some(values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64)
}

fn average_f64(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    Some(values.iter().sum::<f64>() / values.len() as f64)
}

pub fn read_receipt(path: &Path) -> anyhow::Result<ExecutionReceiptV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse receipt JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn read_batch_receipt(path: &Path) -> anyhow::Result<BatchReceiptV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse batch receipt JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_receipt(receipts_dir: &Path, receipt: &ExecutionReceiptV1) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(receipts_dir)?;
    let path = receipts_dir.join(format!("{}.json", safe_file_component(&receipt.receipt_id)));
    fs::write(&path, serde_json::to_vec_pretty(receipt)?)?;
    Ok(path)
}

pub fn write_batch_receipt(
    receipts_dir: &Path,
    receipt: &BatchReceiptV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(receipts_dir)?;
    let path = receipts_dir.join(format!(
        "{}.json",
        safe_file_component(&receipt.batch_receipt_id)
    ));
    fs::write(&path, serde_json::to_vec_pretty(receipt)?)?;
    Ok(path)
}

pub fn get_receipt(
    receipts_dir: &Path,
    receipt_id: &str,
) -> anyhow::Result<Option<ReceiptLookupResultV1>> {
    let receipt_id = receipt_id.trim();
    if receipt_id.is_empty() {
        anyhow::bail!("receiptId is required");
    }

    let direct_path = receipts_dir.join(format!("{}.json", safe_file_component(receipt_id)));
    if direct_path.exists() {
        if json_schema_is(&direct_path, "swarm-ai.receipt.v1") {
            let receipt = read_receipt(&direct_path)?;
            if receipt.receipt_id == receipt_id {
                return Ok(Some(receipt_lookup(receipt, direct_path)));
            }
        }
    }

    if !receipts_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(receipts_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            if !json_schema_is(&path, "swarm-ai.receipt.v1") {
                continue;
            }
            let receipt = read_receipt(&path)?;
            if receipt.receipt_id == receipt_id {
                return Ok(Some(receipt_lookup(receipt, path)));
            }
        }
    }
    Ok(None)
}

pub fn get_batch_receipt(
    receipts_dir: &Path,
    batch_receipt_id: &str,
) -> anyhow::Result<Option<BatchReceiptLookupV1>> {
    let batch_receipt_id = batch_receipt_id.trim();
    if batch_receipt_id.is_empty() {
        anyhow::bail!("batchReceiptId is required");
    }

    let direct_path = receipts_dir.join(format!("{}.json", safe_file_component(batch_receipt_id)));
    if direct_path.exists() {
        if json_schema_is(&direct_path, "hivemind.batch_receipt.v1") {
            let receipt = read_batch_receipt(&direct_path)?;
            if receipt.batch_receipt_id == batch_receipt_id {
                return Ok(Some(batch_receipt_lookup(receipt, direct_path)));
            }
        }
    }

    if !receipts_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(receipts_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            if !json_schema_is(&path, "hivemind.batch_receipt.v1") {
                continue;
            }
            let receipt = read_batch_receipt(&path)?;
            if receipt.batch_receipt_id == batch_receipt_id {
                return Ok(Some(batch_receipt_lookup(receipt, path)));
            }
        }
    }
    Ok(None)
}

pub fn capture_response_receipt(
    receipts_dir: &Path,
    response: &ExecutionResponseV1,
) -> anyhow::Result<Option<ReceiptCaptureResultV1>> {
    let Some(receipt) = receipt_from_response(response) else {
        return Ok(None);
    };
    let verification = verify_receipt(&receipt);
    let path = write_receipt(receipts_dir, &receipt)?;
    Ok(Some(ReceiptCaptureResultV1 {
        schema_version: "swarm-ai.receipt-capture-result.v1".to_string(),
        receipt,
        verification,
        receipt_path: path.display().to_string(),
    }))
}

pub fn list_receipts(receipts_dir: &Path) -> anyhow::Result<ReceiptStoreSummaryV1> {
    let mut entries = Vec::new();
    if receipts_dir.exists() {
        for entry in fs::read_dir(receipts_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                if !json_schema_is(&path, "swarm-ai.receipt.v1") {
                    continue;
                }
                let receipt = read_receipt(&path)?;
                entries.push(index_entry(&receipt, Some(path.display().to_string())));
            }
        }
    }
    entries.sort_by(|left, right| {
        left.started_at
            .cmp(&right.started_at)
            .then(left.receipt_id.cmp(&right.receipt_id))
    });
    let valid_count = entries
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    let timing_metrics = receipt_timing_aggregates(&entries);
    Ok(ReceiptStoreSummaryV1 {
        schema_version: "swarm-ai.receipt-store-summary.v1".to_string(),
        root: receipts_dir.display().to_string(),
        receipt_count: entries.len(),
        valid_count,
        invalid_count: entries.len().saturating_sub(valid_count),
        with_timing_metric_count: timing_metrics.sample_count,
        average_queue_ms: timing_metrics.average_queue_ms,
        max_queue_ms: timing_metrics.max_queue_ms,
        average_load_ms: timing_metrics.average_load_ms,
        max_load_ms: timing_metrics.max_load_ms,
        average_total_ms: timing_metrics.average_total_ms,
        max_total_ms: timing_metrics.max_total_ms,
        throughput_sample_count: timing_metrics.throughput_sample_count,
        average_output_tokens_per_second: timing_metrics.average_output_tokens_per_second,
        max_output_tokens_per_second: timing_metrics.max_output_tokens_per_second,
        receipts: entries,
    })
}

pub fn list_batch_receipts(receipts_dir: &Path) -> anyhow::Result<BatchReceiptStoreSummaryV1> {
    let mut entries = Vec::new();
    if receipts_dir.exists() {
        for entry in fs::read_dir(receipts_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                if !json_schema_is(&path, "hivemind.batch_receipt.v1") {
                    continue;
                }
                let receipt = read_batch_receipt(&path)?;
                entries.push(batch_receipt_index_entry(
                    &receipt,
                    Some(path.display().to_string()),
                ));
            }
        }
    }
    entries.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.batch_receipt_id.cmp(&right.batch_receipt_id))
    });
    let valid_count = entries
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    let mut total_item_count = 0u32;
    let mut succeeded_item_count = 0u32;
    let mut failed_item_count = 0u32;
    let mut cancelled_item_count = 0u32;
    let mut skipped_item_count = 0u32;
    for entry in &entries {
        total_item_count = total_item_count.saturating_add(entry.item_count);
        succeeded_item_count = succeeded_item_count.saturating_add(entry.succeeded_count);
        failed_item_count = failed_item_count.saturating_add(entry.failed_count);
        cancelled_item_count = cancelled_item_count.saturating_add(entry.cancelled_count);
        skipped_item_count = skipped_item_count.saturating_add(entry.skipped_count);
    }
    Ok(BatchReceiptStoreSummaryV1 {
        schema_version: "hivemind.batch_receipt_store_summary.v1".to_string(),
        root: receipts_dir.display().to_string(),
        batch_receipt_count: entries.len(),
        valid_count,
        invalid_count: entries.len().saturating_sub(valid_count),
        total_item_count,
        succeeded_item_count,
        failed_item_count,
        cancelled_item_count,
        skipped_item_count,
        batch_receipts: entries,
    })
}

pub fn audit_batch_receipts_dir(receipts_dir: &Path) -> anyhow::Result<BatchReceiptAuditSummaryV1> {
    let summary = list_batch_receipts(receipts_dir)?;
    Ok(audit_batch_receipt_store(&summary))
}

pub fn audit_batch_receipt_store(
    summary: &BatchReceiptStoreSummaryV1,
) -> BatchReceiptAuditSummaryV1 {
    let mut by_batch_id = BTreeMap::new();
    let mut by_job_id = BTreeMap::new();
    let mut by_runner_id = BTreeMap::new();
    let mut by_requester = BTreeMap::new();
    let mut by_package_ref = BTreeMap::new();
    let mut by_privacy_mode = BTreeMap::new();
    let mut issues = Vec::new();
    let mut batch_with_failures_count = 0;
    let mut batch_with_cancellations_count = 0;
    let mut partial_settlement_candidate_count = 0;
    let mut missing_job_context_count = 0;
    let mut public_evidence_count = 0;
    let mut redaction_recommended_count = 0;

    for entry in &summary.batch_receipts {
        increment_group(&mut by_batch_id, &entry.batch_id);
        increment_group(&mut by_runner_id, &entry.runner_id);
        increment_group(&mut by_package_ref, &entry.package_ref);
        increment_group(&mut by_privacy_mode, &entry.privacy_mode);
        if let Some(job_id) = &entry.job_id {
            increment_group(&mut by_job_id, job_id);
        } else {
            missing_job_context_count += 1;
            issues.push(batch_receipt_audit_issue(
                ReceiptAuditSeverityV1::Warning,
                &entry.batch_receipt_id,
                "$.jobId",
                "Batch receipt is not linked to a local JobRecordV1; lease, lifecycle, and settlement context may be incomplete",
            ));
        }
        if let Some(requester) = &entry.requester {
            increment_group(&mut by_requester, requester);
        }
        if !entry.verification.valid {
            issues.push(batch_receipt_audit_issue(
                ReceiptAuditSeverityV1::Critical,
                &entry.batch_receipt_id,
                "$.verification",
                "Batch receipt verification failed",
            ));
        }
        if entry.failed_count > 0 {
            batch_with_failures_count += 1;
            issues.push(batch_receipt_audit_issue(
                ReceiptAuditSeverityV1::Warning,
                &entry.batch_receipt_id,
                "$.failedCount",
                format!(
                    "Batch receipt includes {} failed item(s)",
                    entry.failed_count
                ),
            ));
        }
        if entry.cancelled_count > 0 {
            batch_with_cancellations_count += 1;
            issues.push(batch_receipt_audit_issue(
                ReceiptAuditSeverityV1::Warning,
                &entry.batch_receipt_id,
                "$.cancelledCount",
                format!(
                    "Batch receipt includes {} cancelled item(s)",
                    entry.cancelled_count
                ),
            ));
        }
        if entry.skipped_count > 0 {
            issues.push(batch_receipt_audit_issue(
                ReceiptAuditSeverityV1::Info,
                &entry.batch_receipt_id,
                "$.skippedCount",
                format!(
                    "Batch receipt includes {} skipped item(s)",
                    entry.skipped_count
                ),
            ));
        }
        if entry.succeeded_count > 0
            && entry
                .failed_count
                .saturating_add(entry.cancelled_count)
                .saturating_add(entry.skipped_count)
                > 0
        {
            partial_settlement_candidate_count += 1;
            issues.push(batch_receipt_audit_issue(
                ReceiptAuditSeverityV1::Info,
                &entry.batch_receipt_id,
                "$.items",
                "Batch receipt has mixed item outcomes and may require partial settlement or retry handling",
            ));
        }
        match entry.privacy_mode.as_str() {
            "public-evidence" => {
                public_evidence_count += 1;
                redaction_recommended_count += 1;
                issues.push(batch_receipt_audit_issue(
                    ReceiptAuditSeverityV1::Warning,
                    &entry.batch_receipt_id,
                    "$.privacyMode",
                    "Batch receipt uses public-evidence mode; publish a redacted view for broad audit sharing",
                ));
            }
            "encrypted-evidence" => {
                redaction_recommended_count += 1;
            }
            _ => {}
        }
        for issue_item in &entry.verification.issues {
            issues.push(batch_receipt_audit_issue(
                ReceiptAuditSeverityV1::Critical,
                &entry.batch_receipt_id,
                &issue_item.path,
                issue_item.message.clone(),
            ));
        }
        for warning in &entry.verification.warnings {
            issues.push(batch_receipt_audit_issue(
                ReceiptAuditSeverityV1::Warning,
                &entry.batch_receipt_id,
                &warning.path,
                warning.message.clone(),
            ));
        }
    }

    BatchReceiptAuditSummaryV1 {
        schema_version: "hivemind.batch_receipt_audit_summary.v1".to_string(),
        root: summary.root.clone(),
        audited_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        batch_receipt_count: summary.batch_receipt_count,
        valid_count: summary.valid_count,
        invalid_count: summary.invalid_count,
        total_item_count: summary.total_item_count,
        succeeded_item_count: summary.succeeded_item_count,
        failed_item_count: summary.failed_item_count,
        cancelled_item_count: summary.cancelled_item_count,
        skipped_item_count: summary.skipped_item_count,
        batch_with_failures_count,
        batch_with_cancellations_count,
        partial_settlement_candidate_count,
        missing_job_context_count,
        public_evidence_count,
        redaction_recommended_count,
        index: BatchReceiptAuditIndexV1 {
            by_batch_id: group_counts(by_batch_id),
            by_job_id: group_counts(by_job_id),
            by_runner_id: group_counts(by_runner_id),
            by_requester: group_counts(by_requester),
            by_package_ref: group_counts(by_package_ref),
            by_privacy_mode: group_counts(by_privacy_mode),
        },
        issues,
    }
}

pub fn audit_receipts_dir(receipts_dir: &Path) -> anyhow::Result<ReceiptAuditSummaryV1> {
    let summary = list_receipts(receipts_dir)?;
    Ok(audit_receipt_store(&summary))
}

pub fn audit_receipt_store(summary: &ReceiptStoreSummaryV1) -> ReceiptAuditSummaryV1 {
    let mut by_job_id = BTreeMap::new();
    let mut by_runner_id = BTreeMap::new();
    let mut by_requester = BTreeMap::new();
    let mut by_package_ref = BTreeMap::new();
    let mut by_privacy_mode = BTreeMap::new();
    let mut by_settlement_status = BTreeMap::new();
    let mut currency_totals = BTreeMap::<String, f64>::new();
    let mut issues = Vec::new();
    let mut hash_only_count = 0;
    let mut encrypted_evidence_count = 0;
    let mut public_evidence_count = 0;
    let mut missing_job_context_count = 0;
    let mut missing_settlement_status_count = 0;
    let mut ready_for_settlement_count = 0;
    let mut disputed_count = 0;
    let mut redaction_recommended_count = 0;

    for entry in &summary.receipts {
        increment_group(&mut by_runner_id, &entry.runner_id);
        increment_group(&mut by_package_ref, &entry.package_ref);
        increment_group(&mut by_privacy_mode, &entry.privacy_mode);
        if let Some(job_id) = &entry.job_id {
            increment_group(&mut by_job_id, job_id);
        } else {
            missing_job_context_count += 1;
            issues.push(receipt_audit_issue(
                ReceiptAuditSeverityV1::Warning,
                &entry.receipt_id,
                "$.jobId",
                "Receipt is not linked to a local JobRecordV1; lifecycle, lease, stream, and settlement context may be incomplete",
            ));
        }
        if let Some(requester) = &entry.requester {
            increment_group(&mut by_requester, requester);
        }
        if let Some(status) = &entry.settlement_status {
            let label = settlement_status_label(status);
            increment_group(&mut by_settlement_status, &label);
            match status {
                ReceiptSettlementStatusV1::ReadyForSettlement => {
                    ready_for_settlement_count += 1;
                    issues.push(receipt_audit_issue(
                        ReceiptAuditSeverityV1::Info,
                        &entry.receipt_id,
                        "$.settlementStatus",
                        "Receipt is ready for settlement",
                    ));
                }
                ReceiptSettlementStatusV1::Disputed => {
                    disputed_count += 1;
                    issues.push(receipt_audit_issue(
                        ReceiptAuditSeverityV1::Warning,
                        &entry.receipt_id,
                        "$.settlementStatus",
                        "Receipt has an open or recorded dispute",
                    ));
                }
                ReceiptSettlementStatusV1::Blocked
                | ReceiptSettlementStatusV1::Failed
                | ReceiptSettlementStatusV1::Cancelled => {
                    issues.push(receipt_audit_issue(
                        ReceiptAuditSeverityV1::Critical,
                        &entry.receipt_id,
                        "$.settlementStatus",
                        "Receipt settlement path is blocked or failed",
                    ));
                }
                _ => {}
            }
        } else {
            missing_settlement_status_count += 1;
            issues.push(receipt_audit_issue(
                ReceiptAuditSeverityV1::Warning,
                &entry.receipt_id,
                "$.settlementStatus",
                "Receipt has no settlement status context",
            ));
        }
        match entry.privacy_mode.as_str() {
            "hash-only" => hash_only_count += 1,
            "encrypted-evidence" => encrypted_evidence_count += 1,
            "public-evidence" => {
                public_evidence_count += 1;
                redaction_recommended_count += 1;
                issues.push(receipt_audit_issue(
                    ReceiptAuditSeverityV1::Warning,
                    &entry.receipt_id,
                    "$.privacyMode",
                    "Receipt uses public-evidence mode; publish a redacted view for broad audit sharing",
                ));
            }
            _ => {}
        }
        if entry.license_grant_id.is_some()
            || entry.privacy_mode == "encrypted-evidence"
            || entry.privacy_mode == "public-evidence"
        {
            redaction_recommended_count += usize::from(entry.privacy_mode != "public-evidence");
        }
        *currency_totals.entry(entry.currency.clone()).or_default() += entry.estimated_cost;
        if !entry.verification.valid {
            issues.push(receipt_audit_issue(
                ReceiptAuditSeverityV1::Critical,
                &entry.receipt_id,
                "$.verification",
                "Receipt verification failed",
            ));
        }
        for issue_item in &entry.verification.issues {
            issues.push(receipt_audit_issue(
                ReceiptAuditSeverityV1::Critical,
                &entry.receipt_id,
                &issue_item.path,
                issue_item.message.clone(),
            ));
        }
        for warning in &entry.verification.warnings {
            issues.push(receipt_audit_issue(
                ReceiptAuditSeverityV1::Warning,
                &entry.receipt_id,
                &warning.path,
                warning.message.clone(),
            ));
        }
    }

    ReceiptAuditSummaryV1 {
        schema_version: "hivemind.receipt_audit_summary.v1".to_string(),
        root: summary.root.clone(),
        audited_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        receipt_count: summary.receipt_count,
        valid_count: summary.valid_count,
        invalid_count: summary.invalid_count,
        hash_only_count,
        encrypted_evidence_count,
        public_evidence_count,
        missing_job_context_count,
        missing_settlement_status_count,
        ready_for_settlement_count,
        disputed_count,
        redaction_recommended_count,
        currency_totals: currency_totals
            .into_iter()
            .map(|(currency, estimated_cost)| ReceiptAuditCurrencyTotalV1 {
                currency,
                estimated_cost,
            })
            .collect(),
        index: ReceiptAuditIndexV1 {
            by_job_id: group_counts(by_job_id),
            by_runner_id: group_counts(by_runner_id),
            by_requester: group_counts(by_requester),
            by_package_ref: group_counts(by_package_ref),
            by_privacy_mode: group_counts(by_privacy_mode),
            by_settlement_status: group_counts(by_settlement_status),
        },
        issues,
    }
}

fn receipt_lookup(receipt: ExecutionReceiptV1, path: PathBuf) -> ReceiptLookupResultV1 {
    let verification = verify_receipt(&receipt);
    ReceiptLookupResultV1 {
        schema_version: "swarm-ai.receipt-lookup.v1".to_string(),
        receipt_id: receipt.receipt_id.clone(),
        receipt_path: path.display().to_string(),
        receipt,
        verification,
    }
}

fn batch_receipt_lookup(receipt: BatchReceiptV1, path: PathBuf) -> BatchReceiptLookupV1 {
    let verification = verify_batch_receipt(&receipt);
    BatchReceiptLookupV1 {
        schema_version: "hivemind.batch_receipt_lookup.v1".to_string(),
        batch_receipt_id: receipt.batch_receipt_id.clone(),
        batch_receipt_path: path.display().to_string(),
        batch_receipt: receipt,
        verification,
    }
}

fn dispute_index_entry(
    evidence: &DisputeEvidenceV1,
    dispute_path: String,
) -> DisputeEvidenceIndexEntryV1 {
    let verification = verify_dispute_evidence(evidence);
    DisputeEvidenceIndexEntryV1 {
        dispute_id: evidence.dispute_id.clone(),
        receipt_id: evidence.receipt_id.clone(),
        request_id: evidence.request_id.clone(),
        package_id: evidence.package_id.clone(),
        package_ref: evidence.package_ref.clone(),
        runner_id: evidence.runner_id.clone(),
        claimant: evidence.claimant.clone(),
        claim_kind: evidence.claim_kind.clone(),
        privacy_mode: evidence.privacy_mode.clone(),
        evidence_ref_count: evidence.evidence_refs.len(),
        created_at: evidence.created_at.clone(),
        dispute_path,
        verification,
    }
}

fn dispute_lookup(evidence: DisputeEvidenceV1, path: PathBuf) -> DisputeEvidenceLookupResultV1 {
    let verification = verify_dispute_evidence(&evidence);
    DisputeEvidenceLookupResultV1 {
        schema_version: "swarm-ai.dispute-evidence-lookup.v1".to_string(),
        dispute_id: evidence.dispute_id.clone(),
        dispute_path: path.display().to_string(),
        evidence,
        verification,
    }
}

pub fn upload_receipt(
    storage: &mut impl StorageProvider,
    receipt: &ExecutionReceiptV1,
) -> anyhow::Result<ReceiptUploadResultV1> {
    let verification = verify_receipt(receipt);
    if !verification.valid {
        anyhow::bail!("receipt is invalid and will not be uploaded");
    }
    let bytes = serde_json::to_vec_pretty(receipt)?;
    let sha256 = Some(hash_bytes(&bytes));
    let upload = storage
        .upload_bytes(bytes)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let receipt_ref = upload.reference.clone();
    Ok(ReceiptUploadResultV1 {
        schema_version: "swarm-ai.receipt-upload.v1".to_string(),
        receipt_id: receipt.receipt_id.clone(),
        receipt_ref: receipt_ref.clone(),
        storage: ReceiptStorageObjectV1 {
            receipt_ref,
            content_type: "application/json".to_string(),
            size_bytes: upload.size_bytes,
            sha256,
            metrics: Some(upload.metrics.clone()),
        },
        upload,
        verification,
        uploaded_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn download_receipt(
    storage: &impl StorageProvider,
    receipt_ref: &str,
) -> anyhow::Result<ReceiptDownloadResultV1> {
    let download = storage
        .download_bytes(receipt_ref)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let receipt: ExecutionReceiptV1 = serde_json::from_slice(&download.bytes)?;
    let verification = verify_receipt(&receipt);
    Ok(ReceiptDownloadResultV1 {
        schema_version: "swarm-ai.receipt-download.v1".to_string(),
        receipt_ref: receipt_ref.to_string(),
        storage: ReceiptStorageObjectV1 {
            receipt_ref: download.reference,
            content_type: download.content_type,
            size_bytes: download.size_bytes,
            sha256: download.sha256,
            metrics: Some(download.metrics),
        },
        receipt,
        verification,
        downloaded_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn create_batch_receipt(draft: BatchReceiptDraftV1) -> BatchReceiptV1 {
    let (succeeded_count, failed_count, cancelled_count, skipped_count) =
        batch_receipt_status_counts(&draft.items);
    let mut receipt = BatchReceiptV1 {
        schema_version: "hivemind.batch_receipt.v1".to_string(),
        batch_receipt_id: String::new(),
        batch_id: draft.batch_id,
        job_id: draft.job_id,
        requester: draft.requester,
        runner_id: draft.runner_id,
        package_ref: draft.package_ref,
        package_id: draft.package_id,
        package_version: draft.package_version,
        api_surface: draft.api_surface,
        privacy_tier: draft.privacy_tier,
        privacy_mode: draft.privacy_mode,
        verification_mode: draft.verification_mode,
        created_at: draft.created_at,
        completed_at: draft.completed_at,
        item_count: draft.items.len() as u32,
        succeeded_count,
        failed_count,
        cancelled_count,
        skipped_count,
        total_metrics: aggregate_batch_receipt_metrics(&draft.items),
        billing: draft.billing,
        items: draft.items,
        evidence_refs: draft.evidence_refs,
        signature: String::new(),
    };
    receipt.batch_receipt_id =
        canonical_batch_receipt_id(&receipt).expect("batch receipt should serialize for id");
    sign_batch_receipt(&mut receipt);
    receipt
}

pub fn sign_batch_receipt(receipt: &mut BatchReceiptV1) {
    receipt.signature = expected_batch_receipt_signature(receipt);
}

pub fn sign_batch_receipt_with_identity(
    receipt: &mut BatchReceiptV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != receipt.runner_id {
        anyhow::bail!(
            "identity subject {} does not match batch receipt runner {}",
            identity.subject,
            receipt.runner_id
        );
    }
    receipt.batch_receipt_id = canonical_batch_receipt_id(receipt)?;
    let envelope = hivemind_identity::sign_value(
        identity,
        "batch-receipt",
        &batch_receipt_signing_value(receipt),
    )?;
    receipt.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    Ok(envelope)
}

pub fn canonical_batch_receipt_id(receipt: &BatchReceiptV1) -> serde_json::Result<String> {
    let mut unsigned = receipt.clone();
    unsigned.batch_receipt_id.clear();
    unsigned.signature.clear();
    let value: Value = serde_json::to_value(unsigned)?;
    Ok(format!(
        "batch-receipt-{}",
        hash_canonical_json(&value)
            .chars()
            .take(24)
            .collect::<String>()
    ))
}

pub fn expected_batch_receipt_signature(receipt: &BatchReceiptV1) -> String {
    let value = json!({
        "label": "batch-receipt",
        "batchReceiptId": receipt.batch_receipt_id,
        "batchId": receipt.batch_id,
        "runnerId": receipt.runner_id,
        "payload": batch_receipt_signing_value(receipt),
    });
    format!(
        "{DEV_BATCH_RECEIPT_SIGNATURE_PREFIX}:batch-receipt:{}",
        hash_canonical_json(&value)
    )
}

pub fn verify_batch_receipt(receipt: &BatchReceiptV1) -> BatchReceiptVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if receipt.schema_version != "hivemind.batch_receipt.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.batch_receipt.v1",
        ));
    }
    if receipt.batch_receipt_id.trim().is_empty() {
        issues.push(issue("$.batchReceiptId", "Batch receipt id is required"));
    } else {
        match canonical_batch_receipt_id(receipt) {
            Ok(expected_id) if expected_id != receipt.batch_receipt_id => issues.push(issue(
                "$.batchReceiptId",
                "Batch receipt id does not match canonical batch receipt hash",
            )),
            Err(_) => issues.push(issue(
                "$.batchReceiptId",
                "Batch receipt id could not be recomputed",
            )),
            _ => {}
        }
    }
    for (path, value, message) in [
        (
            "$.batchId",
            receipt.batch_id.as_str(),
            "Batch id is required",
        ),
        (
            "$.runnerId",
            receipt.runner_id.as_str(),
            "Runner id is required",
        ),
        (
            "$.packageRef",
            receipt.package_ref.as_str(),
            "Package ref is required",
        ),
        (
            "$.packageId",
            receipt.package_id.as_str(),
            "Package id is required",
        ),
        (
            "$.privacyMode",
            receipt.privacy_mode.as_str(),
            "Privacy mode is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }
    if !matches!(
        receipt.privacy_mode.as_str(),
        "hash-only" | "encrypted-evidence" | "public-evidence"
    ) {
        issues.push(issue(
            "$.privacyMode",
            "Privacy mode must be hash-only, encrypted-evidence, or public-evidence",
        ));
    }
    if receipt.privacy_mode == "hash-only" {
        warnings.push(issue(
            "$.privacyMode",
            "Hash-only batch receipt stores no raw private item input or output",
        ));
    } else if receipt.privacy_mode == "public-evidence" {
        warnings.push(issue(
            "$.privacyMode",
            "Public-evidence batch receipts should publish a redacted audit view before broad sharing",
        ));
    }
    if DateTime::parse_from_rfc3339(&receipt.created_at).is_err() {
        issues.push(issue(
            "$.createdAt",
            "Batch receipt createdAt must be an RFC3339 timestamp",
        ));
    }
    if let Some(completed_at) = &receipt.completed_at {
        match (
            DateTime::parse_from_rfc3339(&receipt.created_at),
            DateTime::parse_from_rfc3339(completed_at),
        ) {
            (Ok(created_at), Ok(completed_at)) if completed_at < created_at => issues.push(issue(
                "$.completedAt",
                "Batch receipt completedAt must not be earlier than createdAt",
            )),
            (_, Err(_)) => issues.push(issue(
                "$.completedAt",
                "Batch receipt completedAt must be an RFC3339 timestamp",
            )),
            _ => {}
        }
    }
    if let Some(billing) = &receipt.billing
        && billing.estimated_cost < 0.0
    {
        issues.push(issue(
            "$.billing.estimatedCost",
            "Estimated cost must be non-negative",
        ));
    }
    verify_batch_receipt_counts(receipt, &mut issues);
    verify_batch_receipt_items(receipt, &mut issues, &mut warnings);
    verify_batch_receipt_evidence_refs(
        "$.evidenceRefs",
        &receipt.evidence_refs,
        &mut issues,
        &mut warnings,
    );
    if receipt.evidence_refs.is_empty() {
        warnings.push(issue(
            "$.evidenceRefs",
            "Batch receipt has no batch-level evidence references",
        ));
    }

    let mut expected_signature = expected_batch_receipt_signature(receipt);
    if receipt
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &receipt.signature,
            "batch-receipt",
            &batch_receipt_signing_value(receipt),
            Some(&receipt.runner_id),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if receipt.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Batch receipt signature does not match canonical dev signature or Ed25519 runner identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Batch receipt uses deterministic local-dev signing",
        ));
    }

    BatchReceiptVerificationV1 {
        schema_version: "hivemind.batch_receipt_verification.v1".to_string(),
        batch_receipt_id: receipt.batch_receipt_id.clone(),
        batch_id: receipt.batch_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn create_partial_receipt(draft: PartialReceiptDraftV1) -> PartialReceiptV1 {
    let mut receipt = PartialReceiptV1 {
        schema_version: "hivemind.partial_receipt.v1".to_string(),
        partial_receipt_id: String::new(),
        request_id: draft.request_id,
        job_id: draft.job_id,
        receipt_id: draft.receipt_id,
        receipt_ref: draft.receipt_ref,
        runner_id: draft.runner_id,
        sequence: draft.sequence,
        status: draft.status,
        emitted_at: draft.emitted_at,
        progress: draft.progress,
        output_hash: draft.output_hash,
        metrics: draft.metrics,
        verification_valid: draft.verification_valid,
        issue_count: draft.issue_count,
        warning_count: draft.warning_count,
        evidence_refs: draft.evidence_refs,
        signature: String::new(),
    };
    sign_partial_receipt(&mut receipt);
    receipt.partial_receipt_id =
        canonical_partial_receipt_id(&receipt).expect("partial receipt should serialize for id");
    receipt
}

pub fn sign_partial_receipt(receipt: &mut PartialReceiptV1) {
    receipt.signature = expected_partial_receipt_signature(receipt);
}

pub fn expected_partial_receipt_signature(receipt: &PartialReceiptV1) -> String {
    let value = json!({
        "label": "partial-receipt",
        "runnerId": receipt.runner_id,
        "requestId": receipt.request_id,
        "payload": partial_receipt_signing_value(receipt),
    });
    format!(
        "{DEV_PARTIAL_RECEIPT_SIGNATURE_PREFIX}:partial-receipt:{}",
        hash_canonical_json(&value)
    )
}

pub fn canonical_partial_receipt_id(receipt: &PartialReceiptV1) -> serde_json::Result<String> {
    let mut signed = receipt.clone();
    signed.partial_receipt_id.clear();
    let value: Value = serde_json::to_value(signed)?;
    Ok(format!(
        "partial-receipt-{}",
        hash_canonical_json(&value)
            .chars()
            .take(24)
            .collect::<String>()
    ))
}

pub fn verify_partial_receipt(receipt: &PartialReceiptV1) -> PartialReceiptVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if receipt.schema_version != "hivemind.partial_receipt.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.partial_receipt.v1",
        ));
    }
    if receipt.partial_receipt_id.trim().is_empty() {
        issues.push(issue(
            "$.partialReceiptId",
            "Partial receipt id is required",
        ));
    } else {
        match canonical_partial_receipt_id(receipt) {
            Ok(expected_id) if expected_id != receipt.partial_receipt_id => issues.push(issue(
                "$.partialReceiptId",
                "Partial receipt id does not match canonical partial receipt hash",
            )),
            Err(_) => issues.push(issue(
                "$.partialReceiptId",
                "Partial receipt id could not be recomputed",
            )),
            _ => {}
        }
    }
    if receipt.request_id.trim().is_empty() {
        issues.push(issue("$.requestId", "Request id is required"));
    }
    if DateTime::parse_from_rfc3339(&receipt.emitted_at).is_err() {
        issues.push(issue(
            "$.emittedAt",
            "Partial receipt emittedAt must be an RFC3339 timestamp",
        ));
    }
    if let Some(progress) = receipt.progress
        && !(0.0..=1.0).contains(&progress)
    {
        issues.push(issue("$.progress", "Progress must be between 0.0 and 1.0"));
    }
    if let Some(output_hash) = &receipt.output_hash
        && !is_sha256_hex(output_hash)
    {
        issues.push(issue(
            "$.outputHash",
            "Output hash must be a 64-character hex digest",
        ));
    }
    if receipt.receipt_id.is_some() && receipt.receipt_ref.is_none() {
        warnings.push(issue(
            "$.receiptRef",
            "Partial receipt references a final receipt id without a receipt ref",
        ));
    }
    if receipt.evidence_refs.is_empty() {
        warnings.push(issue(
            "$.evidenceRefs",
            "Partial receipt has no external evidence references",
        ));
    }
    for (index, reference) in receipt.evidence_refs.iter().enumerate() {
        if reference.trim().is_empty() {
            issues.push(issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference must not be empty",
            ));
        } else if !looks_like_evidence_ref(reference) {
            warnings.push(issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference is not a recognized bzz://, local://, ipfs://, http(s)://, or file path reference",
            ));
        }
    }

    let expected_signature = expected_partial_receipt_signature(receipt);
    if receipt.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Partial receipt signature does not match canonical dev signature",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Partial receipt uses deterministic local-dev signing",
        ));
    }

    PartialReceiptVerificationV1 {
        schema_version: "hivemind.partial_receipt_verification.v1".to_string(),
        partial_receipt_id: receipt.partial_receipt_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn partial_receipts_from_stream_events(events: &[StreamingEventV1]) -> Vec<PartialReceiptV1> {
    events
        .iter()
        .filter_map(partial_receipt_from_stream_event)
        .collect()
}

pub fn partial_receipt_from_stream_event(event: &StreamingEventV1) -> Option<PartialReceiptV1> {
    if event.event_type != StreamingEventType::PartialReceipt {
        return None;
    }
    serde_json::from_value(event.payload.get("partialReceipt")?.clone()).ok()
}

pub fn partial_receipt_index_entry(
    event: &StreamingEventV1,
    receipt: &PartialReceiptV1,
) -> PartialReceiptIndexEntryV1 {
    let verification = verify_partial_receipt(receipt);
    PartialReceiptIndexEntryV1 {
        partial_receipt_id: receipt.partial_receipt_id.clone(),
        request_id: receipt.request_id.clone(),
        job_id: receipt.job_id.clone(),
        receipt_id: receipt.receipt_id.clone(),
        receipt_ref: receipt.receipt_ref.clone(),
        runner_id: receipt.runner_id.clone(),
        sequence: receipt.sequence,
        stream_sequence: event.sequence,
        stream_event_id: event.event_id.clone(),
        stream_event_timestamp: event.timestamp.clone(),
        emitted_at: receipt.emitted_at.clone(),
        status: receipt.status.clone(),
        progress: receipt.progress,
        output_hash: receipt.output_hash.clone(),
        verification_valid: receipt.verification_valid,
        issue_count: receipt.issue_count,
        warning_count: receipt.warning_count,
        evidence_refs: receipt.evidence_refs.clone(),
        verification,
    }
}

pub fn partial_receipt_stream_summary(
    key: impl Into<String>,
    events: &[StreamingEventV1],
) -> PartialReceiptStreamSummaryV1 {
    let mut issues = Vec::new();
    let mut entries = Vec::new();
    let partial_event_count = events
        .iter()
        .filter(|event| event.event_type == StreamingEventType::PartialReceipt)
        .count();

    for (event_index, event) in events.iter().enumerate() {
        if event.event_type != StreamingEventType::PartialReceipt {
            continue;
        }
        let Some(partial_value) = event.payload.get("partialReceipt") else {
            issues.push(issue(
                format!("$.events[{event_index}].payload.partialReceipt"),
                "Partial receipt stream event is missing payload.partialReceipt",
            ));
            continue;
        };
        let receipt: PartialReceiptV1 = match serde_json::from_value(partial_value.clone()) {
            Ok(receipt) => receipt,
            Err(error) => {
                issues.push(issue(
                    format!("$.events[{event_index}].payload.partialReceipt"),
                    format!("Partial receipt payload could not be decoded: {error}"),
                ));
                continue;
            }
        };
        if receipt.request_id != event.request_id {
            issues.push(issue(
                format!("$.events[{event_index}].payload.partialReceipt.requestId"),
                "Partial receipt requestId does not match its stream event requestId",
            ));
        }
        if receipt.job_id != event.job_id {
            issues.push(issue(
                format!("$.events[{event_index}].payload.partialReceipt.jobId"),
                "Partial receipt jobId does not match its stream event jobId",
            ));
        }
        if receipt.sequence != event.sequence {
            issues.push(issue(
                format!("$.events[{event_index}].payload.partialReceipt.sequence"),
                "Partial receipt sequence does not match its stream event sequence",
            ));
        }
        entries.push(partial_receipt_index_entry(event, &receipt));
    }

    entries.sort_by(|left, right| {
        left.stream_sequence
            .cmp(&right.stream_sequence)
            .then_with(|| left.partial_receipt_id.cmp(&right.partial_receipt_id))
    });
    let valid_count = entries
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    let invalid_count = entries.len().saturating_sub(valid_count);
    let malformed_count = partial_event_count.saturating_sub(entries.len());
    PartialReceiptStreamSummaryV1 {
        schema_version: "hivemind.partial_receipt_stream_summary.v1".to_string(),
        key: key.into(),
        event_count: events.len(),
        partial_event_count,
        partial_receipt_count: entries.len(),
        valid_count,
        invalid_count,
        malformed_count,
        stream_issue_count: issues.len(),
        issues,
        partial_receipts: entries,
    }
}

pub fn create_dispute_evidence(
    receipt: ExecutionReceiptV1,
    claimant: impl Into<String>,
    claim_kind: DisputeClaimKind,
    summary: impl Into<String>,
    evidence_refs: Vec<String>,
) -> DisputeEvidenceV1 {
    let receipt_verification = verify_receipt(&receipt);
    let mut evidence = DisputeEvidenceV1 {
        schema_version: "swarm-ai.receipt-dispute-evidence.v1".to_string(),
        dispute_id: String::new(),
        receipt_id: receipt.receipt_id.clone(),
        request_id: receipt.request_id.clone(),
        package_id: receipt.package_id.clone(),
        package_ref: receipt.package_ref.clone(),
        runner_id: receipt.runner_id.clone(),
        claimant: claimant.into(),
        claim_kind,
        summary: summary.into(),
        privacy_mode: receipt.privacy_mode.clone(),
        evidence_refs,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        receipt,
        receipt_verification,
        signature: String::new(),
    };
    sign_dispute_evidence(&mut evidence);
    evidence.dispute_id =
        canonical_dispute_id(&evidence).expect("dispute evidence should serialize for id");
    evidence
}

pub fn sign_dispute_evidence(evidence: &mut DisputeEvidenceV1) {
    evidence.signature = expected_dispute_signature(evidence);
}

pub fn sign_dispute_evidence_with_identity(
    evidence: &mut DisputeEvidenceV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != evidence.claimant {
        anyhow::bail!(
            "identity subject {} does not match dispute claimant {}",
            identity.subject,
            evidence.claimant
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "receipt-dispute-evidence",
        &dispute_signing_value(evidence),
    )?;
    evidence.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    evidence.dispute_id = canonical_dispute_id(evidence)?;
    Ok(envelope)
}

pub fn expected_dispute_signature(evidence: &DisputeEvidenceV1) -> String {
    let value = json!({
        "label": "receipt-dispute-evidence",
        "claimant": evidence.claimant,
        "payload": dispute_signing_value(evidence),
    });
    format!(
        "{DEV_DISPUTE_SIGNATURE_PREFIX}:receipt-dispute-evidence:{}",
        hash_canonical_json(&value)
    )
}

pub fn canonical_dispute_id(evidence: &DisputeEvidenceV1) -> serde_json::Result<String> {
    let mut signed = evidence.clone();
    signed.dispute_id.clear();
    let value: Value = serde_json::to_value(signed)?;
    Ok(format!(
        "dispute-{}",
        hash_canonical_json(&value)
            .chars()
            .take(24)
            .collect::<String>()
    ))
}

pub fn verify_dispute_evidence(evidence: &DisputeEvidenceV1) -> DisputeEvidenceVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if evidence.schema_version != "swarm-ai.receipt-dispute-evidence.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.receipt-dispute-evidence.v1",
        ));
    }
    if evidence.dispute_id.trim().is_empty() {
        issues.push(issue("$.disputeId", "Dispute id is required"));
    } else {
        match canonical_dispute_id(evidence) {
            Ok(expected_id) if expected_id != evidence.dispute_id => issues.push(issue(
                "$.disputeId",
                "Dispute id does not match canonical dispute hash",
            )),
            Err(_) => issues.push(issue("$.disputeId", "Dispute id could not be recomputed")),
            _ => {}
        }
    }

    for (path, value, message) in [
        (
            "$.receiptId",
            evidence.receipt_id.as_str(),
            "Receipt id is required",
        ),
        (
            "$.requestId",
            evidence.request_id.as_str(),
            "Request id is required",
        ),
        (
            "$.packageId",
            evidence.package_id.as_str(),
            "Package id is required",
        ),
        (
            "$.packageRef",
            evidence.package_ref.as_str(),
            "Package ref is required",
        ),
        (
            "$.runnerId",
            evidence.runner_id.as_str(),
            "Runner id is required",
        ),
        (
            "$.claimant",
            evidence.claimant.as_str(),
            "Claimant is required",
        ),
        (
            "$.summary",
            evidence.summary.as_str(),
            "Summary is required",
        ),
        (
            "$.signature",
            evidence.signature.as_str(),
            "Signature is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }

    if evidence.receipt_id != evidence.receipt.receipt_id {
        issues.push(issue(
            "$.receiptId",
            "Dispute receiptId must match embedded receipt",
        ));
    }
    if evidence.request_id != evidence.receipt.request_id {
        issues.push(issue(
            "$.requestId",
            "Dispute requestId must match embedded receipt",
        ));
    }
    if evidence.package_id != evidence.receipt.package_id {
        issues.push(issue(
            "$.packageId",
            "Dispute packageId must match embedded receipt",
        ));
    }
    if evidence.package_ref != evidence.receipt.package_ref {
        issues.push(issue(
            "$.packageRef",
            "Dispute packageRef must match embedded receipt",
        ));
    }
    if evidence.runner_id != evidence.receipt.runner_id {
        issues.push(issue(
            "$.runnerId",
            "Dispute runnerId must match embedded receipt",
        ));
    }
    if evidence.privacy_mode != evidence.receipt.privacy_mode {
        issues.push(issue(
            "$.privacyMode",
            "Dispute privacyMode must match embedded receipt",
        ));
    }
    if DateTime::parse_from_rfc3339(&evidence.created_at).is_err() {
        issues.push(issue(
            "$.createdAt",
            "Dispute createdAt must be an RFC3339 timestamp",
        ));
    }

    let receipt_verification = verify_receipt(&evidence.receipt);
    if !receipt_verification.valid {
        issues.push(issue("$.receipt", "Embedded receipt does not verify"));
    }
    if !evidence.receipt_verification.valid {
        issues.push(issue(
            "$.receiptVerification.valid",
            "Embedded receipt verification claims the receipt is invalid",
        ));
    }
    if evidence.receipt_verification.receipt_id != evidence.receipt_id {
        issues.push(issue(
            "$.receiptVerification.receiptId",
            "Embedded receipt verification receiptId must match dispute receiptId",
        ));
    }

    if evidence.evidence_refs.is_empty() {
        warnings.push(issue(
            "$.evidenceRefs",
            "Dispute has no external evidence references",
        ));
    }
    for (index, reference) in evidence.evidence_refs.iter().enumerate() {
        if reference.trim().is_empty() {
            issues.push(issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference must not be empty",
            ));
        } else if !looks_like_evidence_ref(reference) {
            warnings.push(issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference is not a recognized bzz://, local://, ipfs://, http(s)://, or file path reference",
            ));
        }
    }

    let mut expected_signature = expected_dispute_signature(evidence);
    if evidence
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &evidence.signature,
            "receipt-dispute-evidence",
            &dispute_signing_value(evidence),
            Some(&evidence.claimant),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if evidence.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Dispute evidence signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Dispute evidence uses deterministic local-dev signing",
        ));
    }

    DisputeEvidenceVerificationV1 {
        schema_version: "swarm-ai.receipt-dispute-verification.v1".to_string(),
        dispute_id: evidence.dispute_id.clone(),
        receipt_id: evidence.receipt_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn read_dispute_evidence(path: &Path) -> anyhow::Result<DisputeEvidenceV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse dispute evidence JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_dispute_evidence(
    disputes_dir: &Path,
    evidence: &DisputeEvidenceV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(disputes_dir)?;
    let path = disputes_dir.join(format!(
        "{}.json",
        safe_file_component(&evidence.dispute_id)
    ));
    fs::write(&path, serde_json::to_vec_pretty(evidence)?)?;
    Ok(path)
}

pub fn get_dispute_evidence(
    disputes_dir: &Path,
    dispute_id: &str,
) -> anyhow::Result<Option<DisputeEvidenceLookupResultV1>> {
    let dispute_id = dispute_id.trim();
    if dispute_id.is_empty() {
        anyhow::bail!("disputeId is required");
    }

    let direct_path = disputes_dir.join(format!("{}.json", safe_file_component(dispute_id)));
    if direct_path.exists() {
        let evidence = read_dispute_evidence(&direct_path)?;
        if evidence.dispute_id == dispute_id {
            return Ok(Some(dispute_lookup(evidence, direct_path)));
        }
    }

    if !disputes_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(disputes_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let evidence = read_dispute_evidence(&path)?;
            if evidence.dispute_id == dispute_id {
                return Ok(Some(dispute_lookup(evidence, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_dispute_evidence(disputes_dir: &Path) -> anyhow::Result<DisputeEvidenceStoreSummaryV1> {
    let mut disputes = Vec::new();
    if disputes_dir.exists() {
        for entry in fs::read_dir(disputes_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let evidence = read_dispute_evidence(&path)?;
                disputes.push(dispute_index_entry(&evidence, path.display().to_string()));
            }
        }
    }
    disputes.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.dispute_id.cmp(&right.dispute_id))
    });
    let valid_count = disputes
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    Ok(DisputeEvidenceStoreSummaryV1 {
        schema_version: "swarm-ai.dispute-evidence-store-summary.v1".to_string(),
        root: disputes_dir.display().to_string(),
        dispute_count: disputes.len(),
        valid_count,
        invalid_count: disputes.len().saturating_sub(valid_count),
        disputes,
    })
}

fn batch_receipt_status_counts(items: &[BatchReceiptItemV1]) -> (u32, u32, u32, u32) {
    let mut succeeded = 0;
    let mut failed = 0;
    let mut cancelled = 0;
    let mut skipped = 0;
    for item in items {
        match item.status {
            BatchReceiptItemStatusV1::Succeeded => succeeded += 1,
            BatchReceiptItemStatusV1::Failed => failed += 1,
            BatchReceiptItemStatusV1::Cancelled => cancelled += 1,
            BatchReceiptItemStatusV1::Skipped => skipped += 1,
        }
    }
    (succeeded, failed, cancelled, skipped)
}

fn aggregate_batch_receipt_metrics(items: &[BatchReceiptItemV1]) -> ExecutionMetrics {
    let mut metrics = ExecutionMetrics::default();
    for item in items {
        metrics.queue_ms = metrics.queue_ms.saturating_add(item.metrics.queue_ms);
        metrics.load_ms = metrics.load_ms.saturating_add(item.metrics.load_ms);
        metrics.compute_ms = metrics.compute_ms.saturating_add(item.metrics.compute_ms);
        metrics.total_ms = metrics.total_ms.saturating_add(item.metrics.total_ms);
        if let Some(input_tokens) = item.metrics.input_tokens {
            metrics.input_tokens = Some(
                metrics
                    .input_tokens
                    .unwrap_or_default()
                    .saturating_add(input_tokens),
            );
        }
        if let Some(output_tokens) = item.metrics.output_tokens {
            metrics.output_tokens = Some(
                metrics
                    .output_tokens
                    .unwrap_or_default()
                    .saturating_add(output_tokens),
            );
        }
    }
    metrics
}

fn verify_batch_receipt_counts(
    receipt: &BatchReceiptV1,
    issues: &mut Vec<ReceiptVerificationIssueV1>,
) {
    let (succeeded, failed, cancelled, skipped) = batch_receipt_status_counts(&receipt.items);
    if receipt.item_count != receipt.items.len() as u32 {
        issues.push(issue(
            "$.itemCount",
            "itemCount must match the number of receipt items",
        ));
    }
    for (path, declared, actual, label) in [
        (
            "$.succeededCount",
            receipt.succeeded_count,
            succeeded,
            "succeeded",
        ),
        ("$.failedCount", receipt.failed_count, failed, "failed"),
        (
            "$.cancelledCount",
            receipt.cancelled_count,
            cancelled,
            "cancelled",
        ),
        ("$.skippedCount", receipt.skipped_count, skipped, "skipped"),
    ] {
        if declared != actual {
            issues.push(issue(
                path,
                format!("{label} count must match item statuses"),
            ));
        }
    }
    if receipt
        .succeeded_count
        .saturating_add(receipt.failed_count)
        .saturating_add(receipt.cancelled_count)
        .saturating_add(receipt.skipped_count)
        != receipt.item_count
    {
        issues.push(issue(
            "$.itemCount",
            "Status counts must add up to itemCount",
        ));
    }
    let expected_metrics = aggregate_batch_receipt_metrics(&receipt.items);
    if receipt.total_metrics != expected_metrics {
        issues.push(issue(
            "$.totalMetrics",
            "totalMetrics must equal the sum of item metrics",
        ));
    }
}

fn verify_batch_receipt_items(
    receipt: &BatchReceiptV1,
    issues: &mut Vec<ReceiptVerificationIssueV1>,
    warnings: &mut Vec<ReceiptVerificationIssueV1>,
) {
    if receipt.items.is_empty() {
        issues.push(issue(
            "$.items",
            "Batch receipt must include at least one item",
        ));
        return;
    }

    let mut item_ids = BTreeSet::new();
    for (index, item) in receipt.items.iter().enumerate() {
        let path = format!("$.items[{index}]");
        if item.item_id.trim().is_empty() {
            issues.push(issue(
                format!("{path}.itemId"),
                "Batch receipt item id is required",
            ));
        } else if !item_ids.insert(item.item_id.clone()) {
            issues.push(issue(
                format!("{path}.itemId"),
                "Batch receipt item id must be unique",
            ));
        }
        if let Some(request_id) = &item.request_id
            && request_id.trim().is_empty()
        {
            issues.push(issue(
                format!("{path}.requestId"),
                "Item requestId must not be empty when present",
            ));
        }
        if !is_sha256_hex(&item.input_hash) {
            issues.push(issue(
                format!("{path}.inputHash"),
                "Item input hash must be a 64-character hex digest",
            ));
        }
        match item.status {
            BatchReceiptItemStatusV1::Succeeded => {
                if item.output_hash.is_none() {
                    issues.push(issue(
                        format!("{path}.outputHash"),
                        "Succeeded batch items must include an output hash",
                    ));
                }
                if item.error.is_some() {
                    issues.push(issue(
                        format!("{path}.error"),
                        "Succeeded batch items must not include an error",
                    ));
                }
            }
            BatchReceiptItemStatusV1::Failed => {
                if item.error.is_none() {
                    issues.push(issue(
                        format!("{path}.error"),
                        "Failed batch items must include an error",
                    ));
                }
            }
            BatchReceiptItemStatusV1::Cancelled => {
                if item.error.is_none() {
                    warnings.push(issue(
                        format!("{path}.error"),
                        "Cancelled batch items should include a cancellation reason",
                    ));
                }
            }
            BatchReceiptItemStatusV1::Skipped => {
                if item.output_hash.is_some() {
                    warnings.push(issue(
                        format!("{path}.outputHash"),
                        "Skipped batch items normally do not include an output hash",
                    ));
                }
            }
        }
        if let Some(output_hash) = &item.output_hash
            && !is_sha256_hex(output_hash)
        {
            issues.push(issue(
                format!("{path}.outputHash"),
                "Item output hash must be a 64-character hex digest",
            ));
        }
        verify_batch_receipt_item_timestamps(&path, item, issues, warnings);
        if let Some(receipt_id) = &item.receipt_id {
            if receipt_id.trim().is_empty() {
                issues.push(issue(
                    format!("{path}.receiptId"),
                    "Item receiptId must not be empty when present",
                ));
            } else if item.receipt_ref.is_none() {
                warnings.push(issue(
                    format!("{path}.receiptRef"),
                    "Item references a final receipt id without a receipt ref",
                ));
            }
        }
        verify_batch_receipt_evidence_refs(
            &format!("{path}.evidenceRefs"),
            &item.evidence_refs,
            issues,
            warnings,
        );
    }
}

fn verify_batch_receipt_item_timestamps(
    path: &str,
    item: &BatchReceiptItemV1,
    issues: &mut Vec<ReceiptVerificationIssueV1>,
    warnings: &mut Vec<ReceiptVerificationIssueV1>,
) {
    let started_at = match item.started_at.as_deref() {
        Some(value) => match DateTime::parse_from_rfc3339(value) {
            Ok(timestamp) => Some(timestamp),
            Err(_) => {
                issues.push(issue(
                    format!("{path}.startedAt"),
                    "Item startedAt must be an RFC3339 timestamp",
                ));
                None
            }
        },
        None if item.status != BatchReceiptItemStatusV1::Skipped => {
            warnings.push(issue(
                format!("{path}.startedAt"),
                "Executed batch items should include startedAt",
            ));
            None
        }
        None => None,
    };
    let completed_at = match item.completed_at.as_deref() {
        Some(value) => match DateTime::parse_from_rfc3339(value) {
            Ok(timestamp) => Some(timestamp),
            Err(_) => {
                issues.push(issue(
                    format!("{path}.completedAt"),
                    "Item completedAt must be an RFC3339 timestamp",
                ));
                None
            }
        },
        None if matches!(
            item.status,
            BatchReceiptItemStatusV1::Succeeded
                | BatchReceiptItemStatusV1::Failed
                | BatchReceiptItemStatusV1::Cancelled
        ) =>
        {
            warnings.push(issue(
                format!("{path}.completedAt"),
                "Terminal batch items should include completedAt",
            ));
            None
        }
        None => None,
    };
    if let (Some(started_at), Some(completed_at)) = (started_at, completed_at)
        && completed_at < started_at
    {
        issues.push(issue(
            format!("{path}.completedAt"),
            "Item completedAt must not be earlier than startedAt",
        ));
    }
}

fn verify_batch_receipt_evidence_refs(
    path: &str,
    evidence_refs: &[String],
    issues: &mut Vec<ReceiptVerificationIssueV1>,
    warnings: &mut Vec<ReceiptVerificationIssueV1>,
) {
    for (index, reference) in evidence_refs.iter().enumerate() {
        if reference.trim().is_empty() {
            issues.push(issue(
                format!("{path}[{index}]"),
                "Evidence reference must not be empty",
            ));
        } else if !looks_like_evidence_ref(reference) {
            warnings.push(issue(
                format!("{path}[{index}]"),
                "Evidence reference is not a recognized bzz://, local://, ipfs://, http(s)://, or file path reference",
            ));
        }
    }
}

fn batch_receipt_signing_value(receipt: &BatchReceiptV1) -> Value {
    json!({
        "schemaVersion": receipt.schema_version,
        "batchReceiptId": receipt.batch_receipt_id,
        "batchId": receipt.batch_id,
        "jobId": receipt.job_id,
        "requester": receipt.requester,
        "runnerId": receipt.runner_id,
        "packageRef": receipt.package_ref,
        "packageId": receipt.package_id,
        "packageVersion": receipt.package_version,
        "apiSurface": receipt.api_surface,
        "privacyTier": receipt.privacy_tier,
        "privacyMode": receipt.privacy_mode,
        "verificationMode": receipt.verification_mode,
        "createdAt": receipt.created_at,
        "completedAt": receipt.completed_at,
        "itemCount": receipt.item_count,
        "succeededCount": receipt.succeeded_count,
        "failedCount": receipt.failed_count,
        "cancelledCount": receipt.cancelled_count,
        "skippedCount": receipt.skipped_count,
        "totalMetrics": receipt.total_metrics,
        "billing": receipt.billing,
        "items": receipt.items,
        "evidenceRefs": receipt.evidence_refs,
    })
}

fn dispute_signing_value(evidence: &DisputeEvidenceV1) -> Value {
    json!({
        "schemaVersion": evidence.schema_version,
        "receiptId": evidence.receipt_id,
        "requestId": evidence.request_id,
        "packageId": evidence.package_id,
        "packageRef": evidence.package_ref,
        "runnerId": evidence.runner_id,
        "claimant": evidence.claimant,
        "claimKind": evidence.claim_kind,
        "summary": evidence.summary,
        "privacyMode": evidence.privacy_mode,
        "evidenceRefs": evidence.evidence_refs,
        "createdAt": evidence.created_at,
        "receipt": evidence.receipt,
        "receiptVerification": evidence.receipt_verification,
    })
}

fn partial_receipt_signing_value(receipt: &PartialReceiptV1) -> Value {
    json!({
        "schemaVersion": receipt.schema_version,
        "requestId": receipt.request_id,
        "jobId": receipt.job_id,
        "receiptId": receipt.receipt_id,
        "receiptRef": receipt.receipt_ref,
        "runnerId": receipt.runner_id,
        "sequence": receipt.sequence,
        "status": receipt.status,
        "emittedAt": receipt.emitted_at,
        "progress": receipt.progress,
        "outputHash": receipt.output_hash,
        "metrics": receipt.metrics,
        "verificationValid": receipt.verification_valid,
        "issueCount": receipt.issue_count,
        "warningCount": receipt.warning_count,
        "evidenceRefs": receipt.evidence_refs,
    })
}

fn redacted_receipt_signing_value(redacted: &RedactedReceiptV1) -> Value {
    json!({
        "schemaVersion": redacted.schema_version,
        "redactionId": redacted.redaction_id,
        "originalReceiptId": redacted.original_receipt_id,
        "originalReceiptHash": redacted.original_receipt_hash,
        "redactionPolicy": redacted.redaction_policy,
        "redactedAt": redacted.redacted_at,
        "fields": redacted.fields,
        "retainedFields": redacted.retained_fields,
        "redactedFields": redacted.redacted_fields,
        "sourceVerification": redacted.source_verification,
    })
}

fn receipt_signing_value(receipt: &ExecutionReceiptV1) -> Value {
    json!({
        "schemaVersion": receipt.schema_version,
        "requestId": receipt.request_id,
        "packageId": receipt.package_id,
        "packageRef": receipt.package_ref,
        "artifactGroup": receipt.artifact_group,
        "packageManifestHash": receipt.package_manifest_hash,
        "runnerId": receipt.runner_id,
        "routeId": receipt.route_id,
        "inputHash": receipt.input_hash,
        "outputHash": receipt.output_hash,
        "privacyMode": receipt.privacy_mode,
        "startedAt": receipt.started_at,
        "finishedAt": receipt.finished_at,
        "metrics": receipt.metrics,
        "billing": receipt.billing,
        "access": receipt.access,
        "policy": receipt.policy,
    })
}

fn verify_receipt_v2_refs(
    receipt: &ExecutionReceiptV2,
    issues: &mut Vec<ReceiptVerificationIssueV1>,
    warnings: &mut Vec<ReceiptVerificationIssueV1>,
) {
    for (field, values) in [
        ("packageRefs", &receipt.package_refs),
        ("toolCallRefs", &receipt.tool_call_refs),
        ("retrievalRefs", &receipt.retrieval_refs),
        ("policyRefs", &receipt.policy_refs),
        ("accessGrantRefs", &receipt.access_grant_refs),
        ("proofRefs", &receipt.proof_refs),
    ] {
        for (index, reference) in values.iter().enumerate() {
            if reference.trim().is_empty() {
                issues.push(issue(
                    format!("$.{field}[{index}]"),
                    "Reference must not be empty",
                ));
            } else if !looks_like_evidence_ref(reference) && !looks_like_hash_ref(reference) {
                warnings.push(issue(
                    format!("$.{field}[{index}]"),
                    "Reference is not a recognized content, local, web, file, or hash reference",
                ));
            }
        }
    }
    for (field, values) in [
        ("inputHashes", &receipt.input_hashes),
        ("outputHashes", &receipt.output_hashes),
    ] {
        for (index, hash) in values.iter().enumerate() {
            if !looks_like_hash_ref(hash) {
                issues.push(issue(
                    format!("$.{field}[{index}]"),
                    "Receipt input/output hashes must be sha256 hex or sha256: references",
                ));
            }
        }
    }
    for (path, reference) in [
        ("$.routeDecisionRef", receipt.route_decision_ref.as_ref()),
        ("$.traceRef", receipt.trace_ref.as_ref()),
        ("$.attestationRef", receipt.attestation_ref.as_ref()),
    ] {
        if let Some(reference) = reference {
            if reference.trim().is_empty() {
                issues.push(issue(path, "Reference must not be empty"));
            } else if !looks_like_evidence_ref(reference) && !looks_like_hash_ref(reference) {
                warnings.push(issue(
                    path,
                    "Reference is not a recognized content, local, web, file, or hash reference",
                ));
            }
        }
    }
}

fn verify_receipt_v2_timing(
    receipt: &ExecutionReceiptV2,
    issues: &mut Vec<ReceiptVerificationIssueV1>,
) {
    if DateTime::parse_from_rfc3339(&receipt.started_at).is_err() {
        issues.push(issue(
            "$.startedAt",
            "Receipt startedAt must be an RFC3339 timestamp",
        ));
    }
    if let Some(completed_at) = &receipt.completed_at {
        match (
            DateTime::parse_from_rfc3339(&receipt.started_at),
            DateTime::parse_from_rfc3339(completed_at),
        ) {
            (Ok(started), Ok(completed)) if completed < started => issues.push(issue(
                "$.completedAt",
                "Receipt completedAt must not be earlier than startedAt",
            )),
            (_, Err(_)) => issues.push(issue(
                "$.completedAt",
                "Receipt completedAt must be an RFC3339 timestamp",
            )),
            _ => {}
        }
    }
    if receipt.timing.total_ms < receipt.timing.compute_ms {
        issues.push(issue(
            "$.timing.totalMs",
            "Receipt totalMs must not be less than computeMs",
        ));
    }
    if let Some(cost) = &receipt.cost
        && cost.amount < 0.0
    {
        issues.push(issue("$.cost.amount", "Receipt cost must be non-negative"));
    }
}

fn verify_receipt_v2_status(
    receipt: &ExecutionReceiptV2,
    issues: &mut Vec<ReceiptVerificationIssueV1>,
    warnings: &mut Vec<ReceiptVerificationIssueV1>,
) {
    if receipt.status != ExecutionStatus::Partial && receipt.completed_at.is_none() {
        issues.push(issue(
            "$.completedAt",
            "Terminal receipts must include completedAt",
        ));
    }
    if receipt.status == ExecutionStatus::Failed && receipt.errors.is_empty() {
        issues.push(issue(
            "$.errors",
            "Failed receipts must include at least one standard error",
        ));
    }
    if receipt.status == ExecutionStatus::Succeeded && !receipt.errors.is_empty() {
        warnings.push(issue(
            "$.errors",
            "Succeeded receipt carries errors; confirm status before settlement",
        ));
    }
    for (index, error) in receipt.errors.iter().enumerate() {
        if error.message.trim().is_empty() {
            issues.push(issue(
                format!("$.errors[{index}].message"),
                "Receipt error message is required",
            ));
        }
    }
}

fn verify_receipt_v2_privacy_mode(
    receipt: &ExecutionReceiptV2,
    issues: &mut Vec<ReceiptVerificationIssueV1>,
    warnings: &mut Vec<ReceiptVerificationIssueV1>,
) {
    let allowed_modes = [
        "hash-only",
        "encrypted-evidence",
        "public-evidence",
        "standard",
        "no-log",
        "redacted-input",
        "local-only",
        "tee-confidential",
        "fhe-encrypted",
        "mpc-experimental",
    ];
    if !allowed_modes.contains(&receipt.privacy_mode.as_str()) {
        issues.push(issue(
            "$.privacyMode",
            "Privacy mode must be a receipt privacy mode or v0.2 privacy tier",
        ));
    }
    match receipt.privacy_mode.as_str() {
        "hash-only" => warnings.push(issue(
            "$.privacyMode",
            "Hash-only receipt stores no raw private input or output",
        )),
        "public-evidence" => warnings.push(issue(
            "$.privacyMode",
            "Public-evidence receipts should be redacted before broad sharing",
        )),
        "tee-confidential" if receipt.attestation_ref.is_none() => issues.push(issue(
            "$.attestationRef",
            "TEE-confidential receipts must include an attestationRef",
        )),
        "fhe-encrypted" if receipt.proof_refs.is_empty() => warnings.push(issue(
            "$.proofRefs",
            "FHE-encrypted receipts should include proof or encrypted-result evidence refs",
        )),
        _ => {}
    }
}

fn verify_receipt_v2_integrity_mode(
    receipt: &ExecutionReceiptV2,
    issues: &mut Vec<ReceiptVerificationIssueV1>,
    warnings: &mut Vec<ReceiptVerificationIssueV1>,
) {
    match receipt.verification_mode {
        IntegrityTier::TeeAttested if receipt.attestation_ref.is_none() => issues.push(issue(
            "$.attestationRef",
            "TEE-attested verification mode requires attestationRef",
        )),
        IntegrityTier::ZkProofWhenSupported if receipt.proof_refs.is_empty() => issues.push(issue(
            "$.proofRefs",
            "ZK-proof verification mode requires proofRefs",
        )),
        IntegrityTier::RedundantExecution if receipt.output_hashes.len() < 2 => warnings.push(
            issue(
                "$.outputHashes",
                "Redundant-execution receipts should include hashes from multiple executions or linked validation evidence",
            ),
        ),
        IntegrityTier::DeterministicReplay
            if receipt.trace_ref.is_none() && receipt.proof_refs.is_empty() =>
        {
            warnings.push(issue(
                "$.traceRef",
                "Deterministic-replay receipts should link replay trace or replay proof evidence",
            ));
        }
        _ => {}
    }
}

fn default_correctness_methods_for_integrity_tier(
    tier: &IntegrityTier,
) -> Vec<ReceiptCorrectnessEvidenceMethodV1> {
    match tier {
        IntegrityTier::ReceiptOnly => Vec::new(),
        IntegrityTier::ValidatorSpotCheck => {
            vec![ReceiptCorrectnessEvidenceMethodV1::ValidatorSpotCheck]
        }
        IntegrityTier::RedundantExecution => {
            vec![ReceiptCorrectnessEvidenceMethodV1::RedundantExecution]
        }
        IntegrityTier::DeterministicReplay => {
            vec![ReceiptCorrectnessEvidenceMethodV1::DeterministicReplay]
        }
        IntegrityTier::TeeAttested => {
            vec![ReceiptCorrectnessEvidenceMethodV1::TeeAttestationCheck]
        }
        IntegrityTier::ZkProofWhenSupported => {
            vec![ReceiptCorrectnessEvidenceMethodV1::ZkProofCheck]
        }
    }
}

fn dedup_correctness_methods(
    methods: Vec<ReceiptCorrectnessEvidenceMethodV1>,
) -> Vec<ReceiptCorrectnessEvidenceMethodV1> {
    methods
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn apply_receipt_embedded_correctness_evidence(
    receipt: &ExecutionReceiptV2,
    accepted_methods: &mut BTreeSet<ReceiptCorrectnessEvidenceMethodV1>,
) {
    if receipt.output_hashes.len() > 1 {
        accepted_methods.insert(ReceiptCorrectnessEvidenceMethodV1::RedundantExecution);
    }
    if receipt.trace_ref.is_some() {
        accepted_methods.insert(ReceiptCorrectnessEvidenceMethodV1::DeterministicReplay);
    }
}

fn correctness_method_satisfies(
    required: ReceiptCorrectnessEvidenceMethodV1,
    actual: ReceiptCorrectnessEvidenceMethodV1,
) -> bool {
    if required == actual {
        return true;
    }
    matches!(
        required,
        ReceiptCorrectnessEvidenceMethodV1::ValidatorSpotCheck
    ) && matches!(
        actual,
        ReceiptCorrectnessEvidenceMethodV1::HiddenChallenge
            | ReceiptCorrectnessEvidenceMethodV1::RedundantExecution
            | ReceiptCorrectnessEvidenceMethodV1::DeterministicReplay
            | ReceiptCorrectnessEvidenceMethodV1::BenchmarkScore
            | ReceiptCorrectnessEvidenceMethodV1::TeeAttestationCheck
            | ReceiptCorrectnessEvidenceMethodV1::ZkProofCheck
            | ReceiptCorrectnessEvidenceMethodV1::FheResultCheck
            | ReceiptCorrectnessEvidenceMethodV1::ArtifactHashCheck
            | ReceiptCorrectnessEvidenceMethodV1::ManifestCompatibility
    )
}

fn correctness_method_name(method: &ReceiptCorrectnessEvidenceMethodV1) -> &'static str {
    match method {
        ReceiptCorrectnessEvidenceMethodV1::ManifestCompatibility => "manifest-compatibility",
        ReceiptCorrectnessEvidenceMethodV1::ArtifactHashCheck => "artifact-hash-check",
        ReceiptCorrectnessEvidenceMethodV1::ValidatorSpotCheck => "validator-spot-check",
        ReceiptCorrectnessEvidenceMethodV1::HiddenChallenge => "hidden-challenge",
        ReceiptCorrectnessEvidenceMethodV1::RedundantExecution => "redundant-execution",
        ReceiptCorrectnessEvidenceMethodV1::DeterministicReplay => "deterministic-replay",
        ReceiptCorrectnessEvidenceMethodV1::BenchmarkScore => "benchmark-score",
        ReceiptCorrectnessEvidenceMethodV1::LlmJudgeWithDisclosure => "llm-judge-with-disclosure",
        ReceiptCorrectnessEvidenceMethodV1::HumanReview => "human-review",
        ReceiptCorrectnessEvidenceMethodV1::TeeAttestationCheck => "tee-attestation-check",
        ReceiptCorrectnessEvidenceMethodV1::ZkProofCheck => "zk-proof-check",
        ReceiptCorrectnessEvidenceMethodV1::FheResultCheck => "fhe-result-check",
    }
}

fn correctness_level_for_assessment(
    tier: &IntegrityTier,
    receipt_valid: bool,
    required_methods_satisfied: bool,
    failed_methods: &[ReceiptCorrectnessEvidenceMethodV1],
    accepted_evidence_count: usize,
) -> ReceiptCorrectnessLevelV1 {
    if !receipt_valid || !failed_methods.is_empty() {
        return ReceiptCorrectnessLevelV1::Failed;
    }
    if !required_methods_satisfied {
        return ReceiptCorrectnessLevelV1::Unverified;
    }
    match tier {
        IntegrityTier::ZkProofWhenSupported => ReceiptCorrectnessLevelV1::CryptographicProof,
        IntegrityTier::TeeAttested => ReceiptCorrectnessLevelV1::Attested,
        IntegrityTier::RedundantExecution | IntegrityTier::DeterministicReplay => {
            ReceiptCorrectnessLevelV1::RedundantOrReplayBacked
        }
        IntegrityTier::ValidatorSpotCheck => ReceiptCorrectnessLevelV1::ValidatorBacked,
        IntegrityTier::ReceiptOnly if accepted_evidence_count > 0 => {
            ReceiptCorrectnessLevelV1::ValidatorBacked
        }
        IntegrityTier::ReceiptOnly => ReceiptCorrectnessLevelV1::ReceiptOnly,
    }
}

fn verify_receipt_v2_lease_context(
    receipt: &ExecutionReceiptV2,
    issues: &mut Vec<ReceiptVerificationIssueV1>,
    warnings: &mut Vec<ReceiptVerificationIssueV1>,
) {
    if receipt.lease_id.is_some() && receipt.lease_context.is_none() {
        warnings.push(issue(
            "$.leaseContext",
            "Receipt has leaseId but no leaseContext for quote and settlement audit",
        ));
    }
    let Some(context) = &receipt.lease_context else {
        return;
    };
    if let Some(max_cost) = &context.max_cost
        && max_cost.amount < 0.0
    {
        issues.push(issue(
            "$.leaseContext.maxCost.amount",
            "Lease maxCost amount must be non-negative",
        ));
    }
    for (path, timestamp) in [
        ("$.leaseContext.startAfter", context.start_after.as_ref()),
        ("$.leaseContext.deadline", context.deadline.as_ref()),
    ] {
        if let Some(timestamp) = timestamp
            && DateTime::parse_from_rfc3339(timestamp).is_err()
        {
            issues.push(issue(path, "Lease timestamp must be RFC3339"));
        }
    }
    if let (Some(start_after), Some(deadline)) = (&context.start_after, &context.deadline)
        && let (Ok(start_after), Ok(deadline)) = (
            DateTime::parse_from_rfc3339(start_after),
            DateTime::parse_from_rfc3339(deadline),
        )
        && deadline < start_after
    {
        issues.push(issue(
            "$.leaseContext.deadline",
            "Lease deadline must not be earlier than startAfter",
        ));
    }
    if context.allowed_package_refs.is_empty() {
        warnings.push(issue(
            "$.leaseContext.allowedPackageRefs",
            "Lease context has no allowed package refs",
        ));
    }
    if context.allowed_input_refs.is_empty() && context.allowed_input_hashes.is_empty() {
        warnings.push(issue(
            "$.leaseContext.allowedInputRefs",
            "Lease context has no allowed input refs or hashes",
        ));
    }
}

fn compare_receipt_v2_source(
    receipt: &ExecutionReceiptV2,
    source: &ExecutionReceiptV1,
    issues: &mut Vec<ReceiptVerificationIssueV1>,
    warnings: &mut Vec<ReceiptVerificationIssueV1>,
) {
    for (path, v2_value, source_value, message) in [
        (
            "$.receiptId",
            receipt.receipt_id.as_str(),
            source.receipt_id.as_str(),
            "Receipt v2 id must match source receipt id",
        ),
        (
            "$.requestId",
            receipt.request_id.as_str(),
            source.request_id.as_str(),
            "Receipt v2 requestId must match source receipt requestId",
        ),
        (
            "$.runnerId",
            receipt.runner_id.as_str(),
            source.runner_id.as_str(),
            "Receipt v2 runnerId must match source receipt runnerId",
        ),
        (
            "$.startedAt",
            receipt.started_at.as_str(),
            source.started_at.as_str(),
            "Receipt v2 startedAt must match source receipt startedAt",
        ),
    ] {
        if v2_value != source_value {
            issues.push(issue(path, message));
        }
    }
    if receipt.completed_at.as_deref() != Some(source.finished_at.as_str()) {
        issues.push(issue(
            "$.completedAt",
            "Receipt v2 completedAt must match source receipt finishedAt",
        ));
    }
    for (path, values, expected, message) in [
        (
            "$.packageRefs",
            &receipt.package_refs,
            source.package_ref.as_str(),
            "Receipt v2 packageRefs must include source packageRef",
        ),
        (
            "$.modelArtifactRefs",
            &receipt.model_artifact_refs,
            source.package_manifest_hash.as_str(),
            "Receipt v2 modelArtifactRefs must include source packageManifestHash",
        ),
        (
            "$.artifactGroupIds",
            &receipt.artifact_group_ids,
            source.artifact_group.as_str(),
            "Receipt v2 artifactGroupIds must include source artifactGroup",
        ),
        (
            "$.inputHashes",
            &receipt.input_hashes,
            source.input_hash.as_str(),
            "Receipt v2 inputHashes must include source inputHash",
        ),
        (
            "$.outputHashes",
            &receipt.output_hashes,
            source.output_hash.as_str(),
            "Receipt v2 outputHashes must include source outputHash",
        ),
    ] {
        if !values.iter().any(|value| value == expected) {
            issues.push(issue(path, message));
        }
    }
    if receipt.timing.queue_ms != source.metrics.queue_ms {
        issues.push(issue(
            "$.timing.queueMs",
            "Receipt v2 queueMs must match source receipt metrics.queueMs",
        ));
    }
    if receipt.timing.load_ms != source.metrics.load_ms {
        issues.push(issue(
            "$.timing.loadMs",
            "Receipt v2 loadMs must match source receipt metrics.loadMs",
        ));
    }
    if receipt.timing.compute_ms != source.metrics.compute_ms {
        issues.push(issue(
            "$.timing.computeMs",
            "Receipt v2 computeMs must match source receipt metrics.computeMs",
        ));
    }
    if receipt.timing.total_ms != source.metrics.total_ms {
        issues.push(issue(
            "$.timing.totalMs",
            "Receipt v2 totalMs must match source receipt metrics.totalMs",
        ));
    }
    if receipt.usage.input_tokens != source.metrics.input_tokens {
        issues.push(issue(
            "$.usage.inputTokens",
            "Receipt v2 inputTokens must match source receipt metrics.inputTokens",
        ));
    }
    if receipt.usage.output_tokens != source.metrics.output_tokens {
        issues.push(issue(
            "$.usage.outputTokens",
            "Receipt v2 outputTokens must match source receipt metrics.outputTokens",
        ));
    }
    if let Some(cost) = &receipt.cost
        && ((cost.amount - source.billing.estimated_cost).abs() > f64::EPSILON
            || cost.currency != source.billing.currency)
    {
        issues.push(issue(
            "$.cost",
            "Receipt v2 cost must match source receipt billing",
        ));
    }
    if receipt.privacy_mode != source.privacy_mode {
        issues.push(issue(
            "$.privacyMode",
            "Receipt v2 privacyMode must match source receipt privacyMode",
        ));
    }
    if let Some(route_id) = &source.route_id {
        match &receipt.route_decision_ref {
            Some(reference) if reference.contains(route_id) => {}
            Some(_) => warnings.push(issue(
                "$.routeDecisionRef",
                "Receipt v2 routeDecisionRef does not mention the source routeId",
            )),
            None => warnings.push(issue(
                "$.routeDecisionRef",
                "Receipt v2 is missing routeDecisionRef for source routeId",
            )),
        }
    }
    if let Some(grant_id) = &source.access.license_grant_id
        && !receipt
            .access_grant_refs
            .iter()
            .any(|reference| reference == grant_id)
    {
        issues.push(issue(
            "$.accessGrantRefs",
            "Receipt v2 accessGrantRefs must include source licenseGrantId",
        ));
    }
    if let Some(policy) = &source.policy
        && !receipt
            .policy_refs
            .iter()
            .any(|reference| reference == &policy.policy_decision_id)
    {
        issues.push(issue(
            "$.policyRefs",
            "Receipt v2 policyRefs must include source policyDecisionId",
        ));
    }
}

fn reveal_or_hash(
    retained_fields: &mut Vec<String>,
    redacted_fields: &mut Vec<String>,
    path: &str,
    value: &str,
    reveal: bool,
) -> (Option<String>, Option<String>) {
    if reveal {
        retained_fields.push(path.to_string());
        (Some(value.to_string()), None)
    } else {
        redacted_fields.push(path.to_string());
        (None, Some(redacted_value_hash(value)))
    }
}

fn reveal_optional_or_hash(
    retained_fields: &mut Vec<String>,
    redacted_fields: &mut Vec<String>,
    path: &str,
    value: Option<&str>,
    reveal: bool,
) -> (Option<String>, Option<String>) {
    let Some(value) = value else {
        return (None, None);
    };
    reveal_or_hash(retained_fields, redacted_fields, path, value, reveal)
}

fn redacted_value_hash<T: Serialize + ?Sized>(value: &T) -> String {
    let value = serde_json::to_value(value).unwrap_or_else(|_| json!(null));
    format!("sha256://{}", hash_canonical_json(&value))
}

fn increment_group(groups: &mut BTreeMap<String, usize>, key: &str) {
    let key = key.trim();
    if key.is_empty() {
        return;
    }
    *groups.entry(key.to_string()).or_default() += 1;
}

fn group_counts(groups: BTreeMap<String, usize>) -> Vec<ReceiptAuditGroupCountV1> {
    groups
        .into_iter()
        .map(|(key, count)| ReceiptAuditGroupCountV1 { key, count })
        .collect()
}

fn settlement_status_label(status: &ReceiptSettlementStatusV1) -> String {
    serde_json::to_value(status)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{status:?}"))
}

fn receipt_audit_issue(
    severity: ReceiptAuditSeverityV1,
    receipt_id: &str,
    path: impl Into<String>,
    message: impl Into<String>,
) -> ReceiptAuditIssueV1 {
    ReceiptAuditIssueV1 {
        severity,
        receipt_id: Some(receipt_id.to_string()),
        path: path.into(),
        message: message.into(),
    }
}

fn batch_receipt_audit_issue(
    severity: ReceiptAuditSeverityV1,
    batch_receipt_id: &str,
    path: impl Into<String>,
    message: impl Into<String>,
) -> BatchReceiptAuditIssueV1 {
    BatchReceiptAuditIssueV1 {
        severity,
        batch_receipt_id: Some(batch_receipt_id.to_string()),
        path: path.into(),
        message: message.into(),
    }
}

fn enforce_redaction_policy(
    redacted: &RedactedReceiptV1,
    issues: &mut Vec<ReceiptVerificationIssueV1>,
) {
    let policy = &redacted.redaction_policy;
    let fields = &redacted.fields;
    if !policy.reveal_package_ref && fields.package_ref.is_some() {
        issues.push(issue(
            "$.fields.packageRef",
            "packageRef is present but redactionPolicy.revealPackageRef is false",
        ));
    }
    if !policy.reveal_runner_id && fields.runner_id.is_some() {
        issues.push(issue(
            "$.fields.runnerId",
            "runnerId is present but redactionPolicy.revealRunnerId is false",
        ));
    }
    if !policy.reveal_route_id && fields.route_id.is_some() {
        issues.push(issue(
            "$.fields.routeId",
            "routeId is present but redactionPolicy.revealRouteId is false",
        ));
    }
    if !policy.reveal_access_grant_refs && fields.license_grant_id.is_some() {
        issues.push(issue(
            "$.fields.licenseGrantId",
            "licenseGrantId is present but redactionPolicy.revealAccessGrantRefs is false",
        ));
    }
    if !policy.reveal_policy_refs && fields.policy_decision_id.is_some() {
        issues.push(issue(
            "$.fields.policyDecisionId",
            "policyDecisionId is present but redactionPolicy.revealPolicyRefs is false",
        ));
    }
    if !policy.reveal_signature && fields.signature.is_some() {
        issues.push(issue(
            "$.fields.signature",
            "signature is present but redactionPolicy.revealSignature is false",
        ));
    }
    if !policy.reveal_timing
        && (fields.started_at.is_some() || fields.finished_at.is_some() || fields.metrics.is_some())
    {
        issues.push(issue(
            "$.fields.metrics",
            "timing fields are present but redactionPolicy.revealTiming is false",
        ));
    }
    if !policy.reveal_cost && fields.billing.is_some() {
        issues.push(issue(
            "$.fields.billing",
            "billing is present but redactionPolicy.revealCost is false",
        ));
    }
}

fn signature_issue_path(path: &str) -> String {
    if path == "$" {
        return "$.signature".to_string();
    }
    if let Some(rest) = path.strip_prefix("$.") {
        return format!("$.signature.{rest}");
    }
    format!("$.signature.{path}")
}

fn empty_metadata() -> Value {
    json!({})
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ReceiptVerificationIssueV1 {
    ReceiptVerificationIssueV1 {
        path: path.into(),
        message: message.into(),
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
}

fn looks_like_hash_ref(value: &str) -> bool {
    is_sha256_hex(value) || value.starts_with("sha256:") || value.starts_with("sha256://")
}

fn hash_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn looks_like_evidence_ref(value: &str) -> bool {
    value.starts_with("bzz://")
        || value.starts_with("local://")
        || value.starts_with("ipfs://")
        || value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("file:")
}

fn json_schema_version(path: &Path) -> anyhow::Result<Option<String>> {
    let bytes = fs::read(path)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to inspect JSON schemaVersion from {}: {error}",
            path.display()
        )
    })?;
    Ok(value
        .get("schemaVersion")
        .and_then(Value::as_str)
        .map(str::to_string))
}

fn json_schema_is(path: &Path, expected: &str) -> bool {
    matches!(json_schema_version(path), Ok(Some(schema_version)) if schema_version == expected)
}

fn safe_file_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ApiSurface, ErrorCode, ExecutionMetrics, ExecutionStatus, IntegrityTier, PolicyDecision,
        PolicyDecisionV1, PrivacyTier, StreamingEventType,
        policy::RiskLevel,
        receipt::{AccessInfo, BillingInfo},
        streaming_event,
    };
    use hivemind_storage::MemoryStorageProvider;
    use serde_json::json;

    #[test]
    fn verifies_canonical_receipt_id() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();

        let verification = verify_receipt(&receipt);

        assert!(verification.valid, "{verification:#?}");
    }

    #[test]
    fn identity_signed_receipt_verifies() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let identity =
            hivemind_identity::identity_from_seed(&receipt.runner_id, b"runner-seed").unwrap();

        let envelope = sign_receipt_with_identity(&mut receipt, &identity).unwrap();
        let verification = verify_receipt(&receipt);

        assert_eq!(envelope.signer, receipt.runner_id);
        assert!(
            receipt
                .signature
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .starts_with("ed25519-payload-hash:")
        );
        assert!(
            !verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signature")
        );
    }

    #[test]
    fn verifies_execution_receipt_v2_with_source_receipt() {
        let mut receipt = receipt();
        receipt.route_id = Some("route-v2-1".to_string());
        receipt.access.license_grant_id = Some("grant-v2-1".to_string());
        receipt.policy = Some(receipt_policy_evidence(
            &policy_decision(&receipt),
            "2026-05-22T00:00:00Z",
        ));
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();

        let v2 = execution_receipt_v2_from_v1(
            &receipt,
            ExecutionReceiptV2Context {
                job_id: Some("job-v2-verify".to_string()),
                lease_id: Some("lease-v2-verify".to_string()),
                requester: Some("local-dev-requester".to_string()),
                api_surface: Some(ApiSurface::OpenAiChatCompletions),
                input_modalities: vec!["text".to_string()],
                output_modalities: vec!["text".to_string()],
                verification_mode: Some(IntegrityTier::TeeAttested),
                attestation_ref: Some("local://integrity/attestation-v2".to_string()),
                route_decision_ref: Some("local://route/route-v2-1".to_string()),
                ..Default::default()
            },
        );

        let verification = verify_execution_receipt_v2(&v2, Some(&receipt));

        assert!(verification.valid, "{verification:#?}");
        assert!(verification.signature_verified);
        assert_eq!(verification.source_receipt_valid, Some(true));
        assert_eq!(
            verification.expected_signature.as_deref(),
            Some(receipt.signature.as_str())
        );
    }

    #[test]
    fn execution_receipt_v2_requires_source_for_signature_and_detects_tampering() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut v2 = execution_receipt_v2_from_v1(
            &receipt,
            ExecutionReceiptV2Context {
                job_id: Some("job-v2-tamper".to_string()),
                requester: Some("local-dev-requester".to_string()),
                input_modalities: vec!["text".to_string()],
                output_modalities: vec!["json".to_string()],
                ..Default::default()
            },
        );

        let standalone = verify_execution_receipt_v2(&v2, None);
        assert!(!standalone.valid);
        assert!(!standalone.signature_verified);
        assert!(
            standalone
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signatures")
        );

        v2.input_hashes = vec!["0".repeat(64)];
        let tampered = verify_execution_receipt_v2(&v2, Some(&receipt));
        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path == "$.inputHashes")
        );
    }

    #[test]
    fn receipt_correctness_assessment_accepts_verified_attestation_evidence() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let v2 = execution_receipt_v2_from_v1(
            &receipt,
            ExecutionReceiptV2Context {
                job_id: Some("job-correctness-tee".to_string()),
                requester: Some("local-dev-requester".to_string()),
                input_modalities: vec!["text".to_string()],
                output_modalities: vec!["text".to_string()],
                verification_mode: Some(IntegrityTier::TeeAttested),
                attestation_ref: Some("local://integrity/attestation-correctness".to_string()),
                ..Default::default()
            },
        );

        let assessment = assess_receipt_correctness(&ReceiptCorrectnessAssessmentRequestV1 {
            schema_version: RECEIPT_CORRECTNESS_ASSESSMENT_REQUEST_SCHEMA_VERSION.to_string(),
            receipt: v2.clone(),
            source_receipt: Some(receipt),
            validation_evidence: vec![ReceiptCorrectnessEvidenceV1 {
                method: ReceiptCorrectnessEvidenceMethodV1::TeeAttestationCheck,
                evidence_ref: "local://integrity/attestation-correctness".to_string(),
                validator_id: Some("validator-tee".to_string()),
                receipt_id: Some(v2.receipt_id.clone()),
                status: ReceiptCorrectnessEvidenceStatusV1::Passed,
                confidence: Some(1.0),
                subjective: false,
                private_evidence: false,
                signature_verified: true,
                checked_at: Some("2026-05-22T00:00:00Z".to_string()),
                metadata: json!({ "measurement": "matched" }),
            }],
            required_integrity_tier: None,
            required_methods: Vec::new(),
            minimum_confidence: Some(0.9),
            allow_subjective_only: false,
        });

        assert!(assessment.valid, "{assessment:#?}");
        assert_eq!(
            assessment.correctness_level,
            ReceiptCorrectnessLevelV1::Attested
        );
        assert_eq!(assessment.accepted_evidence_count, 1);
        assert_eq!(
            assessment.satisfied_methods,
            vec![ReceiptCorrectnessEvidenceMethodV1::TeeAttestationCheck]
        );
        assert!(assessment.missing_methods.is_empty());
        assert!(
            assessment
                .validation_refs
                .contains(&"local://integrity/attestation-correctness".to_string())
        );
    }

    #[test]
    fn receipt_correctness_assessment_does_not_treat_unchecked_proof_ref_as_correctness() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let v2 = execution_receipt_v2_from_v1(
            &receipt,
            ExecutionReceiptV2Context {
                job_id: Some("job-correctness-zk".to_string()),
                requester: Some("local-dev-requester".to_string()),
                input_modalities: vec!["text".to_string()],
                output_modalities: vec!["text".to_string()],
                verification_mode: Some(IntegrityTier::ZkProofWhenSupported),
                proof_refs: vec!["bzz://zk-proof-correctness".to_string()],
                ..Default::default()
            },
        );

        let receipt_verification = verify_execution_receipt_v2(&v2, Some(&receipt));
        assert!(receipt_verification.valid, "{receipt_verification:#?}");

        let assessment = assess_receipt_correctness(&ReceiptCorrectnessAssessmentRequestV1 {
            schema_version: RECEIPT_CORRECTNESS_ASSESSMENT_REQUEST_SCHEMA_VERSION.to_string(),
            receipt: v2,
            source_receipt: Some(receipt),
            validation_evidence: Vec::new(),
            required_integrity_tier: None,
            required_methods: Vec::new(),
            minimum_confidence: None,
            allow_subjective_only: false,
        });

        assert!(!assessment.valid);
        assert_eq!(
            assessment.correctness_level,
            ReceiptCorrectnessLevelV1::Unverified
        );
        assert_eq!(
            assessment.missing_methods,
            vec![ReceiptCorrectnessEvidenceMethodV1::ZkProofCheck]
        );
        assert!(
            assessment
                .issues
                .iter()
                .any(|issue| issue.message.contains("zk-proof-check"))
        );
    }

    #[test]
    fn redacts_receipt_for_public_audit_and_verifies_policy() {
        let mut receipt = receipt();
        receipt.route_id = Some("route-private-1".to_string());
        receipt.access.license_grant_id = Some("grant-private-1".to_string());
        receipt.policy = Some(receipt_policy_evidence(
            &policy_decision(&receipt),
            "2026-05-22T00:00:00Z",
        ));
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();

        let redacted = redact_receipt(
            &receipt,
            receipt_redaction_policy(ReceiptRedactionProfileV1::PublicAudit),
        );
        let verification = verify_redacted_receipt(&redacted);

        assert!(verification.valid, "{verification:#?}");
        assert!(redacted.redaction_id.starts_with("receipt-redaction-"));
        assert_eq!(redacted.original_receipt_id, receipt.receipt_id);
        assert_eq!(redacted.fields.package_ref, None);
        assert!(redacted.fields.package_ref_hash.is_some());
        assert_eq!(redacted.fields.runner_id, None);
        assert!(redacted.fields.runner_id_hash.is_some());
        assert_eq!(redacted.fields.route_id, None);
        assert!(redacted.fields.route_id_hash.is_some());
        assert_eq!(redacted.fields.license_grant_id, None);
        assert!(redacted.fields.license_grant_id_hash.is_some());
        assert_eq!(redacted.fields.signature, None);
        assert!(redacted.fields.signature_hash.is_some());
        assert_eq!(redacted.fields.input_hashes, vec![receipt.input_hash]);
        assert!(redacted.redacted_fields.contains(&"$.runnerId".to_string()));
        assert!(
            redacted
                .retained_fields
                .contains(&"$.inputHashes".to_string())
        );

        let mut leaked = redacted;
        leaked.fields.runner_id = Some("runner-1".to_string());
        leaked.redaction_id = canonical_redacted_receipt_id(&leaked).unwrap();
        sign_redacted_receipt(&mut leaked);
        let verification = verify_redacted_receipt(&leaked);
        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.fields.runnerId")
        );
    }

    #[test]
    fn audits_receipt_store_for_operator_followups() {
        let mut valid_receipt = receipt();
        sign_receipt(&mut valid_receipt);
        valid_receipt.receipt_id = canonical_receipt_id(&valid_receipt).unwrap();
        let mut valid_entry = index_entry(&valid_receipt, Option::<String>::None);
        valid_entry.job_id = Some("job-audit-1".to_string());
        valid_entry.requester = Some("requester-audit".to_string());
        valid_entry.settlement_status = Some(ReceiptSettlementStatusV1::NotRequired);

        let mut invalid_receipt = receipt();
        invalid_receipt.request_id = "request-audit-invalid".to_string();
        invalid_receipt.privacy_mode = "public-evidence".to_string();
        sign_receipt(&mut invalid_receipt);
        invalid_receipt.receipt_id = canonical_receipt_id(&invalid_receipt).unwrap();
        invalid_receipt.signature = "bad-signature".to_string();
        let invalid_entry = index_entry(&invalid_receipt, Option::<String>::None);

        let summary = ReceiptStoreSummaryV1 {
            schema_version: "swarm-ai.receipt-store-summary.v1".to_string(),
            root: "memory://receipts".to_string(),
            receipt_count: 2,
            valid_count: 1,
            invalid_count: 1,
            with_timing_metric_count: 2,
            average_queue_ms: Some(0.0),
            max_queue_ms: Some(0),
            average_load_ms: Some(0.0),
            max_load_ms: Some(0),
            average_total_ms: Some(0.0),
            max_total_ms: Some(0),
            throughput_sample_count: 0,
            average_output_tokens_per_second: None,
            max_output_tokens_per_second: None,
            receipts: vec![valid_entry, invalid_entry],
        };

        let audit = audit_receipt_store(&summary);

        assert_eq!(audit.schema_version, "hivemind.receipt_audit_summary.v1");
        assert_eq!(audit.receipt_count, 2);
        assert_eq!(audit.valid_count, 1);
        assert_eq!(audit.invalid_count, 1);
        assert_eq!(audit.hash_only_count, 1);
        assert_eq!(audit.public_evidence_count, 1);
        assert_eq!(audit.missing_job_context_count, 1);
        assert_eq!(audit.missing_settlement_status_count, 1);
        assert_eq!(audit.redaction_recommended_count, 1);
        assert!(
            audit
                .index
                .by_runner_id
                .iter()
                .any(|count| count.key == "runner-1" && count.count == 2)
        );
        assert!(
            audit
                .index
                .by_settlement_status
                .iter()
                .any(|count| count.key == "not-required" && count.count == 1)
        );
        assert!(
            audit
                .issues
                .iter()
                .any(|issue| issue.severity == ReceiptAuditSeverityV1::Critical
                    && issue.path == "$.verification")
        );
        assert!(
            audit
                .issues
                .iter()
                .any(|issue| issue.path == "$.privacyMode"
                    && issue.message.contains("redacted view"))
        );
    }

    #[test]
    fn rejects_tampered_identity_signed_receipt() {
        let mut receipt = receipt();
        let identity =
            hivemind_identity::identity_from_seed(&receipt.runner_id, b"runner-seed").unwrap();
        sign_receipt_with_identity(&mut receipt, &identity).unwrap();
        receipt.output_hash = "1".repeat(64);

        let verification = verify_receipt(&receipt);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.receiptId"
                    || issue.path == "$.signature.payloadHash")
        );
    }

    #[test]
    fn rejects_modified_receipt_id() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        receipt.output_hash = "1".repeat(64);

        let verification = verify_receipt(&receipt);

        assert!(!verification.valid);
    }

    #[test]
    fn rejects_modified_receipt_signature() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        receipt.signature = "dev-signature-v1:execution-receipt:bad".to_string();

        let verification = verify_receipt(&receipt);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signature")
        );
    }

    #[test]
    fn verifies_embedded_policy_evidence() {
        let mut receipt = receipt();
        let policy = policy_decision(&receipt);
        receipt.policy = Some(receipt_policy_evidence(&policy, receipt.started_at.clone()));
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();

        let verification = verify_receipt(&receipt);

        assert!(verification.valid, "{verification:#?}");

        let mut tampered = receipt;
        tampered.policy.as_mut().unwrap().policy_decision_id = "policy-bad".to_string();
        sign_receipt(&mut tampered);
        tampered.receipt_id = canonical_receipt_id(&tampered).unwrap();

        let verification = verify_receipt(&tampered);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.policy.policyDecisionId")
        );
    }

    #[test]
    fn creates_and_verifies_dispute_evidence() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();

        let evidence = create_dispute_evidence(
            receipt,
            "0xClaimant",
            DisputeClaimKind::OutputMismatch,
            "Output did not match expected benchmark answer",
            vec!["bzz://evidence".to_string()],
        );

        let verification = verify_dispute_evidence(&evidence);

        assert!(verification.valid, "{verification:#?}");
        assert!(evidence.dispute_id.starts_with("dispute-"));
        assert_eq!(evidence.claim_kind, DisputeClaimKind::OutputMismatch);
    }

    #[test]
    fn identity_signed_dispute_evidence_verifies() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut evidence = create_dispute_evidence(
            receipt,
            "0xClaimant",
            DisputeClaimKind::OutputMismatch,
            "Output did not match expected benchmark answer",
            vec!["bzz://evidence".to_string()],
        );
        let identity =
            hivemind_identity::identity_from_seed("0xClaimant", b"claimant-seed").unwrap();

        let envelope = sign_dispute_evidence_with_identity(&mut evidence, &identity).unwrap();
        let verification = verify_dispute_evidence(&evidence);

        assert_eq!(envelope.signer, evidence.claimant);
        assert!(
            evidence
                .signature
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .starts_with("ed25519-payload-hash:")
        );
        assert!(
            !verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signature")
        );
    }

    #[test]
    fn rejects_tampered_identity_signed_dispute_evidence() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut evidence = create_dispute_evidence(
            receipt,
            "0xClaimant",
            DisputeClaimKind::IncorrectBilling,
            "Billing was higher than the quote",
            vec!["local://quote".to_string()],
        );
        let identity =
            hivemind_identity::identity_from_seed("0xClaimant", b"claimant-seed").unwrap();
        sign_dispute_evidence_with_identity(&mut evidence, &identity).unwrap();
        evidence.summary = "A different claim after signing".to_string();

        let verification = verify_dispute_evidence(&evidence);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.disputeId"
                    || issue.path == "$.signature.payloadHash")
        );
    }

    #[test]
    fn rejects_tampered_dispute_evidence() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut evidence = create_dispute_evidence(
            receipt,
            "0xClaimant",
            DisputeClaimKind::IncorrectBilling,
            "Billing was higher than the quote",
            vec!["local://quote".to_string()],
        );
        evidence.summary = "A different claim after signing".to_string();

        let verification = verify_dispute_evidence(&evidence);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.disputeId" || issue.path == "$.signature")
        );
    }

    #[test]
    fn creates_and_verifies_batch_receipt_with_item_statuses() {
        let receipt = batch_receipt();

        let verification = verify_batch_receipt(&receipt);

        assert!(verification.valid, "{verification:#?}");
        assert!(receipt.batch_receipt_id.starts_with("batch-receipt-"));
        assert_eq!(receipt.item_count, 2);
        assert_eq!(receipt.succeeded_count, 1);
        assert_eq!(receipt.failed_count, 1);
        assert_eq!(receipt.cancelled_count, 0);
        assert_eq!(receipt.skipped_count, 0);
        assert_eq!(receipt.total_metrics.total_ms, 42);
        assert_eq!(receipt.total_metrics.input_tokens, Some(16));
        assert_eq!(receipt.total_metrics.output_tokens, Some(8));
    }

    #[test]
    fn identity_signed_batch_receipt_verifies() {
        let mut receipt = batch_receipt();
        let identity =
            hivemind_identity::identity_from_seed(&receipt.runner_id, b"batch-runner-seed")
                .unwrap();

        let envelope = sign_batch_receipt_with_identity(&mut receipt, &identity).unwrap();
        let verification = verify_batch_receipt(&receipt);

        assert_eq!(envelope.signer, receipt.runner_id);
        assert!(
            receipt
                .signature
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .starts_with("ed25519-payload-hash:")
        );
        assert!(
            !verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signature")
        );
    }

    #[test]
    fn rejects_tampered_batch_receipt_item_status_and_metrics() {
        let mut receipt = batch_receipt();
        receipt.items[0].status = BatchReceiptItemStatusV1::Failed;
        receipt.total_metrics.total_ms += 1;

        let verification = verify_batch_receipt(&receipt);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.batchReceiptId")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.succeededCount")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.totalMetrics")
        );
    }

    #[test]
    fn receipt_store_ignores_non_final_receipt_artifacts() {
        let root = unique_temp_dir("hivemind-mixed-receipt-store-test");
        let mut receipt = receipt();
        receipt.route_id = Some("route-private-1".to_string());
        receipt.access.license_grant_id = Some("grant-private-1".to_string());
        receipt.metrics = ExecutionMetrics {
            queue_ms: 2,
            load_ms: 3,
            compute_ms: 10,
            total_ms: 20,
            input_tokens: Some(4),
            output_tokens: Some(6),
        };
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        write_receipt(&root, &receipt).unwrap();

        let batch = batch_receipt();
        write_batch_receipt(&root, &batch).unwrap();
        let redacted = redact_receipt(
            &receipt,
            receipt_redaction_policy(ReceiptRedactionProfileV1::PublicAudit),
        );
        fs::write(
            root.join(format!("{}.json", redacted.redaction_id)),
            serde_json::to_vec_pretty(&redacted).unwrap(),
        )
        .unwrap();
        let v2 = execution_receipt_v2_from_v1(
            &receipt,
            ExecutionReceiptV2Context {
                job_id: Some("job-mixed-store".to_string()),
                requester: Some("local-dev".to_string()),
                input_modalities: vec!["text".to_string()],
                output_modalities: vec!["json".to_string()],
                ..Default::default()
            },
        );
        fs::write(
            root.join("smoke.receipt-v2.json"),
            serde_json::to_vec_pretty(&v2).unwrap(),
        )
        .unwrap();
        fs::write(root.join("malformed.json"), b"\xef\xbb\xbfnot-json").unwrap();

        let summary = list_receipts(&root).unwrap();

        assert_eq!(summary.receipt_count, 1);
        assert_eq!(summary.receipts[0].receipt_id, receipt.receipt_id);
        assert_eq!(summary.with_timing_metric_count, 1);
        assert_eq!(summary.average_queue_ms, Some(2.0));
        assert_eq!(summary.max_queue_ms, Some(2));
        assert_eq!(summary.average_load_ms, Some(3.0));
        assert_eq!(summary.max_load_ms, Some(3));
        assert_eq!(summary.average_total_ms, Some(20.0));
        assert_eq!(summary.max_total_ms, Some(20));
        assert_eq!(summary.throughput_sample_count, 1);
        assert_eq!(summary.average_output_tokens_per_second, Some(300.0));
        assert_eq!(summary.max_output_tokens_per_second, Some(300.0));
        assert_eq!(summary.receipts[0].queue_ms, 2);
        assert_eq!(summary.receipts[0].load_ms, 3);
        assert_eq!(summary.receipts[0].compute_ms, 10);
        assert_eq!(summary.receipts[0].output_tokens_per_second, Some(300.0));
        assert!(
            get_receipt(&root, &batch.batch_receipt_id)
                .unwrap()
                .is_none()
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn batch_receipt_store_lists_and_gets_receipts() {
        let root = unique_temp_dir("hivemind-batch-receipt-store-test");
        let receipt = batch_receipt();
        let path = write_batch_receipt(&root, &receipt).unwrap();

        let summary = list_batch_receipts(&root).unwrap();
        let lookup = get_batch_receipt(&root, &receipt.batch_receipt_id)
            .unwrap()
            .expect("batch receipt should be found");
        let missing = get_batch_receipt(&root, "missing-batch-receipt").unwrap();

        assert_eq!(summary.batch_receipt_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.total_item_count, 2);
        assert_eq!(summary.succeeded_item_count, 1);
        assert_eq!(summary.failed_item_count, 1);
        assert_eq!(
            summary.batch_receipts[0].batch_receipt_id,
            receipt.batch_receipt_id
        );
        assert_eq!(
            summary.batch_receipts[0].batch_receipt_path.clone(),
            Some(path.display().to_string())
        );
        assert_eq!(
            lookup.batch_receipt.batch_receipt_id,
            receipt.batch_receipt_id
        );
        assert!(lookup.verification.valid);
        assert!(missing.is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn audits_batch_receipts_for_operator_followups() {
        let mut entry = batch_receipt_index_entry(&batch_receipt(), None::<String>);
        entry.job_id = None;
        entry.privacy_mode = "public-evidence".to_string();
        let summary = BatchReceiptStoreSummaryV1 {
            schema_version: "hivemind.batch_receipt_store_summary.v1".to_string(),
            root: "memory://batch-receipts".to_string(),
            batch_receipt_count: 1,
            valid_count: 1,
            invalid_count: 0,
            total_item_count: entry.item_count,
            succeeded_item_count: entry.succeeded_count,
            failed_item_count: entry.failed_count,
            cancelled_item_count: entry.cancelled_count,
            skipped_item_count: entry.skipped_count,
            batch_receipts: vec![entry],
        };

        let audit = audit_batch_receipt_store(&summary);

        assert_eq!(
            audit.schema_version,
            "hivemind.batch_receipt_audit_summary.v1"
        );
        assert_eq!(audit.batch_receipt_count, 1);
        assert_eq!(audit.total_item_count, 2);
        assert_eq!(audit.failed_item_count, 1);
        assert_eq!(audit.batch_with_failures_count, 1);
        assert_eq!(audit.partial_settlement_candidate_count, 1);
        assert_eq!(audit.missing_job_context_count, 1);
        assert_eq!(audit.public_evidence_count, 1);
        assert_eq!(audit.redaction_recommended_count, 1);
        assert!(
            audit
                .index
                .by_runner_id
                .iter()
                .any(|group| group.key == "runner-1" && group.count == 1)
        );
        assert!(
            audit.issues.iter().any(
                |issue| issue.path == "$.items" && issue.message.contains("partial settlement")
            )
        );
    }

    #[test]
    fn uploads_and_downloads_verified_receipt() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut storage = MemoryStorageProvider::default();

        let upload = upload_receipt(&mut storage, &receipt).unwrap();
        let download = download_receipt(&storage, &upload.receipt_ref).unwrap();

        assert!(upload.verification.valid);
        assert!(download.verification.valid);
        assert_eq!(download.receipt.receipt_id, receipt.receipt_id);
        assert_eq!(download.storage.sha256, upload.storage.sha256);
    }

    #[test]
    fn creates_and_verifies_partial_receipt() {
        let partial = create_partial_receipt(PartialReceiptDraftV1 {
            request_id: "request-partial-1".to_string(),
            job_id: Some("job-partial-1".to_string()),
            receipt_id: Some("receipt-final-1".to_string()),
            receipt_ref: Some("local://receipt/receipt-final-1".to_string()),
            runner_id: Some("local-dev-runner".to_string()),
            sequence: 2,
            status: ExecutionStatus::Partial,
            emitted_at: "2026-06-02T00:00:01Z".to_string(),
            progress: Some(1.0),
            output_hash: Some("b".repeat(64)),
            metrics: ExecutionMetrics {
                queue_ms: 1,
                load_ms: 2,
                compute_ms: 3,
                total_ms: 6,
                input_tokens: Some(7),
                output_tokens: Some(8),
            },
            verification_valid: Some(true),
            issue_count: Some(0),
            warning_count: Some(1),
            evidence_refs: vec!["local://receipt/receipt-final-1".to_string()],
        });

        let verification = verify_partial_receipt(&partial);

        assert!(verification.valid, "{verification:#?}");
        assert!(partial.partial_receipt_id.starts_with("partial-receipt-"));
        assert_eq!(partial.status, ExecutionStatus::Partial);
        assert_eq!(
            partial.output_hash.as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );

        let mut tampered = partial;
        tampered.metrics.output_tokens = Some(99);
        let verification = verify_partial_receipt(&tampered);
        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.partialReceiptId" || issue.path == "$.signature")
        );
    }

    #[test]
    fn summarizes_partial_receipts_from_stream_history() {
        let partial = create_partial_receipt(PartialReceiptDraftV1 {
            request_id: "request-partial-summary-1".to_string(),
            job_id: Some("job-partial-summary-1".to_string()),
            receipt_id: Some("receipt-summary-1".to_string()),
            receipt_ref: Some("local://receipt/receipt-summary-1".to_string()),
            runner_id: Some("local-dev-runner".to_string()),
            sequence: 1,
            status: ExecutionStatus::Partial,
            emitted_at: "2026-06-02T00:00:01Z".to_string(),
            progress: Some(0.5),
            output_hash: Some("c".repeat(64)),
            metrics: ExecutionMetrics::default(),
            verification_valid: Some(true),
            issue_count: Some(0),
            warning_count: Some(1),
            evidence_refs: vec!["local://receipt/receipt-summary-1".to_string()],
        });
        let events = vec![
            streaming_event(
                "request-partial-summary-1",
                Some("job-partial-summary-1".to_string()),
                0,
                StreamingEventType::Started,
                "2026-06-02T00:00:00Z",
                json!({ "status": "started" }),
            ),
            streaming_event(
                "request-partial-summary-1",
                Some("job-partial-summary-1".to_string()),
                1,
                StreamingEventType::PartialReceipt,
                "2026-06-02T00:00:01Z",
                json!({
                    "partialReceiptId": partial.partial_receipt_id,
                    "partialReceipt": partial,
                }),
            ),
            streaming_event(
                "request-partial-summary-1",
                Some("job-partial-summary-1".to_string()),
                2,
                StreamingEventType::PartialReceipt,
                "2026-06-02T00:00:02Z",
                json!({ "partialReceipt": { "schemaVersion": "broken" } }),
            ),
        ];

        let summary = partial_receipt_stream_summary("job-partial-summary-1", &events);

        assert_eq!(
            summary.schema_version,
            "hivemind.partial_receipt_stream_summary.v1"
        );
        assert_eq!(summary.event_count, 3);
        assert_eq!(summary.partial_event_count, 2);
        assert_eq!(summary.partial_receipt_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.invalid_count, 0);
        assert_eq!(summary.malformed_count, 1);
        assert_eq!(summary.stream_issue_count, 1);
        assert_eq!(
            summary.partial_receipts[0].request_id,
            "request-partial-summary-1"
        );
        assert_eq!(summary.partial_receipts[0].stream_sequence, 1);
        assert!(summary.partial_receipts[0].verification.valid);
    }

    #[test]
    fn gets_receipt_by_id_from_store() {
        let root = unique_temp_dir("hivemind-receipt-lookup-test");
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        write_receipt(&root, &receipt).unwrap();

        let lookup = get_receipt(&root, &receipt.receipt_id)
            .unwrap()
            .expect("receipt should be found");
        let missing = get_receipt(&root, "missing-receipt").unwrap();

        assert_eq!(lookup.receipt.receipt_id, receipt.receipt_id);
        assert!(lookup.verification.valid);
        assert!(missing.is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lists_and_gets_dispute_evidence_from_store() {
        let root = unique_temp_dir("hivemind-dispute-lookup-test");
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let evidence = create_dispute_evidence(
            receipt,
            "0xClaimant",
            DisputeClaimKind::OutputMismatch,
            "Output did not match expected benchmark answer",
            vec!["bzz://evidence".to_string()],
        );
        let dispute_path = write_dispute_evidence(&root, &evidence).unwrap();

        let summary = list_dispute_evidence(&root).unwrap();
        let lookup = get_dispute_evidence(&root, &evidence.dispute_id)
            .unwrap()
            .expect("dispute should be found");
        let missing = get_dispute_evidence(&root, "missing-dispute").unwrap();

        assert_eq!(summary.dispute_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.disputes[0].dispute_id, evidence.dispute_id);
        assert_eq!(
            summary.disputes[0].dispute_path,
            dispute_path.display().to_string()
        );
        assert_eq!(lookup.evidence.dispute_id, evidence.dispute_id);
        assert!(lookup.verification.valid);
        assert!(missing.is_none());

        let _ = fs::remove_dir_all(root);
    }

    fn batch_receipt() -> BatchReceiptV1 {
        create_batch_receipt(BatchReceiptDraftV1 {
            batch_id: "batch-test-1".to_string(),
            job_id: Some("job-batch-1".to_string()),
            requester: Some("0xRequester".to_string()),
            runner_id: "runner-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: "hivemind/test".to_string(),
            package_version: Some("0.1.0".to_string()),
            api_surface: Some(ApiSurface::OpenAiBatches),
            privacy_tier: Some(PrivacyTier::NoLog),
            privacy_mode: "hash-only".to_string(),
            verification_mode: Some(IntegrityTier::ReceiptOnly),
            created_at: "2026-06-03T00:00:00Z".to_string(),
            completed_at: Some("2026-06-03T00:00:05Z".to_string()),
            billing: Some(BillingInfo {
                estimated_cost: 0.25,
                currency: "USD".to_string(),
            }),
            items: vec![
                BatchReceiptItemV1 {
                    item_id: "item-1".to_string(),
                    request_id: Some("request-batch-1".to_string()),
                    status: BatchReceiptItemStatusV1::Succeeded,
                    input_hash: "a".repeat(64),
                    output_hash: Some("b".repeat(64)),
                    error: None,
                    started_at: Some("2026-06-03T00:00:01Z".to_string()),
                    completed_at: Some("2026-06-03T00:00:02Z".to_string()),
                    metrics: ExecutionMetrics {
                        queue_ms: 2,
                        load_ms: 3,
                        compute_ms: 10,
                        total_ms: 15,
                        input_tokens: Some(10),
                        output_tokens: Some(8),
                    },
                    receipt_id: Some("receipt-item-1".to_string()),
                    receipt_ref: Some("local://receipt/receipt-item-1".to_string()),
                    evidence_refs: vec!["local://receipt/receipt-item-1".to_string()],
                },
                BatchReceiptItemV1 {
                    item_id: "item-2".to_string(),
                    request_id: Some("request-batch-2".to_string()),
                    status: BatchReceiptItemStatusV1::Failed,
                    input_hash: "c".repeat(64),
                    output_hash: None,
                    error: Some(ExecutionReceiptErrorV2 {
                        code: ErrorCode::ExecutionFailed,
                        message: "model execution failed".to_string(),
                        details: json!({ "stderrHash": "d".repeat(64) }),
                    }),
                    started_at: Some("2026-06-03T00:00:02Z".to_string()),
                    completed_at: Some("2026-06-03T00:00:04Z".to_string()),
                    metrics: ExecutionMetrics {
                        queue_ms: 1,
                        load_ms: 4,
                        compute_ms: 20,
                        total_ms: 27,
                        input_tokens: Some(6),
                        output_tokens: None,
                    },
                    receipt_id: None,
                    receipt_ref: None,
                    evidence_refs: vec!["bzz://batch-evidence/item-2".to_string()],
                },
            ],
            evidence_refs: vec!["bzz://batch-evidence/root".to_string()],
        })
    }

    fn receipt() -> ExecutionReceiptV1 {
        ExecutionReceiptV1 {
            schema_version: "swarm-ai.receipt.v1".to_string(),
            receipt_id: String::new(),
            request_id: "request-1".to_string(),
            package_id: "hivemind/test".to_string(),
            package_ref: "bzz://pkg".to_string(),
            artifact_group: "local".to_string(),
            package_manifest_hash: "0".repeat(64),
            runner_id: "runner-1".to_string(),
            route_id: None,
            input_hash: "a".repeat(64),
            output_hash: "b".repeat(64),
            privacy_mode: "hash-only".to_string(),
            started_at: "2026-05-22T00:00:00Z".to_string(),
            finished_at: "2026-05-22T00:00:01Z".to_string(),
            metrics: ExecutionMetrics::default(),
            billing: BillingInfo {
                estimated_cost: 0.0,
                currency: "none".to_string(),
            },
            access: AccessInfo {
                license_grant_id: None,
            },
            policy: None,
            signature: String::new(),
        }
    }

    fn policy_decision(receipt: &ExecutionReceiptV1) -> PolicyDecisionV1 {
        PolicyDecisionV1 {
            schema_version: "swarm-ai.policy-decision.v1".to_string(),
            package_id: receipt.package_id.clone(),
            package_ref: receipt.package_ref.clone(),
            runner_id: Some(receipt.runner_id.clone()),
            decision: PolicyDecision::AllowWithRestrictions,
            reasons: vec!["test policy".to_string()],
            restrictions: json!({ "network": "blocked-except-allowlist" }),
            risk_level: RiskLevel::Medium,
        }
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        path
    }
}
