use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
use hivemind_core::{
    ErrorCode, SwarmAiErrorV1, ValidationIssue, canonicalize_json, hash_canonical_json,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const BEE_DEFAULT_MAX_RETRIES: u32 = 2;
const BEE_RETRY_BACKOFF_MS: u64 = 150;
const DEV_BROWSER_STORAGE_CONSENT_SIGNATURE_PREFIX: &str =
    "dev-browser-storage-consent-signature-v1";
const DEV_BROWSER_STORAGE_SESSION_SIGNATURE_PREFIX: &str =
    "dev-browser-storage-session-signature-v1";
const DEV_STORAGE_EVENT_RECEIPT_SIGNATURE_PREFIX: &str = "dev-storage-event-receipt-signature-v1";
const DEV_STORAGE_SPONSORSHIP_SIGNATURE_PREFIX: &str = "dev-storage-sponsorship-signature-v1";
const DEV_BROWSER_STORAGE_SECURITY_ASSESSMENT_SIGNATURE_PREFIX: &str =
    "dev-browser-storage-security-assessment-signature-v1";
const DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX: &str = "dev-browser-storage-v5-signature-v1";

pub const BROWSER_STORAGE_SECURITY_ASSESSMENT_REQUEST_SCHEMA_VERSION: &str =
    "hivemind.browser-storage-security-assessment-request.v1";
pub const BROWSER_STORAGE_SECURITY_ASSESSMENT_SCHEMA_VERSION: &str =
    "hivemind.browser-storage-security-assessment.v1";
pub const BROWSER_STORAGE_SECURITY_ASSESSMENT_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.browser-storage-security-assessment-verification.v1";
pub const BROWSER_STORAGE_CAPABILITY_PROBE_SCHEMA_VERSION: &str =
    "hivemind.browser-storage-capability-probe.v1";
pub const BROWSER_STORAGE_PURCHASE_QUOTE_SCHEMA_VERSION: &str =
    "hivemind.browser-storage-purchase-quote.v1";
pub const BROWSER_STORAGE_PURCHASE_AUTHORIZATION_SCHEMA_VERSION: &str =
    "hivemind.browser-storage-purchase-authorization.v1";
pub const BROWSER_STORAGE_SESSION_V2_SCHEMA_VERSION: &str = "hivemind.browser-storage-session.v2";
pub const STORAGE_EVENT_RECEIPT_V2_SCHEMA_VERSION: &str = "hivemind.storage-event-receipt.v2";
pub const BROWSER_STORAGE_STATE_REPORT_SCHEMA_VERSION: &str =
    "hivemind.browser-storage-state-report.v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageCapabilities {
    pub upload: bool,
    pub download: bool,
    pub feeds: bool,
    pub pinning: bool,
    pub act: bool,
    pub pss: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageStatusV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub provider: String,
    pub capabilities: StorageCapabilities,
    #[serde(
        rename = "retryPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub retry_policy: Option<StorageRetryPolicyV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageRetryPolicyV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "maxRetries")]
    pub max_retries: u32,
    #[serde(rename = "backoffMs")]
    pub backoff_ms: u64,
    #[serde(rename = "retryableStatusCodes")]
    pub retryable_status_codes: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageFeedPointerV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "feedRef")]
    pub feed_ref: String,
    pub topic: String,
    pub owner: String,
    #[serde(rename = "targetRef", default)]
    pub target_ref: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageFeedUpdateResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "feedRef")]
    pub feed_ref: String,
    pub pointer: StorageFeedPointerV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageFeedResolutionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "feedRef")]
    pub feed_ref: String,
    pub pointer: StorageFeedPointerV1,
    #[serde(rename = "targetRef", default)]
    pub target_ref: Option<String>,
    #[serde(rename = "resolvedAt")]
    pub resolved_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StoragePinResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub pinned: bool,
    pub provider: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageTransferMetricsV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "resolveMs")]
    pub resolve_ms: u64,
    #[serde(rename = "firstByteMs")]
    pub first_byte_ms: u64,
    #[serde(rename = "totalMs")]
    pub total_ms: u64,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    #[serde(rename = "retryCount")]
    pub retry_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum StorageTransferDirectionV1 {
    Upload,
    Download,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageTransferAuditRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "transferId")]
    pub transfer_id: String,
    pub provider: String,
    pub direction: StorageTransferDirectionV1,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(
        rename = "contentType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type: Option<String>,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    pub metrics: StorageTransferMetricsV1,
    #[serde(rename = "recordedAt")]
    pub recorded_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageTransferAuditSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "transferCount")]
    pub transfer_count: usize,
    #[serde(rename = "uploadCount")]
    pub upload_count: usize,
    #[serde(rename = "downloadCount")]
    pub download_count: usize,
    #[serde(rename = "totalSizeBytes")]
    pub total_size_bytes: u64,
    #[serde(rename = "retryCount")]
    pub retry_count: u64,
    #[serde(rename = "withTimingMetricCount")]
    pub with_timing_metric_count: usize,
    #[serde(
        rename = "averageTransferTotalMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub average_transfer_total_ms: Option<f64>,
    #[serde(
        rename = "maxTransferTotalMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_transfer_total_ms: Option<u64>,
    #[serde(
        rename = "averageUploadTotalMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub average_upload_total_ms: Option<f64>,
    #[serde(
        rename = "maxUploadTotalMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_upload_total_ms: Option<u64>,
    #[serde(
        rename = "averageDownloadTotalMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub average_download_total_ms: Option<f64>,
    #[serde(
        rename = "maxDownloadTotalMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_download_total_ms: Option<u64>,
    pub transfers: Vec<StorageTransferAuditRecordV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StorageProviderKindV3 {
    LocalDev,
    BeeHttp,
    BeeJsGateway,
    Gateway,
    Weeb3Npm,
    LocalBeeBridge,
    HostedUploadRelay,
    Relay,
    ArchiveMirror,
    MockDev,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StorageEnvironmentV3 {
    Browser,
    Node,
    Service,
    Runner,
    Validator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StorageProviderCapabilityV3 {
    Retrieve,
    UploadBytes,
    UploadFile,
    UploadCollection,
    BuyStorage,
    ReuseStorage,
    ResetStorage,
    CreateFeed,
    UpdateFeed,
    ResolveFeed,
    Encrypt,
    AccessControl,
    Pin,
    Status,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageProviderDescriptorV3 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV3,
    pub environment: StorageEnvironmentV3,
    #[serde(default)]
    pub capabilities: Vec<StorageProviderCapabilityV3>,
    #[serde(
        rename = "maxRecommendedUploadBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_recommended_upload_bytes: Option<u64>,
    #[serde(rename = "requiresWallet")]
    pub requires_wallet: bool,
    #[serde(rename = "requiresTrustedGateway")]
    pub requires_trusted_gateway: bool,
    #[serde(rename = "supportsProgressEvents")]
    pub supports_progress_events: bool,
    #[serde(rename = "supportsResumableUpload")]
    pub supports_resumable_upload: bool,
    #[serde(rename = "securityNotes", default)]
    pub security_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum StorageProviderKindV4 {
    Weeb3Browser,
    BeeJsBrowser,
    BeeJsNode,
    BeeHttp,
    Gateway,
    LocalDir,
    InMemory,
    Relay,
    ArchiveMirror,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum StorageProviderEnvironmentV4 {
    Browser,
    Node,
    Service,
    Runner,
    Validator,
    LocalDev,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserSwarmProviderProfileV1 {
    DirectBrowserPublishing,
    BrowserGatewayFallback,
    LocalDevelopment,
    ServerBridge,
    UploadRelay,
    ArchiveMirror,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Ord, PartialOrd)]
#[serde(rename_all = "camelCase")]
pub enum BrowserSwarmStorageMethodV4 {
    ProbeCapabilities,
    ConnectWallet,
    BuyStorage,
    ReuseStorage,
    ResetStorage,
    UploadBlob,
    UploadFiles,
    UploadJson,
    UploadManifest,
    UpdateFeed,
    Retrieve,
    Verify,
    GetSessionStatus,
    ClearSensitiveBrowserState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserStorageSessionStatusV1 {
    Requested,
    Active,
    Expired,
    Revoked,
    Cleared,
    Error,
}

impl Default for BrowserStorageSessionStatusV1 {
    fn default() -> Self {
        Self::Requested
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserStorageQuotaEstimateV1 {
    #[serde(
        rename = "quotaBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub quota_bytes: Option<u64>,
    #[serde(
        rename = "usageBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub usage_bytes: Option<u64>,
    #[serde(
        rename = "availableBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub available_bytes: Option<u64>,
    #[serde(rename = "source")]
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmCapabilityReportV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "providerName")]
    pub provider_name: String,
    #[serde(rename = "providerVersion")]
    pub provider_version: String,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV4,
    pub profile: BrowserSwarmProviderProfileV1,
    pub environment: StorageProviderEnvironmentV4,
    #[serde(
        rename = "browserOrigin",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub browser_origin: Option<String>,
    #[serde(default)]
    pub methods: Vec<BrowserSwarmStorageMethodV4>,
    #[serde(
        rename = "maxRecommendedUploadBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_recommended_upload_bytes: Option<u64>,
    #[serde(rename = "supportsProgressEvents")]
    pub supports_progress_events: bool,
    #[serde(rename = "supportsResumableUpload")]
    pub supports_resumable_upload: bool,
    #[serde(rename = "supportsHashVerification")]
    pub supports_hash_verification: bool,
    #[serde(rename = "supportsGatewayFallback")]
    pub supports_gateway_fallback: bool,
    #[serde(rename = "supportsWalletStoragePurchase")]
    pub supports_wallet_storage_purchase: bool,
    #[serde(rename = "requiresWallet")]
    pub requires_wallet: bool,
    #[serde(rename = "requiresTrustedGateway")]
    pub requires_trusted_gateway: bool,
    #[serde(
        rename = "quotaEstimate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub quota_estimate: Option<BrowserStorageQuotaEstimateV1>,
    #[serde(rename = "peerStatus", default)]
    pub peer_status: Value,
    #[serde(rename = "batchStatus", default)]
    pub batch_status: Value,
    #[serde(rename = "cacheStatus", default)]
    pub cache_status: Value,
    #[serde(rename = "securityWarnings", default)]
    pub security_warnings: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmStorageProviderV4 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "providerName")]
    pub provider_name: String,
    #[serde(rename = "providerVersion")]
    pub provider_version: String,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV4,
    pub profile: BrowserSwarmProviderProfileV1,
    pub environment: StorageProviderEnvironmentV4,
    #[serde(rename = "capabilityReport")]
    pub capability_report: BrowserSwarmCapabilityReportV1,
    #[serde(rename = "fallbackProviderIds", default)]
    pub fallback_provider_ids: Vec<String>,
    #[serde(rename = "sessionRequired")]
    pub session_required: bool,
    #[serde(rename = "walletRequired")]
    pub wallet_required: bool,
    #[serde(rename = "storageReceiptRequired")]
    pub storage_receipt_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmConformanceCheckV1 {
    pub check: String,
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmProviderConformanceReportV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV4,
    pub profile: BrowserSwarmProviderProfileV1,
    pub valid: bool,
    #[serde(rename = "requiredMethods")]
    pub required_methods: Vec<BrowserSwarmStorageMethodV4>,
    #[serde(rename = "supportedRequiredMethods")]
    pub supported_required_methods: Vec<BrowserSwarmStorageMethodV4>,
    #[serde(rename = "missingRequiredMethods")]
    pub missing_required_methods: Vec<BrowserSwarmStorageMethodV4>,
    #[serde(default)]
    pub checks: Vec<BrowserSwarmConformanceCheckV1>,
    #[serde(default)]
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "checkedAt")]
    pub checked_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmProviderCatalogV4 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub providers: Vec<BrowserSwarmStorageProviderV4>,
    #[serde(rename = "conformanceReports")]
    pub conformance_reports: Vec<BrowserSwarmProviderConformanceReportV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum WalletConnectionStatusV1 {
    Connected,
    Rejected,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WalletConnectionResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub status: WalletConnectionStatusV1,
    #[serde(
        rename = "walletAddress",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub wallet_address: Option<String>,
    #[serde(rename = "chainId", default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<SwarmAiErrorV1>,
    #[serde(rename = "connectedAt")]
    pub connected_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RetrievedAssetV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV4,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "byteSize")]
    pub byte_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(rename = "retrievedAt")]
    pub retrieved_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageReferenceVerificationResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV4,
    #[serde(rename = "expectedHash")]
    pub expected_hash: String,
    #[serde(
        rename = "actualHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub actual_hash: Option<String>,
    pub valid: bool,
    #[serde(default)]
    pub errors: Vec<SwarmAiErrorV1>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClearStateReceiptV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV4,
    pub origin: String,
    pub scope: String,
    #[serde(rename = "clearedKeyRefs", default)]
    pub cleared_key_refs: Vec<String>,
    pub status: StorageEventStatusV1,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserStorageCapabilityProbeV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "probeId")]
    pub probe_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "providerName")]
    pub provider_name: String,
    #[serde(rename = "providerVersion")]
    pub provider_version: String,
    #[serde(rename = "browserName")]
    pub browser_name: String,
    #[serde(rename = "browserVersion")]
    pub browser_version: String,
    pub origin: String,
    #[serde(rename = "networkId", default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(rename = "canStart")]
    pub can_start: bool,
    #[serde(rename = "canRetrieve")]
    pub can_retrieve: bool,
    #[serde(rename = "canUpload")]
    pub can_upload: bool,
    #[serde(rename = "canUploadFileList")]
    pub can_upload_file_list: bool,
    #[serde(rename = "canBuyStorage")]
    pub can_buy_storage: bool,
    #[serde(rename = "canReuseStorage")]
    pub can_reuse_storage: bool,
    #[serde(rename = "canResetStorage")]
    pub can_reset_storage: bool,
    #[serde(rename = "canUpdateFeed")]
    pub can_update_feed: bool,
    #[serde(rename = "canEncryptUpload")]
    pub can_encrypt_upload: bool,
    #[serde(rename = "canReportProgress")]
    pub can_report_progress: bool,
    #[serde(rename = "canUseServiceWorker")]
    pub can_use_service_worker: bool,
    #[serde(rename = "canPersistIndexedDb")]
    pub can_persist_indexed_db: bool,
    #[serde(rename = "canClearIndexedDb")]
    pub can_clear_indexed_db: bool,
    #[serde(rename = "walletProvidersDetected", default)]
    pub wallet_providers_detected: Vec<String>,
    #[serde(
        rename = "maxRecommendedUploadBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_recommended_upload_bytes: Option<u64>,
    #[serde(
        rename = "estimatedQuotaBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub estimated_quota_bytes: Option<u64>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(rename = "fallbackProviders", default)]
    pub fallback_providers: Vec<String>,
    #[serde(rename = "probedAt")]
    pub probed_at: String,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserStoragePurchaseQuoteV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "providerName")]
    pub provider_name: String,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV4,
    pub origin: String,
    #[serde(rename = "requestedBytes")]
    pub requested_bytes: u64,
    #[serde(rename = "durationSeconds")]
    pub duration_seconds: u64,
    #[serde(rename = "estimatedCost")]
    pub estimated_cost: StorageCostV1,
    #[serde(rename = "chainId", default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(rename = "networkId", default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(default)]
    pub risks: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserStoragePurchaseAuthorizationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "authorizationId")]
    pub authorization_id: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    pub origin: String,
    #[serde(rename = "walletAddress")]
    pub wallet_address: String,
    #[serde(rename = "chainId", default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(rename = "networkId", default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    pub approved: bool,
    #[serde(rename = "requestedBytes")]
    pub requested_bytes: u64,
    #[serde(rename = "durationSeconds")]
    pub duration_seconds: u64,
    #[serde(rename = "maxCost")]
    pub max_cost: StorageCostV1,
    #[serde(rename = "promptTextHash")]
    pub prompt_text_hash: String,
    #[serde(rename = "risksAccepted", default)]
    pub risks_accepted: Vec<String>,
    #[serde(rename = "approvedAt")]
    pub approved_at: String,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StorageEventActionV2 {
    Start,
    Buy,
    Reuse,
    Reset,
    Upload,
    Retrieve,
    FeedUpdate,
    ClearState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BrowserStorageEncryptionModeV1 {
    None,
    ClientSide,
    ProviderManaged,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserStorageSessionV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "providerName")]
    pub provider_name: String,
    #[serde(rename = "providerVersion")]
    pub provider_version: String,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV4,
    pub origin: String,
    #[serde(
        rename = "walletAddress",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub wallet_address: Option<String>,
    #[serde(rename = "chainId", default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(rename = "networkId", default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(rename = "batchId", default, skip_serializing_if = "Option::is_none")]
    pub batch_id: Option<String>,
    #[serde(rename = "quotaBytes")]
    pub quota_bytes: u64,
    #[serde(rename = "usedBytes")]
    pub used_bytes: u64,
    #[serde(rename = "availableBytes")]
    pub available_bytes: u64,
    #[serde(
        rename = "capabilityProbeRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub capability_probe_ref: Option<String>,
    #[serde(
        rename = "authorizationRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub authorization_ref: Option<String>,
    #[serde(
        rename = "consentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub consent_ref: Option<String>,
    #[serde(default)]
    pub permissions: Vec<BrowserStoragePermissionV1>,
    #[serde(default)]
    pub capabilities: Vec<BrowserSwarmStorageMethodV4>,
    #[serde(rename = "securityWarnings", default)]
    pub security_warnings: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(default)]
    pub status: BrowserStorageSessionStatusV1,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageEventReceiptV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    pub action: StorageEventActionV2,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "providerName")]
    pub provider_name: String,
    #[serde(rename = "providerVersion")]
    pub provider_version: String,
    pub origin: String,
    #[serde(
        rename = "walletAddress",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub wallet_address: Option<String>,
    #[serde(rename = "chainId", default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(rename = "networkId", default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(rename = "feedTopic", default, skip_serializing_if = "Option::is_none")]
    pub feed_topic: Option<String>,
    #[serde(
        rename = "contentHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_hash: Option<String>,
    #[serde(rename = "byteSize")]
    pub byte_size: u64,
    #[serde(rename = "batchId", default, skip_serializing_if = "Option::is_none")]
    pub batch_id: Option<String>,
    #[serde(rename = "encryptionMode")]
    pub encryption_mode: BrowserStorageEncryptionModeV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<StorageTransferMetricsV1>,
    #[serde(rename = "consentId", default, skip_serializing_if = "Option::is_none")]
    pub consent_id: Option<String>,
    #[serde(
        rename = "authorizationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub authorization_id: Option<String>,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<SwarmAiErrorV1>,
    pub status: StorageEventStatusV1,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserStorageStateEntryV1 {
    #[serde(rename = "stateKind")]
    pub state_kind: String,
    #[serde(rename = "keyRef")]
    pub key_ref: String,
    pub sensitive: bool,
    pub clearable: bool,
    #[serde(rename = "sizeBytes", default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserStorageStateReportV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "reportId")]
    pub report_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    pub origin: String,
    #[serde(
        rename = "walletAddress",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub wallet_address: Option<String>,
    #[serde(rename = "indexedDbEntries", default)]
    pub indexed_db_entries: Vec<BrowserStorageStateEntryV1>,
    #[serde(rename = "serviceWorkerScopes", default)]
    pub service_worker_scopes: Vec<String>,
    #[serde(rename = "activeSessionRefs", default)]
    pub active_session_refs: Vec<String>,
    #[serde(rename = "batchRefs", default)]
    pub batch_refs: Vec<String>,
    #[serde(rename = "feedOwnerKeyRefs", default)]
    pub feed_owner_key_refs: Vec<String>,
    #[serde(rename = "clearStateSupported")]
    pub clear_state_supported: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageCostV1 {
    pub amount: f64,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BrowserStorageConsentActionV1 {
    BuyStorage,
    ReuseStorage,
    ResetStorage,
    UploadFile,
    UploadCollection,
    UploadPrivateData,
    UpdateFeed,
    GrantPackageAccess,
    SendDataToRunner,
    PublishRunnerOutputs,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserStorageConsentV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "consentId")]
    pub consent_id: String,
    pub origin: String,
    pub action: BrowserStorageConsentActionV1,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV3,
    #[serde(
        rename = "walletAddress",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub wallet_address: Option<String>,
    #[serde(
        rename = "spaceBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub space_bytes: Option<u64>,
    #[serde(
        rename = "durationSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub duration_seconds: Option<u64>,
    #[serde(rename = "maxCost", default, skip_serializing_if = "Option::is_none")]
    pub max_cost: Option<StorageCostV1>,
    #[serde(rename = "allowedRefs", default)]
    pub allowed_refs: Vec<String>,
    pub accepted: bool,
    #[serde(rename = "promptTextHash")]
    pub prompt_text_hash: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BrowserStoragePermissionV1 {
    BuyStorage,
    ReuseStorage,
    ResetStorage,
    Upload,
    Retrieve,
    FeedUpdate,
    PublishPackage,
    PublishReceipt,
    PublishOutput,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserStorageSessionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV3,
    #[serde(
        rename = "providerName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub provider_name: Option<String>,
    #[serde(
        rename = "providerVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub provider_version: Option<String>,
    pub origin: String,
    #[serde(
        rename = "browserOrigin",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub browser_origin: Option<String>,
    #[serde(
        rename = "walletAddress",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub wallet_address: Option<String>,
    #[serde(rename = "chainId", default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(rename = "batchId", default, skip_serializing_if = "Option::is_none")]
    pub batch_id: Option<String>,
    #[serde(
        rename = "batchOwnerKeyRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub batch_owner_key_ref: Option<String>,
    #[serde(
        rename = "feedOwnerKeyRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub feed_owner_key_ref: Option<String>,
    #[serde(rename = "spaceId", default, skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(rename = "spaceBytes")]
    pub space_bytes: u64,
    #[serde(rename = "purchasedSize")]
    pub purchased_size: u64,
    #[serde(rename = "usedSize")]
    pub used_size: u64,
    #[serde(
        rename = "quotaEstimate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub quota_estimate: Option<BrowserStorageQuotaEstimateV1>,
    #[serde(rename = "durationSeconds")]
    pub duration_seconds: u64,
    #[serde(default)]
    pub permissions: Vec<BrowserStoragePermissionV1>,
    #[serde(default)]
    pub capabilities: Vec<BrowserSwarmStorageMethodV4>,
    #[serde(rename = "userConsentRef")]
    pub user_consent_ref: String,
    #[serde(
        rename = "consentRecord",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub consent_record: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(
        rename = "providerCompatibilityReportRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub provider_compatibility_report_ref: Option<String>,
    #[serde(rename = "securityWarnings", default)]
    pub security_warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<BrowserStorageSessionStatusV1>,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StorageEventActionV1 {
    BuyStorage,
    ReuseStorage,
    ResetStorage,
    UploadFile,
    UploadCollection,
    Retrieve,
    CreateFeed,
    UpdateFeed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StorageEventStatusV1 {
    Requested,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageEventReceiptV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "storageEventId")]
    pub storage_event_id: String,
    pub action: StorageEventActionV1,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV3,
    pub origin: String,
    #[serde(rename = "sessionRef")]
    pub session_ref: String,
    #[serde(
        rename = "walletAddress",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub wallet_address: Option<String>,
    #[serde(
        rename = "userConsentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub user_consent_ref: Option<String>,
    #[serde(rename = "inputHashes", default)]
    pub input_hashes: Vec<String>,
    #[serde(rename = "outputRefs", default)]
    pub output_refs: Vec<String>,
    #[serde(rename = "byteCount")]
    pub byte_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<StorageCostV1>,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(
        rename = "finishedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub finished_at: Option<String>,
    pub status: StorageEventStatusV1,
    #[serde(default)]
    pub errors: Vec<SwarmAiErrorV1>,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageSponsorshipV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "sponsorshipId")]
    pub sponsorship_id: String,
    pub sponsor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beneficiary: Option<String>,
    #[serde(rename = "beneficiaryOrigin")]
    pub beneficiary_origin: String,
    #[serde(rename = "providerKinds")]
    pub provider_kinds: Vec<StorageProviderKindV3>,
    #[serde(rename = "maxSpaceBytes")]
    pub max_space_bytes: u64,
    #[serde(rename = "maxDurationSeconds")]
    pub max_duration_seconds: u64,
    #[serde(rename = "maxCost", default, skip_serializing_if = "Option::is_none")]
    pub max_cost: Option<StorageCostV1>,
    #[serde(rename = "allowedActions", default)]
    pub allowed_actions: Vec<BrowserStorageConsentActionV1>,
    #[serde(rename = "allowedOrigins", default)]
    pub allowed_origins: Vec<String>,
    #[serde(rename = "allowedAssetClasses", default)]
    pub allowed_asset_classes: Vec<String>,
    #[serde(rename = "allowedNamespaces", default)]
    pub allowed_namespaces: Vec<String>,
    #[serde(rename = "settlementPolicy", default)]
    pub settlement_policy: Value,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserStorageSecurityControlKindV1 {
    ProviderConformance,
    OriginIsolation,
    SandboxedSwarmContent,
    ServiceWorkerScope,
    ServiceWorkerUpdatePolicy,
    IndexedDbOriginScope,
    IndexedDbStateVisibility,
    ClearStateControl,
    KeySeparation,
    UserConsent,
    PrivateUploadEncryption,
    PenetrationTesting,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserStorageSecurityControlStatusV1 {
    Passed,
    Warning,
    Failed,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserStorageSecurityRiskLevelV1 {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserServiceWorkerPolicyV1 {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(
        rename = "updatePolicyRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub update_policy_ref: Option<String>,
    #[serde(default)]
    pub replaceable: bool,
    #[serde(rename = "packageContentScopeAllowed", default)]
    pub package_content_scope_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserStorageSecurityAssessmentRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub provider: BrowserSwarmStorageProviderV4,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<BrowserStorageSessionV1>,
    #[serde(
        rename = "browserOrigin",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub browser_origin: Option<String>,
    #[serde(rename = "originIsolationEnabled", default)]
    pub origin_isolation_enabled: bool,
    #[serde(rename = "sandboxedSwarmContent", default)]
    pub sandboxed_swarm_content: bool,
    #[serde(rename = "indexedDbOriginScoped", default)]
    pub indexed_db_origin_scoped: bool,
    #[serde(rename = "indexedDbStateVisible", default)]
    pub indexed_db_state_visible: bool,
    #[serde(rename = "clearStateControlVisible", default)]
    pub clear_state_control_visible: bool,
    #[serde(rename = "keySeparationDeclared", default)]
    pub key_separation_declared: bool,
    #[serde(rename = "userConsentVerified", default)]
    pub user_consent_verified: bool,
    #[serde(rename = "privateUploadsExpected", default)]
    pub private_uploads_expected: bool,
    #[serde(rename = "privateUploadEncryptionAvailable", default)]
    pub private_upload_encryption_available: bool,
    #[serde(
        rename = "serviceWorkerPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub service_worker_policy: Option<BrowserServiceWorkerPolicyV1>,
    #[serde(rename = "clearStateReceiptRefs", default)]
    pub clear_state_receipt_refs: Vec<String>,
    #[serde(rename = "penetrationTestRefs", default)]
    pub penetration_test_refs: Vec<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserStorageSecurityControlV1 {
    pub control: BrowserStorageSecurityControlKindV1,
    pub status: BrowserStorageSecurityControlStatusV1,
    pub required: bool,
    pub message: String,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub remediation: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserStorageSecurityAssessmentV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "assessmentId")]
    pub assessment_id: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV4,
    #[serde(rename = "providerProfile")]
    pub provider_profile: BrowserSwarmProviderProfileV1,
    #[serde(
        rename = "browserOrigin",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub browser_origin: Option<String>,
    #[serde(
        rename = "sessionRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_ref: Option<String>,
    #[serde(rename = "riskLevel")]
    pub risk_level: BrowserStorageSecurityRiskLevelV1,
    #[serde(rename = "approvedForBrowserPublishing")]
    pub approved_for_browser_publishing: bool,
    #[serde(rename = "approvedForPrivateUploads")]
    pub approved_for_private_uploads: bool,
    #[serde(rename = "allRequiredControlsPassed")]
    pub all_required_controls_passed: bool,
    #[serde(default)]
    pub controls: Vec<BrowserStorageSecurityControlV1>,
    #[serde(default)]
    pub issues: Vec<ValidationIssue>,
    #[serde(default)]
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageContractVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectId")]
    pub object_id: String,
    #[serde(rename = "expectedObjectId")]
    pub expected_object_id: String,
    pub valid: bool,
    #[serde(default)]
    pub issues: Vec<ValidationIssue>,
    #[serde(default)]
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DownloadResponseV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub path: Option<String>,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    pub sha256: Option<String>,
    pub metrics: StorageTransferMetricsV1,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UploadResponseV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    pub pinned: bool,
    #[serde(rename = "redundancyLevel")]
    pub redundancy_level: u8,
    #[serde(rename = "postageBatchId")]
    pub postage_batch_id: Option<String>,
    pub metrics: StorageTransferMetricsV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StoredFileV1 {
    pub path: String,
    #[serde(rename = "contentRef")]
    pub content_ref: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DirectoryManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub files: Vec<StoredFileV1>,
    #[serde(rename = "totalBytes")]
    pub total_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LocalStorageInspectionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub kind: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    #[serde(rename = "fileCount")]
    pub file_count: usize,
    #[serde(default)]
    pub manifest: Option<DirectoryManifestV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LocalStorageCacheSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "objectCount")]
    pub object_count: usize,
    #[serde(rename = "manifestCount")]
    pub manifest_count: usize,
    #[serde(rename = "totalObjectBytes")]
    pub total_object_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BeeStorageConfig {
    #[serde(rename = "apiUrl")]
    pub api_url: String,
    #[serde(rename = "postageBatchId")]
    pub postage_batch_id: Option<String>,
    pub pin: bool,
    #[serde(rename = "deferredUpload")]
    pub deferred_upload: bool,
    #[serde(rename = "redundancyLevel")]
    pub redundancy_level: u8,
}

impl BeeStorageConfig {
    pub fn local(postage_batch_id: Option<String>) -> Self {
        Self {
            api_url: "http://127.0.0.1:1633".to_string(),
            postage_batch_id,
            pin: false,
            deferred_upload: true,
            redundancy_level: 0,
        }
    }

    pub fn status(&self) -> StorageStatusV1 {
        StorageStatusV1 {
            schema_version: "swarm-ai.storage.status.v1".to_string(),
            provider: "bee-http".to_string(),
            capabilities: StorageCapabilities {
                upload: self.postage_batch_id.is_some(),
                download: true,
                feeds: false,
                pinning: true,
                act: false,
                pss: false,
            },
            retry_policy: Some(bee_retry_policy()),
        }
    }
}

pub trait StorageProvider {
    fn get_status(&self) -> StorageStatusV1;
    fn download_bytes(&self, reference: &str) -> Result<DownloadResponseV1, SwarmAiErrorV1>;
    fn upload_bytes(&mut self, bytes: Vec<u8>) -> Result<UploadResponseV1, SwarmAiErrorV1>;
    fn upload_directory(&mut self, root: &Path) -> Result<UploadResponseV1, SwarmAiErrorV1>;
    fn download_manifest(&self, reference: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1>;
    fn download_file(
        &self,
        reference: &str,
        path: &str,
    ) -> Result<DownloadResponseV1, SwarmAiErrorV1>;
    fn create_feed(
        &mut self,
        topic: &str,
        owner: &str,
    ) -> Result<StorageFeedPointerV1, SwarmAiErrorV1> {
        let _ = (topic, owner);
        Err(unsupported(
            "storage provider does not support feed creation",
        ))
    }
    fn update_feed(
        &mut self,
        topic: &str,
        owner: &str,
        reference: &str,
    ) -> Result<StorageFeedUpdateResultV1, SwarmAiErrorV1> {
        let _ = (topic, owner, reference);
        Err(unsupported(
            "storage provider does not support feed updates",
        ))
    }
    fn resolve_feed(&self, feed_ref: &str) -> Result<StorageFeedResolutionV1, SwarmAiErrorV1> {
        let _ = feed_ref;
        Err(unsupported(
            "storage provider does not support feed resolution",
        ))
    }
    fn pin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        let _ = reference;
        Err(unsupported("storage provider does not support pinning"))
    }
    fn unpin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        let _ = reference;
        Err(unsupported("storage provider does not support unpinning"))
    }
}

#[derive(Debug, Clone)]
pub struct BeeHttpStorageProvider {
    config: BeeStorageConfig,
}

#[derive(Debug, Deserialize)]
struct BeeReferenceResponse {
    reference: String,
}

#[derive(Debug, Clone)]
enum BeeHttpMethod {
    Get,
    Post,
    Delete,
}

#[derive(Debug, Clone)]
struct BeeHttpRequest {
    method: BeeHttpMethod,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct BeeHttpResponse {
    status: reqwest::StatusCode,
    content_type: String,
    bytes: Vec<u8>,
}

impl BeeHttpRequest {
    fn get(url: String) -> Self {
        Self {
            method: BeeHttpMethod::Get,
            url,
            headers: Vec::new(),
            body: None,
        }
    }

    fn post(url: String) -> Self {
        Self {
            method: BeeHttpMethod::Post,
            url,
            headers: Vec::new(),
            body: None,
        }
    }

    fn delete(url: String) -> Self {
        Self {
            method: BeeHttpMethod::Delete,
            url,
            headers: Vec::new(),
            body: None,
        }
    }

    fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

impl BeeHttpResponse {
    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).to_string()
    }
}

impl BeeHttpStorageProvider {
    pub fn new(config: BeeStorageConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &BeeStorageConfig {
        &self.config
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.config.api_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    fn upload_request(&self, path: &str) -> Result<BeeHttpRequest, SwarmAiErrorV1> {
        let Some(batch_id) = self.config.postage_batch_id.as_deref() else {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "Bee uploads require a postage batch id",
            ));
        };

        Ok(BeeHttpRequest::post(self.endpoint(path))
            .header("swarm-postage-batch-id", batch_id)
            .header("swarm-pin", self.config.pin.to_string())
            .header(
                "swarm-deferred-upload",
                self.config.deferred_upload.to_string(),
            )
            .header(
                "swarm-redundancy-level",
                self.config.redundancy_level.to_string(),
            ))
    }

    fn response_error(
        &self,
        status: reqwest::StatusCode,
        body: String,
        operation: &str,
        retry_count: u32,
    ) -> SwarmAiErrorV1 {
        let code = match status.as_u16() {
            400 => ErrorCode::InvalidRequest,
            402 | 403 => ErrorCode::AccessDenied,
            404 => ErrorCode::PackageNotFound,
            _ => ErrorCode::ExecutionFailed,
        };
        SwarmAiErrorV1::new(code, format!("Bee {operation} failed with HTTP {status}"))
            .with_details(json!({ "body": body, "retryCount": retry_count }))
    }

    fn send_with_retry(
        &self,
        operation: &str,
        mut request: impl FnMut() -> Result<BeeHttpRequest, SwarmAiErrorV1>,
    ) -> Result<(BeeHttpResponse, u32), SwarmAiErrorV1> {
        let mut retry_count = 0;
        loop {
            let request = request()?;
            match send_bee_http_request(request, operation) {
                Ok(response) => {
                    if is_transient_status(response.status) && retry_count < BEE_DEFAULT_MAX_RETRIES
                    {
                        retry_count += 1;
                        sleep_before_retry(retry_count);
                        continue;
                    }
                    return Ok((response, retry_count));
                }
                Err(error) => {
                    if retry_count < BEE_DEFAULT_MAX_RETRIES {
                        retry_count += 1;
                        sleep_before_retry(retry_count);
                        continue;
                    }
                    return Err(bee_error_with_retry(error, operation, retry_count));
                }
            }
        }
    }
}

impl StorageProvider for BeeHttpStorageProvider {
    fn get_status(&self) -> StorageStatusV1 {
        self.config.status()
    }

    fn download_bytes(&self, reference: &str) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let reference = normalize_ref(reference);
        let endpoint = self.endpoint(&format!("bytes/{reference}"));
        let (response, retry_count) = self.send_with_retry("download bytes", || {
            Ok(BeeHttpRequest::get(endpoint.clone()))
        })?;
        let first_byte_ms = elapsed_ms(start);
        let status = response.status;
        if !status.is_success() {
            let body = response.body_text();
            return Err(self.response_error(status, body, "download bytes", retry_count));
        }
        let bytes = response.bytes;
        let metrics = transfer_metrics(start, first_byte_ms, bytes.len(), retry_count);
        Ok(DownloadResponseV1 {
            schema_version: "swarm-ai.storage.download.v1".to_string(),
            reference: normalized_ref(&reference),
            path: None,
            content_type: response.content_type,
            size_bytes: bytes.len(),
            sha256: Some(sha256_hex(&bytes)),
            metrics,
            bytes,
        })
    }

    fn upload_bytes(&mut self, bytes: Vec<u8>) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let size_bytes = bytes.len();
        let (response, retry_count) = self.send_with_retry("upload bytes", || {
            Ok(self
                .upload_request("bytes")?
                .header("content-type", "application/octet-stream")
                .body(bytes.clone()))
        })?;
        let first_byte_ms = elapsed_ms(start);
        let status = response.status;
        if !status.is_success() {
            let body = response.body_text();
            return Err(self.response_error(status, body, "upload bytes", retry_count));
        }
        let body = parse_bee_reference_response(&response.bytes, "upload bytes")?;
        Ok(upload_response(
            normalized_ref(&body.reference),
            size_bytes,
            self.config.pin,
            self.config.redundancy_level,
            transfer_metrics(start, first_byte_ms, size_bytes, retry_count),
        ))
    }

    fn upload_directory(&mut self, root: &Path) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let tarball = tar_directory(root)?;
        let size_bytes = tarball.len();
        let (response, retry_count) = self.send_with_retry("upload directory", || {
            Ok(self
                .upload_request("bzz")?
                .header("content-type", "application/x-tar")
                .header("swarm-collection", "true")
                .body(tarball.clone()))
        })?;
        let first_byte_ms = elapsed_ms(start);
        let status = response.status;
        if !status.is_success() {
            let body = response.body_text();
            return Err(self.response_error(status, body, "upload directory", retry_count));
        }
        let body = parse_bee_reference_response(&response.bytes, "upload directory")?;
        Ok(upload_response(
            normalized_ref(&body.reference),
            size_bytes,
            self.config.pin,
            self.config.redundancy_level,
            transfer_metrics(start, first_byte_ms, size_bytes, retry_count),
        ))
    }

    fn download_manifest(&self, _reference: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1> {
        Err(unsupported(
            "Bee manifests are virtual filesystem tries; use download_file for paths",
        ))
    }

    fn download_file(
        &self,
        reference: &str,
        path: &str,
    ) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        if !is_relative_package_path(path) {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "requested file path is not a safe relative path",
            )
            .with_details(json!({ "path": path })));
        }
        let reference_without_scheme = normalize_ref(reference);
        let endpoint = self.endpoint(&format!("bzz/{reference_without_scheme}/{path}"));
        let (response, retry_count) = self.send_with_retry("download file", || {
            Ok(BeeHttpRequest::get(endpoint.clone()))
        })?;
        let first_byte_ms = elapsed_ms(start);
        let status = response.status;
        if !status.is_success() {
            let body = response.body_text();
            return Err(self.response_error(status, body, "download file", retry_count));
        }
        let bytes = response.bytes;
        let metrics = transfer_metrics(start, first_byte_ms, bytes.len(), retry_count);
        Ok(DownloadResponseV1 {
            schema_version: "swarm-ai.storage.download.v1".to_string(),
            reference: normalized_ref(&reference_without_scheme),
            path: Some(path.to_string()),
            content_type: response.content_type,
            size_bytes: bytes.len(),
            sha256: Some(sha256_hex(&bytes)),
            metrics,
            bytes,
        })
    }

    fn pin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        let reference_without_scheme = normalize_ref(reference);
        let endpoint = self.endpoint(&format!("pins/{reference_without_scheme}"));
        let (response, retry_count) = self.send_with_retry("pin reference", || {
            Ok(BeeHttpRequest::post(endpoint.clone()))
        })?;
        let status = response.status;
        if !status.is_success() {
            let body = response.body_text();
            return Err(self.response_error(status, body, "pin reference", retry_count));
        }
        Ok(pin_result(
            normalized_ref(&reference_without_scheme),
            true,
            "bee-http",
        ))
    }

    fn unpin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        let reference_without_scheme = normalize_ref(reference);
        let endpoint = self.endpoint(&format!("pins/{reference_without_scheme}"));
        let (response, retry_count) = self.send_with_retry("unpin reference", || {
            Ok(BeeHttpRequest::delete(endpoint.clone()))
        })?;
        let status = response.status;
        if !status.is_success() {
            let body = response.body_text();
            return Err(self.response_error(status, body, "unpin reference", retry_count));
        }
        Ok(pin_result(
            normalized_ref(&reference_without_scheme),
            false,
            "bee-http",
        ))
    }
}

#[derive(Debug, Default)]
pub struct MemoryStorageProvider {
    objects: BTreeMap<String, Vec<u8>>,
    feeds: BTreeMap<String, StorageFeedPointerV1>,
    pins: BTreeSet<String>,
}

impl StorageProvider for MemoryStorageProvider {
    fn get_status(&self) -> StorageStatusV1 {
        StorageStatusV1 {
            schema_version: "swarm-ai.storage.status.v1".to_string(),
            provider: "memory".to_string(),
            capabilities: StorageCapabilities {
                upload: true,
                download: true,
                feeds: true,
                pinning: true,
                act: false,
                pss: false,
            },
            retry_policy: None,
        }
    }

    fn download_bytes(&self, reference: &str) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let Some(bytes) = self.objects.get(reference) else {
            return Err(not_found(reference));
        };
        let metrics = transfer_metrics(start, elapsed_ms(start), bytes.len(), 0);

        Ok(DownloadResponseV1 {
            schema_version: "swarm-ai.storage.download.v1".to_string(),
            reference: reference.to_string(),
            path: None,
            content_type: "application/octet-stream".to_string(),
            size_bytes: bytes.len(),
            sha256: Some(sha256_hex(bytes)),
            metrics,
            bytes: bytes.clone(),
        })
    }

    fn upload_bytes(&mut self, bytes: Vec<u8>) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let digest = sha256_hex(&bytes);
        let reference = format!("bzz://memory-bytes-{digest}");
        let size_bytes = bytes.len();
        self.objects.insert(reference.clone(), bytes);
        Ok(upload_response(
            reference,
            size_bytes,
            false,
            0,
            transfer_metrics(start, elapsed_ms(start), size_bytes, 0),
        ))
    }

    fn upload_directory(&mut self, _root: &Path) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        Err(unsupported(
            "memory provider does not support directory upload",
        ))
    }

    fn download_manifest(&self, reference: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1> {
        let response = self.download_bytes(reference)?;
        serde_json::from_slice(&response.bytes).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::InvalidManifest,
                "object is not a directory manifest",
            )
            .with_details(json!({ "ref": reference, "error": error.to_string() }))
        })
    }

    fn download_file(
        &self,
        reference: &str,
        path: &str,
    ) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let manifest = self.download_manifest(reference)?;
        let Some(file) = manifest.files.iter().find(|file| file.path == path) else {
            return Err(not_found(path));
        };
        let mut response = self.download_bytes(&file.content_ref)?;
        response.reference = reference.to_string();
        response.path = Some(path.to_string());
        response.content_type = file.content_type.clone();
        response.size_bytes = file.size_bytes;
        response.sha256 = Some(file.sha256.clone());
        response.metrics = transfer_metrics(start, elapsed_ms(start), file.size_bytes, 0);
        Ok(response)
    }

    fn create_feed(
        &mut self,
        topic: &str,
        owner: &str,
    ) -> Result<StorageFeedPointerV1, SwarmAiErrorV1> {
        validate_feed_identity(topic, owner)?;
        let feed_ref = memory_feed_ref(topic, owner);
        let pointer = StorageFeedPointerV1 {
            schema_version: "swarm-ai.storage.feed-pointer.v1".to_string(),
            feed_ref: feed_ref.clone(),
            topic: topic.to_string(),
            owner: owner.to_string(),
            target_ref: None,
            updated_at: timestamp(),
        };
        self.feeds.insert(feed_ref, pointer.clone());
        Ok(pointer)
    }

    fn update_feed(
        &mut self,
        topic: &str,
        owner: &str,
        reference: &str,
    ) -> Result<StorageFeedUpdateResultV1, SwarmAiErrorV1> {
        validate_feed_identity(topic, owner)?;
        let target_ref = normalize_target_ref(reference)?;
        let feed_ref = memory_feed_ref(topic, owner);
        let pointer = StorageFeedPointerV1 {
            schema_version: "swarm-ai.storage.feed-pointer.v1".to_string(),
            feed_ref: feed_ref.clone(),
            topic: topic.to_string(),
            owner: owner.to_string(),
            target_ref: Some(target_ref),
            updated_at: timestamp(),
        };
        self.feeds.insert(feed_ref.clone(), pointer.clone());
        Ok(StorageFeedUpdateResultV1 {
            schema_version: "swarm-ai.storage.feed-update-result.v1".to_string(),
            feed_ref,
            pointer,
        })
    }

    fn resolve_feed(&self, feed_ref: &str) -> Result<StorageFeedResolutionV1, SwarmAiErrorV1> {
        let feed_ref = normalize_memory_feed_ref(feed_ref)?;
        let Some(pointer) = self.feeds.get(&feed_ref) else {
            return Err(not_found(&feed_ref));
        };
        Ok(StorageFeedResolutionV1 {
            schema_version: "swarm-ai.storage.feed-resolution.v1".to_string(),
            feed_ref,
            pointer: pointer.clone(),
            target_ref: pointer.target_ref.clone(),
            resolved_at: timestamp(),
        })
    }

    fn pin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        let reference = normalize_target_ref(reference)?;
        self.pins.insert(reference.clone());
        Ok(pin_result(reference, true, "memory"))
    }

    fn unpin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        let reference = normalize_target_ref(reference)?;
        self.pins.remove(&reference);
        Ok(pin_result(reference, false, "memory"))
    }
}

#[derive(Debug, Clone)]
pub struct LocalDirectoryStorageProvider {
    root: PathBuf,
}

impl LocalDirectoryStorageProvider {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn inspect(&self, reference: &str) -> Result<LocalStorageInspectionV1, SwarmAiErrorV1> {
        let normalized = normalize_ref(reference);
        if let Some(hash) = normalized.strip_prefix("local-dir-") {
            let manifest = self.read_manifest_by_hash(hash)?;
            return Ok(LocalStorageInspectionV1 {
                schema_version: "swarm-ai.storage.inspect.v1".to_string(),
                reference: normalized_ref(&normalized),
                kind: "directory".to_string(),
                size_bytes: manifest.total_bytes,
                file_count: manifest.files.len(),
                manifest: Some(manifest),
            });
        }

        if let Some(hash) = normalized.strip_prefix("local-bytes-") {
            let bytes = self.read_object_by_hash(hash)?;
            return Ok(LocalStorageInspectionV1 {
                schema_version: "swarm-ai.storage.inspect.v1".to_string(),
                reference: normalized_ref(&normalized),
                kind: "bytes".to_string(),
                size_bytes: bytes.len(),
                file_count: 1,
                manifest: None,
            });
        }

        Err(not_found(reference))
    }

    pub fn cache_summary(&self) -> Result<LocalStorageCacheSummaryV1, SwarmAiErrorV1> {
        self.ensure_dirs()?;
        let object_dir = self.objects_dir();
        let manifest_dir = self.manifests_dir();
        let object_files = list_files(&object_dir)?;
        let manifest_files = list_files(&manifest_dir)?;
        let total_object_bytes = object_files
            .iter()
            .filter_map(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .sum();

        Ok(LocalStorageCacheSummaryV1 {
            schema_version: "swarm-ai.storage.cache-summary.v1".to_string(),
            root: self.root.display().to_string(),
            object_count: object_files.len(),
            manifest_count: manifest_files.len(),
            total_object_bytes,
        })
    }

    fn ensure_dirs(&self) -> Result<(), SwarmAiErrorV1> {
        fs::create_dir_all(self.objects_dir()).map_err(io_error)?;
        fs::create_dir_all(self.manifests_dir()).map_err(io_error)?;
        fs::create_dir_all(self.feeds_dir()).map_err(io_error)?;
        fs::create_dir_all(self.pins_dir()).map_err(io_error)?;
        Ok(())
    }

    fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    fn manifests_dir(&self) -> PathBuf {
        self.root.join("manifests")
    }

    fn feeds_dir(&self) -> PathBuf {
        self.root.join("feeds")
    }

    fn pins_dir(&self) -> PathBuf {
        self.root.join("pins")
    }

    fn feed_path(&self, feed_ref: &str) -> Result<PathBuf, SwarmAiErrorV1> {
        let feed_ref = normalize_local_feed_ref(feed_ref)?;
        let Some(hash) = normalize_ref(&feed_ref)
            .strip_prefix("local-feed-")
            .map(str::to_string)
        else {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "feedRef must be a local storage feed reference",
            )
            .with_details(json!({ "feedRef": feed_ref })));
        };
        Ok(self.feeds_dir().join(format!("{hash}.json")))
    }

    fn pin_path(&self, reference: &str) -> PathBuf {
        self.pins_dir()
            .join(format!("{}.json", safe_file_component(reference)))
    }

    fn write_feed_pointer(&self, pointer: &StorageFeedPointerV1) -> Result<(), SwarmAiErrorV1> {
        let path = self.feed_path(&pointer.feed_ref)?;
        fs::write(
            &path,
            serde_json::to_vec_pretty(pointer).map_err(serialization_error)?,
        )
        .map_err(io_error)
    }

    fn read_feed_pointer(&self, feed_ref: &str) -> Result<StorageFeedPointerV1, SwarmAiErrorV1> {
        let path = self.feed_path(feed_ref)?;
        let bytes = fs::read(&path).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::PackageNotFound,
                "feed pointer is not present in local storage",
            )
            .with_details(json!({ "path": path.display().to_string(), "error": error.to_string() }))
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            SwarmAiErrorV1::new(ErrorCode::InvalidManifest, "stored feed pointer is invalid")
                .with_details(
                    json!({ "path": path.display().to_string(), "error": error.to_string() }),
                )
        })
    }

    fn read_object_by_hash(&self, hash: &str) -> Result<Vec<u8>, SwarmAiErrorV1> {
        let path = self.objects_dir().join(hash);
        fs::read(&path).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::PackageNotFound,
                "object is not present in local storage",
            )
            .with_details(json!({ "path": path.display().to_string(), "error": error.to_string() }))
        })
    }

    fn read_manifest_by_hash(&self, hash: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1> {
        let path = self.manifests_dir().join(format!("{hash}.json"));
        let bytes = fs::read(&path).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::PackageNotFound,
                "manifest is not present in local storage",
            )
            .with_details(json!({ "path": path.display().to_string(), "error": error.to_string() }))
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            SwarmAiErrorV1::new(ErrorCode::InvalidManifest, "stored manifest is invalid")
                .with_details(
                    json!({ "path": path.display().to_string(), "error": error.to_string() }),
                )
        })
    }
}

impl StorageProvider for LocalDirectoryStorageProvider {
    fn get_status(&self) -> StorageStatusV1 {
        StorageStatusV1 {
            schema_version: "swarm-ai.storage.status.v1".to_string(),
            provider: "local-directory".to_string(),
            capabilities: StorageCapabilities {
                upload: true,
                download: true,
                feeds: true,
                pinning: true,
                act: false,
                pss: false,
            },
            retry_policy: None,
        }
    }

    fn download_bytes(&self, reference: &str) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let normalized = normalize_ref(reference);
        let Some(hash) = normalized.strip_prefix("local-bytes-") else {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::UnsupportedOperation,
                "reference is not a byte object",
            )
            .with_details(json!({ "ref": reference })));
        };
        let bytes = self.read_object_by_hash(hash)?;
        let metrics = transfer_metrics(start, elapsed_ms(start), bytes.len(), 0);
        Ok(DownloadResponseV1 {
            schema_version: "swarm-ai.storage.download.v1".to_string(),
            reference: normalized_ref(&normalized),
            path: None,
            content_type: "application/octet-stream".to_string(),
            size_bytes: bytes.len(),
            sha256: Some(sha256_hex(&bytes)),
            metrics,
            bytes,
        })
    }

    fn upload_bytes(&mut self, bytes: Vec<u8>) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        self.ensure_dirs()?;
        let hash = sha256_hex(&bytes);
        let path = self.objects_dir().join(&hash);
        if !path.exists() {
            fs::write(&path, &bytes).map_err(io_error)?;
        }
        Ok(upload_response(
            format!("bzz://local-bytes-{hash}"),
            bytes.len(),
            false,
            0,
            transfer_metrics(start, elapsed_ms(start), bytes.len(), 0),
        ))
    }

    fn upload_directory(&mut self, root: &Path) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        self.ensure_dirs()?;
        let mut files = Vec::new();
        for source in list_files(root)? {
            let relative = source
                .strip_prefix(root)
                .map_err(|error| {
                    SwarmAiErrorV1::new(
                        ErrorCode::ExecutionFailed,
                        "failed to resolve relative path",
                    )
                    .with_details(json!({ "error": error.to_string() }))
                })?
                .to_string_lossy()
                .replace('\\', "/");

            if !is_relative_package_path(&relative) {
                return Err(SwarmAiErrorV1::new(
                    ErrorCode::InvalidManifest,
                    "directory contains an unsafe path",
                )
                .with_details(json!({ "path": relative })));
            }

            let bytes = fs::read(&source).map_err(io_error)?;
            let upload = self.upload_bytes(bytes.clone())?;
            files.push(StoredFileV1 {
                path: relative.clone(),
                content_ref: upload.reference,
                content_type: content_type_for_path(&relative).to_string(),
                size_bytes: bytes.len(),
                sha256: sha256_hex(&bytes),
            });
        }

        files.sort_by(|left, right| left.path.cmp(&right.path));
        let total_bytes = files.iter().map(|file| file.size_bytes).sum();
        let manifest = DirectoryManifestV1 {
            schema_version: "swarm-ai.storage.directory-manifest.v1".to_string(),
            files,
            total_bytes,
        };
        let value = serde_json::to_value(&manifest).map_err(serialization_error)?;
        let manifest_hash = hash_canonical_json(&canonicalize_json(&value));
        let manifest_path = self.manifests_dir().join(format!("{manifest_hash}.json"));
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(serialization_error)?;
        if !manifest_path.exists() {
            fs::write(&manifest_path, manifest_bytes).map_err(io_error)?;
        }

        Ok(upload_response(
            format!("bzz://local-dir-{manifest_hash}"),
            total_bytes,
            false,
            0,
            transfer_metrics(start, elapsed_ms(start), total_bytes, 0),
        ))
    }

    fn download_manifest(&self, reference: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1> {
        let normalized = normalize_ref(reference);
        let Some(hash) = normalized.strip_prefix("local-dir-") else {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::UnsupportedOperation,
                "reference is not a directory manifest",
            )
            .with_details(json!({ "ref": reference })));
        };
        self.read_manifest_by_hash(hash)
    }

    fn download_file(
        &self,
        reference: &str,
        path: &str,
    ) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        if !is_relative_package_path(path) {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "requested file path is not a safe relative path",
            )
            .with_details(json!({ "path": path })));
        }
        let manifest = self.download_manifest(reference)?;
        let Some(file) = manifest.files.iter().find(|file| file.path == path) else {
            return Err(not_found(path));
        };
        let mut response = self.download_bytes(&file.content_ref)?;
        response.reference = reference.to_string();
        response.path = Some(path.to_string());
        response.content_type = file.content_type.clone();
        response.size_bytes = file.size_bytes;
        response.sha256 = Some(file.sha256.clone());
        response.metrics = transfer_metrics(start, elapsed_ms(start), file.size_bytes, 0);
        Ok(response)
    }

    fn create_feed(
        &mut self,
        topic: &str,
        owner: &str,
    ) -> Result<StorageFeedPointerV1, SwarmAiErrorV1> {
        validate_feed_identity(topic, owner)?;
        self.ensure_dirs()?;
        let feed_ref = local_feed_ref(topic, owner);
        let pointer = StorageFeedPointerV1 {
            schema_version: "swarm-ai.storage.feed-pointer.v1".to_string(),
            feed_ref: feed_ref.clone(),
            topic: topic.to_string(),
            owner: owner.to_string(),
            target_ref: None,
            updated_at: timestamp(),
        };
        self.write_feed_pointer(&pointer)?;
        Ok(pointer)
    }

    fn update_feed(
        &mut self,
        topic: &str,
        owner: &str,
        reference: &str,
    ) -> Result<StorageFeedUpdateResultV1, SwarmAiErrorV1> {
        validate_feed_identity(topic, owner)?;
        self.ensure_dirs()?;
        let target_ref = normalize_target_ref(reference)?;
        let feed_ref = local_feed_ref(topic, owner);
        let pointer = StorageFeedPointerV1 {
            schema_version: "swarm-ai.storage.feed-pointer.v1".to_string(),
            feed_ref: feed_ref.clone(),
            topic: topic.to_string(),
            owner: owner.to_string(),
            target_ref: Some(target_ref),
            updated_at: timestamp(),
        };
        self.write_feed_pointer(&pointer)?;
        Ok(StorageFeedUpdateResultV1 {
            schema_version: "swarm-ai.storage.feed-update-result.v1".to_string(),
            feed_ref,
            pointer,
        })
    }

    fn resolve_feed(&self, feed_ref: &str) -> Result<StorageFeedResolutionV1, SwarmAiErrorV1> {
        let feed_ref = normalize_local_feed_ref(feed_ref)?;
        let pointer = self.read_feed_pointer(&feed_ref)?;
        Ok(StorageFeedResolutionV1 {
            schema_version: "swarm-ai.storage.feed-resolution.v1".to_string(),
            feed_ref,
            target_ref: pointer.target_ref.clone(),
            pointer,
            resolved_at: timestamp(),
        })
    }

    fn pin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        self.ensure_dirs()?;
        let reference = normalize_target_ref(reference)?;
        let result = pin_result(reference.clone(), true, "local-directory");
        let path = self.pin_path(&reference);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&result).map_err(serialization_error)?,
        )
        .map_err(io_error)?;
        Ok(result)
    }

    fn unpin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        self.ensure_dirs()?;
        let reference = normalize_target_ref(reference)?;
        let path = self.pin_path(&reference);
        if path.exists() {
            fs::remove_file(&path).map_err(io_error)?;
        }
        Ok(pin_result(reference, false, "local-directory"))
    }
}

pub fn default_storage_provider_descriptors_v3() -> Vec<StorageProviderDescriptorV3> {
    vec![
        StorageProviderDescriptorV3 {
            schema_version: "hivemind.storage-provider-descriptor.v3".to_string(),
            provider_id: "local-dev".to_string(),
            provider_kind: StorageProviderKindV3::LocalDev,
            environment: StorageEnvironmentV3::Node,
            capabilities: vec![
                StorageProviderCapabilityV3::Retrieve,
                StorageProviderCapabilityV3::UploadBytes,
                StorageProviderCapabilityV3::UploadFile,
                StorageProviderCapabilityV3::UploadCollection,
                StorageProviderCapabilityV3::CreateFeed,
                StorageProviderCapabilityV3::UpdateFeed,
                StorageProviderCapabilityV3::ResolveFeed,
                StorageProviderCapabilityV3::Pin,
                StorageProviderCapabilityV3::Status,
            ],
            max_recommended_upload_bytes: Some(256 * 1024 * 1024),
            requires_wallet: false,
            requires_trusted_gateway: false,
            supports_progress_events: false,
            supports_resumable_upload: false,
            security_notes: vec![
                "Local development storage is not production Swarm persistence".to_string(),
            ],
        },
        StorageProviderDescriptorV3 {
            schema_version: "hivemind.storage-provider-descriptor.v3".to_string(),
            provider_id: "bee-http".to_string(),
            provider_kind: StorageProviderKindV3::BeeHttp,
            environment: StorageEnvironmentV3::Service,
            capabilities: vec![
                StorageProviderCapabilityV3::Retrieve,
                StorageProviderCapabilityV3::UploadBytes,
                StorageProviderCapabilityV3::UploadFile,
                StorageProviderCapabilityV3::UploadCollection,
                StorageProviderCapabilityV3::ReuseStorage,
                StorageProviderCapabilityV3::ResetStorage,
                StorageProviderCapabilityV3::Pin,
                StorageProviderCapabilityV3::Status,
            ],
            max_recommended_upload_bytes: Some(1024 * 1024 * 1024),
            requires_wallet: false,
            requires_trusted_gateway: false,
            supports_progress_events: false,
            supports_resumable_upload: false,
            security_notes: vec![
                "Postage batch management is supplied out-of-band by the Bee node operator"
                    .to_string(),
            ],
        },
        StorageProviderDescriptorV3 {
            schema_version: "hivemind.storage-provider-descriptor.v3".to_string(),
            provider_id: "bee-js-gateway".to_string(),
            provider_kind: StorageProviderKindV3::BeeJsGateway,
            environment: StorageEnvironmentV3::Browser,
            capabilities: vec![
                StorageProviderCapabilityV3::Retrieve,
                StorageProviderCapabilityV3::UploadBytes,
                StorageProviderCapabilityV3::UploadFile,
                StorageProviderCapabilityV3::UploadCollection,
                StorageProviderCapabilityV3::BuyStorage,
                StorageProviderCapabilityV3::ReuseStorage,
                StorageProviderCapabilityV3::ResetStorage,
                StorageProviderCapabilityV3::CreateFeed,
                StorageProviderCapabilityV3::UpdateFeed,
                StorageProviderCapabilityV3::ResolveFeed,
                StorageProviderCapabilityV3::Encrypt,
                StorageProviderCapabilityV3::AccessControl,
                StorageProviderCapabilityV3::Status,
            ],
            max_recommended_upload_bytes: Some(128 * 1024 * 1024),
            requires_wallet: true,
            requires_trusted_gateway: true,
            supports_progress_events: true,
            supports_resumable_upload: false,
            security_notes: vec![
                "Gateway trust must be disclosed and content hashes must still be verified"
                    .to_string(),
                "Require explicit wallet consent before buying storage".to_string(),
            ],
        },
        StorageProviderDescriptorV3 {
            schema_version: "hivemind.storage-provider-descriptor.v3".to_string(),
            provider_id: "weeb3-npm".to_string(),
            provider_kind: StorageProviderKindV3::Weeb3Npm,
            environment: StorageEnvironmentV3::Browser,
            capabilities: vec![
                StorageProviderCapabilityV3::Retrieve,
                StorageProviderCapabilityV3::UploadBytes,
                StorageProviderCapabilityV3::UploadFile,
                StorageProviderCapabilityV3::UploadCollection,
                StorageProviderCapabilityV3::BuyStorage,
                StorageProviderCapabilityV3::ReuseStorage,
                StorageProviderCapabilityV3::ResetStorage,
                StorageProviderCapabilityV3::CreateFeed,
                StorageProviderCapabilityV3::UpdateFeed,
                StorageProviderCapabilityV3::ResolveFeed,
                StorageProviderCapabilityV3::Encrypt,
                StorageProviderCapabilityV3::AccessControl,
                StorageProviderCapabilityV3::Status,
            ],
            max_recommended_upload_bytes: Some(64 * 1024 * 1024),
            requires_wallet: true,
            requires_trusted_gateway: false,
            supports_progress_events: true,
            supports_resumable_upload: true,
            security_notes: vec![
                "Never expose storage, batch, feed, or decryption keys to untrusted frames"
                    .to_string(),
                "Require trusted HTTPS origins for service-worker publishing flows".to_string(),
                "Record explicit consent and storage receipts for wallet-funded actions"
                    .to_string(),
            ],
        },
        StorageProviderDescriptorV3 {
            schema_version: "hivemind.storage-provider-descriptor.v3".to_string(),
            provider_id: "hosted-upload-relay".to_string(),
            provider_kind: StorageProviderKindV3::HostedUploadRelay,
            environment: StorageEnvironmentV3::Browser,
            capabilities: vec![
                StorageProviderCapabilityV3::Retrieve,
                StorageProviderCapabilityV3::UploadBytes,
                StorageProviderCapabilityV3::UploadFile,
                StorageProviderCapabilityV3::UploadCollection,
                StorageProviderCapabilityV3::Status,
            ],
            max_recommended_upload_bytes: Some(512 * 1024 * 1024),
            requires_wallet: false,
            requires_trusted_gateway: true,
            supports_progress_events: true,
            supports_resumable_upload: true,
            security_notes: vec![
                "Hosted relays improve onboarding but are less decentralized than direct browser Swarm"
                    .to_string(),
            ],
        },
    ]
}

pub fn default_browser_swarm_storage_providers_v4() -> Vec<BrowserSwarmStorageProviderV4> {
    vec![
        browser_swarm_storage_provider_v4(
            "weeb3-browser",
            "Weeb-3 Browser",
            "v4-contract",
            StorageProviderKindV4::Weeb3Browser,
            BrowserSwarmProviderProfileV1::DirectBrowserPublishing,
            StorageProviderEnvironmentV4::Browser,
            direct_browser_methods(),
            Some(64 * 1024 * 1024),
            true,
            true,
            true,
            false,
            true,
            true,
            false,
            vec!["gateway"],
            vec![
                "Never expose storage, batch, feed, or decryption keys to untrusted frames"
                    .to_string(),
                "Require trusted HTTPS origins for service-worker publishing flows".to_string(),
                "Record explicit consent and storage receipts for wallet-funded actions".to_string(),
            ],
            vec![
                "Browser memory, worker, wallet, and quota limits can prevent large uploads"
                    .to_string(),
            ],
        ),
        browser_swarm_storage_provider_v4(
            "bee-js-browser",
            "bee-js Browser",
            "v4-contract",
            StorageProviderKindV4::BeeJsBrowser,
            BrowserSwarmProviderProfileV1::DirectBrowserPublishing,
            StorageProviderEnvironmentV4::Browser,
            direct_browser_methods(),
            Some(128 * 1024 * 1024),
            true,
            false,
            true,
            true,
            true,
            true,
            true,
            vec!["gateway"],
            vec![
                "Gateway trust must be disclosed and content hashes must still be verified"
                    .to_string(),
                "Require explicit wallet consent before buying storage".to_string(),
            ],
            vec![
                "Resumable upload support depends on the selected Bee-compatible endpoint"
                    .to_string(),
            ],
        ),
        browser_swarm_storage_provider_v4(
            "gateway",
            "Verified Gateway Fallback",
            "v4-contract",
            StorageProviderKindV4::Gateway,
            BrowserSwarmProviderProfileV1::BrowserGatewayFallback,
            StorageProviderEnvironmentV4::Browser,
            vec![
                BrowserSwarmStorageMethodV4::ProbeCapabilities,
                BrowserSwarmStorageMethodV4::Retrieve,
                BrowserSwarmStorageMethodV4::Verify,
                BrowserSwarmStorageMethodV4::ClearSensitiveBrowserState,
            ],
            Some(0),
            false,
            false,
            true,
            false,
            false,
            false,
            true,
            Vec::new(),
            vec![
                "Gateway fallback is retrieval-oriented and must verify expected hashes".to_string(),
            ],
            vec!["Does not provide direct browser publishing or storage purchase".to_string()],
        ),
        browser_swarm_storage_provider_v4(
            "local-dev",
            "Local Development Storage",
            "v4-contract",
            StorageProviderKindV4::LocalDir,
            BrowserSwarmProviderProfileV1::LocalDevelopment,
            StorageProviderEnvironmentV4::LocalDev,
            local_development_methods(),
            Some(256 * 1024 * 1024),
            true,
            false,
            true,
            false,
            false,
            false,
            false,
            Vec::new(),
            vec!["Local development storage is not production Swarm persistence".to_string()],
            vec!["Use only for tests, fixtures, and offline demos".to_string()],
        ),
        browser_swarm_storage_provider_v4(
            "hosted-upload-relay",
            "Hosted Upload Relay",
            "v4-contract",
            StorageProviderKindV4::Relay,
            BrowserSwarmProviderProfileV1::UploadRelay,
            StorageProviderEnvironmentV4::Browser,
            upload_relay_methods(),
            Some(512 * 1024 * 1024),
            true,
            true,
            true,
            true,
            false,
            true,
            true,
            vec!["gateway"],
            vec![
                "Hosted relays improve onboarding but are less decentralized than direct browser Swarm"
                    .to_string(),
            ],
            vec!["Relay operators may observe metadata unless encryption is applied first".to_string()],
        ),
    ]
}

pub fn browser_swarm_provider_catalog_v4() -> BrowserSwarmProviderCatalogV4 {
    let providers = default_browser_swarm_storage_providers_v4();
    let conformance_reports = providers
        .iter()
        .map(browser_swarm_provider_conformance_report)
        .collect();
    BrowserSwarmProviderCatalogV4 {
        schema_version: "hivemind.browser-swarm-provider-catalog.v4".to_string(),
        providers,
        conformance_reports,
    }
}

pub fn browser_swarm_provider_conformance_report(
    provider: &BrowserSwarmStorageProviderV4,
) -> BrowserSwarmProviderConformanceReportV1 {
    let required_methods = required_methods_for_profile(&provider.profile);
    let supported: BTreeSet<_> = provider.capability_report.methods.iter().cloned().collect();
    let required: BTreeSet<_> = required_methods.iter().cloned().collect();
    let supported_required_methods = required
        .intersection(&supported)
        .cloned()
        .collect::<Vec<_>>();
    let missing_required_methods = required.difference(&supported).cloned().collect::<Vec<_>>();
    let upload_capable = provider
        .capability_report
        .methods
        .iter()
        .any(is_upload_method);
    let checks = vec![
        conformance_check(
            "required_methods",
            missing_required_methods.is_empty(),
            if missing_required_methods.is_empty() {
                None
            } else {
                Some("provider does not expose every method required by its profile")
            },
        ),
        conformance_check(
            "progress_events_for_large_operations",
            !upload_capable || provider.capability_report.supports_progress_events,
            Some("upload-capable browser providers must expose progress events"),
        ),
        conformance_check(
            "hash_verification",
            provider.capability_report.supports_hash_verification,
            Some("gateway and fallback paths must verify expected content hashes"),
        ),
        conformance_check(
            "wallet_semantics_are_declared",
            !provider.capability_report.supports_wallet_storage_purchase
                || provider.capability_report.requires_wallet,
            Some("wallet-funded storage purchase requires an explicit wallet requirement"),
        ),
        conformance_check(
            "session_status_available",
            !matches!(
                provider.profile,
                BrowserSwarmProviderProfileV1::DirectBrowserPublishing
                    | BrowserSwarmProviderProfileV1::LocalDevelopment
                    | BrowserSwarmProviderProfileV1::UploadRelay
            ) || provider
                .capability_report
                .methods
                .contains(&BrowserSwarmStorageMethodV4::GetSessionStatus),
            Some("session-capable providers must expose getSessionStatus"),
        ),
        conformance_check(
            "clear_sensitive_state",
            provider
                .capability_report
                .methods
                .contains(&BrowserSwarmStorageMethodV4::ClearSensitiveBrowserState),
            Some("browser providers must expose an origin-scoped clear-state path"),
        ),
        conformance_check(
            "security_warnings_present",
            !provider.capability_report.security_warnings.is_empty(),
            Some("provider must disclose security and trust limitations"),
        ),
    ];
    let mut warnings = Vec::new();
    if provider.capability_report.requires_trusted_gateway {
        warnings.push(issue(
            "$.requiresTrustedGateway",
            "Provider requires gateway trust; callers must verify hashes and disclose trust assumptions",
        ));
    }
    if matches!(
        provider.profile,
        BrowserSwarmProviderProfileV1::BrowserGatewayFallback
    ) {
        warnings.push(issue(
            "$.profile",
            "Gateway fallback is not a direct browser publishing provider",
        ));
    }
    let valid = missing_required_methods.is_empty() && checks.iter().all(|check| check.passed);
    BrowserSwarmProviderConformanceReportV1 {
        schema_version: "hivemind.browser-swarm-provider-conformance.v1".to_string(),
        provider_id: provider.provider_id.clone(),
        provider_kind: provider.provider_kind.clone(),
        profile: provider.profile.clone(),
        valid,
        required_methods,
        supported_required_methods,
        missing_required_methods,
        checks,
        warnings,
        checked_at: timestamp(),
    }
}

#[allow(clippy::too_many_arguments)]
fn browser_swarm_storage_provider_v4(
    provider_id: &str,
    provider_name: &str,
    provider_version: &str,
    provider_kind: StorageProviderKindV4,
    profile: BrowserSwarmProviderProfileV1,
    environment: StorageProviderEnvironmentV4,
    methods: Vec<BrowserSwarmStorageMethodV4>,
    max_recommended_upload_bytes: Option<u64>,
    supports_progress_events: bool,
    supports_resumable_upload: bool,
    supports_hash_verification: bool,
    supports_gateway_fallback: bool,
    supports_wallet_storage_purchase: bool,
    requires_wallet: bool,
    requires_trusted_gateway: bool,
    fallback_provider_ids: Vec<&str>,
    security_warnings: Vec<String>,
    limitations: Vec<String>,
) -> BrowserSwarmStorageProviderV4 {
    let capability_report = BrowserSwarmCapabilityReportV1 {
        schema_version: "hivemind.browser-swarm-capability-report.v1".to_string(),
        provider_id: provider_id.to_string(),
        provider_name: provider_name.to_string(),
        provider_version: provider_version.to_string(),
        provider_kind: provider_kind.clone(),
        profile: profile.clone(),
        environment: environment.clone(),
        browser_origin: None,
        methods: dedup_methods(methods),
        max_recommended_upload_bytes,
        supports_progress_events,
        supports_resumable_upload,
        supports_hash_verification,
        supports_gateway_fallback,
        supports_wallet_storage_purchase,
        requires_wallet,
        requires_trusted_gateway,
        quota_estimate: Some(BrowserStorageQuotaEstimateV1 {
            quota_bytes: max_recommended_upload_bytes,
            usage_bytes: Some(0),
            available_bytes: max_recommended_upload_bytes,
            source: "capability-probe-template".to_string(),
        }),
        peer_status: json!({ "status": "unknown_until_probe" }),
        batch_status: json!({ "status": "unknown_until_session" }),
        cache_status: json!({ "status": "provider_reported" }),
        security_warnings,
        limitations,
    };
    BrowserSwarmStorageProviderV4 {
        schema_version: "hivemind.browser-swarm-storage-provider.v4".to_string(),
        object_kind: "browser_swarm_storage_provider".to_string(),
        provider_id: provider_id.to_string(),
        provider_name: provider_name.to_string(),
        provider_version: provider_version.to_string(),
        provider_kind,
        profile: profile.clone(),
        environment,
        capability_report,
        fallback_provider_ids: fallback_provider_ids
            .into_iter()
            .map(str::to_string)
            .collect(),
        session_required: !matches!(
            profile,
            BrowserSwarmProviderProfileV1::BrowserGatewayFallback
                | BrowserSwarmProviderProfileV1::ArchiveMirror
        ),
        wallet_required: requires_wallet,
        storage_receipt_required: !matches!(
            profile,
            BrowserSwarmProviderProfileV1::BrowserGatewayFallback
                | BrowserSwarmProviderProfileV1::ArchiveMirror
        ),
    }
}

fn direct_browser_methods() -> Vec<BrowserSwarmStorageMethodV4> {
    vec![
        BrowserSwarmStorageMethodV4::ProbeCapabilities,
        BrowserSwarmStorageMethodV4::ConnectWallet,
        BrowserSwarmStorageMethodV4::BuyStorage,
        BrowserSwarmStorageMethodV4::ReuseStorage,
        BrowserSwarmStorageMethodV4::ResetStorage,
        BrowserSwarmStorageMethodV4::UploadBlob,
        BrowserSwarmStorageMethodV4::UploadFiles,
        BrowserSwarmStorageMethodV4::UploadJson,
        BrowserSwarmStorageMethodV4::UploadManifest,
        BrowserSwarmStorageMethodV4::UpdateFeed,
        BrowserSwarmStorageMethodV4::Retrieve,
        BrowserSwarmStorageMethodV4::Verify,
        BrowserSwarmStorageMethodV4::GetSessionStatus,
        BrowserSwarmStorageMethodV4::ClearSensitiveBrowserState,
    ]
}

fn local_development_methods() -> Vec<BrowserSwarmStorageMethodV4> {
    vec![
        BrowserSwarmStorageMethodV4::ProbeCapabilities,
        BrowserSwarmStorageMethodV4::ReuseStorage,
        BrowserSwarmStorageMethodV4::ResetStorage,
        BrowserSwarmStorageMethodV4::UploadBlob,
        BrowserSwarmStorageMethodV4::UploadFiles,
        BrowserSwarmStorageMethodV4::UploadJson,
        BrowserSwarmStorageMethodV4::UploadManifest,
        BrowserSwarmStorageMethodV4::UpdateFeed,
        BrowserSwarmStorageMethodV4::Retrieve,
        BrowserSwarmStorageMethodV4::Verify,
        BrowserSwarmStorageMethodV4::GetSessionStatus,
        BrowserSwarmStorageMethodV4::ClearSensitiveBrowserState,
    ]
}

fn upload_relay_methods() -> Vec<BrowserSwarmStorageMethodV4> {
    vec![
        BrowserSwarmStorageMethodV4::ProbeCapabilities,
        BrowserSwarmStorageMethodV4::UploadBlob,
        BrowserSwarmStorageMethodV4::UploadFiles,
        BrowserSwarmStorageMethodV4::UploadJson,
        BrowserSwarmStorageMethodV4::UploadManifest,
        BrowserSwarmStorageMethodV4::Retrieve,
        BrowserSwarmStorageMethodV4::Verify,
        BrowserSwarmStorageMethodV4::GetSessionStatus,
        BrowserSwarmStorageMethodV4::ClearSensitiveBrowserState,
    ]
}

fn required_methods_for_profile(
    profile: &BrowserSwarmProviderProfileV1,
) -> Vec<BrowserSwarmStorageMethodV4> {
    match profile {
        BrowserSwarmProviderProfileV1::DirectBrowserPublishing => direct_browser_methods(),
        BrowserSwarmProviderProfileV1::BrowserGatewayFallback => vec![
            BrowserSwarmStorageMethodV4::ProbeCapabilities,
            BrowserSwarmStorageMethodV4::Retrieve,
            BrowserSwarmStorageMethodV4::Verify,
            BrowserSwarmStorageMethodV4::ClearSensitiveBrowserState,
        ],
        BrowserSwarmProviderProfileV1::LocalDevelopment => local_development_methods(),
        BrowserSwarmProviderProfileV1::ServerBridge
        | BrowserSwarmProviderProfileV1::UploadRelay => upload_relay_methods(),
        BrowserSwarmProviderProfileV1::ArchiveMirror => vec![
            BrowserSwarmStorageMethodV4::ProbeCapabilities,
            BrowserSwarmStorageMethodV4::Retrieve,
            BrowserSwarmStorageMethodV4::Verify,
        ],
    }
}

fn is_upload_method(method: &BrowserSwarmStorageMethodV4) -> bool {
    matches!(
        method,
        BrowserSwarmStorageMethodV4::UploadBlob
            | BrowserSwarmStorageMethodV4::UploadFiles
            | BrowserSwarmStorageMethodV4::UploadJson
            | BrowserSwarmStorageMethodV4::UploadManifest
    )
}

fn conformance_check(
    check: &str,
    passed: bool,
    detail: Option<&str>,
) -> BrowserSwarmConformanceCheckV1 {
    BrowserSwarmConformanceCheckV1 {
        check: check.to_string(),
        passed,
        detail: detail.map(str::to_string),
    }
}

fn dedup_methods(methods: Vec<BrowserSwarmStorageMethodV4>) -> Vec<BrowserSwarmStorageMethodV4> {
    let methods = methods.into_iter().collect::<BTreeSet<_>>();
    methods.into_iter().collect()
}

fn provider_name_for_kind_v3(kind: &StorageProviderKindV3) -> &'static str {
    match kind {
        StorageProviderKindV3::LocalDev => "Local Development Storage",
        StorageProviderKindV3::BeeHttp => "Bee HTTP",
        StorageProviderKindV3::BeeJsGateway => "bee-js Browser",
        StorageProviderKindV3::Gateway => "Verified Gateway Fallback",
        StorageProviderKindV3::Weeb3Npm => "Weeb-3 Browser",
        StorageProviderKindV3::LocalBeeBridge => "Local Bee Bridge",
        StorageProviderKindV3::HostedUploadRelay => "Hosted Upload Relay",
        StorageProviderKindV3::Relay => "Relay",
        StorageProviderKindV3::ArchiveMirror => "Archive Mirror",
        StorageProviderKindV3::MockDev => "Mock Development Storage",
    }
}

fn session_capabilities_for_kind_v3(
    kind: &StorageProviderKindV3,
) -> Vec<BrowserSwarmStorageMethodV4> {
    match kind {
        StorageProviderKindV3::Weeb3Npm | StorageProviderKindV3::BeeJsGateway => {
            direct_browser_methods()
        }
        StorageProviderKindV3::HostedUploadRelay | StorageProviderKindV3::Relay => {
            upload_relay_methods()
        }
        StorageProviderKindV3::Gateway => {
            required_methods_for_profile(&BrowserSwarmProviderProfileV1::BrowserGatewayFallback)
        }
        StorageProviderKindV3::LocalDev | StorageProviderKindV3::MockDev => {
            local_development_methods()
        }
        StorageProviderKindV3::BeeHttp
        | StorageProviderKindV3::LocalBeeBridge
        | StorageProviderKindV3::ArchiveMirror => upload_relay_methods(),
    }
}

fn session_security_warnings_for_kind_v3(kind: &StorageProviderKindV3) -> Vec<String> {
    match kind {
        StorageProviderKindV3::Weeb3Npm => vec![
            "Keep wallet, batch, feed, and decryption keys origin-scoped and clearable".to_string(),
            "Require explicit consent before wallet-funded storage actions".to_string(),
        ],
        StorageProviderKindV3::BeeJsGateway | StorageProviderKindV3::Gateway => vec![
            "Gateway fallback requires content-hash verification".to_string(),
            "Do not disclose private upload metadata to untrusted endpoints".to_string(),
        ],
        StorageProviderKindV3::LocalDev | StorageProviderKindV3::MockDev => {
            vec!["Local development storage is not production Swarm persistence".to_string()]
        }
        _ => vec!["Provider-specific secrets must not be written into manifests".to_string()],
    }
}

pub fn browser_storage_consent_ref(consent_id: &str) -> String {
    format!("local://browser-storage/consent/{consent_id}")
}

pub fn browser_storage_session_ref(session_id: &str) -> String {
    format!("local://browser-storage/session/{session_id}")
}

pub fn storage_event_receipt_ref(storage_event_id: &str) -> String {
    format!("local://storage-event/{storage_event_id}")
}

pub fn browser_storage_consent(
    origin: impl Into<String>,
    action: BrowserStorageConsentActionV1,
    provider_kind: StorageProviderKindV3,
    accepted: bool,
    prompt_text: impl AsRef<[u8]>,
) -> BrowserStorageConsentV1 {
    let mut consent = BrowserStorageConsentV1 {
        schema_version: "hivemind.browser-storage-consent.v1".to_string(),
        consent_id: String::new(),
        origin: origin.into(),
        action,
        provider_kind,
        wallet_address: None,
        space_bytes: None,
        duration_seconds: None,
        max_cost: None,
        allowed_refs: Vec::new(),
        accepted,
        prompt_text_hash: format!("sha256:{}", sha256_hex(prompt_text.as_ref())),
        created_at: timestamp(),
        expires_at: None,
        signatures: Vec::new(),
    };
    consent.consent_id = canonical_browser_storage_consent_id(&consent)
        .expect("browser storage consent should serialize for id");
    consent
}

pub fn browser_storage_session(
    provider_kind: StorageProviderKindV3,
    origin: impl Into<String>,
    user_consent_ref: impl Into<String>,
    space_bytes: u64,
    duration_seconds: u64,
) -> BrowserStorageSessionV1 {
    let created_at = timestamp();
    let origin = origin.into();
    let user_consent_ref = user_consent_ref.into();
    let provider_name = provider_name_for_kind_v3(&provider_kind).to_string();
    let mut session = BrowserStorageSessionV1 {
        schema_version: "hivemind.browser-storage-session.v1".to_string(),
        session_id: String::new(),
        provider_kind: provider_kind.clone(),
        provider_name: Some(provider_name),
        provider_version: Some("v4-contract".to_string()),
        origin: origin.clone(),
        browser_origin: Some(origin),
        wallet_address: None,
        chain_id: None,
        batch_id: None,
        batch_owner_key_ref: None,
        feed_owner_key_ref: None,
        space_id: None,
        space_bytes,
        purchased_size: space_bytes,
        used_size: 0,
        quota_estimate: Some(BrowserStorageQuotaEstimateV1 {
            quota_bytes: Some(space_bytes),
            usage_bytes: Some(0),
            available_bytes: Some(space_bytes),
            source: "session-request".to_string(),
        }),
        duration_seconds,
        permissions: vec![
            BrowserStoragePermissionV1::Upload,
            BrowserStoragePermissionV1::Retrieve,
        ],
        capabilities: session_capabilities_for_kind_v3(&provider_kind),
        user_consent_ref: user_consent_ref.clone(),
        consent_record: Some(user_consent_ref),
        created_at,
        expires_at: timestamp_after_seconds(duration_seconds),
        provider_compatibility_report_ref: None,
        security_warnings: session_security_warnings_for_kind_v3(&provider_kind),
        status: Some(BrowserStorageSessionStatusV1::Active),
        signatures: Vec::new(),
    };
    session.session_id = canonical_browser_storage_session_id(&session)
        .expect("browser storage session should serialize for id");
    session
}

pub fn storage_event_receipt_for_upload(
    session: &BrowserStorageSessionV1,
    action: StorageEventActionV1,
    input_hashes: Vec<String>,
    upload: &UploadResponseV1,
) -> StorageEventReceiptV1 {
    let now = timestamp();
    let mut receipt = StorageEventReceiptV1 {
        schema_version: "hivemind.storage-event-receipt.v1".to_string(),
        storage_event_id: String::new(),
        action,
        provider_kind: session.provider_kind.clone(),
        origin: session.origin.clone(),
        session_ref: browser_storage_session_ref(&session.session_id),
        wallet_address: session.wallet_address.clone(),
        user_consent_ref: Some(session.user_consent_ref.clone()),
        input_hashes,
        output_refs: vec![upload.reference.clone()],
        byte_count: upload.size_bytes as u64,
        cost: None,
        started_at: now.clone(),
        finished_at: Some(now),
        status: StorageEventStatusV1::Succeeded,
        errors: Vec::new(),
        signatures: Vec::new(),
    };
    receipt.storage_event_id = canonical_storage_event_receipt_id(&receipt)
        .expect("storage event receipt should serialize for id");
    receipt
}

pub fn browser_storage_capability_probe_ref(probe_id: &str) -> String {
    format!("local://browser-storage/capability-probes/{probe_id}")
}

pub fn browser_storage_purchase_quote_ref(quote_id: &str) -> String {
    format!("local://browser-storage/purchase-quotes/{quote_id}")
}

pub fn browser_storage_purchase_authorization_ref(authorization_id: &str) -> String {
    format!("local://browser-storage/purchase-authorizations/{authorization_id}")
}

pub fn browser_storage_session_v2_ref(session_id: &str) -> String {
    format!("local://browser-storage/sessions-v2/{session_id}")
}

pub fn storage_event_receipt_v2_ref(receipt_id: &str) -> String {
    format!("local://browser-storage/storage-event-receipts-v2/{receipt_id}")
}

pub fn browser_storage_capability_probe(
    provider: &BrowserSwarmStorageProviderV4,
    browser_name: impl Into<String>,
    browser_version: impl Into<String>,
    origin: impl Into<String>,
    network_id: Option<String>,
    wallet_providers_detected: Vec<String>,
    estimated_quota_bytes: Option<u64>,
) -> BrowserStorageCapabilityProbeV1 {
    let methods = &provider.capability_report.methods;
    let mut probe = BrowserStorageCapabilityProbeV1 {
        schema_version: BROWSER_STORAGE_CAPABILITY_PROBE_SCHEMA_VERSION.to_string(),
        probe_id: String::new(),
        provider_id: provider.provider_id.clone(),
        provider_name: provider.provider_name.clone(),
        provider_version: provider.provider_version.clone(),
        browser_name: browser_name.into(),
        browser_version: browser_version.into(),
        origin: origin.into(),
        network_id,
        can_start: methods.contains(&BrowserSwarmStorageMethodV4::ProbeCapabilities),
        can_retrieve: methods.contains(&BrowserSwarmStorageMethodV4::Retrieve),
        can_upload: methods.iter().any(|method| {
            matches!(
                method,
                BrowserSwarmStorageMethodV4::UploadBlob
                    | BrowserSwarmStorageMethodV4::UploadFiles
                    | BrowserSwarmStorageMethodV4::UploadJson
                    | BrowserSwarmStorageMethodV4::UploadManifest
            )
        }),
        can_upload_file_list: methods.contains(&BrowserSwarmStorageMethodV4::UploadFiles),
        can_buy_storage: methods.contains(&BrowserSwarmStorageMethodV4::BuyStorage),
        can_reuse_storage: methods.contains(&BrowserSwarmStorageMethodV4::ReuseStorage),
        can_reset_storage: methods.contains(&BrowserSwarmStorageMethodV4::ResetStorage),
        can_update_feed: methods.contains(&BrowserSwarmStorageMethodV4::UpdateFeed),
        can_encrypt_upload: methods.contains(&BrowserSwarmStorageMethodV4::UploadBlob)
            || methods.contains(&BrowserSwarmStorageMethodV4::UploadFiles),
        can_report_progress: provider.capability_report.supports_progress_events,
        can_use_service_worker: matches!(
            provider.profile,
            BrowserSwarmProviderProfileV1::DirectBrowserPublishing
                | BrowserSwarmProviderProfileV1::BrowserGatewayFallback
        ),
        can_persist_indexed_db: matches!(
            provider.provider_kind,
            StorageProviderKindV4::Weeb3Browser | StorageProviderKindV4::BeeJsBrowser
        ),
        can_clear_indexed_db: methods
            .contains(&BrowserSwarmStorageMethodV4::ClearSensitiveBrowserState),
        wallet_providers_detected,
        max_recommended_upload_bytes: provider.capability_report.max_recommended_upload_bytes,
        estimated_quota_bytes,
        warnings: provider
            .capability_report
            .security_warnings
            .iter()
            .chain(provider.capability_report.limitations.iter())
            .cloned()
            .collect(),
        fallback_providers: provider.fallback_provider_ids.clone(),
        probed_at: timestamp(),
        signatures: Vec::new(),
    };
    probe.probe_id = canonical_browser_storage_capability_probe_id(&probe);
    probe
}

pub fn browser_storage_purchase_quote(
    provider: &BrowserSwarmStorageProviderV4,
    probe: &BrowserStorageCapabilityProbeV1,
    requested_bytes: u64,
    duration_seconds: u64,
    estimated_cost: StorageCostV1,
    chain_id: Option<String>,
) -> BrowserStoragePurchaseQuoteV1 {
    let mut warnings = Vec::new();
    if !probe.can_buy_storage {
        warnings.push("Provider probe does not advertise storage purchase support".to_string());
    }
    if let Some(max_bytes) = probe.max_recommended_upload_bytes
        && requested_bytes > max_bytes
    {
        warnings.push("Requested storage exceeds provider maxRecommendedUploadBytes".to_string());
    }
    let mut quote = BrowserStoragePurchaseQuoteV1 {
        schema_version: BROWSER_STORAGE_PURCHASE_QUOTE_SCHEMA_VERSION.to_string(),
        quote_id: String::new(),
        provider_id: provider.provider_id.clone(),
        provider_name: provider.provider_name.clone(),
        provider_kind: provider.provider_kind.clone(),
        origin: probe.origin.clone(),
        requested_bytes,
        duration_seconds,
        estimated_cost,
        chain_id,
        network_id: probe.network_id.clone(),
        risks: vec![
            "User wallet may reject the storage purchase".to_string(),
            "Browser quota or provider batch state can change before purchase".to_string(),
        ],
        warnings,
        created_at: timestamp(),
        expires_at: timestamp_after_seconds(600),
        signatures: Vec::new(),
    };
    quote.quote_id = canonical_browser_storage_purchase_quote_id(&quote)
        .expect("browser storage purchase quote should serialize for id");
    quote
}

pub fn browser_storage_purchase_authorization(
    quote: &BrowserStoragePurchaseQuoteV1,
    wallet_address: impl Into<String>,
    approved: bool,
    prompt_text: impl AsRef<[u8]>,
) -> BrowserStoragePurchaseAuthorizationV1 {
    let mut authorization = BrowserStoragePurchaseAuthorizationV1 {
        schema_version: BROWSER_STORAGE_PURCHASE_AUTHORIZATION_SCHEMA_VERSION.to_string(),
        authorization_id: String::new(),
        quote_id: quote.quote_id.clone(),
        provider_id: quote.provider_id.clone(),
        origin: quote.origin.clone(),
        wallet_address: wallet_address.into(),
        chain_id: quote.chain_id.clone(),
        network_id: quote.network_id.clone(),
        approved,
        requested_bytes: quote.requested_bytes,
        duration_seconds: quote.duration_seconds,
        max_cost: quote.estimated_cost.clone(),
        prompt_text_hash: format!("sha256:{}", sha256_hex(prompt_text.as_ref())),
        risks_accepted: quote.risks.clone(),
        approved_at: timestamp(),
        signatures: Vec::new(),
    };
    authorization.authorization_id =
        canonical_browser_storage_purchase_authorization_id(&authorization)
            .expect("browser storage purchase authorization should serialize for id");
    authorization
}

pub fn browser_storage_session_v2(
    provider: &BrowserSwarmStorageProviderV4,
    probe: &BrowserStorageCapabilityProbeV1,
    authorization: Option<&BrowserStoragePurchaseAuthorizationV1>,
    quota_bytes: u64,
    duration_seconds: u64,
) -> BrowserStorageSessionV2 {
    let used_bytes = 0;
    let mut permissions = Vec::new();
    if probe.can_buy_storage {
        permissions.push(BrowserStoragePermissionV1::BuyStorage);
    }
    if probe.can_reuse_storage {
        permissions.push(BrowserStoragePermissionV1::ReuseStorage);
    }
    if probe.can_reset_storage {
        permissions.push(BrowserStoragePermissionV1::ResetStorage);
    }
    if probe.can_upload {
        permissions.push(BrowserStoragePermissionV1::Upload);
    }
    if probe.can_retrieve {
        permissions.push(BrowserStoragePermissionV1::Retrieve);
    }
    if probe.can_update_feed {
        permissions.push(BrowserStoragePermissionV1::FeedUpdate);
    }
    let status = if authorization
        .map(|authorization| authorization.approved)
        .unwrap_or(true)
    {
        BrowserStorageSessionStatusV1::Active
    } else {
        BrowserStorageSessionStatusV1::Requested
    };
    let mut session = BrowserStorageSessionV2 {
        schema_version: BROWSER_STORAGE_SESSION_V2_SCHEMA_VERSION.to_string(),
        session_id: String::new(),
        provider_id: provider.provider_id.clone(),
        provider_name: provider.provider_name.clone(),
        provider_version: provider.provider_version.clone(),
        provider_kind: provider.provider_kind.clone(),
        origin: probe.origin.clone(),
        wallet_address: authorization.map(|authorization| authorization.wallet_address.clone()),
        chain_id: authorization.and_then(|authorization| authorization.chain_id.clone()),
        network_id: probe.network_id.clone(),
        batch_id: None,
        quota_bytes,
        used_bytes,
        available_bytes: quota_bytes.saturating_sub(used_bytes),
        capability_probe_ref: Some(browser_storage_capability_probe_ref(&probe.probe_id)),
        authorization_ref: authorization.map(|authorization| {
            browser_storage_purchase_authorization_ref(&authorization.authorization_id)
        }),
        consent_ref: None,
        permissions,
        capabilities: provider.capability_report.methods.clone(),
        security_warnings: probe.warnings.clone(),
        created_at: timestamp(),
        expires_at: timestamp_after_seconds(duration_seconds),
        status,
        signatures: Vec::new(),
    };
    session.session_id = canonical_browser_storage_session_v2_id(&session)
        .expect("browser storage session v2 should serialize for id");
    session
}

pub fn storage_event_receipt_v2(
    session: &BrowserStorageSessionV2,
    action: StorageEventActionV2,
    reference: Option<String>,
    content_hash: Option<String>,
    byte_size: u64,
    encryption_mode: BrowserStorageEncryptionModeV1,
    status: StorageEventStatusV1,
    error: Option<SwarmAiErrorV1>,
) -> StorageEventReceiptV2 {
    let mut warnings = Vec::new();
    if matches!(action, StorageEventActionV2::Upload)
        && !session.capabilities.iter().any(|method| {
            matches!(
                method,
                BrowserSwarmStorageMethodV4::UploadBlob
                    | BrowserSwarmStorageMethodV4::UploadFiles
                    | BrowserSwarmStorageMethodV4::UploadJson
                    | BrowserSwarmStorageMethodV4::UploadManifest
            )
        })
    {
        warnings.push("Session provider did not advertise upload support".to_string());
    }
    let mut receipt = StorageEventReceiptV2 {
        schema_version: STORAGE_EVENT_RECEIPT_V2_SCHEMA_VERSION.to_string(),
        receipt_id: String::new(),
        action,
        provider_id: session.provider_id.clone(),
        provider_name: session.provider_name.clone(),
        provider_version: session.provider_version.clone(),
        origin: session.origin.clone(),
        wallet_address: session.wallet_address.clone(),
        chain_id: session.chain_id.clone(),
        network_id: session.network_id.clone(),
        reference,
        feed_topic: None,
        content_hash,
        byte_size,
        batch_id: session.batch_id.clone(),
        encryption_mode,
        timing: Some(StorageTransferMetricsV1 {
            schema_version: "swarm-ai.storage.transfer-metrics.v1".to_string(),
            resolve_ms: 0,
            first_byte_ms: 0,
            total_ms: 0,
            size_bytes: usize::try_from(byte_size).unwrap_or(usize::MAX),
            retry_count: 0,
        }),
        consent_id: session.consent_ref.as_deref().and_then(ref_tail),
        authorization_id: session.authorization_ref.as_deref().and_then(ref_tail),
        session_id: Some(session.session_id.clone()),
        warnings,
        error,
        status,
        created_at: timestamp(),
        signatures: Vec::new(),
    };
    receipt.receipt_id = canonical_storage_event_receipt_v2_id(&receipt)
        .expect("storage event receipt v2 should serialize for id");
    receipt
}

pub fn browser_storage_state_report(
    session: &BrowserStorageSessionV2,
    indexed_db_entries: Vec<BrowserStorageStateEntryV1>,
    service_worker_scopes: Vec<String>,
) -> BrowserStorageStateReportV1 {
    let mut warnings = Vec::new();
    if indexed_db_entries
        .iter()
        .any(|entry| entry.sensitive && !entry.clearable)
    {
        warnings.push("Sensitive browser storage state includes non-clearable entries".to_string());
    }
    let mut report = BrowserStorageStateReportV1 {
        schema_version: BROWSER_STORAGE_STATE_REPORT_SCHEMA_VERSION.to_string(),
        report_id: String::new(),
        provider_id: session.provider_id.clone(),
        origin: session.origin.clone(),
        wallet_address: session.wallet_address.clone(),
        indexed_db_entries,
        service_worker_scopes,
        active_session_refs: vec![browser_storage_session_v2_ref(&session.session_id)],
        batch_refs: session.batch_id.clone().into_iter().collect(),
        feed_owner_key_refs: Vec::new(),
        clear_state_supported: session
            .capabilities
            .contains(&BrowserSwarmStorageMethodV4::ClearSensitiveBrowserState),
        warnings,
        created_at: timestamp(),
        signatures: Vec::new(),
    };
    report.report_id = canonical_browser_storage_state_report_id(&report);
    report
}

pub fn canonical_browser_storage_capability_probe_id(
    probe: &BrowserStorageCapabilityProbeV1,
) -> String {
    canonical_id(
        "browser-storage-probe",
        signing_value(probe, "probeId").expect("browser storage probe should serialize"),
    )
    .expect("browser storage probe id should serialize")
}

pub fn expected_browser_storage_capability_probe_signature(
    probe: &BrowserStorageCapabilityProbeV1,
) -> serde_json::Result<String> {
    expected_dev_signature(
        DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX,
        browser_storage_capability_probe_signing_value(probe)?,
    )
}

pub fn sign_browser_storage_capability_probe(
    probe: &mut BrowserStorageCapabilityProbeV1,
) -> serde_json::Result<String> {
    let expected_signature = expected_browser_storage_capability_probe_signature(probe)?;
    probe
        .signatures
        .retain(|value| !value.starts_with(DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX));
    probe.signatures.push(expected_signature.clone());
    probe.probe_id = canonical_browser_storage_capability_probe_id(probe);
    Ok(expected_signature)
}

pub fn verify_browser_storage_capability_probe(
    probe: &BrowserStorageCapabilityProbeV1,
) -> StorageContractVerificationV1 {
    let expected_id = canonical_browser_storage_capability_probe_id(probe);
    let expected_signature = expected_browser_storage_capability_probe_signature(probe)
        .unwrap_or_else(|_| format!("{DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX}:invalid"));
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    require_schema(
        &mut issues,
        &probe.schema_version,
        BROWSER_STORAGE_CAPABILITY_PROBE_SCHEMA_VERSION,
    );
    require_non_empty(&mut issues, "$.providerId", &probe.provider_id);
    require_non_empty(&mut issues, "$.providerName", &probe.provider_name);
    require_non_empty(&mut issues, "$.browserName", &probe.browser_name);
    require_non_empty(&mut issues, "$.origin", &probe.origin);
    if !probe.can_start && !probe.can_retrieve && !probe.can_upload {
        issues.push(issue(
            "$",
            "BrowserStorageCapabilityProbeV1 must advertise at least one usable storage capability",
        ));
    }
    verify_contract_signature(
        &probe.signatures,
        &expected_signature,
        DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX,
        "browser storage capability probe",
        &mut issues,
        &mut warnings,
    );
    verification(
        "hivemind.browser-storage-capability-probe-verification.v1",
        probe.probe_id.clone(),
        expected_id,
        expected_signature,
        issues,
        warnings,
    )
}

pub fn canonical_browser_storage_purchase_quote_id(
    quote: &BrowserStoragePurchaseQuoteV1,
) -> serde_json::Result<String> {
    canonical_id(
        "browser-storage-purchase-quote",
        browser_storage_purchase_quote_signing_value(quote)?,
    )
}

pub fn expected_browser_storage_purchase_quote_signature(
    quote: &BrowserStoragePurchaseQuoteV1,
) -> serde_json::Result<String> {
    expected_dev_signature(
        DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX,
        browser_storage_purchase_quote_signing_value(quote)?,
    )
}

pub fn sign_browser_storage_purchase_quote(
    quote: &mut BrowserStoragePurchaseQuoteV1,
) -> serde_json::Result<String> {
    let expected_signature = expected_browser_storage_purchase_quote_signature(quote)?;
    quote
        .signatures
        .retain(|value| !value.starts_with(DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX));
    quote.signatures.push(expected_signature.clone());
    quote.quote_id = canonical_browser_storage_purchase_quote_id(quote)?;
    Ok(expected_signature)
}

pub fn verify_browser_storage_purchase_quote(
    quote: &BrowserStoragePurchaseQuoteV1,
) -> StorageContractVerificationV1 {
    let expected_id = canonical_browser_storage_purchase_quote_id(quote)
        .unwrap_or_else(|_| "browser-storage-purchase-quote-invalid".to_string());
    let expected_signature = expected_browser_storage_purchase_quote_signature(quote)
        .unwrap_or_else(|_| format!("{DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX}:invalid"));
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    require_schema(
        &mut issues,
        &quote.schema_version,
        BROWSER_STORAGE_PURCHASE_QUOTE_SCHEMA_VERSION,
    );
    require_non_empty(&mut issues, "$.providerId", &quote.provider_id);
    require_non_empty(&mut issues, "$.origin", &quote.origin);
    if quote.requested_bytes == 0 {
        issues.push(issue("$.requestedBytes", "requestedBytes must be non-zero"));
    }
    if quote.duration_seconds == 0 {
        issues.push(issue(
            "$.durationSeconds",
            "durationSeconds must be non-zero",
        ));
    }
    if quote.estimated_cost.amount < 0.0 {
        issues.push(issue(
            "$.estimatedCost.amount",
            "estimatedCost.amount must not be negative",
        ));
    }
    require_non_empty(
        &mut issues,
        "$.estimatedCost.currency",
        &quote.estimated_cost.currency,
    );
    verify_contract_signature(
        &quote.signatures,
        &expected_signature,
        DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX,
        "browser storage purchase quote",
        &mut issues,
        &mut warnings,
    );
    verification(
        "hivemind.browser-storage-purchase-quote-verification.v1",
        quote.quote_id.clone(),
        expected_id,
        expected_signature,
        issues,
        warnings,
    )
}

pub fn canonical_browser_storage_purchase_authorization_id(
    authorization: &BrowserStoragePurchaseAuthorizationV1,
) -> serde_json::Result<String> {
    canonical_id(
        "browser-storage-purchase-authorization",
        browser_storage_purchase_authorization_signing_value(authorization)?,
    )
}

pub fn expected_browser_storage_purchase_authorization_signature(
    authorization: &BrowserStoragePurchaseAuthorizationV1,
) -> serde_json::Result<String> {
    expected_dev_signature(
        DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX,
        browser_storage_purchase_authorization_signing_value(authorization)?,
    )
}

pub fn sign_browser_storage_purchase_authorization(
    authorization: &mut BrowserStoragePurchaseAuthorizationV1,
) -> serde_json::Result<String> {
    let expected_signature =
        expected_browser_storage_purchase_authorization_signature(authorization)?;
    authorization
        .signatures
        .retain(|value| !value.starts_with(DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX));
    authorization.signatures.push(expected_signature.clone());
    authorization.authorization_id =
        canonical_browser_storage_purchase_authorization_id(authorization)?;
    Ok(expected_signature)
}

pub fn verify_browser_storage_purchase_authorization(
    authorization: &BrowserStoragePurchaseAuthorizationV1,
) -> StorageContractVerificationV1 {
    let expected_id = canonical_browser_storage_purchase_authorization_id(authorization)
        .unwrap_or_else(|_| "browser-storage-purchase-authorization-invalid".to_string());
    let expected_signature =
        expected_browser_storage_purchase_authorization_signature(authorization)
            .unwrap_or_else(|_| format!("{DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX}:invalid"));
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    require_schema(
        &mut issues,
        &authorization.schema_version,
        BROWSER_STORAGE_PURCHASE_AUTHORIZATION_SCHEMA_VERSION,
    );
    require_non_empty(&mut issues, "$.quoteId", &authorization.quote_id);
    require_non_empty(&mut issues, "$.providerId", &authorization.provider_id);
    require_non_empty(&mut issues, "$.origin", &authorization.origin);
    require_non_empty(
        &mut issues,
        "$.walletAddress",
        &authorization.wallet_address,
    );
    if !authorization.approved {
        warnings.push(issue(
            "$.approved",
            "Authorization was recorded as not approved; storage purchase must not proceed",
        ));
    }
    verify_contract_signature(
        &authorization.signatures,
        &expected_signature,
        DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX,
        "browser storage purchase authorization",
        &mut issues,
        &mut warnings,
    );
    verification(
        "hivemind.browser-storage-purchase-authorization-verification.v1",
        authorization.authorization_id.clone(),
        expected_id,
        expected_signature,
        issues,
        warnings,
    )
}

pub fn canonical_browser_storage_session_v2_id(
    session: &BrowserStorageSessionV2,
) -> serde_json::Result<String> {
    canonical_id(
        "browser-storage-session-v2",
        browser_storage_session_v2_signing_value(session)?,
    )
}

pub fn expected_browser_storage_session_v2_signature(
    session: &BrowserStorageSessionV2,
) -> serde_json::Result<String> {
    expected_dev_signature(
        DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX,
        browser_storage_session_v2_signing_value(session)?,
    )
}

pub fn sign_browser_storage_session_v2(
    session: &mut BrowserStorageSessionV2,
) -> serde_json::Result<String> {
    let expected_signature = expected_browser_storage_session_v2_signature(session)?;
    session
        .signatures
        .retain(|value| !value.starts_with(DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX));
    session.signatures.push(expected_signature.clone());
    session.session_id = canonical_browser_storage_session_v2_id(session)?;
    Ok(expected_signature)
}

pub fn verify_browser_storage_session_v2(
    session: &BrowserStorageSessionV2,
) -> StorageContractVerificationV1 {
    let expected_id = canonical_browser_storage_session_v2_id(session)
        .unwrap_or_else(|_| "browser-storage-session-v2-invalid".to_string());
    let expected_signature = expected_browser_storage_session_v2_signature(session)
        .unwrap_or_else(|_| format!("{DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX}:invalid"));
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    require_schema(
        &mut issues,
        &session.schema_version,
        BROWSER_STORAGE_SESSION_V2_SCHEMA_VERSION,
    );
    require_non_empty(&mut issues, "$.providerId", &session.provider_id);
    require_non_empty(&mut issues, "$.origin", &session.origin);
    if session.quota_bytes == 0 {
        issues.push(issue("$.quotaBytes", "quotaBytes must be non-zero"));
    }
    if session.used_bytes > session.quota_bytes {
        issues.push(issue("$.usedBytes", "usedBytes must not exceed quotaBytes"));
    }
    if session.available_bytes != session.quota_bytes.saturating_sub(session.used_bytes) {
        warnings.push(issue(
            "$.availableBytes",
            "availableBytes should equal quotaBytes - usedBytes",
        ));
    }
    if session.permissions.is_empty() {
        issues.push(issue(
            "$.permissions",
            "BrowserStorageSessionV2 must include scoped permissions",
        ));
    }
    verify_contract_signature(
        &session.signatures,
        &expected_signature,
        DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX,
        "browser storage session v2",
        &mut issues,
        &mut warnings,
    );
    verification(
        "hivemind.browser-storage-session-v2-verification.v1",
        session.session_id.clone(),
        expected_id,
        expected_signature,
        issues,
        warnings,
    )
}

pub fn canonical_storage_event_receipt_v2_id(
    receipt: &StorageEventReceiptV2,
) -> serde_json::Result<String> {
    canonical_id(
        "storage-event-receipt-v2",
        storage_event_receipt_v2_signing_value(receipt)?,
    )
}

pub fn expected_storage_event_receipt_v2_signature(
    receipt: &StorageEventReceiptV2,
) -> serde_json::Result<String> {
    expected_dev_signature(
        DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX,
        storage_event_receipt_v2_signing_value(receipt)?,
    )
}

pub fn sign_storage_event_receipt_v2(
    receipt: &mut StorageEventReceiptV2,
) -> serde_json::Result<String> {
    let expected_signature = expected_storage_event_receipt_v2_signature(receipt)?;
    receipt
        .signatures
        .retain(|value| !value.starts_with(DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX));
    receipt.signatures.push(expected_signature.clone());
    receipt.receipt_id = canonical_storage_event_receipt_v2_id(receipt)?;
    Ok(expected_signature)
}

pub fn verify_storage_event_receipt_v2(
    receipt: &StorageEventReceiptV2,
) -> StorageContractVerificationV1 {
    let expected_id = canonical_storage_event_receipt_v2_id(receipt)
        .unwrap_or_else(|_| "storage-event-receipt-v2-invalid".to_string());
    let expected_signature = expected_storage_event_receipt_v2_signature(receipt)
        .unwrap_or_else(|_| format!("{DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX}:invalid"));
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    require_schema(
        &mut issues,
        &receipt.schema_version,
        STORAGE_EVENT_RECEIPT_V2_SCHEMA_VERSION,
    );
    require_non_empty(&mut issues, "$.providerId", &receipt.provider_id);
    require_non_empty(&mut issues, "$.origin", &receipt.origin);
    if matches!(
        receipt.action,
        StorageEventActionV2::Upload | StorageEventActionV2::Retrieve
    ) && receipt.reference.is_none()
        && receipt.status == StorageEventStatusV1::Succeeded
    {
        issues.push(issue(
            "$.ref",
            "Succeeded upload and retrieve receipts must include a reference",
        ));
    }
    if matches!(
        receipt.action,
        StorageEventActionV2::Upload | StorageEventActionV2::Retrieve
    ) && receipt.content_hash.is_none()
    {
        warnings.push(issue(
            "$.contentHash",
            "Upload and retrieve receipts should include contentHash when possible",
        ));
    }
    if receipt.status == StorageEventStatusV1::Failed && receipt.error.is_none() {
        issues.push(issue(
            "$.error",
            "Failed StorageEventReceiptV2 must include an error",
        ));
    }
    verify_contract_signature(
        &receipt.signatures,
        &expected_signature,
        DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX,
        "storage event receipt v2",
        &mut issues,
        &mut warnings,
    );
    verification(
        "hivemind.storage-event-receipt-v2-verification.v1",
        receipt.receipt_id.clone(),
        expected_id,
        expected_signature,
        issues,
        warnings,
    )
}

pub fn canonical_browser_storage_state_report_id(report: &BrowserStorageStateReportV1) -> String {
    canonical_id(
        "browser-storage-state-report",
        signing_value(report, "reportId").expect("browser storage state report should serialize"),
    )
    .expect("browser storage state report id should serialize")
}

pub fn expected_browser_storage_state_report_signature(
    report: &BrowserStorageStateReportV1,
) -> serde_json::Result<String> {
    expected_dev_signature(
        DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX,
        browser_storage_state_report_signing_value(report)?,
    )
}

pub fn sign_browser_storage_state_report(
    report: &mut BrowserStorageStateReportV1,
) -> serde_json::Result<String> {
    let expected_signature = expected_browser_storage_state_report_signature(report)?;
    report
        .signatures
        .retain(|value| !value.starts_with(DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX));
    report.signatures.push(expected_signature.clone());
    report.report_id = canonical_browser_storage_state_report_id(report);
    Ok(expected_signature)
}

pub fn verify_browser_storage_state_report(
    report: &BrowserStorageStateReportV1,
) -> StorageContractVerificationV1 {
    let expected_id = canonical_browser_storage_state_report_id(report);
    let expected_signature = expected_browser_storage_state_report_signature(report)
        .unwrap_or_else(|_| format!("{DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX}:invalid"));
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    require_schema(
        &mut issues,
        &report.schema_version,
        BROWSER_STORAGE_STATE_REPORT_SCHEMA_VERSION,
    );
    require_non_empty(&mut issues, "$.providerId", &report.provider_id);
    require_non_empty(&mut issues, "$.origin", &report.origin);
    if report
        .indexed_db_entries
        .iter()
        .any(|entry| entry.sensitive && !entry.clearable)
    {
        warnings.push(issue(
            "$.indexedDbEntries",
            "Sensitive browser storage state includes non-clearable entries",
        ));
    }
    verify_contract_signature(
        &report.signatures,
        &expected_signature,
        DEV_BROWSER_STORAGE_V5_SIGNATURE_PREFIX,
        "browser storage state report",
        &mut issues,
        &mut warnings,
    );
    verification(
        "hivemind.browser-storage-state-report-verification.v1",
        report.report_id.clone(),
        expected_id,
        expected_signature,
        issues,
        warnings,
    )
}

pub fn canonical_browser_storage_consent_id(
    consent: &BrowserStorageConsentV1,
) -> serde_json::Result<String> {
    canonical_id(
        "storage-consent",
        browser_storage_consent_signing_value(consent)?,
    )
}

pub fn expected_browser_storage_consent_signature(
    consent: &BrowserStorageConsentV1,
) -> serde_json::Result<String> {
    expected_dev_signature(
        DEV_BROWSER_STORAGE_CONSENT_SIGNATURE_PREFIX,
        browser_storage_consent_signing_value(consent)?,
    )
}

pub fn sign_browser_storage_consent(
    consent: &mut BrowserStorageConsentV1,
) -> serde_json::Result<String> {
    let expected_signature = expected_browser_storage_consent_signature(consent)?;
    consent
        .signatures
        .retain(|value| !value.starts_with(DEV_BROWSER_STORAGE_CONSENT_SIGNATURE_PREFIX));
    consent.signatures.push(expected_signature.clone());
    consent.consent_id = canonical_browser_storage_consent_id(consent)?;
    Ok(expected_signature)
}

pub fn verify_browser_storage_consent(
    consent: &BrowserStorageConsentV1,
) -> StorageContractVerificationV1 {
    let expected_id = canonical_browser_storage_consent_id(consent)
        .unwrap_or_else(|_| "storage-consent-invalid".to_string());
    let expected_signature = expected_browser_storage_consent_signature(consent)
        .unwrap_or_else(|_| format!("{DEV_BROWSER_STORAGE_CONSENT_SIGNATURE_PREFIX}:invalid"));
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    require_schema(
        &mut issues,
        &consent.schema_version,
        "hivemind.browser-storage-consent.v1",
    );
    require_non_empty(&mut issues, "$.origin", &consent.origin);
    require_non_empty(&mut issues, "$.promptTextHash", &consent.prompt_text_hash);
    if matches!(
        consent.action,
        BrowserStorageConsentActionV1::BuyStorage
            | BrowserStorageConsentActionV1::UploadPrivateData
    ) {
        if consent.space_bytes.unwrap_or_default() == 0 {
            issues.push(issue(
                "$.spaceBytes",
                "Storage purchase or private upload consent must include non-zero spaceBytes",
            ));
        }
        if consent.duration_seconds.unwrap_or_default() == 0 {
            issues.push(issue(
                "$.durationSeconds",
                "Storage purchase or private upload consent must include non-zero durationSeconds",
            ));
        }
    }
    if !consent.accepted {
        warnings.push(issue(
            "$.accepted",
            "Consent was recorded as not accepted; action must not proceed",
        ));
    }
    verify_contract_signature(
        &consent.signatures,
        &expected_signature,
        DEV_BROWSER_STORAGE_CONSENT_SIGNATURE_PREFIX,
        "browser storage consent",
        &mut issues,
        &mut warnings,
    );
    verification(
        "hivemind.browser-storage-consent-verification.v1",
        consent.consent_id.clone(),
        expected_id,
        expected_signature,
        issues,
        warnings,
    )
}

pub fn canonical_browser_storage_session_id(
    session: &BrowserStorageSessionV1,
) -> serde_json::Result<String> {
    canonical_id(
        "storage-session",
        browser_storage_session_signing_value(session)?,
    )
}

pub fn expected_browser_storage_session_signature(
    session: &BrowserStorageSessionV1,
) -> serde_json::Result<String> {
    expected_dev_signature(
        DEV_BROWSER_STORAGE_SESSION_SIGNATURE_PREFIX,
        browser_storage_session_signing_value(session)?,
    )
}

pub fn sign_browser_storage_session(
    session: &mut BrowserStorageSessionV1,
) -> serde_json::Result<String> {
    let expected_signature = expected_browser_storage_session_signature(session)?;
    session
        .signatures
        .retain(|value| !value.starts_with(DEV_BROWSER_STORAGE_SESSION_SIGNATURE_PREFIX));
    session.signatures.push(expected_signature.clone());
    session.session_id = canonical_browser_storage_session_id(session)?;
    Ok(expected_signature)
}

pub fn verify_browser_storage_session(
    session: &BrowserStorageSessionV1,
) -> StorageContractVerificationV1 {
    let expected_id = canonical_browser_storage_session_id(session)
        .unwrap_or_else(|_| "storage-session-invalid".to_string());
    let expected_signature = expected_browser_storage_session_signature(session)
        .unwrap_or_else(|_| format!("{DEV_BROWSER_STORAGE_SESSION_SIGNATURE_PREFIX}:invalid"));
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    require_schema(
        &mut issues,
        &session.schema_version,
        "hivemind.browser-storage-session.v1",
    );
    require_non_empty(&mut issues, "$.origin", &session.origin);
    require_non_empty(&mut issues, "$.userConsentRef", &session.user_consent_ref);
    require_non_empty(&mut issues, "$.createdAt", &session.created_at);
    require_non_empty(&mut issues, "$.expiresAt", &session.expires_at);
    if session.space_bytes == 0 {
        issues.push(issue(
            "$.spaceBytes",
            "spaceBytes must be greater than zero",
        ));
    }
    if session.duration_seconds == 0 {
        issues.push(issue(
            "$.durationSeconds",
            "durationSeconds must be greater than zero",
        ));
    }
    if session.permissions.is_empty() {
        issues.push(issue(
            "$.permissions",
            "Browser storage session must include at least one permission",
        ));
    }
    if session.wallet_address.is_none()
        && matches!(
            session.provider_kind,
            StorageProviderKindV3::Weeb3Npm | StorageProviderKindV3::BeeJsGateway
        )
    {
        warnings.push(issue(
            "$.walletAddress",
            "Browser wallet-backed storage sessions usually include a wallet address",
        ));
    }
    verify_contract_signature(
        &session.signatures,
        &expected_signature,
        DEV_BROWSER_STORAGE_SESSION_SIGNATURE_PREFIX,
        "browser storage session",
        &mut issues,
        &mut warnings,
    );
    verification(
        "hivemind.browser-storage-session-verification.v1",
        session.session_id.clone(),
        expected_id,
        expected_signature,
        issues,
        warnings,
    )
}

pub fn canonical_storage_event_receipt_id(
    receipt: &StorageEventReceiptV1,
) -> serde_json::Result<String> {
    canonical_id(
        "storage-event",
        storage_event_receipt_signing_value(receipt)?,
    )
}

pub fn expected_storage_event_receipt_signature(
    receipt: &StorageEventReceiptV1,
) -> serde_json::Result<String> {
    expected_dev_signature(
        DEV_STORAGE_EVENT_RECEIPT_SIGNATURE_PREFIX,
        storage_event_receipt_signing_value(receipt)?,
    )
}

pub fn sign_storage_event_receipt(
    receipt: &mut StorageEventReceiptV1,
) -> serde_json::Result<String> {
    let expected_signature = expected_storage_event_receipt_signature(receipt)?;
    receipt
        .signatures
        .retain(|value| !value.starts_with(DEV_STORAGE_EVENT_RECEIPT_SIGNATURE_PREFIX));
    receipt.signatures.push(expected_signature.clone());
    receipt.storage_event_id = canonical_storage_event_receipt_id(receipt)?;
    Ok(expected_signature)
}

pub fn verify_storage_event_receipt(
    receipt: &StorageEventReceiptV1,
) -> StorageContractVerificationV1 {
    let expected_id = canonical_storage_event_receipt_id(receipt)
        .unwrap_or_else(|_| "storage-event-invalid".to_string());
    let expected_signature = expected_storage_event_receipt_signature(receipt)
        .unwrap_or_else(|_| format!("{DEV_STORAGE_EVENT_RECEIPT_SIGNATURE_PREFIX}:invalid"));
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    require_schema(
        &mut issues,
        &receipt.schema_version,
        "hivemind.storage-event-receipt.v1",
    );
    require_non_empty(&mut issues, "$.origin", &receipt.origin);
    require_non_empty(&mut issues, "$.sessionRef", &receipt.session_ref);
    require_non_empty(&mut issues, "$.startedAt", &receipt.started_at);
    if matches!(
        receipt.action,
        StorageEventActionV1::UploadFile | StorageEventActionV1::UploadCollection
    ) && receipt.input_hashes.is_empty()
    {
        issues.push(issue(
            "$.inputHashes",
            "Upload storage receipts must include input hashes",
        ));
    }
    if receipt.status == StorageEventStatusV1::Succeeded && receipt.output_refs.is_empty() {
        warnings.push(issue(
            "$.outputRefs",
            "Succeeded storage receipts usually include at least one output ref",
        ));
    }
    if receipt.status == StorageEventStatusV1::Failed && receipt.errors.is_empty() {
        issues.push(issue(
            "$.errors",
            "Failed storage receipts must include at least one error",
        ));
    }
    if receipt.byte_count == 0
        && matches!(
            receipt.action,
            StorageEventActionV1::UploadFile
                | StorageEventActionV1::UploadCollection
                | StorageEventActionV1::Retrieve
        )
    {
        warnings.push(issue(
            "$.byteCount",
            "Storage transfer receipt has a zero byte count",
        ));
    }
    verify_contract_signature(
        &receipt.signatures,
        &expected_signature,
        DEV_STORAGE_EVENT_RECEIPT_SIGNATURE_PREFIX,
        "storage event receipt",
        &mut issues,
        &mut warnings,
    );
    verification(
        "hivemind.storage-event-receipt-verification.v1",
        receipt.storage_event_id.clone(),
        expected_id,
        expected_signature,
        issues,
        warnings,
    )
}

pub fn storage_sponsorship_ref(sponsorship_id: &str) -> String {
    format!("local://browser-storage/sponsorship/{sponsorship_id}")
}

pub fn storage_sponsorship(
    sponsor: impl Into<String>,
    beneficiary_origin: impl Into<String>,
    provider_kinds: Vec<StorageProviderKindV3>,
    max_space_bytes: u64,
    max_duration_seconds: u64,
) -> StorageSponsorshipV1 {
    let mut sponsorship = StorageSponsorshipV1 {
        schema_version: "hivemind.storage-sponsorship.v1".to_string(),
        sponsorship_id: String::new(),
        sponsor: sponsor.into(),
        beneficiary: None,
        beneficiary_origin: beneficiary_origin.into(),
        provider_kinds,
        max_space_bytes,
        max_duration_seconds,
        max_cost: None,
        allowed_actions: vec![
            BrowserStorageConsentActionV1::BuyStorage,
            BrowserStorageConsentActionV1::ReuseStorage,
            BrowserStorageConsentActionV1::UploadFile,
            BrowserStorageConsentActionV1::UploadCollection,
            BrowserStorageConsentActionV1::UploadPrivateData,
        ],
        allowed_origins: Vec::new(),
        allowed_asset_classes: Vec::new(),
        allowed_namespaces: Vec::new(),
        settlement_policy: json!({ "mode": "sponsor_pays_storage_receipts" }),
        evidence_refs: Vec::new(),
        created_at: timestamp(),
        expires_at: None,
        signatures: Vec::new(),
    };
    sponsorship.sponsorship_id = canonical_storage_sponsorship_id(&sponsorship)
        .expect("storage sponsorship should serialize for id");
    sponsorship
}

pub fn canonical_storage_sponsorship_id(
    sponsorship: &StorageSponsorshipV1,
) -> serde_json::Result<String> {
    canonical_id(
        "storage-sponsorship",
        storage_sponsorship_signing_value(sponsorship)?,
    )
}

pub fn expected_storage_sponsorship_signature(
    sponsorship: &StorageSponsorshipV1,
) -> serde_json::Result<String> {
    expected_dev_signature(
        DEV_STORAGE_SPONSORSHIP_SIGNATURE_PREFIX,
        storage_sponsorship_signing_value(sponsorship)?,
    )
}

pub fn sign_storage_sponsorship(
    sponsorship: &mut StorageSponsorshipV1,
) -> serde_json::Result<String> {
    let expected_signature = expected_storage_sponsorship_signature(sponsorship)?;
    sponsorship
        .signatures
        .retain(|value| !value.starts_with(DEV_STORAGE_SPONSORSHIP_SIGNATURE_PREFIX));
    sponsorship.signatures.push(expected_signature.clone());
    sponsorship.sponsorship_id = canonical_storage_sponsorship_id(sponsorship)?;
    Ok(expected_signature)
}

pub fn verify_storage_sponsorship(
    sponsorship: &StorageSponsorshipV1,
) -> StorageContractVerificationV1 {
    let expected_id = canonical_storage_sponsorship_id(sponsorship)
        .unwrap_or_else(|_| "storage-sponsorship-invalid".to_string());
    let expected_signature = expected_storage_sponsorship_signature(sponsorship)
        .unwrap_or_else(|_| format!("{DEV_STORAGE_SPONSORSHIP_SIGNATURE_PREFIX}:invalid"));
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    require_schema(
        &mut issues,
        &sponsorship.schema_version,
        "hivemind.storage-sponsorship.v1",
    );
    require_non_empty(&mut issues, "$.sponsor", &sponsorship.sponsor);
    require_non_empty(
        &mut issues,
        "$.beneficiaryOrigin",
        &sponsorship.beneficiary_origin,
    );
    require_non_empty(&mut issues, "$.createdAt", &sponsorship.created_at);
    if sponsorship.provider_kinds.is_empty() {
        issues.push(issue(
            "$.providerKinds",
            "Storage sponsorship must allow at least one provider kind",
        ));
    }
    if sponsorship.max_space_bytes == 0 {
        issues.push(issue(
            "$.maxSpaceBytes",
            "Storage sponsorship must include a non-zero maxSpaceBytes",
        ));
    }
    if sponsorship.max_duration_seconds == 0 {
        issues.push(issue(
            "$.maxDurationSeconds",
            "Storage sponsorship must include a non-zero maxDurationSeconds",
        ));
    }
    if sponsorship.allowed_actions.is_empty() {
        issues.push(issue(
            "$.allowedActions",
            "Storage sponsorship must scope at least one allowed action",
        ));
    }
    if sponsorship.allowed_origins.is_empty() {
        warnings.push(issue(
            "$.allowedOrigins",
            "Storage sponsorship should scope the browser origins that may use it",
        ));
    }
    if sponsorship.allowed_asset_classes.is_empty() {
        warnings.push(issue(
            "$.allowedAssetClasses",
            "Storage sponsorship should scope the asset classes it may fund",
        ));
    }
    if sponsorship.max_cost.is_none() {
        warnings.push(issue(
            "$.maxCost",
            "Storage sponsorship has no explicit maximum cost",
        ));
    }
    if sponsorship.expires_at.is_none() {
        warnings.push(issue(
            "$.expiresAt",
            "Storage sponsorship should include an expiry time",
        ));
    }
    verify_contract_signature(
        &sponsorship.signatures,
        &expected_signature,
        DEV_STORAGE_SPONSORSHIP_SIGNATURE_PREFIX,
        "storage sponsorship",
        &mut issues,
        &mut warnings,
    );
    verification(
        "hivemind.storage-sponsorship-verification.v1",
        sponsorship.sponsorship_id.clone(),
        expected_id,
        expected_signature,
        issues,
        warnings,
    )
}

pub fn assess_browser_storage_security(
    request: BrowserStorageSecurityAssessmentRequestV1,
) -> BrowserStorageSecurityAssessmentV1 {
    let provider = request.provider;
    let session = request.session.as_ref();
    let provider_conformance = browser_swarm_provider_conformance_report(&provider);
    let browser_origin = session
        .and_then(|session| session.browser_origin.clone())
        .or_else(|| session.map(|session| session.origin.clone()))
        .or(request.browser_origin)
        .or(provider.capability_report.browser_origin.clone());
    let browser_provider = matches!(provider.environment, StorageProviderEnvironmentV4::Browser);
    let publishing_provider = matches!(
        provider.profile,
        BrowserSwarmProviderProfileV1::DirectBrowserPublishing
            | BrowserSwarmProviderProfileV1::UploadRelay
    );
    let clear_state_supported = provider
        .capability_report
        .methods
        .contains(&BrowserSwarmStorageMethodV4::ClearSensitiveBrowserState);

    let mut controls = Vec::new();
    controls.push(browser_security_control(
        BrowserStorageSecurityControlKindV1::ProviderConformance,
        provider_conformance.valid,
        true,
        if provider_conformance.valid {
            "Provider exposes the review-4 browser storage methods required by its profile"
        } else {
            "Provider conformance report has missing required methods or failed checks"
        },
        Vec::new(),
        vec!["Fix provider method/capability declarations before browser use"],
    ));

    let origin_trusted = browser_origin
        .as_deref()
        .map(is_trusted_browser_origin)
        .unwrap_or(false);
    controls.push(browser_security_control(
        BrowserStorageSecurityControlKindV1::OriginIsolation,
        !browser_provider || (request.origin_isolation_enabled && origin_trusted),
        browser_provider,
        if browser_provider {
            "Browser provider must run from an isolated HTTPS or localhost app origin"
        } else {
            "Non-browser providers do not rely on browser origin isolation"
        },
        Vec::new(),
        vec!["Use HTTPS app origins, localhost for development, and separate package content origins"],
    ));
    controls.push(browser_security_control(
        BrowserStorageSecurityControlKindV1::SandboxedSwarmContent,
        !browser_provider || request.sandboxed_swarm_content,
        browser_provider,
        if browser_provider {
            "Swarm-loaded package/content frames must be sandboxed away from storage keys"
        } else {
            "Non-browser providers do not expose Swarm-loaded frames"
        },
        Vec::new(),
        vec!["Render Swarm-loaded sites in sandboxed iframes or separate origins without storage-key delegation"],
    ));
    let service_worker_policy =
        request
            .service_worker_policy
            .unwrap_or(BrowserServiceWorkerPolicyV1 {
                enabled: false,
                scope: None,
                update_policy_ref: None,
                replaceable: false,
                package_content_scope_allowed: false,
            });
    let service_worker_scope_ok = !service_worker_policy.enabled
        || (service_worker_policy
            .scope
            .as_deref()
            .map(service_worker_scope_is_safe)
            .unwrap_or(false)
            && !service_worker_policy.package_content_scope_allowed);
    controls.push(browser_security_control(
        BrowserStorageSecurityControlKindV1::ServiceWorkerScope,
        service_worker_scope_ok,
        browser_provider && service_worker_policy.enabled,
        if service_worker_policy.enabled {
            "Service workers must be scoped to the app, not Swarm package content"
        } else {
            "Service workers are disabled for this flow"
        },
        Vec::new(),
        vec!["Use a narrow app-owned service-worker scope and never register workers from package content"],
    ));
    let service_worker_update_ok = !service_worker_policy.enabled
        || (service_worker_policy.replaceable && service_worker_policy.update_policy_ref.is_some());
    controls.push(browser_security_control(
        BrowserStorageSecurityControlKindV1::ServiceWorkerUpdatePolicy,
        service_worker_update_ok,
        browser_provider && service_worker_policy.enabled,
        if service_worker_policy.enabled {
            "Service workers must have an explicit safe update/replace policy"
        } else {
            "Service workers are disabled for this flow"
        },
        service_worker_policy
            .update_policy_ref
            .iter()
            .cloned()
            .collect(),
        vec!["Publish and review a service-worker update policy before enabling worker-backed upload paths"],
    ));
    controls.push(browser_security_control(
        BrowserStorageSecurityControlKindV1::IndexedDbOriginScope,
        !browser_provider || request.indexed_db_origin_scoped,
        browser_provider,
        if browser_provider {
            "IndexedDB-held keys, batch metadata, and cache entries must be origin-scoped"
        } else {
            "Non-browser providers do not rely on IndexedDB"
        },
        Vec::new(),
        vec!["Namespace IndexedDB by app origin and never share storage state with package-content origins"],
    ));
    controls.push(browser_security_control(
        BrowserStorageSecurityControlKindV1::IndexedDbStateVisibility,
        !browser_provider || request.indexed_db_state_visible,
        browser_provider,
        if browser_provider {
            "IndexedDB state must be visible in a browser security dashboard"
        } else {
            "Non-browser providers do not expose browser IndexedDB state"
        },
        Vec::new(),
        vec!["Show storage batches, key refs, quota, cache use, and clear-state actions to users"],
    ));
    controls.push(browser_security_control(
        BrowserStorageSecurityControlKindV1::ClearStateControl,
        !browser_provider || (clear_state_supported && request.clear_state_control_visible),
        browser_provider,
        if browser_provider {
            "Browser storage sessions must expose a user-visible origin-scoped clear-state action"
        } else {
            "Non-browser providers do not require browser clear-state controls"
        },
        request.clear_state_receipt_refs.clone(),
        vec![
            "Expose clearSensitiveBrowserState and record ClearStateReceiptV1 when state is reset",
        ],
    ));
    controls.push(browser_security_control(
        BrowserStorageSecurityControlKindV1::KeySeparation,
        !browser_provider
            || (request.key_separation_declared && session_key_refs_are_separated(session)),
        browser_provider,
        if browser_provider {
            "Wallet, postage/batch, feed/SOC publisher, and decryption keys must remain separate"
        } else {
            "Non-browser providers do not expose browser-held wallet and IndexedDB keys"
        },
        Vec::new(),
        vec!["Use distinct key refs for funds-holding wallets, batch ownership, feed publishing, and encryption"],
    ));
    let consent_ok =
        !provider.wallet_required && !request.private_uploads_expected && !publishing_provider
            || (request.user_consent_verified
                && session
                    .map(|session| !session.user_consent_ref.trim().is_empty())
                    .unwrap_or(true));
    controls.push(browser_security_control(
        BrowserStorageSecurityControlKindV1::UserConsent,
        consent_ok,
        provider.wallet_required || request.private_uploads_expected || publishing_provider,
        "Wallet, upload, feed, and private-data actions must have explicit user consent evidence",
        session
            .map(|session| vec![session.user_consent_ref.clone()])
            .unwrap_or_default(),
        vec!["Record BrowserStorageConsentV1 before wallet-funded, upload, feed, or private-data actions"],
    ));
    controls.push(browser_security_control(
        BrowserStorageSecurityControlKindV1::PrivateUploadEncryption,
        !request.private_uploads_expected || request.private_upload_encryption_available,
        request.private_uploads_expected,
        if request.private_uploads_expected {
            "Private browser uploads must offer encryption before publishing to Swarm"
        } else {
            "Private browser uploads are not expected for this flow"
        },
        Vec::new(),
        vec!["Enable client-side encryption and avoid publishing plaintext private documents"],
    ));
    controls.push(browser_security_control(
        BrowserStorageSecurityControlKindV1::PenetrationTesting,
        !(browser_provider && publishing_provider) || !request.penetration_test_refs.is_empty(),
        browser_provider && publishing_provider,
        if browser_provider && publishing_provider {
            "Production browser publishing must link penetration-test or security-review evidence"
        } else {
            "Penetration test evidence is optional for this non-publishing or non-browser provider"
        },
        request.penetration_test_refs.clone(),
        vec!["Publish a current browser storage penetration-test report before production browser publishing"],
    ));

    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if request.schema_version != BROWSER_STORAGE_SECURITY_ASSESSMENT_REQUEST_SCHEMA_VERSION {
        warnings.push(issue(
            "$.request.schemaVersion",
            format!(
                "Expected request schemaVersion to be {BROWSER_STORAGE_SECURITY_ASSESSMENT_REQUEST_SCHEMA_VERSION}"
            ),
        ));
    }
    if let Some(session) = session {
        let verification = verify_browser_storage_session(session);
        if !verification.valid {
            issues.push(issue(
                "$.session",
                "Browser storage session attached to the security assessment is not valid",
            ));
        }
    }
    for (index, control) in controls.iter().enumerate() {
        match control.status {
            BrowserStorageSecurityControlStatusV1::Failed if control.required => {
                issues.push(issue(
                    format!("$.controls[{index}].{}", "status"),
                    control.message.clone(),
                ))
            }
            BrowserStorageSecurityControlStatusV1::Failed
            | BrowserStorageSecurityControlStatusV1::Warning => warnings.push(issue(
                format!("$.controls[{index}].{}", "status"),
                control.message.clone(),
            )),
            BrowserStorageSecurityControlStatusV1::Passed
            | BrowserStorageSecurityControlStatusV1::NotApplicable => {}
        }
    }
    if clear_state_supported && request.clear_state_receipt_refs.is_empty() && browser_provider {
        warnings.push(issue(
            "$.clearStateReceiptRefs",
            "No clear-state receipt refs were supplied; dashboard should record them when users reset state",
        ));
    }
    for reference in request.evidence_refs {
        if reference.trim().is_empty() {
            issues.push(issue("$.evidenceRefs", "Evidence refs must not be empty"));
        }
    }

    let all_required_controls_passed = controls.iter().all(|control| {
        !control.required
            || matches!(
                control.status,
                BrowserStorageSecurityControlStatusV1::Passed
                    | BrowserStorageSecurityControlStatusV1::NotApplicable
            )
    });
    let risk_level = browser_security_risk_level(&controls, &issues, &warnings);
    let approved_for_browser_publishing = all_required_controls_passed
        && issues.is_empty()
        && !matches!(risk_level, BrowserStorageSecurityRiskLevelV1::Critical);
    let private_upload_control_ok = controls.iter().all(|control| {
        control.control != BrowserStorageSecurityControlKindV1::PrivateUploadEncryption
            || matches!(
                control.status,
                BrowserStorageSecurityControlStatusV1::Passed
            )
    });
    let approved_for_private_uploads = approved_for_browser_publishing
        && private_upload_control_ok
        && request.private_uploads_expected;

    let mut assessment = BrowserStorageSecurityAssessmentV1 {
        schema_version: BROWSER_STORAGE_SECURITY_ASSESSMENT_SCHEMA_VERSION.to_string(),
        assessment_id: String::new(),
        provider_id: provider.provider_id.clone(),
        provider_kind: provider.provider_kind.clone(),
        provider_profile: provider.profile.clone(),
        browser_origin,
        session_ref: session.map(|session| browser_storage_session_ref(&session.session_id)),
        risk_level,
        approved_for_browser_publishing,
        approved_for_private_uploads,
        all_required_controls_passed,
        controls,
        issues,
        warnings,
        created_at: timestamp(),
        signatures: Vec::new(),
    };
    assessment.assessment_id = canonical_browser_storage_security_assessment_id(&assessment)
        .expect("browser storage security assessment should serialize for id");
    let _ = sign_browser_storage_security_assessment(&mut assessment);
    assessment
}

pub fn canonical_browser_storage_security_assessment_id(
    assessment: &BrowserStorageSecurityAssessmentV1,
) -> serde_json::Result<String> {
    canonical_id(
        "browser-storage-security",
        browser_storage_security_assessment_signing_value(assessment)?,
    )
}

pub fn expected_browser_storage_security_assessment_signature(
    assessment: &BrowserStorageSecurityAssessmentV1,
) -> serde_json::Result<String> {
    expected_dev_signature(
        DEV_BROWSER_STORAGE_SECURITY_ASSESSMENT_SIGNATURE_PREFIX,
        browser_storage_security_assessment_signing_value(assessment)?,
    )
}

pub fn sign_browser_storage_security_assessment(
    assessment: &mut BrowserStorageSecurityAssessmentV1,
) -> serde_json::Result<String> {
    let expected_signature = expected_browser_storage_security_assessment_signature(assessment)?;
    assessment.signatures.retain(|value| {
        !value.starts_with(DEV_BROWSER_STORAGE_SECURITY_ASSESSMENT_SIGNATURE_PREFIX)
    });
    assessment.signatures.push(expected_signature.clone());
    assessment.assessment_id = canonical_browser_storage_security_assessment_id(assessment)?;
    Ok(expected_signature)
}

pub fn verify_browser_storage_security_assessment(
    assessment: &BrowserStorageSecurityAssessmentV1,
) -> StorageContractVerificationV1 {
    let expected_id = canonical_browser_storage_security_assessment_id(assessment)
        .unwrap_or_else(|_| "browser-storage-security-invalid".to_string());
    let expected_signature = expected_browser_storage_security_assessment_signature(assessment)
        .unwrap_or_else(|_| {
            format!("{DEV_BROWSER_STORAGE_SECURITY_ASSESSMENT_SIGNATURE_PREFIX}:invalid")
        });
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    require_schema(
        &mut issues,
        &assessment.schema_version,
        BROWSER_STORAGE_SECURITY_ASSESSMENT_SCHEMA_VERSION,
    );
    require_non_empty(&mut issues, "$.assessmentId", &assessment.assessment_id);
    require_non_empty(&mut issues, "$.providerId", &assessment.provider_id);
    require_non_empty(&mut issues, "$.createdAt", &assessment.created_at);
    if assessment.controls.is_empty() {
        issues.push(issue(
            "$.controls",
            "Browser storage security assessment must include controls",
        ));
    }
    let required_controls_passed = assessment.controls.iter().all(|control| {
        !control.required
            || matches!(
                control.status,
                BrowserStorageSecurityControlStatusV1::Passed
                    | BrowserStorageSecurityControlStatusV1::NotApplicable
            )
    });
    if assessment.all_required_controls_passed != required_controls_passed {
        issues.push(issue(
            "$.allRequiredControlsPassed",
            "allRequiredControlsPassed does not match the embedded controls",
        ));
    }
    if assessment.approved_for_browser_publishing && !required_controls_passed {
        issues.push(issue(
            "$.approvedForBrowserPublishing",
            "Browser publishing cannot be approved when required controls have failed",
        ));
    }
    if assessment.approved_for_private_uploads && !assessment.approved_for_browser_publishing {
        issues.push(issue(
            "$.approvedForPrivateUploads",
            "Private upload approval requires browser publishing approval",
        ));
    }
    if matches!(
        assessment.risk_level,
        BrowserStorageSecurityRiskLevelV1::Critical
    ) && assessment.approved_for_browser_publishing
    {
        issues.push(issue(
            "$.riskLevel",
            "Critical browser storage risk cannot be approved for browser publishing",
        ));
    }
    for (index, control) in assessment.controls.iter().enumerate() {
        if control.message.trim().is_empty() {
            issues.push(issue(
                format!("$.controls[{index}].message"),
                "Security control message is required",
            ));
        }
        if control.required
            && matches!(
                control.status,
                BrowserStorageSecurityControlStatusV1::Failed
            )
            && control.remediation.is_empty()
        {
            warnings.push(issue(
                format!("$.controls[{index}].remediation"),
                "Failed required controls should include remediation guidance",
            ));
        }
    }
    verify_contract_signature(
        &assessment.signatures,
        &expected_signature,
        DEV_BROWSER_STORAGE_SECURITY_ASSESSMENT_SIGNATURE_PREFIX,
        "browser storage security assessment",
        &mut issues,
        &mut warnings,
    );
    verification(
        BROWSER_STORAGE_SECURITY_ASSESSMENT_VERIFICATION_SCHEMA_VERSION,
        assessment.assessment_id.clone(),
        expected_id,
        expected_signature,
        issues,
        warnings,
    )
}

fn canonical_id(prefix: &str, value: Value) -> serde_json::Result<String> {
    let canonical = canonicalize_json(&value);
    Ok(format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonical)[..24]
    ))
}

fn expected_dev_signature(prefix: &str, value: Value) -> serde_json::Result<String> {
    let canonical = canonicalize_json(&value);
    Ok(format!(
        "{prefix}:{}",
        &hash_canonical_json(&canonical)[..32]
    ))
}

fn browser_storage_capability_probe_signing_value(
    probe: &BrowserStorageCapabilityProbeV1,
) -> serde_json::Result<Value> {
    signing_value(probe, "probeId")
}

fn browser_storage_purchase_quote_signing_value(
    quote: &BrowserStoragePurchaseQuoteV1,
) -> serde_json::Result<Value> {
    signing_value(quote, "quoteId")
}

fn browser_storage_purchase_authorization_signing_value(
    authorization: &BrowserStoragePurchaseAuthorizationV1,
) -> serde_json::Result<Value> {
    signing_value(authorization, "authorizationId")
}

fn browser_storage_session_v2_signing_value(
    session: &BrowserStorageSessionV2,
) -> serde_json::Result<Value> {
    signing_value(session, "sessionId")
}

fn storage_event_receipt_v2_signing_value(
    receipt: &StorageEventReceiptV2,
) -> serde_json::Result<Value> {
    signing_value(receipt, "receiptId")
}

fn browser_storage_state_report_signing_value(
    report: &BrowserStorageStateReportV1,
) -> serde_json::Result<Value> {
    signing_value(report, "reportId")
}

fn browser_storage_consent_signing_value(
    consent: &BrowserStorageConsentV1,
) -> serde_json::Result<Value> {
    signing_value(consent, "consentId")
}

fn browser_storage_session_signing_value(
    session: &BrowserStorageSessionV1,
) -> serde_json::Result<Value> {
    signing_value(session, "sessionId")
}

fn storage_event_receipt_signing_value(
    receipt: &StorageEventReceiptV1,
) -> serde_json::Result<Value> {
    signing_value(receipt, "storageEventId")
}

fn storage_sponsorship_signing_value(
    sponsorship: &StorageSponsorshipV1,
) -> serde_json::Result<Value> {
    signing_value(sponsorship, "sponsorshipId")
}

fn browser_storage_security_assessment_signing_value(
    assessment: &BrowserStorageSecurityAssessmentV1,
) -> serde_json::Result<Value> {
    signing_value(assessment, "assessmentId")
}

fn signing_value<T: Serialize>(value: &T, id_field: &str) -> serde_json::Result<Value> {
    let mut value = serde_json::to_value(value)?;
    if let Value::Object(ref mut object) = value {
        object.remove(id_field);
        object.remove("signatures");
    }
    Ok(value)
}

fn ref_tail(reference: &str) -> Option<String> {
    reference
        .rsplit('/')
        .next()
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn browser_security_control(
    control: BrowserStorageSecurityControlKindV1,
    passed: bool,
    required: bool,
    message: impl Into<String>,
    evidence_refs: Vec<String>,
    remediation: Vec<&str>,
) -> BrowserStorageSecurityControlV1 {
    let status = if !required {
        if passed {
            BrowserStorageSecurityControlStatusV1::NotApplicable
        } else {
            BrowserStorageSecurityControlStatusV1::Warning
        }
    } else if passed {
        BrowserStorageSecurityControlStatusV1::Passed
    } else {
        BrowserStorageSecurityControlStatusV1::Failed
    };
    BrowserStorageSecurityControlV1 {
        control,
        status,
        required,
        message: message.into(),
        evidence_refs,
        remediation: remediation.into_iter().map(str::to_string).collect(),
    }
}

fn browser_security_risk_level(
    controls: &[BrowserStorageSecurityControlV1],
    issues: &[ValidationIssue],
    warnings: &[ValidationIssue],
) -> BrowserStorageSecurityRiskLevelV1 {
    if !issues.is_empty()
        || controls.iter().any(|control| {
            control.required
                && matches!(
                    control.status,
                    BrowserStorageSecurityControlStatusV1::Failed
                )
        })
    {
        return BrowserStorageSecurityRiskLevelV1::Critical;
    }
    if controls.iter().any(|control| {
        matches!(
            control.status,
            BrowserStorageSecurityControlStatusV1::Failed
                | BrowserStorageSecurityControlStatusV1::Warning
        )
    }) {
        return BrowserStorageSecurityRiskLevelV1::High;
    }
    if !warnings.is_empty() {
        return BrowserStorageSecurityRiskLevelV1::Medium;
    }
    BrowserStorageSecurityRiskLevelV1::Low
}

fn is_trusted_browser_origin(origin: &str) -> bool {
    origin.starts_with("https://")
        || origin.starts_with("http://localhost")
        || origin.starts_with("http://127.0.0.1")
}

fn service_worker_scope_is_safe(scope: &str) -> bool {
    let scope = scope.trim();
    !scope.is_empty()
        && scope != "/"
        && !scope.contains('*')
        && !scope.starts_with("bzz://")
        && !scope.starts_with("feed://")
        && !scope.contains("/package/")
        && !scope.contains("/swarm-content/")
}

fn session_key_refs_are_separated(session: Option<&BrowserStorageSessionV1>) -> bool {
    let Some(session) = session else {
        return true;
    };
    let mut key_refs = Vec::new();
    if let Some(wallet) = &session.wallet_address {
        key_refs.push(wallet.trim().to_ascii_lowercase());
    }
    if let Some(batch_key) = &session.batch_owner_key_ref {
        key_refs.push(batch_key.trim().to_ascii_lowercase());
    }
    if let Some(feed_key) = &session.feed_owner_key_ref {
        key_refs.push(feed_key.trim().to_ascii_lowercase());
    }
    if key_refs.len() < 2 {
        return true;
    }
    let unique = key_refs.iter().collect::<BTreeSet<_>>();
    unique.len() == key_refs.len()
}

fn verification(
    schema_version: &str,
    object_id: String,
    expected_object_id: String,
    expected_signature: String,
    mut issues: Vec<ValidationIssue>,
    warnings: Vec<ValidationIssue>,
) -> StorageContractVerificationV1 {
    if object_id != expected_object_id {
        issues.push(issue(
            "$",
            "Object id does not match the canonical storage contract content",
        ));
    }
    StorageContractVerificationV1 {
        schema_version: schema_version.to_string(),
        object_id,
        expected_object_id,
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: timestamp(),
    }
}

fn verify_contract_signature(
    signatures: &[String],
    expected_signature: &str,
    signature_prefix: &str,
    label: &str,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    let scoped_signature_count = signatures
        .iter()
        .filter(|signature| signature.starts_with(signature_prefix))
        .count();
    if scoped_signature_count == 0 {
        warnings.push(issue(
            "$.signatures",
            format!("{label} has no local-dev canonical signature"),
        ));
    } else if !signatures
        .iter()
        .any(|signature| signature == expected_signature)
    {
        issues.push(issue(
            "$.signatures",
            format!("{label} signature does not match the canonical content"),
        ));
    }
}

fn require_schema(issues: &mut Vec<ValidationIssue>, actual: &str, expected: &str) {
    if actual != expected {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion {expected}, got {actual}"),
        ));
    }
}

fn require_non_empty(issues: &mut Vec<ValidationIssue>, path: &str, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value must not be empty"));
    }
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn timestamp_after_seconds(seconds: u64) -> String {
    let seconds = seconds.min(i64::MAX as u64) as i64;
    (Utc::now() + ChronoDuration::seconds(seconds)).to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub fn normalize_ref(reference: &str) -> String {
    reference
        .trim()
        .strip_prefix("bzz://")
        .unwrap_or(reference.trim())
        .to_string()
}

pub fn storage_transfer_audit_record(
    provider: impl Into<String>,
    direction: StorageTransferDirectionV1,
    reference: impl Into<String>,
    path: Option<String>,
    content_type: Option<String>,
    size_bytes: usize,
    metrics: StorageTransferMetricsV1,
) -> StorageTransferAuditRecordV1 {
    let mut record = StorageTransferAuditRecordV1 {
        schema_version: "hivemind.storage_transfer_audit_record.v1".to_string(),
        transfer_id: String::new(),
        provider: provider.into(),
        direction,
        reference: reference.into(),
        path,
        content_type,
        size_bytes,
        metrics,
        recorded_at: timestamp(),
    };
    record.transfer_id = canonical_storage_transfer_audit_record_id(&record);
    record
}

pub fn canonical_storage_transfer_audit_record_id(record: &StorageTransferAuditRecordV1) -> String {
    let mut value = serde_json::to_value(record).expect("storage transfer audit should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("transferId");
    }
    format!(
        "storage-transfer-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

pub fn write_storage_transfer_audit_record(
    audit_dir: &Path,
    record: &StorageTransferAuditRecordV1,
) -> Result<PathBuf, SwarmAiErrorV1> {
    fs::create_dir_all(audit_dir).map_err(|error| {
        SwarmAiErrorV1::new(
            ErrorCode::ExecutionFailed,
            format!("failed to create storage transfer audit dir: {error}"),
        )
    })?;
    let path = audit_dir.join(format!("{}.json", safe_file_component(&record.transfer_id)));
    fs::write(
        &path,
        serde_json::to_vec_pretty(record).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::ExecutionFailed,
                format!("failed to serialize storage transfer audit record: {error}"),
            )
        })?,
    )
    .map_err(|error| {
        SwarmAiErrorV1::new(
            ErrorCode::ExecutionFailed,
            format!("failed to write storage transfer audit record: {error}"),
        )
    })?;
    Ok(path)
}

pub fn read_storage_transfer_audit_record(
    path: &Path,
) -> Result<StorageTransferAuditRecordV1, SwarmAiErrorV1> {
    let bytes = fs::read(path).map_err(|error| {
        SwarmAiErrorV1::new(
            ErrorCode::ExecutionFailed,
            format!("failed to read storage transfer audit record: {error}"),
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            format!("failed to parse storage transfer audit record: {error}"),
        )
    })
}

pub fn list_storage_transfer_audit(
    audit_dir: &Path,
) -> Result<StorageTransferAuditSummaryV1, SwarmAiErrorV1> {
    let mut transfers = Vec::new();
    if audit_dir.exists() {
        for entry in fs::read_dir(audit_dir).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::ExecutionFailed,
                format!("failed to list storage transfer audit dir: {error}"),
            )
        })? {
            let entry = entry.map_err(|error| {
                SwarmAiErrorV1::new(
                    ErrorCode::ExecutionFailed,
                    format!("failed to read storage transfer audit entry: {error}"),
                )
            })?;
            let path = entry.path();
            let file_type = entry.file_type().map_err(|error| {
                SwarmAiErrorV1::new(
                    ErrorCode::ExecutionFailed,
                    format!("failed to read storage transfer audit entry type: {error}"),
                )
            })?;
            if file_type.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                transfers.push(read_storage_transfer_audit_record(&path)?);
            }
        }
    }
    transfers.sort_by(|left, right| {
        left.recorded_at
            .cmp(&right.recorded_at)
            .then(left.transfer_id.cmp(&right.transfer_id))
    });
    let upload_values = storage_transfer_total_ms(&transfers, StorageTransferDirectionV1::Upload);
    let download_values =
        storage_transfer_total_ms(&transfers, StorageTransferDirectionV1::Download);
    let transfer_values = transfers
        .iter()
        .map(|record| record.metrics.total_ms)
        .collect::<Vec<_>>();
    Ok(StorageTransferAuditSummaryV1 {
        schema_version: "hivemind.storage_transfer_audit_summary.v1".to_string(),
        root: audit_dir.display().to_string(),
        transfer_count: transfers.len(),
        upload_count: upload_values.len(),
        download_count: download_values.len(),
        total_size_bytes: transfers
            .iter()
            .map(|record| record.size_bytes as u64)
            .sum(),
        retry_count: transfers
            .iter()
            .map(|record| record.metrics.retry_count as u64)
            .sum(),
        with_timing_metric_count: transfer_values.len(),
        average_transfer_total_ms: average_u64(&transfer_values),
        max_transfer_total_ms: transfer_values.iter().copied().max(),
        average_upload_total_ms: average_u64(&upload_values),
        max_upload_total_ms: upload_values.iter().copied().max(),
        average_download_total_ms: average_u64(&download_values),
        max_download_total_ms: download_values.iter().copied().max(),
        transfers,
    })
}

fn normalized_ref(reference_without_scheme: &str) -> String {
    format!("bzz://{reference_without_scheme}")
}

fn upload_response(
    reference: String,
    size_bytes: usize,
    pinned: bool,
    redundancy_level: u8,
    metrics: StorageTransferMetricsV1,
) -> UploadResponseV1 {
    UploadResponseV1 {
        schema_version: "swarm-ai.storage.upload.v1".to_string(),
        reference,
        size_bytes,
        pinned,
        redundancy_level,
        postage_batch_id: None,
        metrics,
    }
}

fn transfer_metrics(
    start: Instant,
    first_byte_ms: u64,
    size_bytes: usize,
    retry_count: u32,
) -> StorageTransferMetricsV1 {
    let total_ms = elapsed_ms(start);
    StorageTransferMetricsV1 {
        schema_version: "swarm-ai.storage.transfer-metrics.v1".to_string(),
        resolve_ms: first_byte_ms,
        first_byte_ms,
        total_ms,
        size_bytes,
        retry_count,
    }
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn pin_result(reference: String, pinned: bool, provider: &str) -> StoragePinResultV1 {
    StoragePinResultV1 {
        schema_version: "swarm-ai.storage.pin-result.v1".to_string(),
        reference,
        pinned,
        provider: provider.to_string(),
        updated_at: timestamp(),
    }
}

fn local_feed_ref(topic: &str, owner: &str) -> String {
    format!("bzz://local-feed-{}", feed_hash(topic, owner))
}

fn memory_feed_ref(topic: &str, owner: &str) -> String {
    format!("bzz://memory-feed-{}", feed_hash(topic, owner))
}

fn feed_hash(topic: &str, owner: &str) -> String {
    hash_canonical_json(&canonicalize_json(&json!({
        "topic": topic,
        "owner": owner,
    })))
}

fn normalize_local_feed_ref(feed_ref: &str) -> Result<String, SwarmAiErrorV1> {
    let normalized = normalize_ref(feed_ref);
    if normalized.starts_with("local-feed-") {
        Ok(normalized_ref(&normalized))
    } else {
        Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "feedRef must be a local feed reference",
        )
        .with_details(json!({ "feedRef": feed_ref })))
    }
}

fn normalize_memory_feed_ref(feed_ref: &str) -> Result<String, SwarmAiErrorV1> {
    let normalized = normalize_ref(feed_ref);
    if normalized.starts_with("memory-feed-") {
        Ok(normalized_ref(&normalized))
    } else {
        Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "feedRef must be a memory feed reference",
        )
        .with_details(json!({ "feedRef": feed_ref })))
    }
}

fn normalize_target_ref(reference: &str) -> Result<String, SwarmAiErrorV1> {
    let normalized = normalize_ref(reference);
    if normalized.trim().is_empty() || normalized.contains('/') || normalized.contains('\\') {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "storage reference must be a non-empty bzz:// reference",
        )
        .with_details(json!({ "ref": reference })));
    }
    Ok(normalized_ref(&normalized))
}

fn validate_feed_identity(topic: &str, owner: &str) -> Result<(), SwarmAiErrorV1> {
    if topic.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "feed topic is required",
        ));
    }
    if owner.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "feed owner is required",
        ));
    }
    Ok(())
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn storage_transfer_total_ms(
    transfers: &[StorageTransferAuditRecordV1],
    direction: StorageTransferDirectionV1,
) -> Vec<u64> {
    transfers
        .iter()
        .filter(|record| record.direction == direction)
        .map(|record| record.metrics.total_ms)
        .collect()
}

fn average_u64(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64)
    }
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

fn list_files(root: &Path) -> Result<Vec<PathBuf>, SwarmAiErrorV1> {
    let mut files = Vec::new();
    if !root.exists() {
        return Ok(files);
    }
    collect_files(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), SwarmAiErrorV1> {
    for entry in fs::read_dir(path).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(io_error)?;
        if file_type.is_dir() {
            collect_files(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn tar_directory(root: &Path) -> Result<Vec<u8>, SwarmAiErrorV1> {
    let mut buffer = Vec::new();
    {
        let cursor = Cursor::new(&mut buffer);
        let mut builder = tar::Builder::new(cursor);
        for source in list_files(root)? {
            let relative = source
                .strip_prefix(root)
                .map_err(|error| {
                    SwarmAiErrorV1::new(
                        ErrorCode::ExecutionFailed,
                        "failed to resolve relative path",
                    )
                    .with_details(json!({ "error": error.to_string() }))
                })?
                .to_string_lossy()
                .replace('\\', "/");
            if !is_relative_package_path(&relative) {
                return Err(SwarmAiErrorV1::new(
                    ErrorCode::InvalidManifest,
                    "directory contains an unsafe path",
                )
                .with_details(json!({ "path": relative })));
            }
            builder
                .append_path_with_name(&source, &relative)
                .map_err(io_error)?;
        }
        builder.finish().map_err(io_error)?;
    }
    Ok(buffer)
}

fn is_relative_package_path(path: &str) -> bool {
    if path.trim().is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains(':')
        || path.contains('\\')
    {
        return false;
    }
    !path.split('/').any(|part| part == ".." || part.is_empty())
}

fn content_type_for_path(path: &str) -> &'static str {
    if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".txt") || path.ends_with(".md") {
        "text/plain; charset=utf-8"
    } else if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".wasm") {
        "application/wasm"
    } else {
        "application/octet-stream"
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn io_error(error: std::io::Error) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(ErrorCode::ExecutionFailed, "local storage I/O failed")
        .with_details(json!({ "error": error.to_string() }))
}

fn serialization_error(error: serde_json::Error) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(
        ErrorCode::ExecutionFailed,
        "local storage serialization failed",
    )
    .with_details(json!({ "error": error.to_string() }))
}

fn http_error(error: reqwest::Error) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(ErrorCode::ExecutionFailed, "Bee HTTP request failed")
        .with_details(json!({ "error": error.to_string() }))
}

fn send_bee_http_request(
    request: BeeHttpRequest,
    operation: &str,
) -> Result<BeeHttpResponse, SwarmAiErrorV1> {
    let operation = operation.to_string();
    let handle = thread::Builder::new()
        .name(format!("bee-http-{operation}"))
        .spawn(move || {
            let client = reqwest::blocking::Client::new();
            let mut builder = match request.method {
                BeeHttpMethod::Get => client.get(&request.url),
                BeeHttpMethod::Post => client.post(&request.url),
                BeeHttpMethod::Delete => client.delete(&request.url),
            };
            for (name, value) in &request.headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            if let Some(body) = request.body {
                builder = builder.body(body);
            }
            let response = builder.send().map_err(http_error)?;
            let status = response.status();
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let bytes = response.bytes().map_err(http_error)?.to_vec();
            Ok(BeeHttpResponse {
                status,
                content_type,
                bytes,
            })
        })
        .map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::ExecutionFailed,
                "failed to spawn Bee HTTP worker",
            )
            .with_details(json!({ "operation": operation, "error": error.to_string() }))
        })?;

    handle.join().map_err(|_| {
        SwarmAiErrorV1::new(ErrorCode::ExecutionFailed, "Bee HTTP worker panicked")
            .with_details(json!({ "operation": operation }))
    })?
}

fn parse_bee_reference_response(
    bytes: &[u8],
    operation: &str,
) -> Result<BeeReferenceResponse, SwarmAiErrorV1> {
    serde_json::from_slice(bytes).map_err(|error| {
        SwarmAiErrorV1::new(
            ErrorCode::ExecutionFailed,
            format!("Bee {operation} response was not valid JSON"),
        )
        .with_details(json!({ "error": error.to_string() }))
    })
}

fn bee_error_with_retry(
    mut error: SwarmAiErrorV1,
    operation: &str,
    retry_count: u32,
) -> SwarmAiErrorV1 {
    let details = match error.details {
        Value::Object(mut map) => {
            map.insert("operation".to_string(), json!(operation));
            map.insert("retryCount".to_string(), json!(retry_count));
            Value::Object(map)
        }
        other => json!({
            "operation": operation,
            "retryCount": retry_count,
            "details": other
        }),
    };
    error.details = details;
    error
}

fn is_transient_status(status: reqwest::StatusCode) -> bool {
    bee_retryable_status_codes()
        .iter()
        .any(|code| status.as_u16() == *code)
}

fn sleep_before_retry(retry_count: u32) {
    let multiplier = u64::from(retry_count).min(8);
    thread::sleep(Duration::from_millis(
        BEE_RETRY_BACKOFF_MS.saturating_mul(multiplier),
    ));
}

fn bee_retry_policy() -> StorageRetryPolicyV1 {
    StorageRetryPolicyV1 {
        schema_version: "swarm-ai.storage.retry-policy.v1".to_string(),
        max_retries: BEE_DEFAULT_MAX_RETRIES,
        backoff_ms: BEE_RETRY_BACKOFF_MS,
        retryable_status_codes: bee_retryable_status_codes(),
    }
}

fn bee_retryable_status_codes() -> Vec<u16> {
    vec![408, 429, 502, 503, 504]
}

fn not_found(reference: &str) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(
        ErrorCode::PackageNotFound,
        "object is not present in storage",
    )
    .with_details(json!({ "ref": reference }))
}

fn unsupported(message: &str) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(ErrorCode::UnsupportedOperation, message)
}

#[cfg(test)]
mod tests {
    use super::{
        BROWSER_STORAGE_SECURITY_ASSESSMENT_REQUEST_SCHEMA_VERSION,
        BROWSER_STORAGE_SESSION_V2_SCHEMA_VERSION, BeeHttpStorageProvider, BeeStorageConfig,
        BrowserServiceWorkerPolicyV1, BrowserStorageConsentActionV1,
        BrowserStorageEncryptionModeV1, BrowserStoragePermissionV1, BrowserStorageQuotaEstimateV1,
        BrowserStorageSecurityAssessmentRequestV1, BrowserStorageSecurityControlKindV1,
        BrowserStorageSecurityControlStatusV1, BrowserStorageSecurityRiskLevelV1,
        BrowserStorageSessionStatusV1, BrowserStorageSessionV1, BrowserStorageStateEntryV1,
        BrowserSwarmProviderProfileV1, BrowserSwarmStorageMethodV4, LocalDirectoryStorageProvider,
        StorageCostV1, StorageEventActionV1, StorageEventActionV2, StorageEventStatusV1,
        StorageProvider, StorageProviderKindV3, StorageProviderKindV4,
        StorageTransferAuditRecordV1, StorageTransferDirectionV1, StorageTransferMetricsV1,
        UploadResponseV1, assess_browser_storage_security, browser_storage_capability_probe,
        browser_storage_consent, browser_storage_consent_ref,
        browser_storage_purchase_authorization, browser_storage_purchase_quote,
        browser_storage_session, browser_storage_session_v2, browser_storage_state_report,
        browser_swarm_provider_catalog_v4, default_storage_provider_descriptors_v3,
        list_storage_transfer_audit, read_storage_transfer_audit_record,
        sign_browser_storage_capability_probe, sign_browser_storage_consent,
        sign_browser_storage_purchase_authorization, sign_browser_storage_purchase_quote,
        sign_browser_storage_session, sign_browser_storage_session_v2,
        sign_browser_storage_state_report, sign_storage_event_receipt,
        sign_storage_event_receipt_v2, sign_storage_sponsorship, storage_event_receipt_for_upload,
        storage_event_receipt_v2, storage_sponsorship, storage_transfer_audit_record,
        verify_browser_storage_capability_probe, verify_browser_storage_consent,
        verify_browser_storage_purchase_authorization, verify_browser_storage_purchase_quote,
        verify_browser_storage_security_assessment, verify_browser_storage_session,
        verify_browser_storage_session_v2, verify_browser_storage_state_report,
        verify_storage_event_receipt, verify_storage_event_receipt_v2, verify_storage_sponsorship,
        write_storage_transfer_audit_record,
    };
    use serde_json::json;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::thread;

    #[test]
    fn uploads_and_downloads_directory_file() {
        let root =
            std::env::temp_dir().join(format!("hivemind-storage-test-{}", std::process::id()));
        let package = root.join("package");
        let storage = root.join("storage");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(package.join("model")).unwrap();
        fs::write(package.join("swarm-ai.json"), "{}").unwrap();
        fs::write(package.join("model/config.json"), "{\"ok\":true}").unwrap();

        let mut provider = LocalDirectoryStorageProvider::new(&storage);
        let upload = provider.upload_directory(&package).unwrap();
        assert_eq!(
            upload.metrics.schema_version,
            "swarm-ai.storage.transfer-metrics.v1"
        );
        assert_eq!(upload.metrics.size_bytes, upload.size_bytes);
        let manifest = provider.download_manifest(&upload.reference).unwrap();
        assert_eq!(manifest.files.len(), 2);
        let file = provider
            .download_file(&upload.reference, "model/config.json")
            .unwrap();
        assert_eq!(file.bytes, b"{\"ok\":true}");
        assert_eq!(file.metrics.size_bytes, file.size_bytes);
        assert_eq!(file.metrics.retry_count, 0);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_feeds_and_pins_round_trip() {
        let root =
            std::env::temp_dir().join(format!("hivemind-storage-feed-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let mut provider = LocalDirectoryStorageProvider::new(&root);
        let created = provider.create_feed("latest", "0xPublisher").unwrap();
        assert!(created.target_ref.is_none());

        let update = provider
            .update_feed("latest", "0xPublisher", "bzz://local-dir-example")
            .unwrap();
        assert_eq!(
            update.pointer.target_ref.as_deref(),
            Some("bzz://local-dir-example")
        );

        let resolved = provider.resolve_feed(&update.feed_ref).unwrap();
        assert_eq!(resolved.target_ref, update.pointer.target_ref);

        let pin = provider.pin("bzz://local-dir-example").unwrap();
        assert!(pin.pinned);
        let unpin = provider.unpin("bzz://local-dir-example").unwrap();
        assert!(!unpin.pinned);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn storage_transfer_audit_store_lists_aggregate_timings() {
        let root = std::env::temp_dir().join(format!(
            "hivemind-storage-audit-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);

        let upload = storage_transfer_audit_record(
            "local",
            StorageTransferDirectionV1::Upload,
            "bzz://upload-ref",
            None,
            None,
            10,
            test_metrics(12, 10, 0),
        );
        let download = storage_transfer_audit_record(
            "local",
            StorageTransferDirectionV1::Download,
            "bzz://download-ref",
            Some("receipt.json".to_string()),
            Some("application/json".to_string()),
            30,
            test_metrics(18, 30, 1),
        );

        let upload_path = write_storage_transfer_audit_record(&root, &upload).unwrap();
        write_storage_transfer_audit_record(&root, &download).unwrap();
        let summary = list_storage_transfer_audit(&root).unwrap();
        let reread: StorageTransferAuditRecordV1 =
            read_storage_transfer_audit_record(&upload_path).unwrap();

        assert_eq!(reread.transfer_id, upload.transfer_id);
        assert_eq!(summary.transfer_count, 2);
        assert_eq!(summary.upload_count, 1);
        assert_eq!(summary.download_count, 1);
        assert_eq!(summary.total_size_bytes, 40);
        assert_eq!(summary.retry_count, 1);
        assert_eq!(summary.average_transfer_total_ms, Some(15.0));
        assert_eq!(summary.max_transfer_total_ms, Some(18));
        assert_eq!(summary.average_upload_total_ms, Some(12.0));
        assert_eq!(summary.average_download_total_ms, Some(18.0));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn browser_storage_v3_descriptors_mark_browser_provider_requirements() {
        let descriptors = default_storage_provider_descriptors_v3();
        let weeb3 = descriptors
            .iter()
            .find(|descriptor| descriptor.provider_kind == StorageProviderKindV3::Weeb3Npm)
            .expect("weeb3 provider descriptor");
        assert!(weeb3.requires_wallet);
        assert!(!weeb3.requires_trusted_gateway);
        assert!(weeb3.supports_resumable_upload);

        let bee_gateway = descriptors
            .iter()
            .find(|descriptor| descriptor.provider_kind == StorageProviderKindV3::BeeJsGateway)
            .expect("bee-js gateway descriptor");
        assert!(bee_gateway.requires_wallet);
        assert!(bee_gateway.requires_trusted_gateway);
        assert!(!bee_gateway.supports_resumable_upload);
    }

    #[test]
    fn browser_swarm_v4_catalog_exposes_review4_provider_conformance() {
        let catalog = browser_swarm_provider_catalog_v4();
        assert_eq!(
            catalog.schema_version,
            "hivemind.browser-swarm-provider-catalog.v4"
        );
        assert!(catalog.providers.iter().any(|provider| {
            provider.provider_kind == StorageProviderKindV4::Weeb3Browser
                && provider.profile == BrowserSwarmProviderProfileV1::DirectBrowserPublishing
                && provider
                    .capability_report
                    .methods
                    .contains(&BrowserSwarmStorageMethodV4::UploadManifest)
                && provider
                    .capability_report
                    .methods
                    .contains(&BrowserSwarmStorageMethodV4::ClearSensitiveBrowserState)
        }));
        assert!(
            catalog
                .providers
                .iter()
                .any(
                    |provider| provider.provider_kind == StorageProviderKindV4::Gateway
                        && provider.profile
                            == BrowserSwarmProviderProfileV1::BrowserGatewayFallback
                        && !provider.storage_receipt_required
                )
        );
        assert!(
            catalog
                .conformance_reports
                .iter()
                .all(|report| report.valid)
        );
        let gateway_report = catalog
            .conformance_reports
            .iter()
            .find(|report| report.provider_kind == StorageProviderKindV4::Gateway)
            .expect("gateway conformance report");
        assert!(
            gateway_report
                .required_methods
                .contains(&BrowserSwarmStorageMethodV4::Verify)
        );
        assert!(gateway_report.missing_required_methods.is_empty());
        assert!(!gateway_report.warnings.is_empty());
    }

    #[test]
    fn browser_storage_security_assessment_approves_evidenced_browser_publishing() {
        let provider = browser_swarm_provider_catalog_v4()
            .providers
            .into_iter()
            .find(|provider| provider.provider_kind == StorageProviderKindV4::Weeb3Browser)
            .expect("weeb3 provider");
        let mut consent = browser_storage_consent(
            "https://app.example",
            BrowserStorageConsentActionV1::UploadPrivateData,
            StorageProviderKindV3::Weeb3Npm,
            true,
            "Allow encrypted browser upload.",
        );
        consent.space_bytes = Some(1024 * 1024);
        consent.duration_seconds = Some(3600);
        sign_browser_storage_consent(&mut consent).unwrap();
        let mut session = browser_storage_session(
            StorageProviderKindV3::Weeb3Npm,
            "https://app.example",
            browser_storage_consent_ref(&consent.consent_id),
            1024 * 1024,
            3600,
        );
        session.wallet_address = Some("0xWallet".to_string());
        session.batch_owner_key_ref = Some("local://keys/batch".to_string());
        session.feed_owner_key_ref = Some("local://keys/feed".to_string());
        sign_browser_storage_session(&mut session).unwrap();

        let assessment =
            assess_browser_storage_security(BrowserStorageSecurityAssessmentRequestV1 {
                schema_version: BROWSER_STORAGE_SECURITY_ASSESSMENT_REQUEST_SCHEMA_VERSION
                    .to_string(),
                provider,
                session: Some(session),
                browser_origin: Some("https://app.example".to_string()),
                origin_isolation_enabled: true,
                sandboxed_swarm_content: true,
                indexed_db_origin_scoped: true,
                indexed_db_state_visible: true,
                clear_state_control_visible: true,
                key_separation_declared: true,
                user_consent_verified: true,
                private_uploads_expected: true,
                private_upload_encryption_available: true,
                service_worker_policy: Some(BrowserServiceWorkerPolicyV1 {
                    enabled: true,
                    scope: Some("/app/swarm-upload/".to_string()),
                    update_policy_ref: Some("bzz://service-worker-update-policy".to_string()),
                    replaceable: true,
                    package_content_scope_allowed: false,
                }),
                clear_state_receipt_refs: vec!["local://browser-storage/clear-state/1".to_string()],
                penetration_test_refs: vec!["bzz://browser-storage-pentest".to_string()],
                evidence_refs: vec!["bzz://browser-storage-security-review".to_string()],
            });

        assert!(assessment.all_required_controls_passed, "{assessment:#?}");
        assert!(
            assessment.approved_for_browser_publishing,
            "{assessment:#?}"
        );
        assert!(assessment.approved_for_private_uploads, "{assessment:#?}");
        assert_eq!(
            assessment.risk_level,
            BrowserStorageSecurityRiskLevelV1::Low
        );
        assert!(
            assessment
                .assessment_id
                .starts_with("browser-storage-security-")
        );
        assert!(verify_browser_storage_security_assessment(&assessment).valid);
    }

    #[test]
    fn browser_storage_security_assessment_blocks_unsafe_browser_state() {
        let provider = browser_swarm_provider_catalog_v4()
            .providers
            .into_iter()
            .find(|provider| provider.provider_kind == StorageProviderKindV4::Weeb3Browser)
            .expect("weeb3 provider");
        let mut session = browser_storage_session(
            StorageProviderKindV3::Weeb3Npm,
            "http://untrusted.example",
            "local://browser-storage/consent/test",
            1024,
            3600,
        );
        session.wallet_address = Some("same-key".to_string());
        session.batch_owner_key_ref = Some("same-key".to_string());
        session.feed_owner_key_ref = Some("same-key".to_string());
        sign_browser_storage_session(&mut session).unwrap();

        let assessment =
            assess_browser_storage_security(BrowserStorageSecurityAssessmentRequestV1 {
                schema_version: BROWSER_STORAGE_SECURITY_ASSESSMENT_REQUEST_SCHEMA_VERSION
                    .to_string(),
                provider,
                session: Some(session),
                browser_origin: Some("http://untrusted.example".to_string()),
                origin_isolation_enabled: false,
                sandboxed_swarm_content: false,
                indexed_db_origin_scoped: false,
                indexed_db_state_visible: false,
                clear_state_control_visible: false,
                key_separation_declared: true,
                user_consent_verified: false,
                private_uploads_expected: true,
                private_upload_encryption_available: false,
                service_worker_policy: Some(BrowserServiceWorkerPolicyV1 {
                    enabled: true,
                    scope: Some("/".to_string()),
                    update_policy_ref: None,
                    replaceable: false,
                    package_content_scope_allowed: true,
                }),
                clear_state_receipt_refs: Vec::new(),
                penetration_test_refs: Vec::new(),
                evidence_refs: Vec::new(),
            });

        assert!(!assessment.all_required_controls_passed);
        assert!(!assessment.approved_for_browser_publishing);
        assert!(!assessment.approved_for_private_uploads);
        assert_eq!(
            assessment.risk_level,
            BrowserStorageSecurityRiskLevelV1::Critical
        );
        assert!(assessment.controls.iter().any(|control| control.control
            == BrowserStorageSecurityControlKindV1::PenetrationTesting
            && control.status == BrowserStorageSecurityControlStatusV1::Failed));
        assert!(verify_browser_storage_security_assessment(&assessment).valid);
    }

    #[test]
    fn browser_storage_session_and_receipt_verify_and_detect_tampering() {
        let mut consent = browser_storage_consent(
            "https://app.example",
            BrowserStorageConsentActionV1::BuyStorage,
            StorageProviderKindV3::Weeb3Npm,
            true,
            "Allow this app to buy 1 MiB of Swarm storage.",
        );
        consent.wallet_address = Some("0xWallet".to_string());
        consent.space_bytes = Some(1024 * 1024);
        consent.duration_seconds = Some(3600);
        sign_browser_storage_consent(&mut consent).unwrap();
        assert!(verify_browser_storage_consent(&consent).valid);

        let mut session = browser_storage_session(
            StorageProviderKindV3::Weeb3Npm,
            "https://app.example",
            browser_storage_consent_ref(&consent.consent_id),
            1024 * 1024,
            3600,
        );
        session.wallet_address = Some("0xWallet".to_string());
        sign_browser_storage_session(&mut session).unwrap();
        assert!(verify_browser_storage_session(&session).valid);
        assert_eq!(session.provider_name.as_deref(), Some("Weeb-3 Browser"));
        assert_eq!(
            session.browser_origin.as_deref(),
            Some("https://app.example")
        );
        assert_eq!(session.purchased_size, 1024 * 1024);
        assert!(
            session
                .capabilities
                .contains(&BrowserSwarmStorageMethodV4::UploadManifest)
        );

        let upload = test_upload("bzz://storage-contract-test", 128);
        let mut receipt = storage_event_receipt_for_upload(
            &session,
            StorageEventActionV1::UploadFile,
            vec!["sha256:input".to_string()],
            &upload,
        );
        sign_storage_event_receipt(&mut receipt).unwrap();
        assert!(verify_storage_event_receipt(&receipt).valid);

        receipt.output_refs[0] = "bzz://tampered".to_string();
        let verification = verify_storage_event_receipt(&receipt);
        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$" || issue.path == "$.signatures")
        );
    }

    #[test]
    fn browser_storage_v5_space_purchase_session_receipts_and_state_report() {
        let provider = browser_swarm_provider_catalog_v4()
            .providers
            .into_iter()
            .find(|provider| provider.provider_kind == StorageProviderKindV4::Weeb3Browser)
            .expect("weeb3 browser provider");
        let mut probe = browser_storage_capability_probe(
            &provider,
            "Chromium",
            "125",
            "https://app.example",
            Some("gnosis-mainnet".to_string()),
            vec!["metamask".to_string()],
            Some(10 * 1024 * 1024),
        );
        sign_browser_storage_capability_probe(&mut probe).unwrap();
        let probe_verification = verify_browser_storage_capability_probe(&probe);
        assert!(probe_verification.valid, "{probe_verification:#?}");

        assert!(probe.can_start);
        assert!(probe.can_buy_storage);
        assert!(probe.can_upload);
        assert!(probe.can_upload_file_list);
        assert!(probe.can_clear_indexed_db);

        let mut quote = browser_storage_purchase_quote(
            &provider,
            &probe,
            1024 * 1024,
            3600,
            StorageCostV1 {
                amount: 0.01,
                currency: "xBZZ".to_string(),
                asset: Some("BZZ".to_string()),
            },
            Some("100".to_string()),
        );
        sign_browser_storage_purchase_quote(&mut quote).unwrap();
        let quote_verification = verify_browser_storage_purchase_quote(&quote);
        assert!(quote_verification.valid, "{quote_verification:#?}");

        let mut authorization = browser_storage_purchase_authorization(
            &quote,
            "0x0000000000000000000000000000000000000001",
            true,
            "Allow this app to buy 1 MiB of Swarm storage.",
        );
        sign_browser_storage_purchase_authorization(&mut authorization).unwrap();
        let authorization_verification =
            verify_browser_storage_purchase_authorization(&authorization);
        assert!(
            authorization_verification.valid,
            "{authorization_verification:#?}"
        );

        let mut session = browser_storage_session_v2(
            &provider,
            &probe,
            Some(&authorization),
            quote.requested_bytes,
            quote.duration_seconds,
        );
        sign_browser_storage_session_v2(&mut session).unwrap();
        let session_verification = verify_browser_storage_session_v2(&session);
        assert!(session_verification.valid, "{session_verification:#?}");
        assert_eq!(
            session.schema_version,
            BROWSER_STORAGE_SESSION_V2_SCHEMA_VERSION
        );
        assert_eq!(session.status, BrowserStorageSessionStatusV1::Active);
        assert!(
            session
                .permissions
                .contains(&BrowserStoragePermissionV1::BuyStorage)
        );
        assert!(
            session
                .permissions
                .contains(&BrowserStoragePermissionV1::Upload)
        );

        let mut receipt = storage_event_receipt_v2(
            &session,
            StorageEventActionV2::Upload,
            Some("bzz://browser-upload".to_string()),
            Some("sha256:browser-upload-content".to_string()),
            128,
            BrowserStorageEncryptionModeV1::ClientSide,
            StorageEventStatusV1::Succeeded,
            None,
        );
        sign_storage_event_receipt_v2(&mut receipt).unwrap();
        let receipt_verification = verify_storage_event_receipt_v2(&receipt);
        assert!(receipt_verification.valid, "{receipt_verification:#?}");
        assert_eq!(
            receipt.authorization_id.as_deref(),
            Some(authorization.authorization_id.as_str())
        );
        assert_eq!(
            receipt.session_id.as_deref(),
            Some(session.session_id.as_str())
        );

        let mut report = browser_storage_state_report(
            &session,
            vec![BrowserStorageStateEntryV1 {
                state_kind: "indexed_db".to_string(),
                key_ref: "indexeddb://hivemind/storage-session".to_string(),
                sensitive: true,
                clearable: true,
                size_bytes: Some(2048),
            }],
            vec!["/app/swarm-upload/".to_string()],
        );
        sign_browser_storage_state_report(&mut report).unwrap();
        let report_verification = verify_browser_storage_state_report(&report);
        assert!(report_verification.valid, "{report_verification:#?}");
        assert!(
            report
                .report_id
                .starts_with("browser-storage-state-report-")
        );
        assert_eq!(report.active_session_refs.len(), 1);
        assert!(report.clear_state_supported);
        assert!(report.warnings.is_empty(), "{report:#?}");

        let mut failed_receipt = storage_event_receipt_v2(
            &session,
            StorageEventActionV2::Upload,
            None,
            None,
            0,
            BrowserStorageEncryptionModeV1::ClientSide,
            StorageEventStatusV1::Failed,
            None,
        );
        sign_storage_event_receipt_v2(&mut failed_receipt).unwrap();
        let failed_verification = verify_storage_event_receipt_v2(&failed_receipt);
        assert!(!failed_verification.valid);
        assert!(
            failed_verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.error")
        );
    }

    #[test]
    fn browser_storage_v5_quote_validation_flags_missing_purchase_bounds() {
        let provider = browser_swarm_provider_catalog_v4()
            .providers
            .into_iter()
            .find(|provider| provider.provider_kind == StorageProviderKindV4::Weeb3Browser)
            .expect("weeb3 browser provider");
        let probe = browser_storage_capability_probe(
            &provider,
            "Chromium",
            "125",
            "https://app.example",
            Some("gnosis-mainnet".to_string()),
            vec!["metamask".to_string()],
            Some(10 * 1024 * 1024),
        );
        let mut quote = browser_storage_purchase_quote(
            &provider,
            &probe,
            0,
            0,
            StorageCostV1 {
                amount: -1.0,
                currency: String::new(),
                asset: None,
            },
            Some("100".to_string()),
        );
        sign_browser_storage_purchase_quote(&mut quote).unwrap();

        let verification = verify_browser_storage_purchase_quote(&quote);
        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.requestedBytes")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.estimatedCost.currency")
        );
    }

    #[test]
    fn failed_storage_event_receipt_requires_errors() {
        let session = BrowserStorageSessionV1 {
            schema_version: "hivemind.browser-storage-session.v1".to_string(),
            session_id: "session-test".to_string(),
            provider_kind: StorageProviderKindV3::LocalDev,
            provider_name: Some("Local Development Storage".to_string()),
            provider_version: Some("v4-contract".to_string()),
            origin: "http://localhost".to_string(),
            browser_origin: Some("http://localhost".to_string()),
            wallet_address: None,
            chain_id: None,
            batch_id: None,
            batch_owner_key_ref: None,
            feed_owner_key_ref: None,
            space_id: None,
            space_bytes: 1,
            purchased_size: 1,
            used_size: 0,
            quota_estimate: Some(BrowserStorageQuotaEstimateV1 {
                quota_bytes: Some(1),
                usage_bytes: Some(0),
                available_bytes: Some(1),
                source: "test".to_string(),
            }),
            duration_seconds: 60,
            permissions: Vec::new(),
            capabilities: vec![
                BrowserSwarmStorageMethodV4::UploadBlob,
                BrowserSwarmStorageMethodV4::Retrieve,
            ],
            user_consent_ref: "local://browser-storage/consent/test".to_string(),
            consent_record: Some("local://browser-storage/consent/test".to_string()),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2026-01-01T00:01:00Z".to_string(),
            provider_compatibility_report_ref: None,
            security_warnings: vec![
                "Local development storage is not production Swarm persistence".to_string(),
            ],
            status: Some(BrowserStorageSessionStatusV1::Active),
            signatures: Vec::new(),
        };
        let upload = test_upload("bzz://failed-upload", 0);
        let mut receipt = storage_event_receipt_for_upload(
            &session,
            StorageEventActionV1::UploadFile,
            vec!["sha256:input".to_string()],
            &upload,
        );
        receipt.status = StorageEventStatusV1::Failed;
        receipt.errors.clear();

        let verification = verify_storage_event_receipt(&receipt);
        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.errors")
        );
    }

    #[test]
    fn storage_sponsorship_signs_verifies_and_detects_tampering() {
        let mut sponsorship = storage_sponsorship(
            "marketplace-dao",
            "https://app.example",
            vec![
                StorageProviderKindV3::Weeb3Npm,
                StorageProviderKindV3::BeeJsGateway,
            ],
            10 * 1024 * 1024,
            86_400,
        );
        sponsorship.beneficiary = Some("0xUser".to_string());
        sponsorship.allowed_origins = vec!["https://app.example".to_string()];
        sponsorship.allowed_asset_classes = vec!["dataset".to_string(), "receipt".to_string()];
        sponsorship.allowed_namespaces = vec!["hivemind/community".to_string()];
        sponsorship.max_cost = Some(StorageCostV1 {
            amount: 1.25,
            currency: "xBZZ".to_string(),
            asset: Some("storage-credit".to_string()),
        });
        sponsorship.expires_at = Some("2026-06-06T00:00:00Z".to_string());
        sponsorship.settlement_policy = json!({
            "mode": "sponsor_reimburses_storage_receipts",
            "releaseCondition": "valid_storage_event_receipt"
        });
        sign_storage_sponsorship(&mut sponsorship).unwrap();

        let verification = verify_storage_sponsorship(&sponsorship);
        assert!(verification.valid, "{verification:#?}");
        assert!(verification.warnings.is_empty(), "{verification:#?}");

        sponsorship.max_space_bytes += 1;
        let tampered = verify_storage_sponsorship(&sponsorship);
        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path == "$" || issue.path == "$.signatures")
        );
    }

    #[test]
    fn bee_retry_policy_marks_transient_gateway_failures() {
        assert!(super::is_transient_status(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(super::is_transient_status(
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(super::is_transient_status(
            reqwest::StatusCode::GATEWAY_TIMEOUT
        ));
        assert!(!super::is_transient_status(
            reqwest::StatusCode::BAD_REQUEST
        ));
        assert!(!super::is_transient_status(reqwest::StatusCode::NOT_FOUND));
    }

    #[test]
    fn bee_download_retries_transient_statuses() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_server = attempts.clone();
        let server = thread::spawn(move || {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 1024];
                let _ = stream.read(&mut request);
                let attempt = attempts_for_server.fetch_add(1, Ordering::SeqCst) + 1;
                if attempt < 3 {
                    stream
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nbusy",
                        )
                        .unwrap();
                } else {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
                        )
                        .unwrap();
                }
            }
        });

        let provider = BeeHttpStorageProvider::new(BeeStorageConfig {
            api_url: format!("http://{address}"),
            postage_batch_id: None,
            pin: false,
            deferred_upload: true,
            redundancy_level: 0,
        });
        let response = provider.download_bytes("bzz://retry-test").unwrap();

        assert_eq!(response.bytes, b"ok");
        assert_eq!(response.metrics.retry_count, 2);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        server.join().unwrap();
    }

    fn test_metrics(
        total_ms: u64,
        size_bytes: usize,
        retry_count: u32,
    ) -> StorageTransferMetricsV1 {
        StorageTransferMetricsV1 {
            schema_version: "swarm-ai.storage.transfer-metrics.v1".to_string(),
            resolve_ms: total_ms / 2,
            first_byte_ms: total_ms / 2,
            total_ms,
            size_bytes,
            retry_count,
        }
    }

    fn test_upload(reference: &str, size_bytes: usize) -> UploadResponseV1 {
        UploadResponseV1 {
            schema_version: "swarm-ai.storage.upload.v1".to_string(),
            reference: reference.to_string(),
            size_bytes,
            pinned: true,
            redundancy_level: 0,
            postage_batch_id: None,
            metrics: test_metrics(1, size_bytes, 0),
        }
    }
}
