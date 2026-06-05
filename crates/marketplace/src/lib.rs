use chrono::{DateTime, SecondsFormat, Utc};
use hivemind_core::{
    ApiSurface, ExecutionReceiptV1, ExecutionRequestV1, IntegrityTier, LicenseType, Modality,
    PackageKind, PolicyMode, PriceModel, PriceV1, PrivacyTier, ReceiptMode, RegistryEntryV1,
    RunnerCacheClaimV1, RunnerCapabilityV1, RunnerDescriptorV1, RunnerHardwareV1, RunnerMemoryV1,
    RunnerPriceEntryV1, RunnerType, canonicalize_json, hash_canonical_json,
    runner_capability_from_descriptor,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use hivemind_receipts::{
    DisputeEvidenceV1, DisputeEvidenceVerificationV1, ReceiptCorrectnessAssessmentV1,
    ReceiptVerificationV1,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const DEV_RUNNER_OFFER_SIGNATURE_PREFIX: &str = "dev-runner-offer-signature-v1";
const DEV_HARDWARE_RESOURCE_OFFER_SIGNATURE_PREFIX: &str =
    "dev-hardware-resource-offer-signature-v1";
pub const MARKETPLACE_LISTING_SCHEMA_VERSION: &str = "hivemind.marketplace_listing.v1";
pub const LEGACY_MARKETPLACE_LISTING_SCHEMA_VERSION: &str = "swarm-ai.marketplace.listing.v1";
pub const MARKETPLACE_LISTING_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.marketplace_listing_verification.v1";
pub const MARKETPLACE_LISTING_V2_SCHEMA_VERSION: &str = "hivemind.marketplace_listing.v2";
pub const MARKETPLACE_LISTING_V2_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.marketplace_listing_verification.v2";
pub const RUNNER_OFFER_SCHEMA_VERSION: &str = "hivemind.runner_offer.v1";
pub const LEGACY_RUNNER_OFFER_SCHEMA_VERSION: &str = "swarm-ai.runner-offer.v1";
pub const RUNNER_OFFER_VERIFICATION_SCHEMA_VERSION: &str = "hivemind.runner_offer_verification.v1";
pub const MARKETPLACE_SHORTLIST_REQUEST_SCHEMA_VERSION: &str =
    "hivemind.marketplace_shortlist_request.v1";
pub const LEGACY_MARKETPLACE_SHORTLIST_REQUEST_SCHEMA_VERSION: &str =
    "swarm-ai.marketplace-shortlist-request.v1";
const LEGACY_MARKETPLACE_SHORTLIST_REQUEST_SCHEMA_VERSION_DOT: &str =
    "swarm-ai.marketplace.shortlist-request.v1";
pub const MARKETPLACE_SHORTLIST_SCHEMA_VERSION: &str = "hivemind.marketplace_shortlist.v1";
pub const RUNNER_OFFER_SCORE_SCHEMA_VERSION: &str = "hivemind.runner_offer_score.v1";
pub const HARDWARE_RESOURCE_OFFER_SCHEMA_VERSION: &str = "hivemind.hardware_resource_offer.v1";
pub const LEGACY_HARDWARE_RESOURCE_OFFER_SCHEMA_VERSION: &str =
    "swarm-ai.hardware-resource-offer.v1";
pub const HARDWARE_RESOURCE_OFFER_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.hardware_resource_offer_verification.v1";
pub const SERVICE_QUOTE_SCHEMA_VERSION: &str = "hivemind.quote.v1";
pub const LEGACY_SERVICE_QUOTE_SCHEMA_VERSION: &str = "swarm-ai.service-quote.v1";
pub const SERVICE_QUOTE_VERIFICATION_SCHEMA_VERSION: &str = "hivemind.quote_verification.v1";
pub const PAYMENT_AUTHORIZATION_SCHEMA_VERSION: &str = "hivemind.payment_authorization.v1";
pub const LEGACY_PAYMENT_AUTHORIZATION_SCHEMA_VERSION: &str = "swarm-ai.payment-authorization.v1";
pub const PAYMENT_AUTHORIZATION_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.payment_authorization_verification.v1";
pub const ESCROW_RECORD_SCHEMA_VERSION: &str = "hivemind.escrow_record.v1";
pub const ESCROW_RECORD_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.escrow_record_verification.v1";
pub const ESCROW_RELEASE_REQUEST_SCHEMA_VERSION: &str = "hivemind.escrow_release_request.v1";
pub const ESCROW_RELEASE_RESULT_SCHEMA_VERSION: &str = "hivemind.escrow_release_result.v1";
pub const SETTLEMENT_EVENT_SCHEMA_VERSION: &str = "hivemind.settlement_event.v1";
pub const LEGACY_SETTLEMENT_EVENT_SCHEMA_VERSION: &str = "swarm-ai.settlement-event.v1";
pub const SETTLEMENT_EVENT_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.settlement_event_verification.v1";
pub const REFUND_RECORD_SCHEMA_VERSION: &str = "hivemind.refund_record.v1";
pub const REFUND_RECORD_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.refund_record_verification.v1";
pub const REFUND_BUILD_REQUEST_SCHEMA_VERSION: &str = "hivemind.refund_build_request.v1";
pub const REFUND_BUILD_RESULT_SCHEMA_VERSION: &str = "hivemind.refund_build_result.v1";
pub const SLASHING_RECORD_SCHEMA_VERSION: &str = "hivemind.slashing_record.v1";
pub const SLASHING_RECORD_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.slashing_record_verification.v1";
pub const SLASHING_BUILD_REQUEST_SCHEMA_VERSION: &str = "hivemind.slashing_build_request.v1";
pub const SLASHING_BUILD_RESULT_SCHEMA_VERSION: &str = "hivemind.slashing_build_result.v1";
const DEV_SERVICE_QUOTE_SIGNATURE_PREFIX: &str = "dev-service-quote-signature-v1";
const DEV_MARKETPLACE_LISTING_SIGNATURE_PREFIX: &str = "dev-marketplace-listing-signature-v1";
const DEV_MARKETPLACE_LISTING_V2_SIGNATURE_PREFIX: &str = "dev-marketplace-listing-signature-v2";
const DEV_SETTLEMENT_EVENT_SIGNATURE_PREFIX: &str = "dev-settlement-event-signature-v1";
const DEV_SETTLEMENT_RESOLUTION_SIGNATURE_PREFIX: &str = "dev-settlement-resolution-signature-v1";
const DEV_PAYMENT_SIGNATURE_PREFIX: &str = "dev-signature-v1";
const DEV_ESCROW_RECORD_SIGNATURE_PREFIX: &str = "dev-escrow-record-signature-v1";
const DEV_REFUND_RECORD_SIGNATURE_PREFIX: &str = "dev-refund-record-signature-v1";
const DEV_SLASHING_RECORD_SIGNATURE_PREFIX: &str = "dev-slashing-record-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MarketplaceListingType {
    Package,
    Runner,
    Service,
    Validator,
    Benchmark,
    PackageLicense,
    PackageSubscription,
    HostedAiService,
    RunnerCapacity,
    GpuCapacity,
    BatchCapacity,
    ConfidentialRunner,
    FineTuningCapacity,
    ContainerLeaseExperimental,
    ValidatorService,
    DatasetLicense,
    VectorStoreService,
    BenchmarkBounty,
    ResearchGrant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PricingMode {
    Free,
    PayPerCall,
    PayPerToken,
    Subscription,
    Quote,
    StakeRewarded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ListingStatus {
    Active,
    Paused,
    Deprecated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SettlementModel {
    Free,
    DirectPayPerCall,
    Subscription,
    EscrowVerifiedJob,
    TokenGated,
    StakeRewarded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Authorized,
    Pending,
    Settled,
    PartiallySettled,
    Refunded,
    Disputed,
    DisputeRejected,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentAdapterKind {
    LocalDev,
    ExternalTransaction,
    Free,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentAuthorizationStatus {
    Authorized,
    Captured,
    Refunded,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum EscrowStatusV1 {
    Created,
    Locked,
    Released,
    Refunded,
    Cancelled,
    Disputed,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PricingV1 {
    pub mode: PricingMode,
    pub currency: String,
    #[serde(rename = "basePrice")]
    pub base_price: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PriceHintV1 {
    pub amount: f64,
    pub currency: String,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MarketplaceVerificationIssueV1 {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MarketplaceListingV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "listingId")]
    pub listing_id: String,
    #[serde(rename = "listingType")]
    pub listing_type: MarketplaceListingType,
    pub owner: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef", default)]
    pub package_ref: Option<String>,
    pub title: String,
    #[serde(rename = "descriptionRef", default)]
    pub description_ref: Option<String>,
    pub pricing: PricingV1,
    #[serde(rename = "termsRef", default)]
    pub terms_ref: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(rename = "validationReportRefs", default)]
    pub validation_report_refs: Vec<String>,
    #[serde(
        rename = "reputationRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reputation_ref: Option<String>,
    #[serde(default = "empty_terms")]
    pub details: Value,
    pub status: ListingStatus,
    #[serde(rename = "requiresLicense")]
    pub requires_license: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MarketplaceListingVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "listingId")]
    pub listing_id: String,
    pub valid: bool,
    pub issues: Vec<MarketplaceVerificationIssueV1>,
    pub warnings: Vec<MarketplaceVerificationIssueV1>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MarketplaceListingKindV2 {
    PackageLicense,
    PackageSubscription,
    HostedInference,
    GpuCapacity,
    BatchCapacity,
    ConfidentialRunner,
    ValidatorService,
    DatasetLicense,
    VectorStoreService,
    BenchmarkBounty,
    ResearchGrant,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MarketplaceListingSubjectV2 {
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    #[serde(rename = "subjectRef")]
    pub subject_ref: String,
    #[serde(rename = "packageId", default, skip_serializing_if = "Option::is_none")]
    pub package_id: Option<String>,
    #[serde(
        rename = "packageKind",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_kind: Option<PackageKind>,
    #[serde(rename = "apiSurfaces", default)]
    pub api_surfaces: Vec<ApiSurface>,
    #[serde(default)]
    pub modalities: Vec<Modality>,
    #[serde(default = "empty_terms")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MarketplacePriceModelV2 {
    pub mode: PricingMode,
    pub currency: String,
    pub unit: String,
    #[serde(rename = "basePrice")]
    pub base_price: f64,
    #[serde(rename = "priceHints", default)]
    pub price_hints: Vec<PriceHintV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MarketplaceServiceLevelV2 {
    #[serde(rename = "availabilityTarget", default)]
    pub availability_target: Option<f64>,
    #[serde(rename = "p95FirstOutputMs", default)]
    pub p95_first_output_ms: Option<u64>,
    #[serde(rename = "maxQueueDepth", default)]
    pub max_queue_depth: Option<u32>,
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default = "empty_terms")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MarketplaceListingV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "listingId")]
    pub listing_id: String,
    #[serde(rename = "listingType")]
    pub listing_type: MarketplaceListingKindV2,
    pub seller: String,
    pub subject: MarketplaceListingSubjectV2,
    pub title: String,
    #[serde(
        rename = "descriptionRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description_ref: Option<String>,
    #[serde(rename = "priceModel")]
    pub price_model: MarketplacePriceModelV2,
    #[serde(rename = "accessPolicy", default = "empty_terms")]
    pub access_policy: Value,
    #[serde(rename = "serviceLevel")]
    pub service_level: MarketplaceServiceLevelV2,
    #[serde(rename = "privacyTiers", default)]
    pub privacy_tiers: Vec<PrivacyTier>,
    #[serde(rename = "verificationTiers", default)]
    pub verification_tiers: Vec<IntegrityTier>,
    #[serde(rename = "settlementTerms", default = "empty_terms")]
    pub settlement_terms: Value,
    #[serde(rename = "disputeTerms", default = "empty_terms")]
    pub dispute_terms: Value,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(rename = "validationReportRefs", default)]
    pub validation_report_refs: Vec<String>,
    #[serde(
        rename = "reputationRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reputation_ref: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(
        rename = "sourceListingId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_listing_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MarketplaceListingV2VerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "listingId")]
    pub listing_id: String,
    pub valid: bool,
    pub issues: Vec<MarketplaceVerificationIssueV1>,
    pub warnings: Vec<MarketplaceVerificationIssueV1>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerPricingV1 {
    #[serde(rename = "inputTokenPrice")]
    pub input_token_price: f64,
    #[serde(rename = "outputTokenPrice")]
    pub output_token_price: f64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerServiceLevelV1 {
    #[serde(rename = "p95FirstTokenMs")]
    pub p95_first_token_ms: u64,
    #[serde(rename = "availabilityTarget")]
    pub availability_target: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerReputationV1 {
    #[serde(rename = "validatorScore")]
    pub validator_score: f64,
    #[serde(rename = "completedJobs")]
    pub completed_jobs: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerOfferV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(rename = "publicKey", default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(rename = "runnerType")]
    pub runner_type: RunnerType,
    #[serde(rename = "runnerDescriptorRef")]
    pub runner_descriptor_ref: String,
    #[serde(rename = "supportedPackageRefs")]
    pub supported_package_refs: Vec<String>,
    #[serde(rename = "supportedCapabilities")]
    pub supported_capabilities: Vec<String>,
    #[serde(
        rename = "supportedApis",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub supported_apis: Vec<ApiSurface>,
    #[serde(
        rename = "supportedModalities",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub supported_modalities: Vec<Modality>,
    #[serde(
        rename = "supportedPackageKinds",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub supported_package_kinds: Vec<String>,
    #[serde(
        rename = "supportedModelFormats",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub supported_model_formats: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub engines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware: Option<RunnerHardwareV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<RunnerMemoryV1>,
    #[serde(
        rename = "maxContextTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_context_tokens: Option<u64>,
    #[serde(
        rename = "maxBatchSize",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_batch_size: Option<u64>,
    #[serde(
        rename = "streamingModes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub streaming_modes: Vec<String>,
    #[serde(rename = "priceTable", default, skip_serializing_if = "Vec::is_empty")]
    pub price_table: Vec<RunnerPriceEntryV1>,
    #[serde(rename = "cacheClaims", default, skip_serializing_if = "Vec::is_empty")]
    pub cache_claims: Vec<RunnerCacheClaimV1>,
    #[serde(
        rename = "privacyTiers",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub privacy_tiers: Vec<PrivacyTier>,
    #[serde(
        rename = "verificationTiers",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub verification_tiers: Vec<IntegrityTier>,
    #[serde(
        rename = "regionHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub region_hint: Option<String>,
    #[serde(
        rename = "validatorScoreRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub validator_score_ref: Option<String>,
    #[serde(rename = "termsRef", default, skip_serializing_if = "Option::is_none")]
    pub terms_ref: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub pricing: RunnerPricingV1,
    #[serde(rename = "serviceLevel")]
    pub service_level: RunnerServiceLevelV1,
    pub reputation: RunnerReputationV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerOfferVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    pub valid: bool,
    pub issues: Vec<MarketplaceVerificationIssueV1>,
    pub warnings: Vec<MarketplaceVerificationIssueV1>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MinerTrustTierV1 {
    Open,
    Staked,
    Verified,
    Confidential,
    Cryptographic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HardwareExecutionModeV1 {
    PackageInference,
    BatchInference,
    EmbeddingBatch,
    FineTuneSmall,
    EvaluationRun,
    ContainerLeaseExperimental,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HardwareResourceV1 {
    #[serde(rename = "gpuVendor", default, skip_serializing_if = "Option::is_none")]
    pub gpu_vendor: Option<String>,
    #[serde(rename = "gpuModel", default, skip_serializing_if = "Option::is_none")]
    pub gpu_model: Option<String>,
    #[serde(rename = "gpuCount")]
    pub gpu_count: u32,
    #[serde(rename = "vramGb", default, skip_serializing_if = "Option::is_none")]
    pub vram_gb: Option<f64>,
    #[serde(rename = "cpuCores", default, skip_serializing_if = "Option::is_none")]
    pub cpu_cores: Option<u32>,
    #[serde(rename = "ramGb")]
    pub ram_gb: f64,
    #[serde(rename = "diskGb", default, skip_serializing_if = "Option::is_none")]
    pub disk_gb: Option<f64>,
    #[serde(
        rename = "networkMbps",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub network_mbps: Option<f64>,
    #[serde(
        rename = "driverVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub driver_version: Option<String>,
    #[serde(rename = "runtimeVersions", default)]
    pub runtime_versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HardwareAvailabilityV1 {
    #[serde(rename = "availableNow")]
    pub available_now: bool,
    #[serde(rename = "queueDepth")]
    pub queue_depth: u32,
    #[serde(rename = "maxConcurrentJobs")]
    pub max_concurrent_jobs: u32,
    #[serde(rename = "scheduleRefs", default)]
    pub schedule_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HardwareStakeV1 {
    pub amount: f64,
    pub currency: String,
    #[serde(
        rename = "collateralRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub collateral_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HardwareResourceOfferV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub operator: String,
    pub hardware: HardwareResourceV1,
    #[serde(rename = "supportedExecutionModes")]
    pub supported_execution_modes: Vec<HardwareExecutionModeV1>,
    #[serde(rename = "supportedEngines")]
    pub supported_engines: Vec<String>,
    #[serde(rename = "supportedApis")]
    pub supported_apis: Vec<ApiSurface>,
    #[serde(rename = "supportedModalities")]
    pub supported_modalities: Vec<Modality>,
    #[serde(rename = "priceTable")]
    pub price_table: Vec<RunnerPriceEntryV1>,
    pub availability: HardwareAvailabilityV1,
    #[serde(rename = "cacheClaims")]
    pub cache_claims: Vec<RunnerCacheClaimV1>,
    #[serde(rename = "privacyTiers")]
    pub privacy_tiers: Vec<PrivacyTier>,
    #[serde(rename = "verificationTiers")]
    pub verification_tiers: Vec<IntegrityTier>,
    #[serde(rename = "trustTier")]
    pub trust_tier: MinerTrustTierV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stake: Option<HardwareStakeV1>,
    #[serde(rename = "benchmarkResultRefs", default)]
    pub benchmark_result_refs: Vec<String>,
    #[serde(rename = "termsRef")]
    pub terms_ref: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct HardwareResourceOfferVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    pub valid: bool,
    pub issues: Vec<MarketplaceVerificationIssueV1>,
    pub warnings: Vec<MarketplaceVerificationIssueV1>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

fn default_policy_mode() -> PolicyMode {
    PolicyMode::Balanced
}

fn default_shortlist_max_results() -> usize {
    5
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MarketplaceShortlistRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub task: String,
    #[serde(
        rename = "apiSurface",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub api_surface: Option<ApiSurface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modality: Option<Modality>,
    #[serde(rename = "estimatedInputTokens")]
    pub estimated_input_tokens: u64,
    #[serde(rename = "estimatedOutputTokens")]
    pub estimated_output_tokens: u64,
    #[serde(
        rename = "requiredPrivacyTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub required_privacy_tier: Option<PrivacyTier>,
    #[serde(
        rename = "requiredVerificationTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub required_verification_tier: Option<IntegrityTier>,
    #[serde(rename = "policyMode", default = "default_policy_mode")]
    pub policy_mode: PolicyMode,
    #[serde(rename = "maxResults", default = "default_shortlist_max_results")]
    pub max_results: usize,
    #[serde(rename = "includeRejected", default)]
    pub include_rejected: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerOfferScoreV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub rank: u32,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "runnerType")]
    pub runner_type: RunnerType,
    pub eligible: bool,
    pub score: f64,
    #[serde(rename = "estimatedCost")]
    pub estimated_cost: f64,
    pub currency: String,
    #[serde(rename = "firstTokenMs")]
    pub first_token_ms: u64,
    #[serde(rename = "availabilityTarget")]
    pub availability_target: f64,
    #[serde(rename = "validatorScore")]
    pub validator_score: f64,
    #[serde(rename = "completedJobs")]
    pub completed_jobs: u64,
    #[serde(
        rename = "selectedPrivacyTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub selected_privacy_tier: Option<PrivacyTier>,
    #[serde(
        rename = "selectedVerificationTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub selected_verification_tier: Option<IntegrityTier>,
    #[serde(rename = "cacheHitClaim")]
    pub cache_hit_claim: bool,
    #[serde(rename = "policyFitScore")]
    pub policy_fit_score: f64,
    #[serde(rename = "policyMode")]
    pub policy_mode: PolicyMode,
    pub reasons: Vec<String>,
    pub verification: RunnerOfferVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MarketplaceShortlistV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub task: String,
    #[serde(
        rename = "apiSurface",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub api_surface: Option<ApiSurface>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modality: Option<Modality>,
    #[serde(
        rename = "requiredPrivacyTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub required_privacy_tier: Option<PrivacyTier>,
    #[serde(
        rename = "requiredVerificationTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub required_verification_tier: Option<IntegrityTier>,
    #[serde(rename = "policyMode")]
    pub policy_mode: PolicyMode,
    #[serde(rename = "selectedOfferId", default)]
    pub selected_offer_id: Option<String>,
    pub rankings: Vec<RunnerOfferScoreV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceQuoteV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "listingId", default, skip_serializing_if = "Option::is_none")]
    pub listing_id: Option<String>,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "estimatedInputTokens")]
    pub estimated_input_tokens: u64,
    #[serde(rename = "estimatedOutputTokens")]
    pub estimated_output_tokens: u64,
    #[serde(rename = "estimatedCost")]
    pub estimated_cost: f64,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price: Option<PriceV1>,
    #[serde(
        rename = "priceModel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub price_model: Option<PriceModel>,
    #[serde(
        rename = "privacyMode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub privacy_mode: Option<PrivacyTier>,
    #[serde(
        rename = "verificationMode",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub verification_mode: Option<IntegrityTier>,
    #[serde(
        rename = "estimatedStartDelayMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub estimated_start_delay_ms: Option<u64>,
    #[serde(
        rename = "estimatedTimeToFirstOutputMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub estimated_time_to_first_output_ms: Option<u64>,
    #[serde(
        rename = "estimatedCompletionMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub estimated_completion_ms: Option<u64>,
    #[serde(
        rename = "cacheHitClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cache_hit_claim: Option<bool>,
    #[serde(rename = "validationSupport", default)]
    pub validation_support: Vec<String>,
    #[serde(rename = "settlementModel")]
    pub settlement_model: SettlementModel,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(default = "empty_terms")]
    pub terms: Value,
    #[serde(default)]
    pub details: Value,
    #[serde(
        rename = "quoteTiming",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub quote_timing: Option<ServiceQuoteTimingV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceQuoteTimingV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "completedAt")]
    pub completed_at: String,
    #[serde(rename = "elapsedMs")]
    pub elapsed_ms: u64,
    #[serde(rename = "offerMatched")]
    pub offer_matched: bool,
    #[serde(rename = "privacyMatched")]
    pub privacy_matched: bool,
    #[serde(rename = "verificationMatched")]
    pub verification_matched: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceQuoteVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    pub valid: bool,
    pub issues: Vec<MarketplaceVerificationIssueV1>,
    pub warnings: Vec<MarketplaceVerificationIssueV1>,
    #[serde(rename = "expectedCost", default)]
    pub expected_cost: Option<f64>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceQuoteIndexEntryV1 {
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "listingId", default, skip_serializing_if = "Option::is_none")]
    pub listing_id: Option<String>,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "estimatedCost")]
    pub estimated_cost: f64,
    pub currency: String,
    #[serde(rename = "settlementModel")]
    pub settlement_model: SettlementModel,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(
        rename = "quoteElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub quote_elapsed_ms: Option<u64>,
    #[serde(
        rename = "quoteStartedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub quote_started_at: Option<String>,
    #[serde(
        rename = "quoteCompletedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub quote_completed_at: Option<String>,
    #[serde(
        rename = "cacheHitClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cache_hit_claim: Option<bool>,
    #[serde(rename = "quotePath")]
    pub quote_path: String,
    pub verification: ServiceQuoteVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceQuoteStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "quoteCount")]
    pub quote_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "withQuoteTimingCount")]
    pub with_quote_timing_count: usize,
    #[serde(
        rename = "averageQuoteElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub average_quote_elapsed_ms: Option<f64>,
    #[serde(
        rename = "maxQuoteElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_quote_elapsed_ms: Option<u64>,
    #[serde(rename = "quoteCacheClaimSampleCount")]
    pub quote_cache_claim_sample_count: usize,
    #[serde(rename = "quoteCacheHitCount")]
    pub quote_cache_hit_count: usize,
    #[serde(rename = "quoteCacheMissCount")]
    pub quote_cache_miss_count: usize,
    #[serde(
        rename = "quoteCacheHitRate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub quote_cache_hit_rate: Option<f64>,
    pub quotes: Vec<ServiceQuoteIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ServiceQuoteLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "quotePath")]
    pub quote_path: String,
    pub quote: ServiceQuoteV1,
    pub verification: ServiceQuoteVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PaymentAuthorizationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "authorizationId")]
    pub authorization_id: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub payer: String,
    pub payee: String,
    pub amount: f64,
    pub currency: String,
    pub adapter: PaymentAdapterKind,
    #[serde(rename = "maxAmount", default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<PaymentAdapterKind>,
    pub status: PaymentAuthorizationStatus,
    #[serde(rename = "paymentRef", default)]
    pub payment_ref: Option<String>,
    #[serde(rename = "escrowRef", default, skip_serializing_if = "Option::is_none")]
    pub escrow_ref: Option<String>,
    #[serde(rename = "authorizedAt")]
    pub authorized_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(rename = "cancellationRules", default = "empty_terms")]
    pub cancellation_rules: Value,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PaymentAuthorizationVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "authorizationId")]
    pub authorization_id: String,
    pub valid: bool,
    pub issues: Vec<MarketplaceVerificationIssueV1>,
    pub warnings: Vec<MarketplaceVerificationIssueV1>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PaymentAuthorizationIndexEntryV1 {
    #[serde(rename = "authorizationId")]
    pub authorization_id: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub payer: String,
    pub payee: String,
    pub amount: f64,
    pub currency: String,
    pub adapter: PaymentAdapterKind,
    #[serde(rename = "maxAmount", default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<PaymentAdapterKind>,
    pub status: PaymentAuthorizationStatus,
    #[serde(rename = "paymentRef", default)]
    pub payment_ref: Option<String>,
    #[serde(rename = "escrowRef", default, skip_serializing_if = "Option::is_none")]
    pub escrow_ref: Option<String>,
    #[serde(rename = "authorizedAt")]
    pub authorized_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(rename = "authorizationPath")]
    pub authorization_path: String,
    pub verification: PaymentAuthorizationVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PaymentAuthorizationStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "authorizationCount")]
    pub authorization_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub authorizations: Vec<PaymentAuthorizationIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PaymentAuthorizationLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "authorizationId")]
    pub authorization_id: String,
    #[serde(rename = "authorizationPath")]
    pub authorization_path: String,
    pub authorization: PaymentAuthorizationV1,
    pub verification: PaymentAuthorizationVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EscrowRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "escrowId")]
    pub escrow_id: String,
    #[serde(rename = "authorizationId")]
    pub authorization_id: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub payer: String,
    pub payee: String,
    pub amount: f64,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    pub adapter: PaymentAdapterKind,
    pub status: EscrowStatusV1,
    pub custodian: String,
    #[serde(
        rename = "paymentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub payment_ref: Option<String>,
    #[serde(rename = "escrowRef", default, skip_serializing_if = "Option::is_none")]
    pub escrow_ref: Option<String>,
    #[serde(
        rename = "settlementId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub settlement_id: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(default = "empty_terms")]
    pub terms: Value,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(rename = "lockedAt", default, skip_serializing_if = "Option::is_none")]
    pub locked_at: Option<String>,
    #[serde(
        rename = "releasedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub released_at: Option<String>,
    #[serde(
        rename = "refundedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub refunded_at: Option<String>,
    #[serde(
        rename = "cancelledAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cancelled_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EscrowRecordVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "escrowId")]
    pub escrow_id: String,
    pub valid: bool,
    pub issues: Vec<MarketplaceVerificationIssueV1>,
    pub warnings: Vec<MarketplaceVerificationIssueV1>,
    #[serde(rename = "paymentAuthorizationVerification", default)]
    pub payment_authorization_verification: Option<PaymentAuthorizationVerificationV1>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EscrowReleaseRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub escrow: EscrowRecordV1,
    pub settlement: SettlementEventV1,
    #[serde(rename = "releasedBy")]
    pub released_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EscrowReleaseResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(default)]
    pub escrow: Option<EscrowRecordV1>,
    pub valid: bool,
    pub issues: Vec<MarketplaceVerificationIssueV1>,
    pub warnings: Vec<MarketplaceVerificationIssueV1>,
    #[serde(rename = "escrowVerification")]
    pub escrow_verification: EscrowRecordVerificationV1,
    #[serde(rename = "settlementVerification")]
    pub settlement_verification: SettlementEventVerificationV1,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EscrowRecordIndexEntryV1 {
    #[serde(rename = "escrowId")]
    pub escrow_id: String,
    #[serde(rename = "authorizationId")]
    pub authorization_id: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub payer: String,
    pub payee: String,
    pub amount: f64,
    pub currency: String,
    pub status: EscrowStatusV1,
    pub custodian: String,
    #[serde(
        rename = "settlementId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub settlement_id: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(rename = "escrowPath")]
    pub escrow_path: String,
    pub verification: EscrowRecordVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EscrowRecordStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "escrowCount")]
    pub escrow_count: usize,
    #[serde(rename = "lockedCount")]
    pub locked_count: usize,
    #[serde(rename = "releasedCount")]
    pub released_count: usize,
    #[serde(rename = "refundedCount")]
    pub refunded_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub escrows: Vec<EscrowRecordIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EscrowRecordLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "escrowId")]
    pub escrow_id: String,
    #[serde(rename = "escrowPath")]
    pub escrow_path: String,
    pub escrow: EscrowRecordV1,
    pub verification: EscrowRecordVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementEventV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "settlementId")]
    pub settlement_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "quoteId", default)]
    pub quote_id: Option<String>,
    #[serde(rename = "paymentAuthorizationId", default)]
    pub payment_authorization_id: Option<String>,
    #[serde(rename = "paymentRef", default)]
    pub payment_ref: Option<String>,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub payer: String,
    pub payee: String,
    pub amount: f64,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    pub status: SettlementStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "occurredAt")]
    pub occurred_at: String,
    #[serde(rename = "receiptRef", default)]
    pub receipt_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementVerificationIssueV1 {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "settlementId", default)]
    pub settlement_id: Option<String>,
    pub valid: bool,
    pub issues: Vec<SettlementVerificationIssueV1>,
    pub warnings: Vec<SettlementVerificationIssueV1>,
    #[serde(rename = "receiptVerification")]
    pub receipt_verification: ReceiptVerificationV1,
    #[serde(rename = "paymentAuthorizationVerification", default)]
    pub payment_authorization_verification: Option<PaymentAuthorizationVerificationV1>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementEventVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "settlementId")]
    pub settlement_id: String,
    pub valid: bool,
    pub issues: Vec<SettlementVerificationIssueV1>,
    pub warnings: Vec<SettlementVerificationIssueV1>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementBuildResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(default)]
    pub settlement: Option<SettlementEventV1>,
    pub verification: SettlementVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SettlementResolutionAction {
    OpenDispute,
    Refund,
    RejectDispute,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementResolutionVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "resolutionId", default)]
    pub resolution_id: Option<String>,
    pub valid: bool,
    pub issues: Vec<SettlementVerificationIssueV1>,
    pub warnings: Vec<SettlementVerificationIssueV1>,
    #[serde(rename = "disputeVerification", default)]
    pub dispute_verification: Option<DisputeEvidenceVerificationV1>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementResolutionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "resolutionId")]
    pub resolution_id: String,
    #[serde(rename = "settlementId")]
    pub settlement_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "disputeId")]
    pub dispute_id: String,
    pub action: SettlementResolutionAction,
    #[serde(rename = "previousStatus")]
    pub previous_status: SettlementStatus,
    #[serde(rename = "newStatus")]
    pub new_status: SettlementStatus,
    pub amount: f64,
    pub currency: String,
    #[serde(rename = "resolvedBy")]
    pub resolved_by: String,
    pub reason: String,
    #[serde(rename = "occurredAt")]
    pub occurred_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementResolutionResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(default)]
    pub resolution: Option<SettlementResolutionV1>,
    #[serde(rename = "updatedSettlement", default)]
    pub updated_settlement: Option<SettlementEventV1>,
    pub verification: SettlementResolutionVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RefundBuildRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub settlement: SettlementEventV1,
    pub resolution: SettlementResolutionV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute: Option<DisputeEvidenceV1>,
    #[serde(rename = "refundedBy")]
    pub refunded_by: String,
    #[serde(rename = "refundRef", default, skip_serializing_if = "Option::is_none")]
    pub refund_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(
        rename = "occurredAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub occurred_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RefundRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "refundId")]
    pub refund_id: String,
    #[serde(rename = "settlementId")]
    pub settlement_id: String,
    #[serde(rename = "sourceSettlementId")]
    pub source_settlement_id: String,
    #[serde(rename = "resolutionId")]
    pub resolution_id: String,
    #[serde(rename = "disputeId", default, skip_serializing_if = "Option::is_none")]
    pub dispute_id: Option<String>,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "quoteId", default, skip_serializing_if = "Option::is_none")]
    pub quote_id: Option<String>,
    #[serde(
        rename = "paymentAuthorizationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub payment_authorization_id: Option<String>,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub payer: String,
    pub payee: String,
    #[serde(rename = "refundedBy")]
    pub refunded_by: String,
    pub amount: f64,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    #[serde(rename = "refundRef", default, skip_serializing_if = "Option::is_none")]
    pub refund_ref: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    pub reason: String,
    #[serde(rename = "occurredAt")]
    pub occurred_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RefundRecordVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "refundId", default, skip_serializing_if = "Option::is_none")]
    pub refund_id: Option<String>,
    pub valid: bool,
    pub issues: Vec<MarketplaceVerificationIssueV1>,
    pub warnings: Vec<MarketplaceVerificationIssueV1>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RefundBuildResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(default)]
    pub refund: Option<RefundRecordV1>,
    pub verification: RefundRecordVerificationV1,
    #[serde(rename = "settlementVerification")]
    pub settlement_verification: SettlementEventVerificationV1,
    #[serde(rename = "resolutionVerification")]
    pub resolution_verification: SettlementResolutionVerificationV1,
    #[serde(rename = "disputeVerification", default)]
    pub dispute_verification: Option<DisputeEvidenceVerificationV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RefundRecordIndexEntryV1 {
    #[serde(rename = "refundId")]
    pub refund_id: String,
    #[serde(rename = "settlementId")]
    pub settlement_id: String,
    #[serde(rename = "sourceSettlementId")]
    pub source_settlement_id: String,
    #[serde(rename = "resolutionId")]
    pub resolution_id: String,
    #[serde(rename = "disputeId", default, skip_serializing_if = "Option::is_none")]
    pub dispute_id: Option<String>,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub payer: String,
    pub payee: String,
    #[serde(rename = "refundedBy")]
    pub refunded_by: String,
    pub amount: f64,
    pub currency: String,
    #[serde(rename = "refundRef", default, skip_serializing_if = "Option::is_none")]
    pub refund_ref: Option<String>,
    #[serde(rename = "occurredAt")]
    pub occurred_at: String,
    #[serde(rename = "refundPath")]
    pub refund_path: String,
    pub verification: RefundRecordVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RefundRecordStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "refundCount")]
    pub refund_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "totalRefundedAmount")]
    pub total_refunded_amount: f64,
    #[serde(rename = "currencyCounts")]
    pub currency_counts: BTreeMap<String, usize>,
    pub refunds: Vec<RefundRecordIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RefundRecordLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "refundId")]
    pub refund_id: String,
    #[serde(rename = "refundPath")]
    pub refund_path: String,
    pub refund: RefundRecordV1,
    pub verification: RefundRecordVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementAuditEntryV1 {
    #[serde(rename = "settlementId")]
    pub settlement_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "quoteId", default)]
    pub quote_id: Option<String>,
    #[serde(rename = "paymentAuthorizationId", default)]
    pub payment_authorization_id: Option<String>,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub payer: String,
    pub payee: String,
    pub amount: f64,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    pub status: SettlementStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "evidenceRefCount")]
    pub evidence_ref_count: usize,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(rename = "occurredAt")]
    pub occurred_at: String,
    #[serde(rename = "settlementPath")]
    pub settlement_path: String,
    #[serde(rename = "signatureVerified")]
    pub signature_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementResolutionAuditEntryV1 {
    #[serde(rename = "resolutionId")]
    pub resolution_id: String,
    #[serde(rename = "settlementId")]
    pub settlement_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "disputeId")]
    pub dispute_id: String,
    pub action: SettlementResolutionAction,
    #[serde(rename = "previousStatus")]
    pub previous_status: SettlementStatus,
    #[serde(rename = "newStatus")]
    pub new_status: SettlementStatus,
    pub amount: f64,
    pub currency: String,
    #[serde(rename = "resolvedBy")]
    pub resolved_by: String,
    #[serde(rename = "occurredAt")]
    pub occurred_at: String,
    #[serde(rename = "resolutionPath")]
    pub resolution_path: String,
    #[serde(rename = "signatureVerified")]
    pub signature_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MarketplaceAuditSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "quoteCount")]
    pub quote_count: usize,
    #[serde(rename = "validQuoteCount")]
    pub valid_quote_count: usize,
    #[serde(rename = "invalidQuoteCount")]
    pub invalid_quote_count: usize,
    #[serde(rename = "settlementCount")]
    pub settlement_count: usize,
    #[serde(rename = "validSettlementCount")]
    pub valid_settlement_count: usize,
    #[serde(rename = "invalidSettlementCount")]
    pub invalid_settlement_count: usize,
    #[serde(rename = "resolutionCount")]
    pub resolution_count: usize,
    #[serde(rename = "validResolutionCount")]
    pub valid_resolution_count: usize,
    #[serde(rename = "invalidResolutionCount")]
    pub invalid_resolution_count: usize,
    #[serde(rename = "settlementLatencySampleCount")]
    pub settlement_latency_sample_count: usize,
    #[serde(
        rename = "averageQuoteToSettlementMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub average_quote_to_settlement_ms: Option<f64>,
    #[serde(
        rename = "maxQuoteToSettlementMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_quote_to_settlement_ms: Option<u64>,
    #[serde(rename = "quoteCacheClaimSampleCount")]
    pub quote_cache_claim_sample_count: usize,
    #[serde(rename = "quoteCacheHitCount")]
    pub quote_cache_hit_count: usize,
    #[serde(rename = "quoteCacheMissCount")]
    pub quote_cache_miss_count: usize,
    #[serde(
        rename = "quoteCacheHitRate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub quote_cache_hit_rate: Option<f64>,
    pub quotes: Vec<ServiceQuoteIndexEntryV1>,
    pub settlements: Vec<SettlementAuditEntryV1>,
    pub resolutions: Vec<SettlementResolutionAuditEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementEventLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "settlementId")]
    pub settlement_id: String,
    #[serde(rename = "settlementPath")]
    pub settlement_path: String,
    pub settlement: SettlementEventV1,
    pub verification: SettlementEventVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SettlementResolutionLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "resolutionId")]
    pub resolution_id: String,
    #[serde(rename = "resolutionPath")]
    pub resolution_path: String,
    pub resolution: SettlementResolutionV1,
    pub verification: SettlementResolutionVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SlashingReasonKindV1 {
    FakeOutput,
    IncorrectBilling,
    PolicyViolation,
    RunnerFailure,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SlashingBuildRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub settlement: SettlementEventV1,
    pub dispute: DisputeEvidenceV1,
    #[serde(rename = "correctnessAssessment")]
    pub correctness_assessment: ReceiptCorrectnessAssessmentV1,
    #[serde(rename = "slashedBy")]
    pub slashed_by: String,
    pub amount: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(rename = "stakeRef", default, skip_serializing_if = "Option::is_none")]
    pub stake_ref: Option<String>,
    #[serde(rename = "reasonKind")]
    pub reason_kind: SlashingReasonKindV1,
    pub reason: String,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(
        rename = "occurredAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub occurred_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SlashingRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "slashingId")]
    pub slashing_id: String,
    #[serde(rename = "settlementId")]
    pub settlement_id: String,
    #[serde(rename = "disputeId")]
    pub dispute_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "jobId", default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "slashedParty")]
    pub slashed_party: String,
    #[serde(rename = "slashedBy")]
    pub slashed_by: String,
    pub amount: f64,
    pub currency: String,
    #[serde(rename = "stakeRef", default, skip_serializing_if = "Option::is_none")]
    pub stake_ref: Option<String>,
    #[serde(rename = "reasonKind")]
    pub reason_kind: SlashingReasonKindV1,
    pub reason: String,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(
        rename = "correctnessAssessmentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub correctness_assessment_ref: Option<String>,
    #[serde(rename = "failedMethods", default)]
    pub failed_methods: Vec<String>,
    #[serde(rename = "occurredAt")]
    pub occurred_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SlashingRecordVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(
        rename = "slashingId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub slashing_id: Option<String>,
    pub valid: bool,
    pub issues: Vec<SettlementVerificationIssueV1>,
    pub warnings: Vec<SettlementVerificationIssueV1>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SlashingBuildResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(default)]
    pub slashing: Option<SlashingRecordV1>,
    pub verification: SlashingRecordVerificationV1,
    #[serde(rename = "settlementVerification")]
    pub settlement_verification: SettlementEventVerificationV1,
    #[serde(rename = "disputeVerification")]
    pub dispute_verification: DisputeEvidenceVerificationV1,
    #[serde(rename = "correctnessAssessmentAccepted")]
    pub correctness_assessment_accepted: bool,
}

pub fn listing_from_registry_entry(
    entry: &RegistryEntryV1,
    owner: impl Into<String>,
) -> Option<MarketplaceListingV1> {
    let package = entry.package_refs.first()?;
    let package_ref = package.package_ref.clone();
    let requires_license = entry.license.license_type != LicenseType::Open;
    let pricing = if requires_license {
        PricingV1 {
            mode: PricingMode::Quote,
            currency: "none".to_string(),
            base_price: 0.0,
        }
    } else {
        PricingV1 {
            mode: PricingMode::Free,
            currency: "none".to_string(),
            base_price: 0.0,
        }
    };
    let mut listing = MarketplaceListingV1 {
        schema_version: MARKETPLACE_LISTING_SCHEMA_VERSION.to_string(),
        listing_id: String::new(),
        listing_type: marketplace_listing_type_for_entry(entry),
        owner: owner.into(),
        package_id: entry.package_id.clone(),
        package_ref: Some(package_ref),
        title: entry.name.clone(),
        description_ref: None,
        pricing,
        terms_ref: entry.license.url.clone(),
        evidence_refs: marketplace_listing_evidence_refs(entry, package),
        validation_report_refs: marketplace_listing_validation_refs(entry),
        reputation_ref: marketplace_listing_reputation_ref(entry),
        details: marketplace_listing_details(entry),
        status: ListingStatus::Active,
        requires_license,
        signature: None,
    };
    sign_marketplace_listing(&mut listing);
    Some(listing)
}

pub fn open_listing_from_registry_entry(
    entry: &RegistryEntryV1,
    seller_id: impl Into<String>,
) -> Option<MarketplaceListingV1> {
    listing_from_registry_entry(entry, seller_id)
}

pub fn listing_v2_from_registry_entry(
    entry: &RegistryEntryV1,
    seller_id: impl Into<String>,
) -> Option<MarketplaceListingV2> {
    let listing = listing_from_registry_entry(entry, seller_id)?;
    let mut listing_v2 = marketplace_listing_v2_from_v1(&listing);
    listing_v2.subject.package_kind = Some(entry.kind.clone());
    listing_v2.subject.api_surfaces = api_surfaces_for_package_kind(&entry.kind);
    listing_v2.subject.modalities = modalities_for_package_kind(&entry.kind);
    listing_v2.subject.metadata["capabilities"] = json!(entry.capabilities);
    listing_v2.subject.metadata["targets"] = json!(entry.targets);
    listing_v2.subject.metadata["engines"] = json!(entry.engines);
    listing_v2.listing_id = canonical_marketplace_listing_v2_id(&listing_v2);
    listing_v2.signature = Some(expected_marketplace_listing_v2_signature(&listing_v2));
    Some(listing_v2)
}

pub fn marketplace_listing_v2_from_v1(listing: &MarketplaceListingV1) -> MarketplaceListingV2 {
    let listing_type = marketplace_listing_kind_v2_from_v1(listing);
    let subject_ref = listing
        .package_ref
        .clone()
        .or_else(|| {
            listing
                .details
                .get("subjectRef")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| {
            format!(
                "local://marketplace/listings/{}/subject",
                listing.listing_id
            )
        });
    let package_kind = listing
        .details
        .get("packageKind")
        .cloned()
        .and_then(|value| serde_json::from_value::<PackageKind>(value).ok());
    let mut listing_v2 = MarketplaceListingV2 {
        schema_version: MARKETPLACE_LISTING_V2_SCHEMA_VERSION.to_string(),
        object_kind: "marketplace_listing".to_string(),
        listing_id: String::new(),
        listing_type: listing_type.clone(),
        seller: listing.owner.clone(),
        subject: MarketplaceListingSubjectV2 {
            subject_type: subject_type_for_listing_kind_v2(&listing_type).to_string(),
            subject_ref,
            package_id: Some(listing.package_id.clone()),
            package_kind,
            api_surfaces: listing
                .details
                .get("supportedApis")
                .and_then(parse_api_surfaces)
                .unwrap_or_default(),
            modalities: listing
                .details
                .get("modalities")
                .and_then(parse_modalities)
                .unwrap_or_default(),
            metadata: json!({
                "sourceDetails": listing.details,
                "requiresLicense": listing.requires_license,
                "legacyListingType": listing.listing_type
            }),
        },
        title: listing.title.clone(),
        description_ref: listing.description_ref.clone(),
        price_model: MarketplacePriceModelV2 {
            mode: listing.pricing.mode.clone(),
            currency: listing.pricing.currency.clone(),
            unit: price_hint(listing).unit,
            base_price: listing.pricing.base_price,
            price_hints: vec![price_hint(listing)],
        },
        access_policy: listing
            .details
            .get("policySummary")
            .cloned()
            .unwrap_or_else(|| {
                json!({
                    "requiresLicense": listing.requires_license,
                    "source": "marketplace-listing-v1"
                })
            }),
        service_level: MarketplaceServiceLevelV2 {
            availability_target: listing
                .details
                .get("serviceLevel")
                .and_then(|value| value.get("availabilityTarget"))
                .and_then(Value::as_f64),
            p95_first_output_ms: listing
                .details
                .get("serviceLevel")
                .and_then(|value| value.get("p95FirstOutputMs"))
                .and_then(Value::as_u64),
            max_queue_depth: listing
                .details
                .get("serviceLevel")
                .and_then(|value| value.get("maxQueueDepth"))
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            regions: listing
                .details
                .get("serviceLevel")
                .and_then(|value| value.get("regions"))
                .and_then(parse_string_array)
                .unwrap_or_default(),
            metadata: json!({}),
        },
        privacy_tiers: listing
            .details
            .get("privacyTiers")
            .and_then(parse_privacy_tiers)
            .unwrap_or_else(|| default_privacy_tiers_for_listing_kind_v2(&listing_type)),
        verification_tiers: listing
            .details
            .get("verificationTiers")
            .and_then(parse_integrity_tiers)
            .unwrap_or_else(|| {
                default_verification_tiers_for_listing_kind_v2(
                    &listing_type,
                    !listing.validation_report_refs.is_empty(),
                )
            }),
        settlement_terms: json!({
            "settlementModel": settlement_model_for_pricing(&listing.pricing.mode),
            "requiresReceipt": listing_requires_receipt(&listing_type),
            "prepayAllowed": matches!(
                listing_type,
                MarketplaceListingKindV2::PackageLicense
                    | MarketplaceListingKindV2::PackageSubscription
                    | MarketplaceListingKindV2::DatasetLicense
            )
        }),
        dispute_terms: json!({
            "evidenceRequired": true,
            "privateDataPolicy": "hashes-or-encrypted-evidence",
            "refundPath": "settlement-resolution"
        }),
        evidence_refs: listing.evidence_refs.clone(),
        validation_report_refs: listing.validation_report_refs.clone(),
        reputation_ref: listing.reputation_ref.clone(),
        expires_at: listing
            .details
            .get("expiresAt")
            .and_then(Value::as_str)
            .map(str::to_string),
        source_listing_id: Some(listing.listing_id.clone()),
        signature: None,
    };
    listing_v2.listing_id = canonical_marketplace_listing_v2_id(&listing_v2);
    listing_v2.signature = Some(expected_marketplace_listing_v2_signature(&listing_v2));
    listing_v2
}

fn marketplace_listing_type_for_entry(entry: &RegistryEntryV1) -> MarketplaceListingType {
    match &entry.kind {
        PackageKind::Dataset => MarketplaceListingType::DatasetLicense,
        PackageKind::VectorIndex | PackageKind::RagPipeline => {
            MarketplaceListingType::VectorStoreService
        }
        PackageKind::Benchmark | PackageKind::EvalSuite | PackageKind::ScoringMethod => {
            MarketplaceListingType::BenchmarkBounty
        }
        PackageKind::Service
        | PackageKind::EmbeddingService
        | PackageKind::RerankerService
        | PackageKind::ImageGenerationService
        | PackageKind::ImageUnderstandingService
        | PackageKind::SpeechToTextService
        | PackageKind::TextToSpeechService
        | PackageKind::RealtimeSessionService
        | PackageKind::ServiceAdapter => MarketplaceListingType::HostedAiService,
        PackageKind::ResearchExperiment => MarketplaceListingType::ResearchGrant,
        _ => MarketplaceListingType::PackageLicense,
    }
}

fn marketplace_listing_evidence_refs(
    entry: &RegistryEntryV1,
    package: &hivemind_core::registry::RegistryPackageRef,
) -> Vec<String> {
    let mut evidence_refs = Vec::new();
    push_evidence_ref(&mut evidence_refs, &package.package_ref);
    push_evidence_ref(
        &mut evidence_refs,
        format!("sha256://{}", package.manifest_hash),
    );
    if let Some(profile_ref) = entry.publisher.publisher_profile_ref.as_deref() {
        push_evidence_ref(&mut evidence_refs, profile_ref);
    }
    for benchmark in &entry.benchmark_scores {
        push_evidence_ref(
            &mut evidence_refs,
            format!("local://evaluation/{}", benchmark.evaluation_id),
        );
    }
    evidence_refs
}

fn marketplace_listing_validation_refs(entry: &RegistryEntryV1) -> Vec<String> {
    let mut validation_refs = Vec::new();
    if entry.trust.validator_score.is_some() {
        push_evidence_ref(
            &mut validation_refs,
            format!(
                "local://validation/package/{}",
                safe_file_component(&entry.package_id)
            ),
        );
    }
    validation_refs
}

fn marketplace_listing_reputation_ref(entry: &RegistryEntryV1) -> Option<String> {
    entry.trust.validator_score.map(|_| {
        format!(
            "local://reputation/package/{}",
            safe_file_component(&entry.package_id)
        )
    })
}

fn marketplace_listing_details(entry: &RegistryEntryV1) -> Value {
    json!({
        "packageKind": entry.kind.clone(),
        "capabilities": entry.capabilities.clone(),
        "targets": entry.targets.clone(),
        "engines": entry.engines.clone(),
        "trust": {
            "signatureVerified": entry.trust.signature_verified,
            "validatorScore": entry.trust.validator_score,
            "curated": entry.trust.curated,
            "downloadCountApprox": entry.trust.download_count_approx
        },
        "policySummary": entry.policy_summary.clone()
    })
}

pub fn sign_marketplace_listing(listing: &mut MarketplaceListingV1) {
    listing.signature = Some(expected_marketplace_listing_signature(listing));
    listing.listing_id = canonical_marketplace_listing_id(listing);
}

pub fn sign_marketplace_listing_with_identity(
    listing: &mut MarketplaceListingV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != listing.owner {
        anyhow::bail!(
            "identity subject {} does not match marketplace listing owner {}",
            identity.subject,
            listing.owner
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "marketplace-listing",
        &marketplace_listing_signing_value(listing),
    )?;
    listing.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    listing.listing_id = canonical_marketplace_listing_id(listing);
    Ok(envelope)
}

pub fn expected_marketplace_listing_signature(listing: &MarketplaceListingV1) -> String {
    format!(
        "{DEV_MARKETPLACE_LISTING_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&marketplace_listing_signing_value(
            listing
        )))
    )
}

pub fn canonical_marketplace_listing_id(listing: &MarketplaceListingV1) -> String {
    stable_id("listing", &marketplace_listing_signing_value(listing))
}

pub fn verify_marketplace_listing(
    listing: &MarketplaceListingV1,
) -> MarketplaceListingVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_marketplace_listing_signature(listing));
    let current_schema = listing.schema_version == MARKETPLACE_LISTING_SCHEMA_VERSION;
    let signature = listing
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if !matches!(
        listing.schema_version.as_str(),
        MARKETPLACE_LISTING_SCHEMA_VERSION | LEGACY_MARKETPLACE_LISTING_SCHEMA_VERSION
    ) {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.marketplace_listing.v1",
        ));
    }
    if current_schema {
        if is_legacy_listing_type(&listing.listing_type) {
            warnings.push(marketplace_issue(
                "$.listingType",
                "Current marketplace listing should use a v0.2 concrete listing type",
            ));
        }
        if listing.evidence_refs.is_empty() {
            issues.push(marketplace_issue(
                "$.evidenceRefs",
                "Current marketplace listing schema requires evidenceRefs",
            ));
        }
    }
    if listing.listing_id.trim().is_empty() {
        issues.push(marketplace_issue("$.listingId", "Listing id is required"));
    } else if signature.is_some() && listing.listing_id != canonical_marketplace_listing_id(listing)
    {
        issues.push(marketplace_issue(
            "$.listingId",
            "Listing id does not match canonical signed content",
        ));
    }
    if listing.owner.trim().is_empty() {
        issues.push(marketplace_issue("$.owner", "Listing owner is required"));
    }
    if listing.package_id.trim().is_empty() {
        issues.push(marketplace_issue("$.packageId", "Package id is required"));
    }
    if listing.title.trim().is_empty() {
        issues.push(marketplace_issue("$.title", "Listing title is required"));
    }
    if let Some(package_ref) = &listing.package_ref {
        if package_ref.trim().is_empty() {
            issues.push(marketplace_issue(
                "$.packageRef",
                "Package ref must not be empty when present",
            ));
        } else if !package_ref.starts_with("bzz://") {
            warnings.push(marketplace_issue(
                "$.packageRef",
                "Listing packageRef is not a bzz:// reference",
            ));
        }
    }
    if let Some(description_ref) = &listing.description_ref {
        if description_ref.trim().is_empty() {
            issues.push(marketplace_issue(
                "$.descriptionRef",
                "Description ref must not be empty when present",
            ));
        } else if !looks_like_marketplace_ref(description_ref) {
            warnings.push(marketplace_issue(
                "$.descriptionRef",
                "Description ref is not a recognized bzz:// or local:// reference",
            ));
        }
    }
    for (index, evidence_ref) in listing.evidence_refs.iter().enumerate() {
        if evidence_ref.trim().is_empty() {
            issues.push(marketplace_issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference must not be empty",
            ));
        } else if !looks_like_marketplace_ref(evidence_ref) {
            warnings.push(marketplace_issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference is not a recognized storage or audit reference",
            ));
        }
    }
    for (index, validation_ref) in listing.validation_report_refs.iter().enumerate() {
        if validation_ref.trim().is_empty() {
            issues.push(marketplace_issue(
                format!("$.validationReportRefs[{index}]"),
                "Validation report reference must not be empty",
            ));
        } else if !looks_like_marketplace_ref(validation_ref) {
            warnings.push(marketplace_issue(
                format!("$.validationReportRefs[{index}]"),
                "Validation report reference is not a recognized storage or audit reference",
            ));
        }
    }
    if let Some(reputation_ref) = &listing.reputation_ref {
        if reputation_ref.trim().is_empty() {
            issues.push(marketplace_issue(
                "$.reputationRef",
                "Reputation ref must not be empty when present",
            ));
        } else if !looks_like_marketplace_ref(reputation_ref) {
            warnings.push(marketplace_issue(
                "$.reputationRef",
                "Reputation ref is not a recognized storage or audit reference",
            ));
        }
    }
    if listing.pricing.base_price < 0.0 {
        issues.push(marketplace_issue(
            "$.pricing.basePrice",
            "Base price must not be negative",
        ));
    }
    if listing.pricing.currency.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.pricing.currency",
            "Pricing currency is required",
        ));
    }
    if listing.requires_license && matches!(listing.pricing.mode, PricingMode::Free) {
        warnings.push(marketplace_issue(
            "$.pricing.mode",
            "Licensed listings usually require quote, subscription, token-gated, or paid pricing",
        ));
    }

    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "marketplace-listing",
                &marketplace_listing_signing_value(listing),
                Some(&listing.owner),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(marketplace_issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(marketplace_issue(
                "$.signature",
                "Marketplace listing signature does not match canonical dev signature or Ed25519 identity envelope",
            ));
        }
    } else {
        warnings.push(marketplace_issue(
            "$.signature",
            "Marketplace listing is unsigned; verify owner and listingId through a trusted source",
        ));
    }

    MarketplaceListingVerificationV1 {
        schema_version: MARKETPLACE_LISTING_VERIFICATION_SCHEMA_VERSION.to_string(),
        listing_id: listing.listing_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn sign_marketplace_listing_v2(listing: &mut MarketplaceListingV2) {
    listing.signature = Some(expected_marketplace_listing_v2_signature(listing));
    listing.listing_id = canonical_marketplace_listing_v2_id(listing);
}

pub fn sign_marketplace_listing_v2_with_identity(
    listing: &mut MarketplaceListingV2,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != listing.seller {
        anyhow::bail!(
            "identity subject {} does not match marketplace listing seller {}",
            identity.subject,
            listing.seller
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "marketplace-listing-v2",
        &marketplace_listing_v2_signing_value(listing),
    )?;
    listing.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    listing.listing_id = canonical_marketplace_listing_v2_id(listing);
    Ok(envelope)
}

pub fn expected_marketplace_listing_v2_signature(listing: &MarketplaceListingV2) -> String {
    format!(
        "{DEV_MARKETPLACE_LISTING_V2_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&marketplace_listing_v2_signing_value(
            listing
        )))
    )
}

pub fn canonical_marketplace_listing_v2_id(listing: &MarketplaceListingV2) -> String {
    stable_id("listing", &marketplace_listing_v2_signing_value(listing))
}

pub fn verify_marketplace_listing_v2(
    listing: &MarketplaceListingV2,
) -> MarketplaceListingV2VerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_marketplace_listing_v2_signature(listing));
    let signature = listing
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if listing.schema_version != MARKETPLACE_LISTING_V2_SCHEMA_VERSION {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.marketplace_listing.v2",
        ));
    }
    if listing.object_kind != "marketplace_listing" {
        issues.push(marketplace_issue(
            "$.objectKind",
            "Expected objectKind to be marketplace_listing",
        ));
    }
    if listing.listing_id.trim().is_empty() {
        issues.push(marketplace_issue("$.listingId", "Listing id is required"));
    } else if signature.is_some()
        && listing.listing_id != canonical_marketplace_listing_v2_id(listing)
    {
        issues.push(marketplace_issue(
            "$.listingId",
            "Listing id does not match canonical signed content",
        ));
    }
    if listing.seller.trim().is_empty() {
        issues.push(marketplace_issue("$.seller", "Listing seller is required"));
    }
    if listing.title.trim().is_empty() {
        issues.push(marketplace_issue("$.title", "Listing title is required"));
    }
    if listing.subject.subject_ref.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.subject.subjectRef",
            "Listing subjectRef is required",
        ));
    } else if !looks_like_marketplace_ref(&listing.subject.subject_ref) {
        warnings.push(marketplace_issue(
            "$.subject.subjectRef",
            "Listing subjectRef is not a recognized storage or audit reference",
        ));
    }
    if listing.subject.subject_type != subject_type_for_listing_kind_v2(&listing.listing_type) {
        issues.push(marketplace_issue(
            "$.subject.subjectType",
            "Listing subjectType must match listingType",
        ));
    }
    if listing.price_model.currency.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.priceModel.currency",
            "Price model currency is required",
        ));
    }
    if !listing.price_model.base_price.is_finite() || listing.price_model.base_price < 0.0 {
        issues.push(marketplace_issue(
            "$.priceModel.basePrice",
            "Price model basePrice must be a finite non-negative number",
        ));
    }
    if listing.price_model.unit.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.priceModel.unit",
            "Price model unit is required",
        ));
    }
    if listing.privacy_tiers.is_empty() {
        issues.push(marketplace_issue(
            "$.privacyTiers",
            "MarketplaceListingV2 must declare supported privacy tiers",
        ));
    }
    if listing.verification_tiers.is_empty() {
        issues.push(marketplace_issue(
            "$.verificationTiers",
            "MarketplaceListingV2 must declare supported verification tiers",
        ));
    }
    if listing.evidence_refs.is_empty() {
        issues.push(marketplace_issue(
            "$.evidenceRefs",
            "MarketplaceListingV2 requires evidenceRefs",
        ));
    }
    for (index, evidence_ref) in listing.evidence_refs.iter().enumerate() {
        if evidence_ref.trim().is_empty() {
            issues.push(marketplace_issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference must not be empty",
            ));
        } else if !looks_like_marketplace_ref(evidence_ref) {
            warnings.push(marketplace_issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference is not a recognized storage or audit reference",
            ));
        }
    }
    for (index, validation_ref) in listing.validation_report_refs.iter().enumerate() {
        if validation_ref.trim().is_empty() {
            issues.push(marketplace_issue(
                format!("$.validationReportRefs[{index}]"),
                "Validation report reference must not be empty",
            ));
        } else if !looks_like_marketplace_ref(validation_ref) {
            warnings.push(marketplace_issue(
                format!("$.validationReportRefs[{index}]"),
                "Validation report reference is not a recognized storage or audit reference",
            ));
        }
    }
    if let Some(expires_at) = &listing.expires_at {
        if DateTime::parse_from_rfc3339(expires_at).is_err() {
            issues.push(marketplace_issue(
                "$.expiresAt",
                "Listing expiresAt must be an RFC3339 timestamp when present",
            ));
        }
    } else if matches!(
        listing.listing_type,
        MarketplaceListingKindV2::GpuCapacity
            | MarketplaceListingKindV2::BatchCapacity
            | MarketplaceListingKindV2::ConfidentialRunner
            | MarketplaceListingKindV2::HostedInference
            | MarketplaceListingKindV2::ValidatorService
    ) {
        warnings.push(marketplace_issue(
            "$.expiresAt",
            "Service and capacity listings should expire or refresh to avoid stale prices",
        ));
    }
    if listing_requires_receipt(&listing.listing_type)
        && !listing
            .settlement_terms
            .get("requiresReceipt")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        issues.push(marketplace_issue(
            "$.settlementTerms.requiresReceipt",
            "Execution, validator, and bounty listings must require receipt-backed settlement",
        ));
    }
    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "marketplace-listing-v2",
                &marketplace_listing_v2_signing_value(listing),
                Some(&listing.seller),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(marketplace_issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(marketplace_issue(
                "$.signature",
                "MarketplaceListingV2 signature does not match canonical dev signature or Ed25519 identity envelope",
            ));
        }
    } else {
        warnings.push(marketplace_issue(
            "$.signature",
            "MarketplaceListingV2 is unsigned; verify seller and listingId through a trusted source",
        ));
    }

    MarketplaceListingV2VerificationV1 {
        schema_version: MARKETPLACE_LISTING_V2_VERIFICATION_SCHEMA_VERSION.to_string(),
        listing_id: listing.listing_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn price_hint(listing: &MarketplaceListingV1) -> PriceHintV1 {
    PriceHintV1 {
        amount: listing.pricing.base_price,
        currency: listing.pricing.currency.clone(),
        unit: match listing.pricing.mode {
            PricingMode::Free => "execution",
            PricingMode::PayPerCall => "call",
            PricingMode::PayPerToken => "token",
            PricingMode::Subscription => "period",
            PricingMode::Quote => "quote",
            PricingMode::StakeRewarded => "stake-reward",
        }
        .to_string(),
    }
}

pub fn default_local_runner_offer(
    descriptor: &RunnerDescriptorV1,
    supported_package_refs: Vec<String>,
) -> RunnerOfferV1 {
    offer_from_runner_descriptor(
        descriptor,
        "local://runner-descriptor/local-dev-runner",
        supported_package_refs,
        RunnerPricingV1 {
            input_token_price: 0.0,
            output_token_price: 0.0,
            currency: "none".to_string(),
        },
        RunnerServiceLevelV1 {
            p95_first_token_ms: 900,
            availability_target: 0.99,
        },
        RunnerReputationV1 {
            validator_score: 0.80,
            completed_jobs: 0,
        },
    )
}

pub fn offer_from_runner_descriptor(
    descriptor: &RunnerDescriptorV1,
    runner_descriptor_ref: impl Into<String>,
    supported_package_refs: Vec<String>,
    pricing: RunnerPricingV1,
    service_level: RunnerServiceLevelV1,
    reputation: RunnerReputationV1,
) -> RunnerOfferV1 {
    let capability = runner_capability_from_descriptor(descriptor);
    let runner_slug = safe_file_component(&descriptor.runner_id);
    let price_table = runner_offer_price_table(&pricing, &capability);
    let mut offer = RunnerOfferV1 {
        schema_version: RUNNER_OFFER_SCHEMA_VERSION.to_string(),
        offer_id: String::new(),
        runner_id: descriptor.runner_id.clone(),
        identity: Some(format!("local://runner/{runner_slug}")),
        public_key: Some("local-dev-public-key-unavailable".to_string()),
        runner_type: descriptor.runner_type.clone(),
        runner_descriptor_ref: runner_descriptor_ref.into(),
        supported_package_refs,
        supported_capabilities: descriptor.capabilities.clone(),
        supported_apis: capability.supported_apis,
        supported_modalities: capability.supported_modalities,
        supported_package_kinds: capability.supported_package_kinds,
        supported_model_formats: capability.supported_model_formats,
        engines: capability.engines,
        hardware: Some(capability.hardware),
        memory: Some(capability.memory),
        max_context_tokens: capability.max_context_tokens,
        max_batch_size: capability.max_batch_size,
        streaming_modes: capability.streaming_modes,
        price_table,
        cache_claims: capability.cache_claims,
        privacy_tiers: capability.privacy_tiers,
        verification_tiers: capability.verification_tiers,
        region_hint: capability.region_hint,
        validator_score_ref: Some(format!("local://reputation/runner/{runner_slug}")),
        terms_ref: Some(format!("local://terms/runner-offer/{runner_slug}")),
        expires_at: Some(
            (Utc::now() + chrono::Duration::minutes(10)).to_rfc3339_opts(SecondsFormat::Secs, true),
        ),
        pricing,
        service_level,
        reputation,
        signature: None,
    };
    sign_runner_offer(&mut offer);
    offer
}

fn runner_offer_price_table(
    pricing: &RunnerPricingV1,
    capability: &RunnerCapabilityV1,
) -> Vec<RunnerPriceEntryV1> {
    if pricing.input_token_price == 0.0
        && pricing.output_token_price == 0.0
        && pricing.currency == "none"
        && !capability.price_table.is_empty()
    {
        return capability.price_table.clone();
    }
    vec![
        RunnerPriceEntryV1 {
            price_model: PriceModel::PerToken,
            unit: "input_token".to_string(),
            price: PriceV1 {
                amount: pricing.input_token_price,
                currency: pricing.currency.clone(),
            },
        },
        RunnerPriceEntryV1 {
            price_model: PriceModel::PerToken,
            unit: "output_token".to_string(),
            price: PriceV1 {
                amount: pricing.output_token_price,
                currency: pricing.currency.clone(),
            },
        },
    ]
}

pub fn sign_runner_offer(offer: &mut RunnerOfferV1) {
    offer.signature = Some(expected_runner_offer_signature(offer));
    offer.offer_id = canonical_runner_offer_id(offer);
}

pub fn sign_runner_offer_with_identity(
    offer: &mut RunnerOfferV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != offer.runner_id {
        anyhow::bail!(
            "identity subject {} does not match runner offer runnerId {}",
            identity.subject,
            offer.runner_id
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "runner-offer",
        &runner_offer_signing_value(offer),
    )?;
    offer.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    offer.offer_id = canonical_runner_offer_id(offer);
    Ok(envelope)
}

pub fn expected_runner_offer_signature(offer: &RunnerOfferV1) -> String {
    format!(
        "{DEV_RUNNER_OFFER_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&runner_offer_signing_value(offer)))
    )
}

pub fn canonical_runner_offer_id(offer: &RunnerOfferV1) -> String {
    stable_id("offer", &runner_offer_signing_value(offer))
}

pub fn verify_runner_offer(offer: &RunnerOfferV1) -> RunnerOfferVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_runner_offer_signature(offer));
    let current_schema = offer.schema_version == RUNNER_OFFER_SCHEMA_VERSION;
    let signature = offer
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if !matches!(
        offer.schema_version.as_str(),
        RUNNER_OFFER_SCHEMA_VERSION | LEGACY_RUNNER_OFFER_SCHEMA_VERSION
    ) {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.runner_offer.v1",
        ));
    }
    if offer.offer_id.trim().is_empty() {
        issues.push(marketplace_issue("$.offerId", "Offer id is required"));
    } else if signature.is_some() && offer.offer_id != canonical_runner_offer_id(offer) {
        issues.push(marketplace_issue(
            "$.offerId",
            "Offer id does not match canonical signed content",
        ));
    }
    if offer.runner_id.trim().is_empty() {
        issues.push(marketplace_issue("$.runnerId", "Runner id is required"));
    }
    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "runner-offer",
                &runner_offer_signing_value(offer),
                Some(&offer.runner_id),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(marketplace_issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(marketplace_issue(
                "$.signature",
                "Runner offer signature does not match canonical dev signature or Ed25519 identity envelope",
            ));
        }
    } else {
        warnings.push(marketplace_issue(
            "$.signature",
            "Runner offer is unsigned; verify runnerId and offerId through a trusted source",
        ));
    }
    if offer.runner_descriptor_ref.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.runnerDescriptorRef",
            "Runner descriptor ref is required",
        ));
    } else if !looks_like_marketplace_ref(&offer.runner_descriptor_ref) {
        warnings.push(marketplace_issue(
            "$.runnerDescriptorRef",
            "Runner descriptor ref is not a recognized bzz:// or local:// reference",
        ));
    }
    if offer.supported_capabilities.is_empty() {
        issues.push(marketplace_issue(
            "$.supportedCapabilities",
            "Offer must declare at least one supported capability",
        ));
    }
    for (index, capability) in offer.supported_capabilities.iter().enumerate() {
        if capability.trim().is_empty() {
            issues.push(marketplace_issue(
                format!("$.supportedCapabilities[{index}]"),
                "Supported capability must not be empty",
            ));
        }
    }
    for (index, package_ref) in offer.supported_package_refs.iter().enumerate() {
        if package_ref.trim().is_empty() {
            issues.push(marketplace_issue(
                format!("$.supportedPackageRefs[{index}]"),
                "Supported package ref must not be empty",
            ));
        } else if !looks_like_marketplace_ref(package_ref) {
            warnings.push(marketplace_issue(
                format!("$.supportedPackageRefs[{index}]"),
                "Supported package ref is not a recognized bzz:// or local:// reference",
            ));
        }
    }
    if current_schema {
        match offer.identity.as_deref().map(str::trim) {
            Some(identity) if !identity.is_empty() => {
                if !looks_like_marketplace_ref(identity) {
                    warnings.push(marketplace_issue(
                        "$.identity",
                        "Runner identity is not a recognized bzz:// or local:// reference",
                    ));
                }
            }
            _ => issues.push(marketplace_issue(
                "$.identity",
                "Current runner offer schema requires identity",
            )),
        }
        match offer.public_key.as_deref().map(str::trim) {
            Some(public_key) if !public_key.is_empty() => {}
            _ => warnings.push(marketplace_issue(
                "$.publicKey",
                "Current runner offer schema should include a public key or local-dev placeholder",
            )),
        }
        if offer.supported_apis.is_empty() {
            issues.push(marketplace_issue(
                "$.supportedApis",
                "Current runner offer schema requires at least one supported API",
            ));
        }
        if offer.supported_modalities.is_empty() {
            issues.push(marketplace_issue(
                "$.supportedModalities",
                "Current runner offer schema requires at least one supported modality",
            ));
        }
        if offer.supported_package_kinds.is_empty() {
            issues.push(marketplace_issue(
                "$.supportedPackageKinds",
                "Current runner offer schema requires at least one supported package kind",
            ));
        }
        for (index, package_kind) in offer.supported_package_kinds.iter().enumerate() {
            if package_kind.trim().is_empty() {
                issues.push(marketplace_issue(
                    format!("$.supportedPackageKinds[{index}]"),
                    "Supported package kind must not be empty",
                ));
            }
        }
        if offer.supported_model_formats.is_empty() {
            issues.push(marketplace_issue(
                "$.supportedModelFormats",
                "Current runner offer schema requires at least one supported model format",
            ));
        }
        for (index, model_format) in offer.supported_model_formats.iter().enumerate() {
            if model_format.trim().is_empty() {
                issues.push(marketplace_issue(
                    format!("$.supportedModelFormats[{index}]"),
                    "Supported model format must not be empty",
                ));
            }
        }
        if offer.engines.is_empty() {
            issues.push(marketplace_issue(
                "$.engines",
                "Current runner offer schema requires at least one execution engine",
            ));
        }
        for (index, engine) in offer.engines.iter().enumerate() {
            if engine.trim().is_empty() {
                issues.push(marketplace_issue(
                    format!("$.engines[{index}]"),
                    "Execution engine must not be empty",
                ));
            }
        }
        if let Some(hardware) = &offer.hardware {
            if hardware.accelerator.trim().is_empty() {
                issues.push(marketplace_issue(
                    "$.hardware.accelerator",
                    "Hardware accelerator is required",
                ));
            }
            if let Some(gpu_memory_mb) = hardware.gpu_memory_mb
                && gpu_memory_mb == 0
            {
                issues.push(marketplace_issue(
                    "$.hardware.gpuMemoryMB",
                    "GPU memory must be greater than zero when present",
                ));
            }
            if let Some(cpu_threads) = hardware.cpu_threads
                && cpu_threads == 0
            {
                issues.push(marketplace_issue(
                    "$.hardware.cpuThreads",
                    "CPU thread count must be greater than zero when present",
                ));
            }
        } else {
            issues.push(marketplace_issue(
                "$.hardware",
                "Current runner offer schema requires hardware",
            ));
        }
        if let Some(memory) = &offer.memory {
            if memory.memory_mb == 0 {
                issues.push(marketplace_issue(
                    "$.memory.memoryMB",
                    "Memory capacity must be greater than zero",
                ));
            }
            if memory.max_input_bytes == 0 {
                issues.push(marketplace_issue(
                    "$.memory.maxInputBytes",
                    "Max input bytes must be greater than zero",
                ));
            }
            if memory.max_concurrent_jobs == 0 {
                issues.push(marketplace_issue(
                    "$.memory.maxConcurrentJobs",
                    "Max concurrent jobs must be greater than zero",
                ));
            }
        } else {
            issues.push(marketplace_issue(
                "$.memory",
                "Current runner offer schema requires memory",
            ));
        }
        if let Some(max_context_tokens) = offer.max_context_tokens
            && max_context_tokens == 0
        {
            issues.push(marketplace_issue(
                "$.maxContextTokens",
                "Max context tokens must be greater than zero when present",
            ));
        }
        if let Some(max_batch_size) = offer.max_batch_size
            && max_batch_size == 0
        {
            issues.push(marketplace_issue(
                "$.maxBatchSize",
                "Max batch size must be greater than zero when present",
            ));
        }
        if offer.streaming_modes.is_empty() {
            issues.push(marketplace_issue(
                "$.streamingModes",
                "Current runner offer schema requires at least one streaming mode",
            ));
        }
        for (index, mode) in offer.streaming_modes.iter().enumerate() {
            if mode.trim().is_empty() {
                issues.push(marketplace_issue(
                    format!("$.streamingModes[{index}]"),
                    "Streaming mode must not be empty",
                ));
            }
        }
        if offer.price_table.is_empty() {
            issues.push(marketplace_issue(
                "$.priceTable",
                "Current runner offer schema requires a comparable price table",
            ));
        }
        for (index, entry) in offer.price_table.iter().enumerate() {
            if entry.price.amount < 0.0 {
                issues.push(marketplace_issue(
                    format!("$.priceTable[{index}].price.amount"),
                    "Price amount must not be negative",
                ));
            }
            if entry.price.currency.trim().is_empty() {
                issues.push(marketplace_issue(
                    format!("$.priceTable[{index}].price.currency"),
                    "Price currency is required",
                ));
            }
            if entry.unit.trim().is_empty() {
                issues.push(marketplace_issue(
                    format!("$.priceTable[{index}].unit"),
                    "Price unit is required",
                ));
            }
        }
        for (index, claim) in offer.cache_claims.iter().enumerate() {
            if claim.package_ref.trim().is_empty() {
                issues.push(marketplace_issue(
                    format!("$.cacheClaims[{index}].packageRef"),
                    "Cache claim package ref must not be empty",
                ));
            } else if !looks_like_marketplace_ref(&claim.package_ref) {
                warnings.push(marketplace_issue(
                    format!("$.cacheClaims[{index}].packageRef"),
                    "Cache claim package ref is not a recognized bzz:// or local:// reference",
                ));
            }
        }
        if offer.privacy_tiers.is_empty() {
            issues.push(marketplace_issue(
                "$.privacyTiers",
                "Current runner offer schema requires at least one privacy tier",
            ));
        }
        if offer.verification_tiers.is_empty() {
            issues.push(marketplace_issue(
                "$.verificationTiers",
                "Current runner offer schema requires at least one verification tier",
            ));
        }
        if let Some(region_hint) = offer.region_hint.as_deref()
            && region_hint.trim().is_empty()
        {
            issues.push(marketplace_issue(
                "$.regionHint",
                "Region hint must not be empty when present",
            ));
        }
        if let Some(validator_score_ref) = offer.validator_score_ref.as_deref() {
            if validator_score_ref.trim().is_empty() {
                issues.push(marketplace_issue(
                    "$.validatorScoreRef",
                    "Validator score ref must not be empty when present",
                ));
            } else if !looks_like_marketplace_ref(validator_score_ref) {
                warnings.push(marketplace_issue(
                    "$.validatorScoreRef",
                    "Validator score ref is not a recognized bzz:// or local:// reference",
                ));
            }
        } else {
            warnings.push(marketplace_issue(
                "$.validatorScoreRef",
                "Current runner offer schema should link validator reputation evidence",
            ));
        }
        match offer.terms_ref.as_deref().map(str::trim) {
            Some(terms_ref) if !terms_ref.is_empty() => {
                if !looks_like_marketplace_ref(terms_ref) {
                    warnings.push(marketplace_issue(
                        "$.termsRef",
                        "Terms ref is not a recognized bzz:// or local:// reference",
                    ));
                }
            }
            _ => issues.push(marketplace_issue(
                "$.termsRef",
                "Current runner offer schema requires termsRef",
            )),
        }
        match offer.expires_at.as_deref().map(str::trim) {
            Some(expires_at) if !expires_at.is_empty() => {
                match DateTime::parse_from_rfc3339(expires_at) {
                    Ok(expires_at) if expires_at.with_timezone(&Utc) <= Utc::now() => {
                        issues.push(marketplace_issue("$.expiresAt", "Runner offer has expired"));
                    }
                    Ok(_) => {}
                    Err(_) => issues.push(marketplace_issue(
                        "$.expiresAt",
                        "expiresAt must be an RFC3339 timestamp",
                    )),
                }
            }
            _ => issues.push(marketplace_issue(
                "$.expiresAt",
                "Current runner offer schema requires expiresAt",
            )),
        }
    }
    if offer.pricing.input_token_price < 0.0 {
        issues.push(marketplace_issue(
            "$.pricing.inputTokenPrice",
            "Input token price must not be negative",
        ));
    }
    if offer.pricing.output_token_price < 0.0 {
        issues.push(marketplace_issue(
            "$.pricing.outputTokenPrice",
            "Output token price must not be negative",
        ));
    }
    if offer.pricing.currency.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.pricing.currency",
            "Pricing currency is required",
        ));
    }
    if offer.service_level.availability_target < 0.0
        || offer.service_level.availability_target > 1.0
    {
        issues.push(marketplace_issue(
            "$.serviceLevel.availabilityTarget",
            "Availability target must be between 0 and 1",
        ));
    }
    if offer.reputation.validator_score < 0.0 || offer.reputation.validator_score > 1.0 {
        issues.push(marketplace_issue(
            "$.reputation.validatorScore",
            "Validator score must be between 0 and 1",
        ));
    }

    RunnerOfferVerificationV1 {
        schema_version: RUNNER_OFFER_VERIFICATION_SCHEMA_VERSION.to_string(),
        offer_id: offer.offer_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn default_hardware_resource_offer(
    descriptor: &RunnerDescriptorV1,
    operator: impl Into<String>,
) -> HardwareResourceOfferV1 {
    let capability = runner_capability_from_descriptor(descriptor);
    hardware_resource_offer_from_capability(
        &capability,
        operator,
        "local://terms/hardware-resource-offer/dev",
        Utc::now() + chrono::Duration::minutes(15),
    )
}

pub fn hardware_resource_offer_from_capability(
    capability: &RunnerCapabilityV1,
    operator: impl Into<String>,
    terms_ref: impl Into<String>,
    expires_at: DateTime<Utc>,
) -> HardwareResourceOfferV1 {
    let mut offer = HardwareResourceOfferV1 {
        schema_version: HARDWARE_RESOURCE_OFFER_SCHEMA_VERSION.to_string(),
        offer_id: String::new(),
        runner_id: capability.runner_id.clone(),
        operator: operator.into(),
        hardware: hardware_resource_from_capability(capability),
        supported_execution_modes: execution_modes_from_capability(capability),
        supported_engines: capability.engines.clone(),
        supported_apis: capability.supported_apis.clone(),
        supported_modalities: capability.supported_modalities.clone(),
        price_table: hardware_offer_price_table(capability),
        availability: HardwareAvailabilityV1 {
            available_now: true,
            queue_depth: 0,
            max_concurrent_jobs: capability.memory.max_concurrent_jobs,
            schedule_refs: Vec::new(),
        },
        cache_claims: capability.cache_claims.clone(),
        privacy_tiers: capability.privacy_tiers.clone(),
        verification_tiers: capability.verification_tiers.clone(),
        trust_tier: miner_trust_tier_for_capability(capability),
        stake: None,
        benchmark_result_refs: Vec::new(),
        terms_ref: terms_ref.into(),
        expires_at: expires_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_hardware_resource_offer(&mut offer);
    offer
}

pub fn sign_hardware_resource_offer(offer: &mut HardwareResourceOfferV1) {
    offer.signature = Some(expected_hardware_resource_offer_signature(offer));
    offer.offer_id = canonical_hardware_resource_offer_id(offer);
}

pub fn sign_hardware_resource_offer_with_identity(
    offer: &mut HardwareResourceOfferV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != offer.operator {
        anyhow::bail!(
            "identity subject {} does not match hardware resource offer operator {}",
            identity.subject,
            offer.operator
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "hardware-resource-offer",
        &hardware_resource_offer_signing_value(offer),
    )?;
    offer.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    offer.offer_id = canonical_hardware_resource_offer_id(offer);
    Ok(envelope)
}

pub fn expected_hardware_resource_offer_signature(offer: &HardwareResourceOfferV1) -> String {
    format!(
        "{DEV_HARDWARE_RESOURCE_OFFER_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&hardware_resource_offer_signing_value(
            offer
        )))
    )
}

pub fn canonical_hardware_resource_offer_id(offer: &HardwareResourceOfferV1) -> String {
    stable_id(
        "hardware-offer",
        &hardware_resource_offer_signing_value(offer),
    )
}

pub fn verify_hardware_resource_offer(
    offer: &HardwareResourceOfferV1,
) -> HardwareResourceOfferVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_hardware_resource_offer_signature(offer));
    let signature = offer
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if !matches!(
        offer.schema_version.as_str(),
        HARDWARE_RESOURCE_OFFER_SCHEMA_VERSION | LEGACY_HARDWARE_RESOURCE_OFFER_SCHEMA_VERSION
    ) {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.hardware_resource_offer.v1",
        ));
    }
    if offer.offer_id.trim().is_empty() {
        issues.push(marketplace_issue("$.offerId", "Offer id is required"));
    } else if signature.is_some() && offer.offer_id != canonical_hardware_resource_offer_id(offer) {
        issues.push(marketplace_issue(
            "$.offerId",
            "Offer id does not match canonical signed content",
        ));
    }
    if offer.runner_id.trim().is_empty() {
        issues.push(marketplace_issue("$.runnerId", "Runner id is required"));
    }
    if offer.operator.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.operator",
            "Operator identity is required",
        ));
    }
    if offer.terms_ref.trim().is_empty() {
        issues.push(marketplace_issue("$.termsRef", "Terms ref is required"));
    } else if !looks_like_marketplace_ref(&offer.terms_ref) {
        warnings.push(marketplace_issue(
            "$.termsRef",
            "Terms ref is not a recognized bzz:// or local:// reference",
        ));
    }
    if offer.supported_execution_modes.is_empty() {
        issues.push(marketplace_issue(
            "$.supportedExecutionModes",
            "Hardware offer must declare at least one execution mode",
        ));
    }
    if offer.supported_apis.is_empty() {
        issues.push(marketplace_issue(
            "$.supportedApis",
            "Hardware offer must declare at least one supported API",
        ));
    }
    if offer.supported_modalities.is_empty() {
        issues.push(marketplace_issue(
            "$.supportedModalities",
            "Hardware offer must declare at least one supported modality",
        ));
    }
    if offer.privacy_tiers.is_empty() {
        issues.push(marketplace_issue(
            "$.privacyTiers",
            "Hardware offer must declare at least one privacy tier",
        ));
    }
    if offer.verification_tiers.is_empty() {
        issues.push(marketplace_issue(
            "$.verificationTiers",
            "Hardware offer must declare at least one verification tier",
        ));
    }
    if offer.hardware.gpu_count == 0
        && offer.hardware.cpu_cores.unwrap_or_default() == 0
        && offer.hardware.ram_gb <= 0.0
    {
        issues.push(marketplace_issue(
            "$.hardware",
            "Hardware offer must declare CPU, GPU, or RAM capacity",
        ));
    }
    if offer.hardware.gpu_count > 0 && offer.hardware.vram_gb.unwrap_or_default() <= 0.0 {
        warnings.push(marketplace_issue(
            "$.hardware.vramGb",
            "GPU offers should declare VRAM for router capacity checks",
        ));
    }
    if offer.hardware.ram_gb <= 0.0 {
        issues.push(marketplace_issue(
            "$.hardware.ramGb",
            "RAM capacity must be greater than zero",
        ));
    }
    if offer.availability.max_concurrent_jobs == 0 {
        issues.push(marketplace_issue(
            "$.availability.maxConcurrentJobs",
            "Maximum concurrent jobs must be greater than zero",
        ));
    }
    for (index, entry) in offer.price_table.iter().enumerate() {
        if entry.price.amount < 0.0 {
            issues.push(marketplace_issue(
                format!("$.priceTable[{index}].price.amount"),
                "Price amount must not be negative",
            ));
        }
        if entry.price.currency.trim().is_empty() {
            issues.push(marketplace_issue(
                format!("$.priceTable[{index}].price.currency"),
                "Price currency is required",
            ));
        }
        if entry.unit.trim().is_empty() {
            issues.push(marketplace_issue(
                format!("$.priceTable[{index}].unit"),
                "Price unit is required",
            ));
        }
    }
    if let Some(stake) = &offer.stake {
        if stake.amount < 0.0 {
            issues.push(marketplace_issue(
                "$.stake.amount",
                "Stake amount must not be negative",
            ));
        }
        if stake.currency.trim().is_empty() {
            issues.push(marketplace_issue(
                "$.stake.currency",
                "Stake currency is required when stake is present",
            ));
        }
    }
    match DateTime::parse_from_rfc3339(&offer.expires_at) {
        Ok(expires_at) if expires_at.with_timezone(&Utc) <= Utc::now() => {
            issues.push(marketplace_issue(
                "$.expiresAt",
                "Hardware offer has expired",
            ));
        }
        Ok(_) => {}
        Err(_) => issues.push(marketplace_issue(
            "$.expiresAt",
            "expiresAt must be an RFC3339 timestamp",
        )),
    }

    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "hardware-resource-offer",
                &hardware_resource_offer_signing_value(offer),
                Some(&offer.operator),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(marketplace_issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(marketplace_issue(
                "$.signature",
                "Hardware resource offer signature does not match canonical dev signature or Ed25519 operator identity envelope",
            ));
        }
    } else {
        warnings.push(marketplace_issue(
            "$.signature",
            "Hardware resource offer is unsigned; verify runnerId and operator through a trusted source",
        ));
    }

    HardwareResourceOfferVerificationV1 {
        schema_version: HARDWARE_RESOURCE_OFFER_VERIFICATION_SCHEMA_VERSION.to_string(),
        offer_id: offer.offer_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn shortlist_request_from_execution(
    request: &ExecutionRequestV1,
    policy_mode: PolicyMode,
    max_results: usize,
) -> MarketplaceShortlistRequestV1 {
    let estimated_input_tokens = estimate_input_tokens(&request.input);
    MarketplaceShortlistRequestV1 {
        schema_version: MARKETPLACE_SHORTLIST_REQUEST_SCHEMA_VERSION.to_string(),
        package_ref: request.package_ref.clone(),
        task: request.task.clone(),
        api_surface: Some(ApiSurface::HivemindNative),
        modality: modality_from_task(&request.task),
        estimated_input_tokens,
        estimated_output_tokens: estimated_input_tokens,
        required_privacy_tier: Some(privacy_tier_from_execution_privacy(&request.privacy)),
        required_verification_tier: Some(IntegrityTier::ReceiptOnly),
        policy_mode,
        max_results,
        include_rejected: false,
    }
}

pub fn shortlist_runner_offers(
    request: &MarketplaceShortlistRequestV1,
    offers: &[RunnerOfferV1],
) -> MarketplaceShortlistV1 {
    let mut rankings: Vec<_> = offers
        .iter()
        .map(|offer| score_runner_offer(request, offer))
        .filter(|ranking| request.include_rejected || ranking.eligible)
        .collect();
    rankings.sort_by(|left, right| {
        right
            .score
            .partial_cmp(&left.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(left.runner_id.cmp(&right.runner_id))
            .then(left.offer_id.cmp(&right.offer_id))
    });
    let max_results = request.max_results.max(1);
    rankings.truncate(max_results);
    for (index, ranking) in rankings.iter_mut().enumerate() {
        ranking.rank = index as u32 + 1;
    }
    let selected_offer_id = rankings
        .iter()
        .find(|ranking| ranking.eligible)
        .map(|ranking| ranking.offer_id.clone());

    MarketplaceShortlistV1 {
        schema_version: MARKETPLACE_SHORTLIST_SCHEMA_VERSION.to_string(),
        package_ref: request.package_ref.clone(),
        task: request.task.clone(),
        api_surface: request.api_surface.clone(),
        modality: request.modality.clone(),
        required_privacy_tier: request.required_privacy_tier.clone(),
        required_verification_tier: request.required_verification_tier.clone(),
        policy_mode: request.policy_mode.clone(),
        selected_offer_id,
        rankings,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn score_runner_offer(
    request: &MarketplaceShortlistRequestV1,
    offer: &RunnerOfferV1,
) -> RunnerOfferScoreV1 {
    let verification = verify_runner_offer(offer);
    let mut eligible = verification.valid;
    let mut reasons = Vec::new();
    let schema_supported = matches!(
        request.schema_version.as_str(),
        MARKETPLACE_SHORTLIST_REQUEST_SCHEMA_VERSION
            | LEGACY_MARKETPLACE_SHORTLIST_REQUEST_SCHEMA_VERSION
            | LEGACY_MARKETPLACE_SHORTLIST_REQUEST_SCHEMA_VERSION_DOT
    );
    let api_matches = request
        .api_surface
        .as_ref()
        .is_none_or(|api| offer.supported_apis.contains(api));
    let modality_matches = request
        .modality
        .as_ref()
        .is_none_or(|modality| offer.supported_modalities.contains(modality));
    let selected_privacy_tier = if let Some(required) = &request.required_privacy_tier {
        select_runner_offer_privacy_tier(&offer.privacy_tiers, required)
    } else {
        preferred_runner_offer_privacy_tier(&offer.privacy_tiers)
    };
    let selected_verification_tier = if let Some(required) = &request.required_verification_tier {
        select_runner_offer_integrity_tier(&offer.verification_tiers, required)
    } else {
        preferred_runner_offer_integrity_tier(&offer.verification_tiers)
    };
    let cache_hit_claim = offer
        .cache_claims
        .iter()
        .any(|claim| claim.warmed && claim.package_ref == request.package_ref);

    if !schema_supported {
        eligible = false;
        reasons.push("Shortlist request schemaVersion is not supported".to_string());
    }
    if !verification.valid {
        eligible = false;
        reasons.push("Runner offer does not verify".to_string());
    }
    if !offer.supported_package_refs.is_empty()
        && !offer
            .supported_package_refs
            .iter()
            .any(|reference| reference == &request.package_ref)
    {
        eligible = false;
        reasons.push("Offer does not support the requested packageRef".to_string());
    }
    if !offer
        .supported_capabilities
        .iter()
        .any(|capability| capability == &request.task)
    {
        eligible = false;
        reasons.push("Offer does not support the requested task".to_string());
    }
    if let Some(api) = &request.api_surface
        && !api_matches
    {
        eligible = false;
        reasons.push(format!(
            "Offer does not support the requested API surface {}",
            tier_wire_name(api)
        ));
    }
    if let Some(modality) = &request.modality
        && !modality_matches
    {
        eligible = false;
        reasons.push(format!(
            "Offer does not support the requested modality {}",
            tier_wire_name(modality)
        ));
    }
    if let Some(required_privacy_tier) = &request.required_privacy_tier
        && selected_privacy_tier.is_none()
    {
        eligible = false;
        reasons.push(format!(
            "Offer cannot satisfy required privacy tier {}",
            tier_wire_name(required_privacy_tier)
        ));
    }
    if let Some(required_verification_tier) = &request.required_verification_tier
        && selected_verification_tier.is_none()
    {
        eligible = false;
        reasons.push(format!(
            "Offer cannot satisfy required verification tier {}",
            tier_wire_name(required_verification_tier)
        ));
    }
    if request.policy_mode == PolicyMode::PrivacyFirst
        && matches!(
            offer.runner_type,
            RunnerType::RemoteGpu | RunnerType::Marketplace
        )
    {
        eligible = false;
        reasons.push("Privacy-first policy avoids remote marketplace execution".to_string());
    }

    let estimated_cost = request.estimated_input_tokens as f64 * offer.pricing.input_token_price
        + request.estimated_output_tokens as f64 * offer.pricing.output_token_price;
    let speed_score = 1.0 / (1.0 + offer.service_level.p95_first_token_ms as f64 / 1_000.0);
    let cost_score = 1.0 / (1.0 + estimated_cost.max(0.0) * 100.0);
    let validator_score = offer.reputation.validator_score.clamp(0.0, 1.0);
    let availability = offer.service_level.availability_target.clamp(0.0, 1.0);
    let job_score = (offer.reputation.completed_jobs as f64).ln_1p() / 10.0;
    let reputation_score = validator_score * 0.65 + availability * 0.25 + job_score.min(1.0) * 0.10;
    let policy_fit_score = shortlist_policy_fit_score(
        request,
        api_matches,
        modality_matches,
        selected_privacy_tier.as_ref(),
        selected_verification_tier.as_ref(),
        cache_hit_claim,
    );
    let score = if eligible {
        let base = match request.policy_mode {
            PolicyMode::PrivacyFirst => reputation_score * 3.0 + cost_score * 3.0 + speed_score,
            PolicyMode::SpeedFirst => speed_score * 10.0 + reputation_score * 2.0 + cost_score,
            PolicyMode::CostFirst => cost_score * 10.0 + reputation_score * 2.0 + speed_score,
            PolicyMode::QualityFirst => reputation_score * 10.0 + speed_score + cost_score,
            PolicyMode::Balanced => reputation_score * 4.0 + speed_score * 3.0 + cost_score * 3.0,
            PolicyMode::Developer => reputation_score + speed_score + cost_score,
        };
        base + policy_fit_score + if cache_hit_claim { 0.5 } else { 0.0 }
    } else {
        -1.0
    };

    if reasons.is_empty() {
        reasons.push(format!(
            "Eligible offer scored for {:?} policy using cost, speed, availability, validator reputation, policy fit, and cache claims",
            request.policy_mode
        ));
    }

    RunnerOfferScoreV1 {
        schema_version: RUNNER_OFFER_SCORE_SCHEMA_VERSION.to_string(),
        rank: 0,
        offer_id: offer.offer_id.clone(),
        runner_id: offer.runner_id.clone(),
        runner_type: offer.runner_type.clone(),
        eligible,
        score,
        estimated_cost,
        currency: offer.pricing.currency.clone(),
        first_token_ms: offer.service_level.p95_first_token_ms,
        availability_target: offer.service_level.availability_target,
        validator_score: offer.reputation.validator_score,
        completed_jobs: offer.reputation.completed_jobs,
        selected_privacy_tier,
        selected_verification_tier,
        cache_hit_claim,
        policy_fit_score,
        policy_mode: request.policy_mode.clone(),
        reasons,
        verification,
    }
}

pub fn quote_execution(
    request: &ExecutionRequestV1,
    offer: &RunnerOfferV1,
    estimated_output_tokens: Option<u64>,
) -> Option<ServiceQuoteV1> {
    let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let started = Instant::now();
    if !offer.supported_package_refs.is_empty()
        && !offer
            .supported_package_refs
            .iter()
            .any(|reference| reference == &request.package_ref)
    {
        return None;
    }
    if !offer
        .supported_capabilities
        .iter()
        .any(|capability| capability == &request.task)
    {
        return None;
    }
    let requested_privacy_tier = privacy_tier_from_execution_privacy(&request.privacy);
    let selected_privacy_tier = if offer.privacy_tiers.is_empty() {
        Some(requested_privacy_tier.clone())
    } else {
        select_runner_offer_privacy_tier(&offer.privacy_tiers, &requested_privacy_tier)
    }?;
    let selected_verification_tier = if offer.verification_tiers.is_empty() {
        Some(IntegrityTier::ReceiptOnly)
    } else {
        select_runner_offer_integrity_tier(&offer.verification_tiers, &IntegrityTier::ReceiptOnly)
    }?;

    let estimated_input_tokens = estimate_input_tokens(&request.input);
    let estimated_output_tokens = estimated_output_tokens.unwrap_or(estimated_input_tokens);
    let estimated_cost = estimated_input_tokens as f64 * offer.pricing.input_token_price
        + estimated_output_tokens as f64 * offer.pricing.output_token_price;
    let settlement_model = if estimated_cost > 0.0 {
        SettlementModel::DirectPayPerCall
    } else {
        SettlementModel::Free
    };
    let expires_at =
        (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339_opts(SecondsFormat::Secs, true);
    let currency = offer.pricing.currency.clone();
    let price = PriceV1 {
        amount: estimated_cost,
        currency: currency.clone(),
    };
    let estimated_start_delay_ms = 0;
    let estimated_time_to_first_output_ms = offer.service_level.p95_first_token_ms;
    let estimated_completion_ms = estimated_time_to_first_output_ms
        .saturating_add(estimated_output_tokens.saturating_mul(10));
    let validation_support = service_quote_validation_support(offer);
    let cache_hit_claim = offer
        .cache_claims
        .iter()
        .any(|claim| claim.warmed && claim.package_ref == request.package_ref);
    let mut quote = ServiceQuoteV1 {
        schema_version: SERVICE_QUOTE_SCHEMA_VERSION.to_string(),
        quote_id: String::new(),
        job_id: Some(format!("job-for-{}", request.request_id)),
        request_id: request.request_id.clone(),
        offer_id: offer.offer_id.clone(),
        listing_id: Some(offer.offer_id.clone()),
        runner_id: offer.runner_id.clone(),
        package_ref: request.package_ref.clone(),
        estimated_input_tokens,
        estimated_output_tokens,
        estimated_cost,
        currency: currency.clone(),
        price: Some(price),
        price_model: Some(PriceModel::PerToken),
        privacy_mode: Some(selected_privacy_tier),
        verification_mode: Some(selected_verification_tier),
        estimated_start_delay_ms: Some(estimated_start_delay_ms),
        estimated_time_to_first_output_ms: Some(estimated_time_to_first_output_ms),
        estimated_completion_ms: Some(estimated_completion_ms),
        cache_hit_claim: Some(cache_hit_claim),
        validation_support,
        settlement_model: settlement_model.clone(),
        expires_at,
        terms: json!({
            "settlementModel": settlement_model,
            "offerId": offer.offer_id,
            "runnerDescriptorRef": offer.runner_descriptor_ref,
            "serviceLevel": offer.service_level,
            "pricing": offer.pricing
        }),
        details: json!({
            "runnerType": offer.runner_type,
            "pricing": offer.pricing,
            "serviceLevel": offer.service_level,
        }),
        quote_timing: Some(ServiceQuoteTimingV1 {
            schema_version: "hivemind.quote_timing.v1".to_string(),
            started_at,
            completed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            offer_matched: true,
            privacy_matched: true,
            verification_matched: true,
        }),
        signature: None,
    };
    sign_service_quote(&mut quote);
    Some(quote)
}

pub fn sign_service_quote(quote: &mut ServiceQuoteV1) {
    quote.signature = Some(expected_service_quote_signature(quote));
    quote.quote_id = canonical_service_quote_id(quote);
}

pub fn sign_service_quote_with_identity(
    quote: &mut ServiceQuoteV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != quote.runner_id {
        anyhow::bail!(
            "identity subject {} does not match service quote runnerId {}",
            identity.subject,
            quote.runner_id
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "service-quote",
        &service_quote_signing_value(quote),
    )?;
    quote.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    quote.quote_id = canonical_service_quote_id(quote);
    Ok(envelope)
}

pub fn expected_service_quote_signature(quote: &ServiceQuoteV1) -> String {
    format!(
        "{DEV_SERVICE_QUOTE_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&service_quote_signing_value(quote)))
    )
}

pub fn canonical_service_quote_id(quote: &ServiceQuoteV1) -> String {
    stable_id("quote", &service_quote_signing_value(quote))
}

pub fn verify_service_quote(
    quote: &ServiceQuoteV1,
    offer: Option<&RunnerOfferV1>,
) -> ServiceQuoteVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_cost = None;
    let mut expected_signature = Some(expected_service_quote_signature(quote));
    let current_schema = quote.schema_version == SERVICE_QUOTE_SCHEMA_VERSION;
    let signature = quote
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if !matches!(
        quote.schema_version.as_str(),
        SERVICE_QUOTE_SCHEMA_VERSION | LEGACY_SERVICE_QUOTE_SCHEMA_VERSION
    ) {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.quote.v1",
        ));
    }
    if current_schema {
        if payment_authorization_job_id(quote).is_none() {
            issues.push(marketplace_issue(
                "$.jobId",
                "Current service quote schema requires jobId",
            ));
        }
        if quote.price.is_none() {
            issues.push(marketplace_issue(
                "$.price",
                "Current service quote schema requires price",
            ));
        }
        if quote.price_model.is_none() {
            issues.push(marketplace_issue(
                "$.priceModel",
                "Current service quote schema requires priceModel",
            ));
        }
        if quote.privacy_mode.is_none() {
            issues.push(marketplace_issue(
                "$.privacyMode",
                "Current service quote schema requires privacyMode",
            ));
        }
        if quote.verification_mode.is_none() {
            issues.push(marketplace_issue(
                "$.verificationMode",
                "Current service quote schema requires verificationMode",
            ));
        }
        if quote.estimated_start_delay_ms.is_none() {
            issues.push(marketplace_issue(
                "$.estimatedStartDelayMs",
                "Current service quote schema requires estimatedStartDelayMs",
            ));
        }
        if quote.cache_hit_claim.is_none() {
            issues.push(marketplace_issue(
                "$.cacheHitClaim",
                "Current service quote schema requires cacheHitClaim",
            ));
        }
        if quote.validation_support.is_empty() {
            issues.push(marketplace_issue(
                "$.validationSupport",
                "Current service quote schema requires validationSupport",
            ));
        }
        if quote.quote_timing.is_none() {
            warnings.push(marketplace_issue(
                "$.quoteTiming",
                "Current service quote should include quote response timing for operational metrics",
            ));
        }
    }
    for (path, value, message) in [
        ("$.quoteId", quote.quote_id.as_str(), "Quote id is required"),
        (
            "$.requestId",
            quote.request_id.as_str(),
            "Request id is required",
        ),
        ("$.offerId", quote.offer_id.as_str(), "Offer id is required"),
        (
            "$.runnerId",
            quote.runner_id.as_str(),
            "Runner id is required",
        ),
        (
            "$.packageRef",
            quote.package_ref.as_str(),
            "Package ref is required",
        ),
        (
            "$.currency",
            quote.currency.as_str(),
            "Currency is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(marketplace_issue(path, message));
        }
    }
    if !quote.quote_id.trim().is_empty()
        && signature.is_some()
        && quote.quote_id != canonical_service_quote_id(quote)
    {
        issues.push(marketplace_issue(
            "$.quoteId",
            "Quote id does not match canonical signed content",
        ));
    }
    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "service-quote",
                &service_quote_signing_value(quote),
                Some(&quote.runner_id),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(marketplace_issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(marketplace_issue(
                "$.signature",
                "Service quote signature does not match canonical dev signature or Ed25519 identity envelope",
            ));
        }
    } else {
        warnings.push(marketplace_issue(
            "$.signature",
            "Service quote is unsigned; verify runnerId and quoteId through a trusted source",
        ));
    }
    if !quote.package_ref.starts_with("bzz://") {
        warnings.push(marketplace_issue(
            "$.packageRef",
            "Quote packageRef is not a bzz:// reference",
        ));
    }
    if quote.estimated_cost < 0.0 {
        issues.push(marketplace_issue(
            "$.estimatedCost",
            "Estimated cost must not be negative",
        ));
    }
    if let Some(price) = &quote.price {
        if price.amount < 0.0 {
            issues.push(marketplace_issue(
                "$.price.amount",
                "Price must not be negative",
            ));
        }
        if price.currency.trim().is_empty() {
            issues.push(marketplace_issue(
                "$.price.currency",
                "Price currency is required",
            ));
        } else if price.currency != quote.currency {
            issues.push(marketplace_issue(
                "$.price.currency",
                "Quote price currency must match currency compatibility field",
            ));
        }
        if (price.amount - quote.estimated_cost).abs() > 0.000_000_1 {
            issues.push(marketplace_issue(
                "$.price.amount",
                "Quote price amount must match estimatedCost compatibility field",
            ));
        }
    }
    if let Some(delay) = quote.estimated_start_delay_ms
        && delay > 86_400_000
    {
        warnings.push(marketplace_issue(
            "$.estimatedStartDelayMs",
            "Estimated start delay is longer than one day",
        ));
    }
    if let Some(first_output_ms) = quote.estimated_time_to_first_output_ms
        && let Some(completion_ms) = quote.estimated_completion_ms
        && completion_ms < first_output_ms
    {
        issues.push(marketplace_issue(
            "$.estimatedCompletionMs",
            "Estimated completion must be greater than or equal to first output estimate",
        ));
    }
    for (index, support) in quote.validation_support.iter().enumerate() {
        if support.trim().is_empty() {
            issues.push(marketplace_issue(
                format!("$.validationSupport[{index}]"),
                "Validation support entry must not be empty",
            ));
        }
    }
    if quote.estimated_input_tokens == 0 {
        warnings.push(marketplace_issue(
            "$.estimatedInputTokens",
            "Estimated input tokens is zero",
        ));
    }
    if quote.estimated_output_tokens == 0 {
        warnings.push(marketplace_issue(
            "$.estimatedOutputTokens",
            "Estimated output tokens is zero",
        ));
    }
    if let Some(timing) = &quote.quote_timing {
        if timing.schema_version != "hivemind.quote_timing.v1" {
            issues.push(marketplace_issue(
                "$.quoteTiming.schemaVersion",
                "Quote timing schemaVersion must be hivemind.quote_timing.v1",
            ));
        }
        let started_at = match DateTime::parse_from_rfc3339(&timing.started_at) {
            Ok(value) => Some(value),
            Err(_) => {
                issues.push(marketplace_issue(
                    "$.quoteTiming.startedAt",
                    "Quote timing startedAt must be RFC3339",
                ));
                None
            }
        };
        let completed_at = match DateTime::parse_from_rfc3339(&timing.completed_at) {
            Ok(value) => Some(value),
            Err(_) => {
                issues.push(marketplace_issue(
                    "$.quoteTiming.completedAt",
                    "Quote timing completedAt must be RFC3339",
                ));
                None
            }
        };
        if let (Some(started_at), Some(completed_at)) = (started_at, completed_at)
            && completed_at < started_at
        {
            issues.push(marketplace_issue(
                "$.quoteTiming.completedAt",
                "Quote timing completedAt must not be earlier than startedAt",
            ));
        }
        if current_schema
            && (!timing.offer_matched || !timing.privacy_matched || !timing.verification_matched)
        {
            issues.push(marketplace_issue(
                "$.quoteTiming",
                "Successful current-schema quote timing must record matched offer, privacy, and verification checks",
            ));
        }
    }
    match DateTime::parse_from_rfc3339(&quote.expires_at) {
        Ok(expires_at) if expires_at.with_timezone(&Utc) < Utc::now() => {
            issues.push(marketplace_issue("$.expiresAt", "Quote has expired"))
        }
        Err(_) => issues.push(marketplace_issue(
            "$.expiresAt",
            "Quote expiration must be RFC3339",
        )),
        _ => {}
    }

    if let Some(offer) = offer {
        let offer_verification = verify_runner_offer(offer);
        if !offer_verification.valid {
            issues.push(marketplace_issue(
                "$.offer",
                "Referenced runner offer does not verify",
            ));
        }
        if quote.offer_id != offer.offer_id {
            issues.push(marketplace_issue(
                "$.offerId",
                "Quote offerId must match runner offer",
            ));
        }
        if quote.runner_id != offer.runner_id {
            issues.push(marketplace_issue(
                "$.runnerId",
                "Quote runnerId must match runner offer",
            ));
        }
        if let Some(privacy_mode) = &quote.privacy_mode
            && !offer.privacy_tiers.is_empty()
            && select_runner_offer_privacy_tier(&offer.privacy_tiers, privacy_mode).is_none()
        {
            issues.push(marketplace_issue(
                "$.privacyMode",
                "Quote privacyMode is not supported by the runner offer",
            ));
        }
        if let Some(verification_mode) = &quote.verification_mode
            && !offer.verification_tiers.is_empty()
            && select_runner_offer_integrity_tier(&offer.verification_tiers, verification_mode)
                .is_none()
        {
            issues.push(marketplace_issue(
                "$.verificationMode",
                "Quote verificationMode is not supported by the runner offer",
            ));
        }
        if quote.cache_hit_claim == Some(true)
            && !offer
                .cache_claims
                .iter()
                .any(|claim| claim.warmed && claim.package_ref == quote.package_ref)
        {
            issues.push(marketplace_issue(
                "$.cacheHitClaim",
                "Quote cacheHitClaim is not backed by the runner offer cache claims",
            ));
        }
        if !offer.supported_package_refs.is_empty()
            && !offer
                .supported_package_refs
                .iter()
                .any(|reference| reference == &quote.package_ref)
        {
            issues.push(marketplace_issue(
                "$.packageRef",
                "Quote packageRef is not supported by runner offer",
            ));
        }
        if quote.currency != offer.pricing.currency {
            issues.push(marketplace_issue(
                "$.currency",
                "Quote currency must match runner offer pricing currency",
            ));
        }
        if let Some(listing_id) = quote.listing_id.as_deref()
            && listing_id != offer.offer_id
        {
            issues.push(marketplace_issue(
                "$.listingId",
                "Quote listingId must match runner offer id when present",
            ));
        }
        if let Some(first_output_ms) = quote.estimated_time_to_first_output_ms
            && first_output_ms != offer.service_level.p95_first_token_ms
        {
            warnings.push(marketplace_issue(
                "$.estimatedTimeToFirstOutputMs",
                "Quote first-output estimate differs from runner offer service level",
            ));
        }
        let cost = quote.estimated_input_tokens as f64 * offer.pricing.input_token_price
            + quote.estimated_output_tokens as f64 * offer.pricing.output_token_price;
        expected_cost = Some(cost);
        if (quote.estimated_cost - cost).abs() > 0.000_000_1 {
            issues.push(marketplace_issue(
                "$.estimatedCost",
                "Quote estimated cost does not match runner offer pricing",
            ));
        }
        if let Some(price) = &quote.price
            && (price.amount - cost).abs() > 0.000_000_1
        {
            issues.push(marketplace_issue(
                "$.price.amount",
                "Quote price amount does not match runner offer pricing",
            ));
        }
    }

    ServiceQuoteVerificationV1 {
        schema_version: SERVICE_QUOTE_VERIFICATION_SCHEMA_VERSION.to_string(),
        quote_id: quote.quote_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_cost,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn read_service_quote(path: &Path) -> anyhow::Result<ServiceQuoteV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse service quote JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_service_quote(audit_dir: &Path, quote: &ServiceQuoteV1) -> anyhow::Result<PathBuf> {
    let quotes_dir = marketplace_quotes_dir(audit_dir);
    fs::create_dir_all(&quotes_dir)?;
    let path = quotes_dir.join(format!("{}.json", safe_file_component(&quote.quote_id)));
    fs::write(&path, serde_json::to_vec_pretty(quote)?)?;
    Ok(path)
}

pub fn get_service_quote(
    audit_dir: &Path,
    quote_id: &str,
) -> anyhow::Result<Option<ServiceQuoteLookupV1>> {
    let quote_id = quote_id.trim();
    if quote_id.is_empty() {
        anyhow::bail!("quoteId is required");
    }

    let quotes_dir = marketplace_quotes_dir(audit_dir);
    let direct_path = quotes_dir.join(format!("{}.json", safe_file_component(quote_id)));
    if direct_path.exists() {
        let quote = read_service_quote(&direct_path)?;
        if quote.quote_id == quote_id {
            return Ok(Some(service_quote_lookup(quote, direct_path)));
        }
    }

    if !quotes_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(&quotes_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let quote = read_service_quote(&path)?;
            if quote.quote_id == quote_id {
                return Ok(Some(service_quote_lookup(quote, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_service_quotes(audit_dir: &Path) -> anyhow::Result<ServiceQuoteStoreSummaryV1> {
    let mut quotes = Vec::new();
    let quotes_dir = marketplace_quotes_dir(audit_dir);
    if quotes_dir.exists() {
        for entry in fs::read_dir(&quotes_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let quote = read_service_quote(&path)?;
                quotes.push(service_quote_index_entry(
                    &quote,
                    path.display().to_string(),
                ));
            }
        }
    }
    quotes.sort_by(|left, right| {
        left.expires_at
            .cmp(&right.expires_at)
            .then(left.quote_id.cmp(&right.quote_id))
    });
    let valid_count = quotes
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    let quote_elapsed_values: Vec<u64> = quotes
        .iter()
        .filter_map(|entry| entry.quote_elapsed_ms)
        .collect();
    let cache_hit_claims = quote_cache_hit_claims(&quotes);
    let quote_cache_hit_count = cache_hit_claims.iter().filter(|claim| **claim).count();
    let with_quote_timing_count = quote_elapsed_values.len();
    let average_quote_elapsed_ms = if quote_elapsed_values.is_empty() {
        None
    } else {
        Some(
            quote_elapsed_values
                .iter()
                .map(|value| *value as f64)
                .sum::<f64>()
                / quote_elapsed_values.len() as f64,
        )
    };
    let max_quote_elapsed_ms = quote_elapsed_values.iter().copied().max();
    Ok(ServiceQuoteStoreSummaryV1 {
        schema_version: "hivemind.service-quote-store-summary.v1".to_string(),
        root: audit_dir.display().to_string(),
        quote_count: quotes.len(),
        valid_count,
        invalid_count: quotes.len().saturating_sub(valid_count),
        with_quote_timing_count,
        average_quote_elapsed_ms,
        max_quote_elapsed_ms,
        quote_cache_claim_sample_count: cache_hit_claims.len(),
        quote_cache_hit_count,
        quote_cache_miss_count: cache_hit_claims.len().saturating_sub(quote_cache_hit_count),
        quote_cache_hit_rate: ratio(quote_cache_hit_count, cache_hit_claims.len()),
        quotes,
    })
}

pub fn authorize_payment(
    quote: &ServiceQuoteV1,
    payer: impl Into<String>,
    payee: impl Into<String>,
    adapter: PaymentAdapterKind,
    payment_ref: Option<String>,
) -> PaymentAuthorizationV1 {
    let job_id = payment_authorization_job_id(quote);
    let escrow_ref = quote_detail_string(quote, "escrowRef");
    let cancellation_rules = quote
        .details
        .get("cancellationRules")
        .cloned()
        .unwrap_or_else(empty_terms);
    let mut authorization = PaymentAuthorizationV1 {
        schema_version: PAYMENT_AUTHORIZATION_SCHEMA_VERSION.to_string(),
        authorization_id: String::new(),
        quote_id: quote.quote_id.clone(),
        job_id,
        request_id: quote.request_id.clone(),
        offer_id: quote.offer_id.clone(),
        runner_id: quote.runner_id.clone(),
        package_ref: quote.package_ref.clone(),
        payer: payer.into(),
        payee: payee.into(),
        amount: quote.estimated_cost,
        currency: quote.currency.clone(),
        adapter: adapter.clone(),
        max_amount: Some(quote.estimated_cost),
        asset: Some(quote.currency.clone()),
        method: Some(adapter),
        status: PaymentAuthorizationStatus::Authorized,
        payment_ref,
        escrow_ref,
        authorized_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        expires_at: quote.expires_at.clone(),
        cancellation_rules,
        signature: String::new(),
    };
    sign_payment_authorization(&mut authorization);
    authorization.authorization_id = canonical_payment_authorization_id(&authorization);
    authorization
}

pub fn sign_payment_authorization(authorization: &mut PaymentAuthorizationV1) {
    authorization.signature = expected_payment_authorization_signature(authorization);
}

pub fn sign_payment_authorization_with_identity(
    authorization: &mut PaymentAuthorizationV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != authorization.payer {
        anyhow::bail!(
            "identity subject {} does not match payment authorization payer {}",
            identity.subject,
            authorization.payer
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "payment-authorization",
        &payment_authorization_signing_value(authorization),
    )?;
    authorization.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    authorization.authorization_id = canonical_payment_authorization_id(authorization);
    Ok(envelope)
}

pub fn expected_payment_authorization_signature(authorization: &PaymentAuthorizationV1) -> String {
    format!(
        "{DEV_PAYMENT_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&payment_authorization_signing_value(
            authorization
        )))
    )
}

pub fn canonical_payment_authorization_id(authorization: &PaymentAuthorizationV1) -> String {
    stable_id(
        "payment-authorization",
        &payment_authorization_signing_value(authorization),
    )
}

pub fn verify_payment_authorization(
    authorization: &PaymentAuthorizationV1,
    quote: Option<&ServiceQuoteV1>,
) -> PaymentAuthorizationVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = expected_payment_authorization_signature(authorization);
    let current_schema = authorization.schema_version == PAYMENT_AUTHORIZATION_SCHEMA_VERSION;

    if !matches!(
        authorization.schema_version.as_str(),
        PAYMENT_AUTHORIZATION_SCHEMA_VERSION | LEGACY_PAYMENT_AUTHORIZATION_SCHEMA_VERSION
    ) {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.payment_authorization.v1",
        ));
    }
    if current_schema {
        if authorization.max_amount.is_none() {
            issues.push(marketplace_issue(
                "$.maxAmount",
                "Current payment authorization schema requires maxAmount",
            ));
        }
        if authorization
            .asset
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
        {
            issues.push(marketplace_issue(
                "$.asset",
                "Current payment authorization schema requires asset",
            ));
        }
        if authorization.method.is_none() {
            issues.push(marketplace_issue(
                "$.method",
                "Current payment authorization schema requires method",
            ));
        }
        if authorization.amount > 0.0
            && authorization
                .payment_ref
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
            && authorization
                .escrow_ref
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
        {
            issues.push(marketplace_issue(
                "$.paymentRef",
                "Current payment authorization schema requires paymentRef or escrowRef for non-free payment",
            ));
        }
    }
    if authorization.authorization_id.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.authorizationId",
            "Payment authorization id is required",
        ));
    } else {
        let canonical_id = canonical_payment_authorization_id(authorization);
        if authorization.authorization_id != canonical_id {
            issues.push(marketplace_issue(
                "$.authorizationId",
                "Payment authorization id does not match canonical content",
            ));
        }
    }
    if authorization.signature.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.signature",
            "Payment authorization signature is required",
        ));
    } else if authorization
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &authorization.signature,
            "payment-authorization",
            &payment_authorization_signing_value(authorization),
            Some(&authorization.payer),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(marketplace_issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if authorization.signature != expected_signature {
        issues.push(marketplace_issue(
            "$.signature",
            "Payment authorization signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    }
    for (path, value, message) in [
        (
            "$.quoteId",
            authorization.quote_id.as_str(),
            "Quote id is required",
        ),
        (
            "$.requestId",
            authorization.request_id.as_str(),
            "Request id is required",
        ),
        (
            "$.offerId",
            authorization.offer_id.as_str(),
            "Offer id is required",
        ),
        (
            "$.runnerId",
            authorization.runner_id.as_str(),
            "Runner id is required",
        ),
        (
            "$.packageRef",
            authorization.package_ref.as_str(),
            "Package ref is required",
        ),
        ("$.payer", authorization.payer.as_str(), "Payer is required"),
        ("$.payee", authorization.payee.as_str(), "Payee is required"),
        (
            "$.currency",
            authorization.currency.as_str(),
            "Currency is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(marketplace_issue(path, message));
        }
    }
    if !authorization.package_ref.starts_with("bzz://") {
        warnings.push(marketplace_issue(
            "$.packageRef",
            "Payment authorization packageRef is not a bzz:// reference",
        ));
    }
    if authorization.amount < 0.0 {
        issues.push(marketplace_issue("$.amount", "Amount must not be negative"));
    }
    if let Some(max_amount) = authorization.max_amount {
        if max_amount < 0.0 {
            issues.push(marketplace_issue(
                "$.maxAmount",
                "Maximum authorization amount must not be negative",
            ));
        }
        if authorization.amount > max_amount + 0.000_000_1 {
            issues.push(marketplace_issue(
                "$.maxAmount",
                "Maximum authorization amount must cover amount",
            ));
        }
    }
    if let Some(asset) = authorization.asset.as_deref() {
        if asset.trim().is_empty() {
            issues.push(marketplace_issue("$.asset", "Asset is empty"));
        } else if asset != authorization.currency {
            issues.push(marketplace_issue(
                "$.asset",
                "Payment authorization asset must match currency",
            ));
        }
    }
    if let Some(method) = &authorization.method
        && method != &authorization.adapter
    {
        issues.push(marketplace_issue(
            "$.method",
            "Payment authorization method must match adapter",
        ));
    }
    if authorization.adapter == PaymentAdapterKind::Free && authorization.amount > 0.0 {
        issues.push(marketplace_issue(
            "$.adapter",
            "Free payment adapter can only authorize zero-cost quotes",
        ));
    }
    if authorization.adapter == PaymentAdapterKind::ExternalTransaction
        && authorization
            .payment_ref
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .is_empty()
    {
        issues.push(marketplace_issue(
            "$.paymentRef",
            "External transaction authorizations require a paymentRef",
        ));
    }
    if let Some(escrow_ref) = authorization.escrow_ref.as_deref()
        && escrow_ref.trim().is_empty()
    {
        issues.push(marketplace_issue("$.escrowRef", "Escrow ref is empty"));
    }
    match authorization.status {
        PaymentAuthorizationStatus::Authorized | PaymentAuthorizationStatus::Captured => {}
        PaymentAuthorizationStatus::Refunded => issues.push(marketplace_issue(
            "$.status",
            "Refunded payment authorizations cannot fund settlement",
        )),
        PaymentAuthorizationStatus::Rejected => issues.push(marketplace_issue(
            "$.status",
            "Rejected payment authorizations cannot fund settlement",
        )),
    }
    let authorized_at = match DateTime::parse_from_rfc3339(&authorization.authorized_at) {
        Ok(authorized_at) => Some(authorized_at.with_timezone(&Utc)),
        Err(_) => {
            issues.push(marketplace_issue(
                "$.authorizedAt",
                "Payment authorization timestamp must be RFC3339",
            ));
            None
        }
    };
    match DateTime::parse_from_rfc3339(&authorization.expires_at) {
        Ok(expires_at) if expires_at.with_timezone(&Utc) < Utc::now() => {
            issues.push(marketplace_issue(
                "$.expiresAt",
                "Payment authorization has expired",
            ));
        }
        Ok(expires_at) => {
            if let Some(authorized_at) = authorized_at
                && authorized_at > expires_at.with_timezone(&Utc)
            {
                issues.push(marketplace_issue(
                    "$.authorizedAt",
                    "Payment authorization timestamp is after expiration",
                ));
            }
        }
        Err(_) => issues.push(marketplace_issue(
            "$.expiresAt",
            "Payment authorization expiration must be RFC3339",
        )),
    }

    if let Some(quote) = quote {
        let quote_verification = verify_service_quote(quote, None);
        if !quote_verification.valid {
            issues.push(marketplace_issue(
                "$.quote",
                "Referenced service quote does not verify",
            ));
        }
        if authorization.quote_id != quote.quote_id {
            issues.push(marketplace_issue(
                "$.quoteId",
                "Payment authorization quoteId must match service quote",
            ));
        }
        if authorization.request_id != quote.request_id {
            issues.push(marketplace_issue(
                "$.requestId",
                "Payment authorization requestId must match service quote",
            ));
        }
        if authorization.offer_id != quote.offer_id {
            issues.push(marketplace_issue(
                "$.offerId",
                "Payment authorization offerId must match service quote",
            ));
        }
        if authorization.runner_id != quote.runner_id {
            issues.push(marketplace_issue(
                "$.runnerId",
                "Payment authorization runnerId must match service quote",
            ));
        }
        if authorization.package_ref != quote.package_ref {
            issues.push(marketplace_issue(
                "$.packageRef",
                "Payment authorization packageRef must match service quote",
            ));
        }
        if (authorization.amount - quote.estimated_cost).abs() > 0.000_000_1 {
            issues.push(marketplace_issue(
                "$.amount",
                "Payment authorization amount must match service quote estimatedCost",
            ));
        }
        if let Some(max_amount) = authorization.max_amount
            && max_amount + 0.000_000_1 < quote.estimated_cost
        {
            issues.push(marketplace_issue(
                "$.maxAmount",
                "Payment authorization maxAmount must cover service quote estimatedCost",
            ));
        }
        if authorization.currency != quote.currency {
            issues.push(marketplace_issue(
                "$.currency",
                "Payment authorization currency must match service quote",
            ));
        }
        if let Some(asset) = authorization.asset.as_deref()
            && asset != quote.currency
        {
            issues.push(marketplace_issue(
                "$.asset",
                "Payment authorization asset must match service quote currency",
            ));
        }
        if let Some(job_id) = authorization.job_id.as_deref()
            && let Some(quote_job_id) = payment_authorization_job_id(quote)
            && job_id != quote_job_id
        {
            issues.push(marketplace_issue(
                "$.jobId",
                "Payment authorization jobId must match service quote jobId",
            ));
        }
        if authorization.expires_at != quote.expires_at {
            issues.push(marketplace_issue(
                "$.expiresAt",
                "Payment authorization expiresAt must match service quote",
            ));
        }
    }

    PaymentAuthorizationVerificationV1 {
        schema_version: PAYMENT_AUTHORIZATION_VERIFICATION_SCHEMA_VERSION.to_string(),
        authorization_id: authorization.authorization_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn read_payment_authorization(path: &Path) -> anyhow::Result<PaymentAuthorizationV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse payment authorization JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_payment_authorization(
    authorizations_dir: &Path,
    authorization: &PaymentAuthorizationV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(authorizations_dir)?;
    let path = authorizations_dir.join(format!(
        "{}.json",
        safe_file_component(&authorization.authorization_id)
    ));
    fs::write(&path, serde_json::to_vec_pretty(authorization)?)?;
    Ok(path)
}

pub fn get_payment_authorization(
    authorizations_dir: &Path,
    authorization_id: &str,
) -> anyhow::Result<Option<PaymentAuthorizationLookupV1>> {
    let authorization_id = authorization_id.trim();
    if authorization_id.is_empty() {
        anyhow::bail!("authorizationId is required");
    }

    let direct_path =
        authorizations_dir.join(format!("{}.json", safe_file_component(authorization_id)));
    if direct_path.exists() {
        let authorization = read_payment_authorization(&direct_path)?;
        if authorization.authorization_id == authorization_id {
            return Ok(Some(payment_authorization_lookup(
                authorization,
                direct_path,
            )));
        }
    }

    if !authorizations_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(authorizations_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let authorization = read_payment_authorization(&path)?;
            if authorization.authorization_id == authorization_id {
                return Ok(Some(payment_authorization_lookup(authorization, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_payment_authorizations(
    authorizations_dir: &Path,
) -> anyhow::Result<PaymentAuthorizationStoreSummaryV1> {
    let mut authorizations = Vec::new();
    if authorizations_dir.exists() {
        for entry in fs::read_dir(authorizations_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let authorization = read_payment_authorization(&path)?;
                authorizations.push(payment_authorization_index_entry(
                    &authorization,
                    path.display().to_string(),
                ));
            }
        }
    }
    authorizations.sort_by(|left, right| {
        left.authorized_at
            .cmp(&right.authorized_at)
            .then(left.authorization_id.cmp(&right.authorization_id))
    });
    let valid_count = authorizations
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    Ok(PaymentAuthorizationStoreSummaryV1 {
        schema_version: "swarm-ai.payment-authorization-store-summary.v1".to_string(),
        root: authorizations_dir.display().to_string(),
        authorization_count: authorizations.len(),
        valid_count,
        invalid_count: authorizations.len().saturating_sub(valid_count),
        authorizations,
    })
}

pub fn create_escrow_record(
    authorization: &PaymentAuthorizationV1,
    quote: Option<&ServiceQuoteV1>,
    custodian: impl Into<String>,
    evidence_refs: Vec<String>,
) -> EscrowRecordV1 {
    let custodian = custodian.into();
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let escrow_ref = authorization
        .escrow_ref
        .clone()
        .or_else(|| Some(format!("local://escrow/{}", authorization.authorization_id)));
    let mut merged_evidence_refs = Vec::new();
    push_evidence_ref(
        &mut merged_evidence_refs,
        format!(
            "local://payment-authorization/{}",
            authorization.authorization_id
        ),
    );
    if let Some(quote) = quote {
        push_evidence_ref(
            &mut merged_evidence_refs,
            format!("local://quote/{}", quote.quote_id),
        );
    }
    if let Some(payment_ref) = authorization.payment_ref.as_deref() {
        push_evidence_ref(&mut merged_evidence_refs, payment_ref);
    }
    if let Some(escrow_ref) = escrow_ref.as_deref() {
        push_evidence_ref(&mut merged_evidence_refs, escrow_ref);
    }
    merge_evidence_refs(&mut merged_evidence_refs, evidence_refs.iter());
    let mut escrow = EscrowRecordV1 {
        schema_version: ESCROW_RECORD_SCHEMA_VERSION.to_string(),
        escrow_id: String::new(),
        authorization_id: authorization.authorization_id.clone(),
        quote_id: authorization.quote_id.clone(),
        job_id: authorization.job_id.clone(),
        request_id: authorization.request_id.clone(),
        offer_id: authorization.offer_id.clone(),
        runner_id: authorization.runner_id.clone(),
        package_ref: authorization.package_ref.clone(),
        payer: authorization.payer.clone(),
        payee: authorization.payee.clone(),
        amount: authorization.amount,
        currency: authorization.currency.clone(),
        asset: authorization.asset.clone(),
        adapter: authorization.adapter.clone(),
        status: EscrowStatusV1::Locked,
        custodian,
        payment_ref: authorization.payment_ref.clone(),
        escrow_ref,
        settlement_id: None,
        evidence_refs: merged_evidence_refs,
        terms: authorization.cancellation_rules.clone(),
        created_at: now.clone(),
        expires_at: authorization.expires_at.clone(),
        locked_at: Some(now),
        released_at: None,
        refunded_at: None,
        cancelled_at: None,
        reason: Some("funds locked for verified settlement".to_string()),
        signature: None,
    };
    sign_escrow_record(&mut escrow);
    escrow
}

pub fn sign_escrow_record(escrow: &mut EscrowRecordV1) {
    escrow.signature = Some(expected_escrow_record_signature(escrow));
    escrow.escrow_id = canonical_escrow_record_id(escrow);
}

pub fn sign_escrow_record_with_identity(
    escrow: &mut EscrowRecordV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != escrow.custodian {
        anyhow::bail!(
            "identity subject {} does not match escrow custodian {}",
            identity.subject,
            escrow.custodian
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "escrow-record",
        &escrow_record_signing_value(escrow),
    )?;
    escrow.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    escrow.escrow_id = canonical_escrow_record_id(escrow);
    Ok(envelope)
}

pub fn expected_escrow_record_signature(escrow: &EscrowRecordV1) -> String {
    format!(
        "{DEV_ESCROW_RECORD_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&escrow_record_signing_value(escrow)))
    )
}

pub fn canonical_escrow_record_id(escrow: &EscrowRecordV1) -> String {
    stable_id("escrow", &escrow_record_signing_value(escrow))
}

pub fn verify_escrow_record(
    escrow: &EscrowRecordV1,
    authorization: Option<&PaymentAuthorizationV1>,
    quote: Option<&ServiceQuoteV1>,
) -> EscrowRecordVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_escrow_record_signature(escrow));
    let signature = escrow
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if escrow.schema_version != ESCROW_RECORD_SCHEMA_VERSION {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {ESCROW_RECORD_SCHEMA_VERSION}"),
        ));
    }
    if escrow.escrow_id.trim().is_empty() {
        issues.push(marketplace_issue("$.escrowId", "Escrow id is required"));
    } else if signature.is_some() && escrow.escrow_id != canonical_escrow_record_id(escrow) {
        issues.push(marketplace_issue(
            "$.escrowId",
            "Escrow id does not match canonical signed content",
        ));
    }
    for (path, value, message) in [
        (
            "$.authorizationId",
            escrow.authorization_id.as_str(),
            "Payment authorization id is required",
        ),
        (
            "$.quoteId",
            escrow.quote_id.as_str(),
            "Quote id is required",
        ),
        (
            "$.requestId",
            escrow.request_id.as_str(),
            "Request id is required",
        ),
        (
            "$.offerId",
            escrow.offer_id.as_str(),
            "Offer id is required",
        ),
        (
            "$.runnerId",
            escrow.runner_id.as_str(),
            "Runner id is required",
        ),
        (
            "$.packageRef",
            escrow.package_ref.as_str(),
            "Package ref is required",
        ),
        ("$.payer", escrow.payer.as_str(), "Payer is required"),
        ("$.payee", escrow.payee.as_str(), "Payee is required"),
        (
            "$.currency",
            escrow.currency.as_str(),
            "Currency is required",
        ),
        (
            "$.custodian",
            escrow.custodian.as_str(),
            "Escrow custodian is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(marketplace_issue(path, message));
        }
    }
    if escrow.amount <= 0.0 {
        issues.push(marketplace_issue(
            "$.amount",
            "Escrow amount must be greater than zero",
        ));
    }
    if let Some(asset) = escrow.asset.as_deref() {
        if asset.trim().is_empty() {
            issues.push(marketplace_issue("$.asset", "Escrow asset is empty"));
        } else if asset != escrow.currency {
            issues.push(marketplace_issue(
                "$.asset",
                "Escrow asset must match currency",
            ));
        }
    } else {
        issues.push(marketplace_issue(
            "$.asset",
            "Escrow record requires asset for review-4 settlement compatibility",
        ));
    }
    if !escrow.package_ref.starts_with("bzz://") {
        warnings.push(marketplace_issue(
            "$.packageRef",
            "Escrow packageRef is not a bzz:// reference",
        ));
    }
    if escrow.evidence_refs.is_empty() {
        issues.push(marketplace_issue(
            "$.evidenceRefs",
            "Escrow record requires authorization/payment evidence refs",
        ));
    }
    for (index, evidence_ref) in escrow.evidence_refs.iter().enumerate() {
        if evidence_ref.trim().is_empty() {
            issues.push(marketplace_issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference must not be empty",
            ));
        } else if !looks_like_marketplace_ref(evidence_ref) {
            warnings.push(marketplace_issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference is not a recognized marketplace reference",
            ));
        }
    }
    if let Some(escrow_ref) = escrow.escrow_ref.as_deref() {
        if escrow_ref.trim().is_empty() {
            issues.push(marketplace_issue("$.escrowRef", "Escrow ref is empty"));
        } else if !looks_like_marketplace_ref(escrow_ref) {
            warnings.push(marketplace_issue(
                "$.escrowRef",
                "Escrow ref is not a recognized marketplace reference",
            ));
        }
    }
    if let Some(payment_ref) = escrow.payment_ref.as_deref()
        && !looks_like_marketplace_ref(payment_ref)
    {
        warnings.push(marketplace_issue(
            "$.paymentRef",
            "Payment ref is not a recognized marketplace reference",
        ));
    }

    let created_at = parse_marketplace_time(
        &escrow.created_at,
        "$.createdAt",
        "Escrow createdAt timestamp must be RFC3339",
        &mut issues,
    );
    let expires_at = parse_marketplace_time(
        &escrow.expires_at,
        "$.expiresAt",
        "Escrow expiration must be RFC3339",
        &mut issues,
    );
    if let (Some(created_at), Some(expires_at)) = (created_at, expires_at) {
        if created_at > expires_at {
            issues.push(marketplace_issue(
                "$.createdAt",
                "Escrow createdAt timestamp is after expiration",
            ));
        }
        if matches!(
            escrow.status,
            EscrowStatusV1::Created | EscrowStatusV1::Locked | EscrowStatusV1::Disputed
        ) && expires_at < Utc::now()
        {
            issues.push(marketplace_issue("$.expiresAt", "Escrow has expired"));
        }
    }
    if let Some(locked_at) = escrow.locked_at.as_deref() {
        parse_marketplace_time(
            locked_at,
            "$.lockedAt",
            "Escrow lockedAt timestamp must be RFC3339",
            &mut issues,
        );
    }
    if let Some(released_at) = escrow.released_at.as_deref() {
        parse_marketplace_time(
            released_at,
            "$.releasedAt",
            "Escrow releasedAt timestamp must be RFC3339",
            &mut issues,
        );
    }
    if let Some(refunded_at) = escrow.refunded_at.as_deref() {
        parse_marketplace_time(
            refunded_at,
            "$.refundedAt",
            "Escrow refundedAt timestamp must be RFC3339",
            &mut issues,
        );
    }
    if let Some(cancelled_at) = escrow.cancelled_at.as_deref() {
        parse_marketplace_time(
            cancelled_at,
            "$.cancelledAt",
            "Escrow cancelledAt timestamp must be RFC3339",
            &mut issues,
        );
    }
    match escrow.status {
        EscrowStatusV1::Created => {}
        EscrowStatusV1::Locked => {
            if escrow.locked_at.is_none() {
                issues.push(marketplace_issue(
                    "$.lockedAt",
                    "Locked escrow records require lockedAt",
                ));
            }
        }
        EscrowStatusV1::Released => {
            if escrow.released_at.is_none() {
                issues.push(marketplace_issue(
                    "$.releasedAt",
                    "Released escrow records require releasedAt",
                ));
            }
            if escrow
                .settlement_id
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                issues.push(marketplace_issue(
                    "$.settlementId",
                    "Released escrow records require settlementId",
                ));
            }
        }
        EscrowStatusV1::Refunded => {
            if escrow.refunded_at.is_none() {
                issues.push(marketplace_issue(
                    "$.refundedAt",
                    "Refunded escrow records require refundedAt",
                ));
            }
        }
        EscrowStatusV1::Cancelled => {
            if escrow.cancelled_at.is_none() {
                issues.push(marketplace_issue(
                    "$.cancelledAt",
                    "Cancelled escrow records require cancelledAt",
                ));
            }
        }
        EscrowStatusV1::Disputed => {
            if escrow.evidence_refs.len() < 2 {
                warnings.push(marketplace_issue(
                    "$.evidenceRefs",
                    "Disputed escrow records should include dispute evidence refs",
                ));
            }
        }
        EscrowStatusV1::Expired => {}
    }

    let payment_authorization_verification = authorization.map(|authorization| {
        let verification = verify_payment_authorization(authorization, quote);
        if !verification.valid {
            issues.push(marketplace_issue(
                "$.authorization",
                "Referenced payment authorization does not verify",
            ));
        }
        verify_escrow_matches_authorization(escrow, authorization, &mut issues, &mut warnings);
        verification
    });

    if let Some(quote) = quote {
        let quote_verification = verify_service_quote(quote, None);
        if !quote_verification.valid {
            issues.push(marketplace_issue(
                "$.quote",
                "Referenced service quote does not verify",
            ));
        }
        verify_escrow_matches_quote(escrow, quote, &mut issues);
    }

    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "escrow-record",
                &escrow_record_signing_value(escrow),
                Some(&escrow.custodian),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(marketplace_issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(marketplace_issue(
                "$.signature",
                "Escrow signature does not match canonical dev signature or Ed25519 identity envelope",
            ));
        }
    } else {
        warnings.push(marketplace_issue(
            "$.signature",
            "Escrow record is unsigned; verify escrowId through a trusted source",
        ));
    }

    EscrowRecordVerificationV1 {
        schema_version: ESCROW_RECORD_VERIFICATION_SCHEMA_VERSION.to_string(),
        escrow_id: escrow.escrow_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        payment_authorization_verification,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn release_escrow_for_settlement(request: &EscrowReleaseRequestV1) -> EscrowReleaseResultV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if request.schema_version != ESCROW_RELEASE_REQUEST_SCHEMA_VERSION {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {ESCROW_RELEASE_REQUEST_SCHEMA_VERSION}"),
        ));
    }
    if request.released_by.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.releasedBy",
            "Escrow release requires releasedBy",
        ));
    }
    let escrow_verification = verify_escrow_record(&request.escrow, None, None);
    if !escrow_verification.valid {
        issues.push(marketplace_issue(
            "$.escrow",
            "Escrow record must verify before release",
        ));
    }
    let settlement_verification = verify_settlement_event(&request.settlement);
    if !settlement_verification.valid {
        issues.push(marketplace_issue(
            "$.settlement",
            "Settlement event must verify before escrow release",
        ));
    }
    verify_escrow_can_release_for_settlement(&request.escrow, &request.settlement, &mut issues);

    let escrow = if issues.is_empty() {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let mut updated = request.escrow.clone();
        updated.status = EscrowStatusV1::Released;
        updated.settlement_id = Some(request.settlement.settlement_id.clone());
        updated.released_at = Some(now);
        updated.reason = Some(
            request
                .reason
                .clone()
                .filter(|reason| !reason.trim().is_empty())
                .unwrap_or_else(|| "released for verified settlement".to_string()),
        );
        push_evidence_ref(
            &mut updated.evidence_refs,
            format!("local://settlement/{}", request.settlement.settlement_id),
        );
        merge_evidence_refs(&mut updated.evidence_refs, request.evidence_refs.iter());
        sign_escrow_record(&mut updated);
        Some(updated)
    } else {
        warnings.extend(escrow_verification.warnings.clone());
        None
    };
    let release_verification = escrow
        .as_ref()
        .map(|escrow| verify_escrow_record(escrow, None, None))
        .unwrap_or_else(|| escrow_verification.clone());
    EscrowReleaseResultV1 {
        schema_version: ESCROW_RELEASE_RESULT_SCHEMA_VERSION.to_string(),
        valid: escrow.is_some() && issues.is_empty() && release_verification.valid,
        escrow,
        issues,
        warnings,
        escrow_verification: release_verification,
        settlement_verification,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn read_escrow_record(path: &Path) -> anyhow::Result<EscrowRecordV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse escrow record JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_escrow_record(escrows_dir: &Path, escrow: &EscrowRecordV1) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(escrows_dir)?;
    let path = escrows_dir.join(format!("{}.json", safe_file_component(&escrow.escrow_id)));
    fs::write(&path, serde_json::to_vec_pretty(escrow)?)?;
    Ok(path)
}

pub fn get_escrow_record(
    escrows_dir: &Path,
    escrow_id: &str,
) -> anyhow::Result<Option<EscrowRecordLookupV1>> {
    let escrow_id = escrow_id.trim();
    if escrow_id.is_empty() {
        anyhow::bail!("escrowId is required");
    }

    let direct_path = escrows_dir.join(format!("{}.json", safe_file_component(escrow_id)));
    if direct_path.exists() {
        let escrow = read_escrow_record(&direct_path)?;
        if escrow.escrow_id == escrow_id {
            return Ok(Some(escrow_record_lookup(escrow, direct_path)));
        }
    }

    if !escrows_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(escrows_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let escrow = read_escrow_record(&path)?;
            if escrow.escrow_id == escrow_id {
                return Ok(Some(escrow_record_lookup(escrow, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_escrow_records(escrows_dir: &Path) -> anyhow::Result<EscrowRecordStoreSummaryV1> {
    let mut escrows = Vec::new();
    if escrows_dir.exists() {
        for entry in fs::read_dir(escrows_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let escrow = read_escrow_record(&path)?;
                escrows.push(escrow_record_index_entry(
                    &escrow,
                    path.display().to_string(),
                ));
            }
        }
    }
    escrows.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.escrow_id.cmp(&right.escrow_id))
    });
    let valid_count = escrows
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    let locked_count = escrows
        .iter()
        .filter(|entry| entry.status == EscrowStatusV1::Locked)
        .count();
    let released_count = escrows
        .iter()
        .filter(|entry| entry.status == EscrowStatusV1::Released)
        .count();
    let refunded_count = escrows
        .iter()
        .filter(|entry| entry.status == EscrowStatusV1::Refunded)
        .count();
    Ok(EscrowRecordStoreSummaryV1 {
        schema_version: "hivemind.escrow-record-store-summary.v1".to_string(),
        root: escrows_dir.display().to_string(),
        escrow_count: escrows.len(),
        locked_count,
        released_count,
        refunded_count,
        valid_count,
        invalid_count: escrows.len().saturating_sub(valid_count),
        escrows,
    })
}

pub fn build_refund_record(request: &RefundBuildRequestV1) -> RefundBuildResultV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if request.schema_version != REFUND_BUILD_REQUEST_SCHEMA_VERSION {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {REFUND_BUILD_REQUEST_SCHEMA_VERSION}"),
        ));
    }
    let settlement_verification = verify_settlement_event(&request.settlement);
    if !settlement_verification.valid {
        issues.push(marketplace_issue(
            "$.settlement",
            "Refund record requires a valid settlement event",
        ));
    }
    let resolution_verification = verify_settlement_resolution(&request.resolution);
    if !resolution_verification.valid {
        issues.push(marketplace_issue(
            "$.resolution",
            "Refund record requires a valid settlement resolution",
        ));
    }
    let dispute_verification = request.dispute.as_ref().map(|dispute| {
        let verification = hivemind_receipts::verify_dispute_evidence(dispute);
        if !verification.valid {
            issues.push(marketplace_issue(
                "$.dispute",
                "Refund dispute evidence must verify",
            ));
        }
        verification
    });
    verify_refund_source_matches(
        &request.settlement,
        &request.resolution,
        request.dispute.as_ref(),
        &mut issues,
        &mut warnings,
    );
    if request.refunded_by.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.refundedBy",
            "Refund record requires refundedBy",
        ));
    } else if request.refunded_by != request.resolution.resolved_by {
        issues.push(marketplace_issue(
            "$.refundedBy",
            "RefundedBy must match settlement resolution resolvedBy",
        ));
    }
    if let Some(refund_ref) = request.refund_ref.as_deref() {
        if refund_ref.trim().is_empty() {
            issues.push(marketplace_issue(
                "$.refundRef",
                "Refund ref must not be empty when present",
            ));
        } else if !looks_like_marketplace_ref(refund_ref) {
            warnings.push(marketplace_issue(
                "$.refundRef",
                "Refund ref is not a recognized marketplace reference",
            ));
        }
    } else {
        warnings.push(marketplace_issue(
            "$.refundRef",
            "Refund record has no refundRef; treat as local audit evidence, not payment finality",
        ));
    }
    if let Some(occurred_at) = request.occurred_at.as_deref() {
        parse_marketplace_time(
            occurred_at,
            "$.occurredAt",
            "Refund timestamp must be RFC3339",
            &mut issues,
        );
    }

    let refund = if issues.is_empty() {
        let mut evidence_refs = refund_evidence_refs(request);
        evidence_refs.sort();
        evidence_refs.dedup();
        let mut record = RefundRecordV1 {
            schema_version: REFUND_RECORD_SCHEMA_VERSION.to_string(),
            refund_id: String::new(),
            settlement_id: request.settlement.settlement_id.clone(),
            source_settlement_id: request.resolution.settlement_id.clone(),
            resolution_id: request.resolution.resolution_id.clone(),
            dispute_id: Some(request.resolution.dispute_id.clone())
                .filter(|value| !value.trim().is_empty()),
            receipt_id: request.settlement.receipt_id.clone(),
            job_id: request.settlement.job_id.clone(),
            request_id: request.settlement.request_id.clone(),
            quote_id: request.settlement.quote_id.clone(),
            payment_authorization_id: request.settlement.payment_authorization_id.clone(),
            package_ref: request.settlement.package_ref.clone(),
            runner_id: request.settlement.runner_id.clone(),
            payer: request.settlement.payer.clone(),
            payee: request.settlement.payee.clone(),
            refunded_by: request.refunded_by.clone(),
            amount: request.settlement.amount,
            currency: request.settlement.currency.clone(),
            asset: request.settlement.asset.clone(),
            refund_ref: request.refund_ref.clone(),
            evidence_refs,
            reason: request
                .reason
                .clone()
                .filter(|reason| !reason.trim().is_empty())
                .unwrap_or_else(|| request.resolution.reason.clone()),
            occurred_at: request
                .occurred_at
                .clone()
                .unwrap_or_else(|| Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)),
            signature: None,
        };
        sign_refund_record(&mut record);
        Some(record)
    } else {
        None
    };

    let verification = if let Some(record) = &refund {
        let mut verification = verify_refund_record(record);
        verification.warnings.extend(warnings);
        verification.valid = verification.valid && verification.issues.is_empty();
        verification
    } else {
        RefundRecordVerificationV1 {
            schema_version: REFUND_RECORD_VERIFICATION_SCHEMA_VERSION.to_string(),
            refund_id: None,
            valid: false,
            issues,
            warnings,
            expected_signature: None,
            verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        }
    };

    RefundBuildResultV1 {
        schema_version: REFUND_BUILD_RESULT_SCHEMA_VERSION.to_string(),
        refund,
        verification,
        settlement_verification,
        resolution_verification,
        dispute_verification,
    }
}

pub fn sign_refund_record(record: &mut RefundRecordV1) {
    record.signature = Some(expected_refund_record_signature(record));
    record.refund_id = canonical_refund_record_id(record);
}

pub fn sign_refund_record_with_identity(
    record: &mut RefundRecordV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != record.refunded_by {
        anyhow::bail!(
            "identity subject {} does not match refund record refundedBy {}",
            identity.subject,
            record.refunded_by
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "refund-record",
        &refund_record_signing_value(record),
    )?;
    record.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    record.refund_id = canonical_refund_record_id(record);
    Ok(envelope)
}

pub fn expected_refund_record_signature(record: &RefundRecordV1) -> String {
    format!(
        "{DEV_REFUND_RECORD_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&refund_record_signing_value(record)))
    )
}

pub fn canonical_refund_record_id(record: &RefundRecordV1) -> String {
    stable_id("refund", &refund_record_signing_value(record))
}

pub fn verify_refund_record(record: &RefundRecordV1) -> RefundRecordVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_refund_record_signature(record));
    let signature = record
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if record.schema_version != REFUND_RECORD_SCHEMA_VERSION {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {REFUND_RECORD_SCHEMA_VERSION}"),
        ));
    }
    if record.refund_id.trim().is_empty() {
        issues.push(marketplace_issue("$.refundId", "Refund id is required"));
    } else if signature.is_some() && record.refund_id != canonical_refund_record_id(record) {
        issues.push(marketplace_issue(
            "$.refundId",
            "Refund id does not match canonical signed content",
        ));
    }
    for (path, value, message) in [
        (
            "$.settlementId",
            record.settlement_id.as_str(),
            "Settlement id is required",
        ),
        (
            "$.sourceSettlementId",
            record.source_settlement_id.as_str(),
            "Source settlement id is required",
        ),
        (
            "$.resolutionId",
            record.resolution_id.as_str(),
            "Resolution id is required",
        ),
        (
            "$.receiptId",
            record.receipt_id.as_str(),
            "Receipt id is required",
        ),
        (
            "$.requestId",
            record.request_id.as_str(),
            "Request id is required",
        ),
        (
            "$.packageRef",
            record.package_ref.as_str(),
            "Package ref is required",
        ),
        (
            "$.runnerId",
            record.runner_id.as_str(),
            "Runner id is required",
        ),
        ("$.payer", record.payer.as_str(), "Payer is required"),
        ("$.payee", record.payee.as_str(), "Payee is required"),
        (
            "$.refundedBy",
            record.refunded_by.as_str(),
            "RefundedBy is required",
        ),
        (
            "$.currency",
            record.currency.as_str(),
            "Currency is required",
        ),
        ("$.reason", record.reason.as_str(), "Reason is required"),
    ] {
        if value.trim().is_empty() {
            issues.push(marketplace_issue(path, message));
        }
    }
    if record.amount <= 0.0 {
        issues.push(marketplace_issue(
            "$.amount",
            "Refund amount must be greater than zero",
        ));
    }
    if let Some(asset) = record.asset.as_deref() {
        if asset.trim().is_empty() {
            issues.push(marketplace_issue("$.asset", "Refund asset is empty"));
        } else if asset != record.currency {
            issues.push(marketplace_issue(
                "$.asset",
                "Refund asset must match currency",
            ));
        }
    } else {
        issues.push(marketplace_issue(
            "$.asset",
            "Refund record requires asset for settlement compatibility",
        ));
    }
    if !record.package_ref.starts_with("bzz://") {
        warnings.push(marketplace_issue(
            "$.packageRef",
            "Refund packageRef is not a bzz:// reference",
        ));
    }
    if record.evidence_refs.is_empty() {
        issues.push(marketplace_issue(
            "$.evidenceRefs",
            "Refund record requires settlement, resolution, and dispute evidence refs",
        ));
    }
    for (index, evidence_ref) in record.evidence_refs.iter().enumerate() {
        if evidence_ref.trim().is_empty() {
            issues.push(marketplace_issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference must not be empty",
            ));
        } else if !looks_like_marketplace_ref(evidence_ref) {
            warnings.push(marketplace_issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference is not a recognized marketplace reference",
            ));
        }
    }
    if let Some(refund_ref) = record.refund_ref.as_deref()
        && !looks_like_marketplace_ref(refund_ref)
    {
        warnings.push(marketplace_issue(
            "$.refundRef",
            "Refund ref is not a recognized marketplace reference",
        ));
    }
    parse_marketplace_time(
        &record.occurred_at,
        "$.occurredAt",
        "Refund timestamp must be RFC3339",
        &mut issues,
    );

    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "refund-record",
                &refund_record_signing_value(record),
                Some(&record.refunded_by),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(marketplace_issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(marketplace_issue(
                "$.signature",
                "Refund signature does not match canonical dev signature or Ed25519 identity envelope",
            ));
        }
    } else {
        warnings.push(marketplace_issue(
            "$.signature",
            "Refund record is unsigned; verify refundId through a trusted source",
        ));
    }

    RefundRecordVerificationV1 {
        schema_version: REFUND_RECORD_VERIFICATION_SCHEMA_VERSION.to_string(),
        refund_id: Some(record.refund_id.clone()),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn read_refund_record(path: &Path) -> anyhow::Result<RefundRecordV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse refund record JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_refund_record(audit_dir: &Path, refund: &RefundRecordV1) -> anyhow::Result<PathBuf> {
    let refunds_dir = marketplace_refunds_dir(audit_dir);
    fs::create_dir_all(&refunds_dir)?;
    let path = refunds_dir.join(format!("{}.json", safe_file_component(&refund.refund_id)));
    fs::write(&path, serde_json::to_vec_pretty(refund)?)?;
    Ok(path)
}

pub fn get_refund_record(
    audit_dir: &Path,
    refund_id: &str,
) -> anyhow::Result<Option<RefundRecordLookupV1>> {
    let refund_id = refund_id.trim();
    if refund_id.is_empty() {
        anyhow::bail!("refundId is required");
    }
    let refunds_dir = marketplace_refunds_dir(audit_dir);
    let direct_path = refunds_dir.join(format!("{}.json", safe_file_component(refund_id)));
    if direct_path.exists() {
        let refund = read_refund_record(&direct_path)?;
        if refund.refund_id == refund_id {
            return Ok(Some(refund_record_lookup(refund, direct_path)));
        }
    }
    if !refunds_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(refunds_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let refund = read_refund_record(&path)?;
            if refund.refund_id == refund_id {
                return Ok(Some(refund_record_lookup(refund, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_refund_records(audit_dir: &Path) -> anyhow::Result<RefundRecordStoreSummaryV1> {
    let refunds_dir = marketplace_refunds_dir(audit_dir);
    let mut refunds = Vec::new();
    if refunds_dir.exists() {
        for entry in fs::read_dir(&refunds_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let refund = read_refund_record(&path)?;
                refunds.push(refund_record_index_entry(
                    &refund,
                    path.display().to_string(),
                ));
            }
        }
    }
    refunds.sort_by(|left, right| {
        left.occurred_at
            .cmp(&right.occurred_at)
            .then(left.refund_id.cmp(&right.refund_id))
    });
    let valid_count = refunds
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    let total_refunded_amount = refunds
        .iter()
        .filter(|entry| entry.verification.valid)
        .map(|entry| entry.amount)
        .sum();
    let mut currency_counts = BTreeMap::new();
    for refund in &refunds {
        *currency_counts.entry(refund.currency.clone()).or_insert(0) += 1;
    }
    Ok(RefundRecordStoreSummaryV1 {
        schema_version: "hivemind.refund-record-store-summary.v1".to_string(),
        root: refunds_dir.display().to_string(),
        refund_count: refunds.len(),
        valid_count,
        invalid_count: refunds.len().saturating_sub(valid_count),
        total_refunded_amount,
        currency_counts,
        refunds,
    })
}

pub fn settlement_from_receipt(
    receipt: &ExecutionReceiptV1,
    quote: Option<&ServiceQuoteV1>,
    payer: impl Into<String>,
    payee: impl Into<String>,
    receipt_ref: Option<String>,
) -> SettlementEventV1 {
    settlement_from_receipt_with_payment(receipt, quote, None, payer, payee, receipt_ref)
}

pub fn settlement_from_receipt_with_payment(
    receipt: &ExecutionReceiptV1,
    quote: Option<&ServiceQuoteV1>,
    payment_authorization: Option<&PaymentAuthorizationV1>,
    payer: impl Into<String>,
    payee: impl Into<String>,
    receipt_ref: Option<String>,
) -> SettlementEventV1 {
    let receipt_ref = receipt_ref;
    let (quote_id, amount, currency) = if let Some(quote) = quote {
        (
            Some(quote.quote_id.clone()),
            quote.estimated_cost,
            quote.currency.clone(),
        )
    } else {
        (
            None,
            receipt.billing.estimated_cost,
            receipt.billing.currency.clone(),
        )
    };
    let job_id = settlement_job_id(receipt, quote, payment_authorization);
    let evidence_refs = settlement_evidence_refs(
        receipt,
        quote,
        payment_authorization,
        receipt_ref.as_deref(),
    );
    let reason = settlement_status_reason(SettlementStatus::Settled, payment_authorization, quote);
    let occurred_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let (payment_authorization_id, payment_ref) =
        if let Some(payment_authorization) = payment_authorization {
            (
                Some(payment_authorization.authorization_id.clone()),
                payment_authorization.payment_ref.clone(),
            )
        } else {
            (None, None)
        };
    let mut settlement = SettlementEventV1 {
        schema_version: SETTLEMENT_EVENT_SCHEMA_VERSION.to_string(),
        settlement_id: String::new(),
        job_id,
        request_id: receipt.request_id.clone(),
        receipt_id: receipt.receipt_id.clone(),
        quote_id,
        payment_authorization_id,
        payment_ref,
        package_ref: receipt.package_ref.clone(),
        runner_id: receipt.runner_id.clone(),
        payer: payer.into(),
        payee: payee.into(),
        amount,
        currency: currency.clone(),
        asset: Some(currency),
        status: SettlementStatus::Settled,
        reason: Some(reason),
        evidence_refs,
        created_at: Some(occurred_at.clone()),
        occurred_at,
        receipt_ref,
        signature: None,
    };
    sign_settlement_event(&mut settlement);
    settlement
}

pub fn sign_settlement_event(settlement: &mut SettlementEventV1) {
    settlement.signature = Some(expected_settlement_event_signature(settlement));
    settlement.settlement_id = canonical_settlement_event_id(settlement);
}

pub fn sign_settlement_event_with_identity(
    settlement: &mut SettlementEventV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != settlement.payee {
        anyhow::bail!(
            "identity subject {} does not match settlement payee {}",
            identity.subject,
            settlement.payee
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "settlement-event",
        &settlement_event_signing_value(settlement),
    )?;
    settlement.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    settlement.settlement_id = canonical_settlement_event_id(settlement);
    Ok(envelope)
}

pub fn expected_settlement_event_signature(settlement: &SettlementEventV1) -> String {
    format!(
        "{DEV_SETTLEMENT_EVENT_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&settlement_event_signing_value(
            settlement
        )))
    )
}

pub fn canonical_settlement_event_id(settlement: &SettlementEventV1) -> String {
    stable_id("settlement", &settlement_event_signing_value(settlement))
}

pub fn verify_settlement_event(settlement: &SettlementEventV1) -> SettlementEventVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_settlement_event_signature(settlement));
    let current_schema = settlement.schema_version == SETTLEMENT_EVENT_SCHEMA_VERSION;
    let signature = settlement
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if !matches!(
        settlement.schema_version.as_str(),
        SETTLEMENT_EVENT_SCHEMA_VERSION | LEGACY_SETTLEMENT_EVENT_SCHEMA_VERSION
    ) {
        issues.push(settlement_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.settlement_event.v1",
        ));
    }
    if current_schema {
        if settlement
            .job_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            issues.push(settlement_issue(
                "$.jobId",
                "Current settlement schema requires jobId",
            ));
        }
        if settlement
            .asset
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            issues.push(settlement_issue(
                "$.asset",
                "Current settlement schema requires asset",
            ));
        }
        if settlement
            .reason
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            issues.push(settlement_issue(
                "$.reason",
                "Current settlement schema requires reason",
            ));
        }
        if settlement.evidence_refs.is_empty() {
            issues.push(settlement_issue(
                "$.evidenceRefs",
                "Current settlement schema requires at least one evidence reference",
            ));
        }
        if settlement
            .created_at
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
        {
            issues.push(settlement_issue(
                "$.createdAt",
                "Current settlement schema requires createdAt",
            ));
        }
    }
    if settlement.settlement_id.trim().is_empty() {
        issues.push(settlement_issue(
            "$.settlementId",
            "Settlement id is required",
        ));
    } else if signature.is_some()
        && settlement.settlement_id != canonical_settlement_event_id(settlement)
    {
        issues.push(settlement_issue(
            "$.settlementId",
            "Settlement id does not match canonical signed content",
        ));
    }
    for (path, value, message) in [
        (
            "$.requestId",
            settlement.request_id.as_str(),
            "Request id is required",
        ),
        (
            "$.receiptId",
            settlement.receipt_id.as_str(),
            "Receipt id is required",
        ),
        (
            "$.packageRef",
            settlement.package_ref.as_str(),
            "Package ref is required",
        ),
        (
            "$.runnerId",
            settlement.runner_id.as_str(),
            "Runner id is required",
        ),
        ("$.payer", settlement.payer.as_str(), "Payer is required"),
        ("$.payee", settlement.payee.as_str(), "Payee is required"),
        (
            "$.currency",
            settlement.currency.as_str(),
            "Currency is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(settlement_issue(path, message));
        }
    }
    if !settlement.package_ref.starts_with("bzz://") {
        warnings.push(settlement_issue(
            "$.packageRef",
            "Settlement packageRef is not a bzz:// reference",
        ));
    }
    if settlement.amount < 0.0 {
        issues.push(settlement_issue("$.amount", "Amount must not be negative"));
    }
    if let Some(asset) = settlement.asset.as_deref()
        && asset.trim() != settlement.currency
    {
        issues.push(settlement_issue(
            "$.asset",
            "Settlement asset must match currency compatibility field",
        ));
    }
    for (index, evidence_ref) in settlement.evidence_refs.iter().enumerate() {
        if evidence_ref.trim().is_empty() {
            issues.push(settlement_issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference must not be empty",
            ));
        } else if !is_settlement_receipt_ref(evidence_ref) {
            warnings.push(settlement_issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference is not a recognized bzz:// or local:// reference",
            ));
        }
    }
    if let Some(receipt_ref) = &settlement.receipt_ref
        && !is_settlement_receipt_ref(receipt_ref)
    {
        warnings.push(settlement_issue(
            "$.receiptRef",
            "Receipt reference is not a recognized bzz:// or local:// reference",
        ));
    }
    match DateTime::parse_from_rfc3339(&settlement.occurred_at) {
        Ok(_) => {}
        Err(_) => issues.push(settlement_issue(
            "$.occurredAt",
            "Settlement timestamp must be RFC3339",
        )),
    }
    if let Some(created_at) = settlement.created_at.as_deref() {
        match DateTime::parse_from_rfc3339(created_at) {
            Ok(_) => {}
            Err(_) => issues.push(settlement_issue(
                "$.createdAt",
                "Settlement createdAt timestamp must be RFC3339",
            )),
        }
    }

    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "settlement-event",
                &settlement_event_signing_value(settlement),
                Some(&settlement.payee),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(settlement_issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(settlement_issue(
                "$.signature",
                "Settlement signature does not match canonical dev signature or Ed25519 identity envelope",
            ));
        }
    } else {
        warnings.push(settlement_issue(
            "$.signature",
            "Settlement is unsigned; verify settlementId through a trusted source",
        ));
    }

    SettlementEventVerificationV1 {
        schema_version: SETTLEMENT_EVENT_VERIFICATION_SCHEMA_VERSION.to_string(),
        settlement_id: settlement.settlement_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn settlement_from_verified_receipt(
    receipt: &ExecutionReceiptV1,
    quote: Option<&ServiceQuoteV1>,
    payer: impl Into<String>,
    payee: impl Into<String>,
    receipt_ref: Option<String>,
) -> SettlementBuildResultV1 {
    settlement_from_verified_receipt_with_payment(receipt, quote, None, payer, payee, receipt_ref)
}

pub fn settlement_from_verified_receipt_with_payment(
    receipt: &ExecutionReceiptV1,
    quote: Option<&ServiceQuoteV1>,
    payment_authorization: Option<&PaymentAuthorizationV1>,
    payer: impl Into<String>,
    payee: impl Into<String>,
    receipt_ref: Option<String>,
) -> SettlementBuildResultV1 {
    let payer = payer.into();
    let payee = payee.into();
    let receipt_ref = receipt_ref;
    let receipt_verification = hivemind_receipts::verify_receipt(receipt);
    let payment_authorization_verification = payment_authorization
        .map(|authorization| verify_payment_authorization(authorization, quote));
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if !receipt_verification.valid {
        issues.push(settlement_issue(
            "$.receipt",
            "Receipt must verify before settlement",
        ));
    }
    if payer.trim().is_empty() {
        issues.push(settlement_issue("$.payer", "Payer is required"));
    }
    if payee.trim().is_empty() {
        issues.push(settlement_issue("$.payee", "Payee is required"));
    }
    if let Some(reference) = &receipt_ref
        && !is_settlement_receipt_ref(reference)
    {
        warnings.push(settlement_issue(
            "$.receiptRef",
            "Receipt reference is not a recognized bzz:// or local:// reference",
        ));
    }

    if let Some(quote) = quote {
        let quote_verification = verify_service_quote(quote, None);
        if !quote_verification.valid {
            issues.push(settlement_issue(
                "$.quote",
                "Service quote must verify before settlement",
            ));
        }
        if quote.request_id != receipt.request_id {
            issues.push(settlement_issue(
                "$.quote.requestId",
                "Quote requestId must match receipt requestId",
            ));
        }
        if quote.package_ref != receipt.package_ref {
            issues.push(settlement_issue(
                "$.quote.packageRef",
                "Quote packageRef must match receipt packageRef",
            ));
        }
        if quote.runner_id != receipt.runner_id {
            issues.push(settlement_issue(
                "$.quote.runnerId",
                "Quote runnerId must match receipt runnerId",
            ));
        }
        match DateTime::parse_from_rfc3339(&quote.expires_at) {
            Ok(expires_at) if expires_at.with_timezone(&Utc) < Utc::now() => {
                issues.push(settlement_issue(
                    "$.quote.expiresAt",
                    "Quote is expired and cannot be settled",
                ));
            }
            Err(_) => issues.push(settlement_issue(
                "$.quote.expiresAt",
                "Quote expiration must be RFC3339",
            )),
            _ => {}
        }
    } else if receipt.billing.currency == "none" && receipt.billing.estimated_cost > 0.0 {
        warnings.push(settlement_issue(
            "$.receipt.billing",
            "Receipt has a positive estimated cost without a marketplace quote",
        ));
    }
    if let Some(payment_verification) = &payment_authorization_verification
        && !payment_verification.valid
    {
        issues.push(settlement_issue(
            "$.paymentAuthorization",
            "Payment authorization must verify before settlement",
        ));
    }
    if let Some(payment_authorization) = payment_authorization {
        if payment_authorization.request_id != receipt.request_id {
            issues.push(settlement_issue(
                "$.paymentAuthorization.requestId",
                "Payment authorization requestId must match receipt requestId",
            ));
        }
        if payment_authorization.package_ref != receipt.package_ref {
            issues.push(settlement_issue(
                "$.paymentAuthorization.packageRef",
                "Payment authorization packageRef must match receipt packageRef",
            ));
        }
        if payment_authorization.runner_id != receipt.runner_id {
            issues.push(settlement_issue(
                "$.paymentAuthorization.runnerId",
                "Payment authorization runnerId must match receipt runnerId",
            ));
        }
        if payment_authorization.payer != payer {
            issues.push(settlement_issue(
                "$.paymentAuthorization.payer",
                "Payment authorization payer must match settlement payer",
            ));
        }
        if payment_authorization.payee != payee {
            issues.push(settlement_issue(
                "$.paymentAuthorization.payee",
                "Payment authorization payee must match settlement payee",
            ));
        }
    } else if let Some(quote) = quote
        && quote.estimated_cost > 0.0
    {
        warnings.push(settlement_issue(
            "$.paymentAuthorization",
            "Positive-cost quote settled without a payment authorization",
        ));
    }

    let settlement = if issues.is_empty() {
        Some(settlement_from_receipt_with_payment(
            receipt,
            quote,
            payment_authorization,
            payer,
            payee,
            receipt_ref,
        ))
    } else {
        None
    };
    let settlement_id = settlement
        .as_ref()
        .map(|settlement| settlement.settlement_id.clone());
    let expected_signature = settlement.as_ref().map(expected_settlement_event_signature);
    let verification = SettlementVerificationV1 {
        schema_version: "swarm-ai.settlement-verification.v1".to_string(),
        settlement_id,
        valid: issues.is_empty(),
        issues,
        warnings,
        receipt_verification,
        payment_authorization_verification,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    };

    SettlementBuildResultV1 {
        schema_version: "swarm-ai.settlement-build-result.v1".to_string(),
        settlement,
        verification,
    }
}

pub fn open_settlement_dispute(
    settlement: &SettlementEventV1,
    dispute: &DisputeEvidenceV1,
    resolved_by: impl Into<String>,
    reason: impl Into<String>,
) -> SettlementResolutionResultV1 {
    resolve_settlement(
        settlement,
        dispute,
        SettlementResolutionAction::OpenDispute,
        SettlementStatus::Disputed,
        resolved_by,
        reason,
    )
}

pub fn refund_settlement(
    settlement: &SettlementEventV1,
    dispute: &DisputeEvidenceV1,
    resolved_by: impl Into<String>,
    reason: impl Into<String>,
) -> SettlementResolutionResultV1 {
    resolve_settlement(
        settlement,
        dispute,
        SettlementResolutionAction::Refund,
        SettlementStatus::Refunded,
        resolved_by,
        reason,
    )
}

pub fn reject_settlement_dispute(
    settlement: &SettlementEventV1,
    dispute: &DisputeEvidenceV1,
    resolved_by: impl Into<String>,
    reason: impl Into<String>,
) -> SettlementResolutionResultV1 {
    resolve_settlement(
        settlement,
        dispute,
        SettlementResolutionAction::RejectDispute,
        SettlementStatus::DisputeRejected,
        resolved_by,
        reason,
    )
}

pub fn sign_settlement_resolution(resolution: &mut SettlementResolutionV1) {
    resolution.signature = Some(expected_settlement_resolution_signature(resolution));
    resolution.resolution_id = canonical_settlement_resolution_id(resolution);
}

pub fn sign_settlement_resolution_with_identity(
    resolution: &mut SettlementResolutionV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != resolution.resolved_by {
        anyhow::bail!(
            "identity subject {} does not match settlement resolution resolvedBy {}",
            identity.subject,
            resolution.resolved_by
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "settlement-resolution",
        &settlement_resolution_signing_value(resolution),
    )?;
    resolution.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    resolution.resolution_id = canonical_settlement_resolution_id(resolution);
    Ok(envelope)
}

pub fn expected_settlement_resolution_signature(resolution: &SettlementResolutionV1) -> String {
    format!(
        "{DEV_SETTLEMENT_RESOLUTION_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&settlement_resolution_signing_value(
            resolution
        )))
    )
}

pub fn canonical_settlement_resolution_id(resolution: &SettlementResolutionV1) -> String {
    stable_id(
        "settlement-resolution",
        &settlement_resolution_signing_value(resolution),
    )
}

pub fn verify_settlement_resolution(
    resolution: &SettlementResolutionV1,
) -> SettlementResolutionVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_settlement_resolution_signature(resolution));
    let signature = resolution
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if resolution.schema_version != "swarm-ai.settlement-resolution.v1" {
        issues.push(settlement_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.settlement-resolution.v1",
        ));
    }
    if resolution.resolution_id.trim().is_empty() {
        issues.push(settlement_issue(
            "$.resolutionId",
            "Settlement resolution id is required",
        ));
    } else if signature.is_some()
        && resolution.resolution_id != canonical_settlement_resolution_id(resolution)
    {
        issues.push(settlement_issue(
            "$.resolutionId",
            "Settlement resolution id does not match canonical signed content",
        ));
    }
    for (path, value, message) in [
        (
            "$.settlementId",
            resolution.settlement_id.as_str(),
            "Settlement id is required",
        ),
        (
            "$.receiptId",
            resolution.receipt_id.as_str(),
            "Receipt id is required",
        ),
        (
            "$.disputeId",
            resolution.dispute_id.as_str(),
            "Dispute id is required",
        ),
        (
            "$.resolvedBy",
            resolution.resolved_by.as_str(),
            "Resolver is required",
        ),
        (
            "$.currency",
            resolution.currency.as_str(),
            "Currency is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(settlement_issue(path, message));
        }
    }
    if resolution.reason.trim().is_empty() {
        warnings.push(settlement_issue(
            "$.reason",
            "Settlement resolution reason is empty",
        ));
    }
    if resolution.amount < 0.0 {
        issues.push(settlement_issue("$.amount", "Amount must not be negative"));
    }
    match DateTime::parse_from_rfc3339(&resolution.occurred_at) {
        Ok(_) => {}
        Err(_) => issues.push(settlement_issue(
            "$.occurredAt",
            "Settlement resolution timestamp must be RFC3339",
        )),
    }

    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "settlement-resolution",
                &settlement_resolution_signing_value(resolution),
                Some(&resolution.resolved_by),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(settlement_issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(settlement_issue(
                "$.signature",
                "Settlement resolution signature does not match canonical dev signature or Ed25519 identity envelope",
            ));
        }
    } else {
        warnings.push(settlement_issue(
            "$.signature",
            "Settlement resolution is unsigned; verify resolutionId through a trusted source",
        ));
    }

    SettlementResolutionVerificationV1 {
        schema_version: "swarm-ai.settlement-resolution-verification.v1".to_string(),
        resolution_id: Some(resolution.resolution_id.clone()),
        valid: issues.is_empty(),
        issues,
        warnings,
        dispute_verification: None,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn build_slashing_record(request: &SlashingBuildRequestV1) -> SlashingBuildResultV1 {
    let settlement_verification = verify_settlement_event(&request.settlement);
    let dispute_verification = hivemind_receipts::verify_dispute_evidence(&request.dispute);
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if request.schema_version != SLASHING_BUILD_REQUEST_SCHEMA_VERSION {
        issues.push(settlement_issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {SLASHING_BUILD_REQUEST_SCHEMA_VERSION}"),
        ));
    }
    if !settlement_verification.valid {
        issues.push(settlement_issue(
            "$.settlement",
            "Settlement must verify before a slashing record can be created",
        ));
    }
    if !dispute_verification.valid {
        issues.push(settlement_issue(
            "$.dispute",
            "Dispute evidence must verify before a slashing record can be created",
        ));
    }
    if request.settlement.status != SettlementStatus::Disputed {
        issues.push(settlement_issue(
            "$.settlement.status",
            "Slashing requires an open disputed settlement as the appeal path",
        ));
    }
    verify_slashing_source_matches(
        &request.settlement,
        &request.dispute,
        &request.correctness_assessment,
        &mut issues,
    );
    let correctness_assessment_accepted =
        slashing_correctness_assessment_is_actionable(&request.correctness_assessment);
    if !correctness_assessment_accepted {
        issues.push(settlement_issue(
            "$.correctnessAssessment",
            "Slashing requires valid receipt verification plus failed validator/proof evidence; missing evidence alone is not enough",
        ));
    }
    if request.slashed_by.trim().is_empty() {
        issues.push(settlement_issue(
            "$.slashedBy",
            "Slasher identity is required",
        ));
    }
    if request.amount <= 0.0 {
        issues.push(settlement_issue(
            "$.amount",
            "Slashing amount must be greater than zero",
        ));
    }
    if request.amount > request.settlement.amount {
        warnings.push(settlement_issue(
            "$.amount",
            "Slashing amount is greater than the original settlement amount; confirm stake policy allows this",
        ));
    }
    if request.reason.trim().is_empty() {
        warnings.push(settlement_issue("$.reason", "Slashing reason is empty"));
    }
    let currency = request
        .currency
        .clone()
        .unwrap_or_else(|| request.settlement.currency.clone());
    if currency.trim().is_empty() {
        issues.push(settlement_issue("$.currency", "Currency is required"));
    }
    if currency != request.settlement.currency {
        warnings.push(settlement_issue(
            "$.currency",
            "Slashing currency differs from settlement currency",
        ));
    }
    if let Some(stake_ref) = request.stake_ref.as_deref() {
        if stake_ref.trim().is_empty() {
            issues.push(settlement_issue(
                "$.stakeRef",
                "Stake ref must not be empty when present",
            ));
        } else if !looks_like_marketplace_ref(stake_ref) {
            warnings.push(settlement_issue(
                "$.stakeRef",
                "Stake ref is not a recognized storage or audit reference",
            ));
        }
    } else {
        warnings.push(settlement_issue(
            "$.stakeRef",
            "Slashing record has no stakeRef; treat as policy/audit evidence, not collateral movement",
        ));
    }

    let slashing = if issues.is_empty() {
        let mut evidence_refs = slashing_evidence_refs(request);
        evidence_refs.sort();
        evidence_refs.dedup();
        let mut record = SlashingRecordV1 {
            schema_version: SLASHING_RECORD_SCHEMA_VERSION.to_string(),
            slashing_id: String::new(),
            settlement_id: request.settlement.settlement_id.clone(),
            dispute_id: request.dispute.dispute_id.clone(),
            receipt_id: request.settlement.receipt_id.clone(),
            job_id: request.settlement.job_id.clone(),
            runner_id: request.settlement.runner_id.clone(),
            slashed_party: request.settlement.payee.clone(),
            slashed_by: request.slashed_by.clone(),
            amount: request.amount,
            currency,
            stake_ref: request.stake_ref.clone(),
            reason_kind: request.reason_kind.clone(),
            reason: request.reason.clone(),
            evidence_refs,
            correctness_assessment_ref: Some(format!(
                "local://receipt-correctness/{}",
                request.correctness_assessment.receipt_id
            )),
            failed_methods: correctness_failed_method_names(&request.correctness_assessment),
            occurred_at: request
                .occurred_at
                .clone()
                .unwrap_or_else(|| Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)),
            signature: None,
        };
        sign_slashing_record(&mut record);
        Some(record)
    } else {
        None
    };

    let verification = if let Some(record) = &slashing {
        let mut verification = verify_slashing_record(record);
        verification.warnings.extend(warnings);
        verification.valid = verification.valid && verification.issues.is_empty();
        verification
    } else {
        SlashingRecordVerificationV1 {
            schema_version: SLASHING_RECORD_VERIFICATION_SCHEMA_VERSION.to_string(),
            slashing_id: None,
            valid: false,
            issues,
            warnings,
            expected_signature: None,
            verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        }
    };

    SlashingBuildResultV1 {
        schema_version: SLASHING_BUILD_RESULT_SCHEMA_VERSION.to_string(),
        slashing,
        verification,
        settlement_verification,
        dispute_verification,
        correctness_assessment_accepted,
    }
}

pub fn sign_slashing_record(record: &mut SlashingRecordV1) {
    record.signature = Some(expected_slashing_record_signature(record));
    record.slashing_id = canonical_slashing_record_id(record);
}

pub fn sign_slashing_record_with_identity(
    record: &mut SlashingRecordV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != record.slashed_by {
        anyhow::bail!(
            "identity subject {} does not match slashing record slashedBy {}",
            identity.subject,
            record.slashed_by
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "slashing-record",
        &slashing_record_signing_value(record),
    )?;
    record.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    record.slashing_id = canonical_slashing_record_id(record);
    Ok(envelope)
}

pub fn expected_slashing_record_signature(record: &SlashingRecordV1) -> String {
    format!(
        "{DEV_SLASHING_RECORD_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&slashing_record_signing_value(record)))
    )
}

pub fn canonical_slashing_record_id(record: &SlashingRecordV1) -> String {
    stable_id("slashing", &slashing_record_signing_value(record))
}

pub fn verify_slashing_record(record: &SlashingRecordV1) -> SlashingRecordVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_slashing_record_signature(record));
    let signature = record
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if record.schema_version != SLASHING_RECORD_SCHEMA_VERSION {
        issues.push(settlement_issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {SLASHING_RECORD_SCHEMA_VERSION}"),
        ));
    }
    if record.slashing_id.trim().is_empty() {
        issues.push(settlement_issue("$.slashingId", "Slashing id is required"));
    } else if signature.is_some() && record.slashing_id != canonical_slashing_record_id(record) {
        issues.push(settlement_issue(
            "$.slashingId",
            "Slashing id does not match canonical signed content",
        ));
    }
    for (path, value, message) in [
        (
            "$.settlementId",
            record.settlement_id.as_str(),
            "Settlement id is required",
        ),
        (
            "$.disputeId",
            record.dispute_id.as_str(),
            "Dispute id is required",
        ),
        (
            "$.receiptId",
            record.receipt_id.as_str(),
            "Receipt id is required",
        ),
        (
            "$.runnerId",
            record.runner_id.as_str(),
            "Runner id is required",
        ),
        (
            "$.slashedParty",
            record.slashed_party.as_str(),
            "Slashed party is required",
        ),
        (
            "$.slashedBy",
            record.slashed_by.as_str(),
            "Slasher identity is required",
        ),
        (
            "$.currency",
            record.currency.as_str(),
            "Currency is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(settlement_issue(path, message));
        }
    }
    if record.amount <= 0.0 {
        issues.push(settlement_issue(
            "$.amount",
            "Slashing amount must be greater than zero",
        ));
    }
    if record.reason.trim().is_empty() {
        warnings.push(settlement_issue("$.reason", "Slashing reason is empty"));
    }
    if record.evidence_refs.is_empty() {
        issues.push(settlement_issue(
            "$.evidenceRefs",
            "Slashing requires signed dispute, settlement, and validator evidence refs",
        ));
    }
    for (index, evidence_ref) in record.evidence_refs.iter().enumerate() {
        if evidence_ref.trim().is_empty() {
            issues.push(settlement_issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference must not be empty",
            ));
        } else if !looks_like_marketplace_ref(evidence_ref) {
            warnings.push(settlement_issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence reference is not a recognized storage or audit reference",
            ));
        }
    }
    if record.failed_methods.is_empty() {
        issues.push(settlement_issue(
            "$.failedMethods",
            "Slashing record must include failed correctness methods",
        ));
    }
    if let Some(reference) = record.correctness_assessment_ref.as_deref() {
        if reference.trim().is_empty() {
            issues.push(settlement_issue(
                "$.correctnessAssessmentRef",
                "Correctness assessment ref must not be empty when present",
            ));
        } else if !looks_like_marketplace_ref(reference) {
            warnings.push(settlement_issue(
                "$.correctnessAssessmentRef",
                "Correctness assessment ref is not a recognized storage or audit reference",
            ));
        }
    } else {
        warnings.push(settlement_issue(
            "$.correctnessAssessmentRef",
            "Slashing record has no correctnessAssessmentRef",
        ));
    }
    if let Some(stake_ref) = record.stake_ref.as_deref()
        && !looks_like_marketplace_ref(stake_ref)
    {
        warnings.push(settlement_issue(
            "$.stakeRef",
            "Stake ref is not a recognized storage or audit reference",
        ));
    }
    if DateTime::parse_from_rfc3339(&record.occurred_at).is_err() {
        issues.push(settlement_issue(
            "$.occurredAt",
            "Slashing timestamp must be RFC3339",
        ));
    }

    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "slashing-record",
                &slashing_record_signing_value(record),
                Some(&record.slashed_by),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(settlement_issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(settlement_issue(
                "$.signature",
                "Slashing signature does not match canonical dev signature or Ed25519 identity envelope",
            ));
        }
    } else {
        warnings.push(settlement_issue(
            "$.signature",
            "Slashing record is unsigned; verify slashingId through a trusted source",
        ));
    }

    SlashingRecordVerificationV1 {
        schema_version: SLASHING_RECORD_VERIFICATION_SCHEMA_VERSION.to_string(),
        slashing_id: Some(record.slashing_id.clone()),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn read_settlement_event(path: &Path) -> anyhow::Result<SettlementEventV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse settlement event JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_settlement_event(
    audit_dir: &Path,
    settlement: &SettlementEventV1,
) -> anyhow::Result<PathBuf> {
    let settlements_dir = marketplace_settlements_dir(audit_dir);
    fs::create_dir_all(&settlements_dir)?;
    let path = settlements_dir.join(format!(
        "{}.json",
        safe_file_component(&settlement.settlement_id)
    ));
    fs::write(&path, serde_json::to_vec_pretty(settlement)?)?;
    Ok(path)
}

pub fn get_settlement_event(
    audit_dir: &Path,
    settlement_id: &str,
) -> anyhow::Result<Option<SettlementEventLookupV1>> {
    let settlement_id = settlement_id.trim();
    if settlement_id.is_empty() {
        anyhow::bail!("settlementId is required");
    }

    let settlements_dir = marketplace_settlements_dir(audit_dir);
    let direct_path = settlements_dir.join(format!("{}.json", safe_file_component(settlement_id)));
    if direct_path.exists() {
        let settlement = read_settlement_event(&direct_path)?;
        if settlement.settlement_id == settlement_id {
            return Ok(Some(settlement_event_lookup(settlement, direct_path)));
        }
    }

    if !settlements_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(&settlements_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let settlement = read_settlement_event(&path)?;
            if settlement.settlement_id == settlement_id {
                return Ok(Some(settlement_event_lookup(settlement, path)));
            }
        }
    }
    Ok(None)
}

pub fn read_settlement_resolution(path: &Path) -> anyhow::Result<SettlementResolutionV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse settlement resolution JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_settlement_resolution(
    audit_dir: &Path,
    resolution: &SettlementResolutionV1,
) -> anyhow::Result<PathBuf> {
    let resolutions_dir = marketplace_resolutions_dir(audit_dir);
    fs::create_dir_all(&resolutions_dir)?;
    let path = resolutions_dir.join(format!(
        "{}.json",
        safe_file_component(&resolution.resolution_id)
    ));
    fs::write(&path, serde_json::to_vec_pretty(resolution)?)?;
    Ok(path)
}

pub fn get_settlement_resolution(
    audit_dir: &Path,
    resolution_id: &str,
) -> anyhow::Result<Option<SettlementResolutionLookupV1>> {
    let resolution_id = resolution_id.trim();
    if resolution_id.is_empty() {
        anyhow::bail!("resolutionId is required");
    }

    let resolutions_dir = marketplace_resolutions_dir(audit_dir);
    let direct_path = resolutions_dir.join(format!("{}.json", safe_file_component(resolution_id)));
    if direct_path.exists() {
        let resolution = read_settlement_resolution(&direct_path)?;
        if resolution.resolution_id == resolution_id {
            return Ok(Some(settlement_resolution_lookup(resolution, direct_path)));
        }
    }

    if !resolutions_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(&resolutions_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let resolution = read_settlement_resolution(&path)?;
            if resolution.resolution_id == resolution_id {
                return Ok(Some(settlement_resolution_lookup(resolution, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_marketplace_audit(audit_dir: &Path) -> anyhow::Result<MarketplaceAuditSummaryV1> {
    let quote_summary = list_service_quotes(audit_dir)?;
    let mut settlements = Vec::new();
    let settlements_dir = marketplace_settlements_dir(audit_dir);
    if settlements_dir.exists() {
        for entry in fs::read_dir(&settlements_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let settlement = read_settlement_event(&path)?;
                settlements.push(settlement_audit_entry(
                    &settlement,
                    path.display().to_string(),
                ));
            }
        }
    }
    settlements.sort_by(|left, right| {
        left.occurred_at
            .cmp(&right.occurred_at)
            .then(left.settlement_id.cmp(&right.settlement_id))
    });

    let mut resolutions = Vec::new();
    let resolutions_dir = marketplace_resolutions_dir(audit_dir);
    if resolutions_dir.exists() {
        for entry in fs::read_dir(&resolutions_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let resolution = read_settlement_resolution(&path)?;
                resolutions.push(settlement_resolution_audit_entry(
                    &resolution,
                    path.display().to_string(),
                ));
            }
        }
    }
    resolutions.sort_by(|left, right| {
        left.occurred_at
            .cmp(&right.occurred_at)
            .then(left.resolution_id.cmp(&right.resolution_id))
    });

    let valid_settlement_count = settlements
        .iter()
        .filter(|entry| entry.signature_verified)
        .count();
    let valid_resolution_count = resolutions
        .iter()
        .filter(|entry| entry.signature_verified)
        .count();
    let settlement_latency_values =
        quote_to_settlement_latency_values(&quote_summary.quotes, &settlements);
    Ok(MarketplaceAuditSummaryV1 {
        schema_version: "swarm-ai.marketplace-audit-summary.v1".to_string(),
        root: audit_dir.display().to_string(),
        quote_count: quote_summary.quote_count,
        valid_quote_count: quote_summary.valid_count,
        invalid_quote_count: quote_summary.invalid_count,
        settlement_count: settlements.len(),
        valid_settlement_count,
        invalid_settlement_count: settlements.len().saturating_sub(valid_settlement_count),
        resolution_count: resolutions.len(),
        valid_resolution_count,
        invalid_resolution_count: resolutions.len().saturating_sub(valid_resolution_count),
        settlement_latency_sample_count: settlement_latency_values.len(),
        average_quote_to_settlement_ms: average_u64(&settlement_latency_values),
        max_quote_to_settlement_ms: settlement_latency_values.iter().copied().max(),
        quote_cache_claim_sample_count: quote_summary.quote_cache_claim_sample_count,
        quote_cache_hit_count: quote_summary.quote_cache_hit_count,
        quote_cache_miss_count: quote_summary.quote_cache_miss_count,
        quote_cache_hit_rate: quote_summary.quote_cache_hit_rate,
        quotes: quote_summary.quotes,
        settlements,
        resolutions,
    })
}

fn quote_to_settlement_latency_values(
    quotes: &[ServiceQuoteIndexEntryV1],
    settlements: &[SettlementAuditEntryV1],
) -> Vec<u64> {
    let completed_at_by_quote_id = quotes
        .iter()
        .filter(|quote| quote.verification.valid)
        .filter_map(|quote| {
            quote
                .quote_completed_at
                .as_deref()
                .map(|completed_at| (quote.quote_id.as_str(), completed_at))
        })
        .collect::<BTreeMap<_, _>>();

    settlements
        .iter()
        .filter(|settlement| {
            settlement.signature_verified && settlement.status == SettlementStatus::Settled
        })
        .filter_map(|settlement| {
            let quote_id = settlement.quote_id.as_deref()?;
            let quote_completed_at = completed_at_by_quote_id.get(quote_id)?;
            quote_to_settlement_latency_ms(quote_completed_at, &settlement.occurred_at)
        })
        .collect()
}

fn quote_cache_hit_claims(quotes: &[ServiceQuoteIndexEntryV1]) -> Vec<bool> {
    quotes
        .iter()
        .filter(|quote| quote.verification.valid)
        .filter_map(|quote| quote.cache_hit_claim)
        .collect()
}

fn quote_to_settlement_latency_ms(
    quote_completed_at: &str,
    settlement_occurred_at: &str,
) -> Option<u64> {
    let quote_completed_at = DateTime::parse_from_rfc3339(quote_completed_at).ok()?;
    let settlement_occurred_at = DateTime::parse_from_rfc3339(settlement_occurred_at).ok()?;
    let elapsed_ms = settlement_occurred_at
        .signed_duration_since(quote_completed_at)
        .num_milliseconds();
    u64::try_from(elapsed_ms).ok()
}

fn average_u64(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64)
    }
}

fn ratio(numerator: usize, denominator: usize) -> Option<f64> {
    if denominator == 0 {
        None
    } else {
        Some(numerator as f64 / denominator as f64)
    }
}

fn estimate_input_tokens(input: &Value) -> u64 {
    input
        .get("text")
        .and_then(Value::as_str)
        .map(|text| text.split_whitespace().count().max(1) as u64)
        .unwrap_or_else(|| {
            let bytes = serde_json::to_vec(input).unwrap_or_default();
            ((bytes.len() as u64).saturating_add(3) / 4).max(1)
        })
}

fn privacy_tier_from_execution_privacy(privacy: &hivemind_core::ExecutionPrivacy) -> PrivacyTier {
    match privacy.receipt_mode {
        ReceiptMode::HashOnly => PrivacyTier::NoLog,
        ReceiptMode::EncryptedEvidence => PrivacyTier::RedactedInput,
        ReceiptMode::PublicEvidence => PrivacyTier::Standard,
    }
}

fn modality_from_task(task: &str) -> Option<Modality> {
    match task {
        "chat" | "completion" | "completions" => Some(Modality::Chat),
        "embedding" | "embeddings" => Some(Modality::Embedding),
        "classification" | "moderation" => Some(Modality::StructuredOutput),
        "ocr" | "image" | "image-generation" | "image-edit" => Some(Modality::Image),
        "audio-transcription" | "speech-to-text" | "text-to-speech" => Some(Modality::Audio),
        _ => None,
    }
}

fn select_runner_offer_privacy_tier(
    available: &[PrivacyTier],
    required: &PrivacyTier,
) -> Option<PrivacyTier> {
    preferred_runner_offer_privacy_order()
        .into_iter()
        .find(|tier| {
            available.contains(tier) && runner_offer_privacy_tier_satisfies(tier, required)
        })
}

fn preferred_runner_offer_privacy_tier(available: &[PrivacyTier]) -> Option<PrivacyTier> {
    preferred_runner_offer_privacy_order()
        .into_iter()
        .find(|tier| available.contains(tier))
}

fn preferred_runner_offer_privacy_order() -> Vec<PrivacyTier> {
    hivemind_core::privacy_tier_preference_order()
}

fn runner_offer_privacy_tier_satisfies(available: &PrivacyTier, required: &PrivacyTier) -> bool {
    hivemind_core::privacy_tier_satisfies(available, required)
}

fn select_runner_offer_integrity_tier(
    available: &[IntegrityTier],
    required: &IntegrityTier,
) -> Option<IntegrityTier> {
    preferred_runner_offer_integrity_order()
        .into_iter()
        .find(|tier| {
            available.contains(tier) && runner_offer_integrity_tier_satisfies(tier, required)
        })
}

fn preferred_runner_offer_integrity_tier(available: &[IntegrityTier]) -> Option<IntegrityTier> {
    preferred_runner_offer_integrity_order()
        .into_iter()
        .find(|tier| available.contains(tier))
}

fn preferred_runner_offer_integrity_order() -> Vec<IntegrityTier> {
    vec![
        IntegrityTier::ZkProofWhenSupported,
        IntegrityTier::TeeAttested,
        IntegrityTier::DeterministicReplay,
        IntegrityTier::RedundantExecution,
        IntegrityTier::ValidatorSpotCheck,
        IntegrityTier::ReceiptOnly,
    ]
}

fn runner_offer_integrity_tier_satisfies(
    available: &IntegrityTier,
    required: &IntegrityTier,
) -> bool {
    available == required || matches!(required, IntegrityTier::ReceiptOnly)
}

fn shortlist_policy_fit_score(
    request: &MarketplaceShortlistRequestV1,
    api_matches: bool,
    modality_matches: bool,
    selected_privacy_tier: Option<&PrivacyTier>,
    selected_verification_tier: Option<&IntegrityTier>,
    cache_hit_claim: bool,
) -> f64 {
    let mut score = 0.0;
    let mut slots = 0.0;
    if request.api_surface.is_some() {
        slots += 1.0;
        if api_matches {
            score += 1.0;
        }
    }
    if request.modality.is_some() {
        slots += 1.0;
        if modality_matches {
            score += 1.0;
        }
    }
    if request.required_privacy_tier.is_some() {
        slots += 1.0;
        if selected_privacy_tier.is_some() {
            score += 1.0;
        }
    }
    if request.required_verification_tier.is_some() {
        slots += 1.0;
        if selected_verification_tier.is_some() {
            score += 1.0;
        }
    }
    if cache_hit_claim {
        score += 0.25;
    }
    if slots == 0.0 { 1.0 } else { score / slots }
}

fn tier_wire_name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn service_quote_validation_support(offer: &RunnerOfferV1) -> Vec<String> {
    let mut support = vec!["receipt".to_string()];
    if offer
        .verification_tiers
        .contains(&IntegrityTier::ValidatorSpotCheck)
    {
        support.push("validator-spot-check".to_string());
    }
    if offer
        .verification_tiers
        .contains(&IntegrityTier::DeterministicReplay)
    {
        support.push("deterministic-replay".to_string());
    }
    if offer.reputation.validator_score > 0.0 {
        support.push("validator-reputation-summary".to_string());
    }
    support.sort();
    support.dedup();
    support
}

fn resolve_settlement(
    settlement: &SettlementEventV1,
    dispute: &DisputeEvidenceV1,
    action: SettlementResolutionAction,
    new_status: SettlementStatus,
    resolved_by: impl Into<String>,
    reason: impl Into<String>,
) -> SettlementResolutionResultV1 {
    let resolved_by = resolved_by.into();
    let reason = reason.into();
    let dispute_verification = hivemind_receipts::verify_dispute_evidence(dispute);
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if !dispute_verification.valid {
        issues.push(settlement_issue(
            "$.dispute",
            "Dispute evidence must verify before settlement resolution",
        ));
    }
    if dispute.receipt_id != settlement.receipt_id {
        issues.push(settlement_issue(
            "$.dispute.receiptId",
            "Dispute receiptId must match settlement receiptId",
        ));
    }
    if dispute.request_id != settlement.request_id {
        issues.push(settlement_issue(
            "$.dispute.requestId",
            "Dispute requestId must match settlement requestId",
        ));
    }
    if dispute.package_ref != settlement.package_ref {
        issues.push(settlement_issue(
            "$.dispute.packageRef",
            "Dispute packageRef must match settlement packageRef",
        ));
    }
    if dispute.runner_id != settlement.runner_id {
        issues.push(settlement_issue(
            "$.dispute.runnerId",
            "Dispute runnerId must match settlement runnerId",
        ));
    }
    if resolved_by.trim().is_empty() {
        issues.push(settlement_issue(
            "$.resolvedBy",
            "Settlement resolver is required",
        ));
    }
    if reason.trim().is_empty() {
        warnings.push(settlement_issue(
            "$.reason",
            "Settlement resolution reason is empty",
        ));
    }
    match action {
        SettlementResolutionAction::OpenDispute
            if settlement.status == SettlementStatus::Refunded =>
        {
            issues.push(settlement_issue(
                "$.settlement.status",
                "Refunded settlements cannot be disputed again",
            ));
        }
        SettlementResolutionAction::Refund if settlement.status != SettlementStatus::Disputed => {
            issues.push(settlement_issue(
                "$.settlement.status",
                "Only disputed settlements can be refunded",
            ));
        }
        SettlementResolutionAction::RejectDispute
            if settlement.status != SettlementStatus::Disputed =>
        {
            issues.push(settlement_issue(
                "$.settlement.status",
                "Only disputed settlements can reject a dispute",
            ));
        }
        _ => {}
    }

    let (resolution, updated_settlement) = if issues.is_empty() {
        let updated_settlement =
            settlement_with_status(settlement, new_status.clone(), reason.as_str(), dispute);
        let mut resolution = SettlementResolutionV1 {
            schema_version: "swarm-ai.settlement-resolution.v1".to_string(),
            resolution_id: String::new(),
            settlement_id: settlement.settlement_id.clone(),
            receipt_id: settlement.receipt_id.clone(),
            dispute_id: dispute.dispute_id.clone(),
            action,
            previous_status: settlement.status.clone(),
            new_status,
            amount: settlement.amount,
            currency: settlement.currency.clone(),
            resolved_by,
            reason,
            occurred_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            signature: None,
        };
        sign_settlement_resolution(&mut resolution);
        (Some(resolution), Some(updated_settlement))
    } else {
        (None, None)
    };
    let expected_signature = resolution
        .as_ref()
        .map(expected_settlement_resolution_signature);

    let verification = SettlementResolutionVerificationV1 {
        schema_version: "swarm-ai.settlement-resolution-verification.v1".to_string(),
        resolution_id: resolution
            .as_ref()
            .map(|resolution| resolution.resolution_id.clone()),
        valid: issues.is_empty(),
        issues,
        warnings,
        dispute_verification: Some(dispute_verification),
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    };

    SettlementResolutionResultV1 {
        schema_version: "swarm-ai.settlement-resolution-result.v1".to_string(),
        resolution,
        updated_settlement,
        verification,
    }
}

fn settlement_with_status(
    settlement: &SettlementEventV1,
    status: SettlementStatus,
    reason: &str,
    dispute: &DisputeEvidenceV1,
) -> SettlementEventV1 {
    let mut updated = settlement.clone();
    updated.status = status.clone();
    updated.reason = Some(settlement_resolution_reason(status, reason));
    merge_evidence_refs(&mut updated.evidence_refs, dispute.evidence_refs.iter());
    let dispute_ref = format!("local://dispute/{}", dispute.dispute_id);
    merge_evidence_refs(&mut updated.evidence_refs, std::iter::once(&dispute_ref));
    let occurred_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    updated
        .created_at
        .get_or_insert_with(|| occurred_at.clone());
    updated.occurred_at = occurred_at;
    updated.settlement_id.clear();
    updated.signature = None;
    sign_settlement_event(&mut updated);
    updated
}

fn verify_slashing_source_matches(
    settlement: &SettlementEventV1,
    dispute: &DisputeEvidenceV1,
    assessment: &ReceiptCorrectnessAssessmentV1,
    issues: &mut Vec<SettlementVerificationIssueV1>,
) {
    if dispute.receipt_id != settlement.receipt_id {
        issues.push(settlement_issue(
            "$.dispute.receiptId",
            "Dispute receiptId must match settlement receiptId",
        ));
    }
    if dispute.request_id != settlement.request_id {
        issues.push(settlement_issue(
            "$.dispute.requestId",
            "Dispute requestId must match settlement requestId",
        ));
    }
    if dispute.package_ref != settlement.package_ref {
        issues.push(settlement_issue(
            "$.dispute.packageRef",
            "Dispute packageRef must match settlement packageRef",
        ));
    }
    if dispute.runner_id != settlement.runner_id {
        issues.push(settlement_issue(
            "$.dispute.runnerId",
            "Dispute runnerId must match settlement runnerId",
        ));
    }
    if assessment.receipt_id != settlement.receipt_id {
        issues.push(settlement_issue(
            "$.correctnessAssessment.receiptId",
            "Correctness assessment receiptId must match settlement receiptId",
        ));
    }
}

fn slashing_correctness_assessment_is_actionable(
    assessment: &ReceiptCorrectnessAssessmentV1,
) -> bool {
    assessment.receipt_verification.valid
        && !assessment.failed_methods.is_empty()
        && !assessment.validation_refs.is_empty()
}

fn refund_evidence_refs(request: &RefundBuildRequestV1) -> Vec<String> {
    let mut refs = request.evidence_refs.clone();
    refs.push(format!(
        "local://marketplace/settlement/{}",
        request.settlement.settlement_id
    ));
    refs.push(format!(
        "local://marketplace/resolution/{}",
        request.resolution.resolution_id
    ));
    if let Some(dispute_id) = request
        .dispute
        .as_ref()
        .map(|dispute| dispute.dispute_id.as_str())
        .filter(|dispute_id| !dispute_id.trim().is_empty())
    {
        refs.push(format!("local://dispute/{dispute_id}"));
    } else if !request.resolution.dispute_id.trim().is_empty() {
        refs.push(format!("local://dispute/{}", request.resolution.dispute_id));
    }
    if let Some(refund_ref) = request.refund_ref.as_deref() {
        refs.push(refund_ref.to_string());
    }
    refs.extend(request.settlement.evidence_refs.clone());
    if let Some(dispute) = request.dispute.as_ref() {
        refs.extend(dispute.evidence_refs.clone());
    }
    refs
}

fn slashing_evidence_refs(request: &SlashingBuildRequestV1) -> Vec<String> {
    let mut refs = request.evidence_refs.clone();
    refs.push(format!(
        "local://marketplace/settlement/{}",
        request.settlement.settlement_id
    ));
    refs.push(format!("local://dispute/{}", request.dispute.dispute_id));
    refs.push(format!(
        "local://receipt-correctness/{}",
        request.correctness_assessment.receipt_id
    ));
    refs.extend(request.dispute.evidence_refs.clone());
    refs.extend(request.correctness_assessment.validation_refs.clone());
    refs
}

fn correctness_failed_method_names(assessment: &ReceiptCorrectnessAssessmentV1) -> Vec<String> {
    let mut methods = assessment
        .failed_methods
        .iter()
        .filter_map(|method| {
            serde_json::to_value(method)
                .ok()
                .and_then(|value| value.as_str().map(str::to_string))
        })
        .collect::<Vec<_>>();
    methods.sort();
    methods.dedup();
    methods
}

fn settlement_issue(
    path: impl Into<String>,
    message: impl Into<String>,
) -> SettlementVerificationIssueV1 {
    SettlementVerificationIssueV1 {
        path: path.into(),
        message: message.into(),
    }
}

fn marketplace_issue(
    path: impl Into<String>,
    message: impl Into<String>,
) -> MarketplaceVerificationIssueV1 {
    MarketplaceVerificationIssueV1 {
        path: path.into(),
        message: message.into(),
    }
}

fn parse_marketplace_time(
    value: &str,
    path: &str,
    message: &str,
    issues: &mut Vec<MarketplaceVerificationIssueV1>,
) -> Option<DateTime<Utc>> {
    match DateTime::parse_from_rfc3339(value) {
        Ok(parsed) => Some(parsed.with_timezone(&Utc)),
        Err(_) => {
            issues.push(marketplace_issue(path, message));
            None
        }
    }
}

fn empty_terms() -> Value {
    json!({})
}

fn payment_authorization_index_entry(
    authorization: &PaymentAuthorizationV1,
    authorization_path: String,
) -> PaymentAuthorizationIndexEntryV1 {
    let verification = verify_payment_authorization(authorization, None);
    PaymentAuthorizationIndexEntryV1 {
        authorization_id: authorization.authorization_id.clone(),
        quote_id: authorization.quote_id.clone(),
        job_id: authorization.job_id.clone(),
        request_id: authorization.request_id.clone(),
        offer_id: authorization.offer_id.clone(),
        runner_id: authorization.runner_id.clone(),
        package_ref: authorization.package_ref.clone(),
        payer: authorization.payer.clone(),
        payee: authorization.payee.clone(),
        amount: authorization.amount,
        currency: authorization.currency.clone(),
        adapter: authorization.adapter.clone(),
        max_amount: authorization.max_amount,
        asset: authorization.asset.clone(),
        method: authorization.method.clone(),
        status: authorization.status.clone(),
        payment_ref: authorization.payment_ref.clone(),
        escrow_ref: authorization.escrow_ref.clone(),
        authorized_at: authorization.authorized_at.clone(),
        expires_at: authorization.expires_at.clone(),
        authorization_path,
        verification,
    }
}

fn service_quote_index_entry(
    quote: &ServiceQuoteV1,
    quote_path: String,
) -> ServiceQuoteIndexEntryV1 {
    let verification = verify_service_quote(quote, None);
    let quote_timing = quote.quote_timing.as_ref();
    ServiceQuoteIndexEntryV1 {
        quote_id: quote.quote_id.clone(),
        job_id: quote.job_id.clone(),
        request_id: quote.request_id.clone(),
        offer_id: quote.offer_id.clone(),
        listing_id: quote.listing_id.clone(),
        runner_id: quote.runner_id.clone(),
        package_ref: quote.package_ref.clone(),
        estimated_cost: quote.estimated_cost,
        currency: quote.currency.clone(),
        settlement_model: quote.settlement_model.clone(),
        expires_at: quote.expires_at.clone(),
        quote_elapsed_ms: quote_timing.map(|timing| timing.elapsed_ms),
        quote_started_at: quote_timing.map(|timing| timing.started_at.clone()),
        quote_completed_at: quote_timing.map(|timing| timing.completed_at.clone()),
        cache_hit_claim: quote.cache_hit_claim,
        quote_path,
        verification,
    }
}

fn service_quote_lookup(quote: ServiceQuoteV1, path: PathBuf) -> ServiceQuoteLookupV1 {
    let verification = verify_service_quote(&quote, None);
    ServiceQuoteLookupV1 {
        schema_version: "hivemind.service-quote-lookup.v1".to_string(),
        quote_id: quote.quote_id.clone(),
        quote_path: path.display().to_string(),
        quote,
        verification,
    }
}

fn payment_authorization_lookup(
    authorization: PaymentAuthorizationV1,
    path: PathBuf,
) -> PaymentAuthorizationLookupV1 {
    let verification = verify_payment_authorization(&authorization, None);
    PaymentAuthorizationLookupV1 {
        schema_version: "swarm-ai.payment-authorization-lookup.v1".to_string(),
        authorization_id: authorization.authorization_id.clone(),
        authorization_path: path.display().to_string(),
        authorization,
        verification,
    }
}

fn escrow_record_index_entry(
    escrow: &EscrowRecordV1,
    escrow_path: String,
) -> EscrowRecordIndexEntryV1 {
    let verification = verify_escrow_record(escrow, None, None);
    EscrowRecordIndexEntryV1 {
        escrow_id: escrow.escrow_id.clone(),
        authorization_id: escrow.authorization_id.clone(),
        quote_id: escrow.quote_id.clone(),
        job_id: escrow.job_id.clone(),
        request_id: escrow.request_id.clone(),
        runner_id: escrow.runner_id.clone(),
        payer: escrow.payer.clone(),
        payee: escrow.payee.clone(),
        amount: escrow.amount,
        currency: escrow.currency.clone(),
        status: escrow.status.clone(),
        custodian: escrow.custodian.clone(),
        settlement_id: escrow.settlement_id.clone(),
        created_at: escrow.created_at.clone(),
        expires_at: escrow.expires_at.clone(),
        escrow_path,
        verification,
    }
}

fn escrow_record_lookup(escrow: EscrowRecordV1, path: PathBuf) -> EscrowRecordLookupV1 {
    let verification = verify_escrow_record(&escrow, None, None);
    EscrowRecordLookupV1 {
        schema_version: "hivemind.escrow-record-lookup.v1".to_string(),
        escrow_id: escrow.escrow_id.clone(),
        escrow_path: path.display().to_string(),
        escrow,
        verification,
    }
}

fn refund_record_index_entry(
    refund: &RefundRecordV1,
    refund_path: String,
) -> RefundRecordIndexEntryV1 {
    let verification = verify_refund_record(refund);
    RefundRecordIndexEntryV1 {
        refund_id: refund.refund_id.clone(),
        settlement_id: refund.settlement_id.clone(),
        source_settlement_id: refund.source_settlement_id.clone(),
        resolution_id: refund.resolution_id.clone(),
        dispute_id: refund.dispute_id.clone(),
        receipt_id: refund.receipt_id.clone(),
        job_id: refund.job_id.clone(),
        request_id: refund.request_id.clone(),
        runner_id: refund.runner_id.clone(),
        payer: refund.payer.clone(),
        payee: refund.payee.clone(),
        refunded_by: refund.refunded_by.clone(),
        amount: refund.amount,
        currency: refund.currency.clone(),
        refund_ref: refund.refund_ref.clone(),
        occurred_at: refund.occurred_at.clone(),
        refund_path,
        verification,
    }
}

fn refund_record_lookup(refund: RefundRecordV1, path: PathBuf) -> RefundRecordLookupV1 {
    let verification = verify_refund_record(&refund);
    RefundRecordLookupV1 {
        schema_version: "hivemind.refund-record-lookup.v1".to_string(),
        refund_id: refund.refund_id.clone(),
        refund_path: path.display().to_string(),
        refund,
        verification,
    }
}

fn marketplace_quotes_dir(audit_dir: &Path) -> PathBuf {
    audit_dir.join("quotes")
}

fn marketplace_settlements_dir(audit_dir: &Path) -> PathBuf {
    audit_dir.join("settlements")
}

fn marketplace_resolutions_dir(audit_dir: &Path) -> PathBuf {
    audit_dir.join("resolutions")
}

fn marketplace_refunds_dir(audit_dir: &Path) -> PathBuf {
    audit_dir.join("refunds")
}

fn settlement_audit_entry(
    settlement: &SettlementEventV1,
    settlement_path: String,
) -> SettlementAuditEntryV1 {
    let verification = verify_settlement_event(settlement);
    SettlementAuditEntryV1 {
        settlement_id: settlement.settlement_id.clone(),
        job_id: settlement.job_id.clone(),
        request_id: settlement.request_id.clone(),
        receipt_id: settlement.receipt_id.clone(),
        quote_id: settlement.quote_id.clone(),
        payment_authorization_id: settlement.payment_authorization_id.clone(),
        package_ref: settlement.package_ref.clone(),
        runner_id: settlement.runner_id.clone(),
        payer: settlement.payer.clone(),
        payee: settlement.payee.clone(),
        amount: settlement.amount,
        currency: settlement.currency.clone(),
        asset: settlement.asset.clone(),
        status: settlement.status.clone(),
        reason: settlement.reason.clone(),
        evidence_ref_count: settlement.evidence_refs.len(),
        created_at: settlement.created_at.clone(),
        occurred_at: settlement.occurred_at.clone(),
        settlement_path,
        signature_verified: verification.valid,
    }
}

fn settlement_resolution_audit_entry(
    resolution: &SettlementResolutionV1,
    resolution_path: String,
) -> SettlementResolutionAuditEntryV1 {
    let verification = verify_settlement_resolution(resolution);
    SettlementResolutionAuditEntryV1 {
        resolution_id: resolution.resolution_id.clone(),
        settlement_id: resolution.settlement_id.clone(),
        receipt_id: resolution.receipt_id.clone(),
        dispute_id: resolution.dispute_id.clone(),
        action: resolution.action.clone(),
        previous_status: resolution.previous_status.clone(),
        new_status: resolution.new_status.clone(),
        amount: resolution.amount,
        currency: resolution.currency.clone(),
        resolved_by: resolution.resolved_by.clone(),
        occurred_at: resolution.occurred_at.clone(),
        resolution_path,
        signature_verified: verification.valid,
    }
}

fn settlement_event_lookup(
    settlement: SettlementEventV1,
    path: PathBuf,
) -> SettlementEventLookupV1 {
    let verification = verify_settlement_event(&settlement);
    SettlementEventLookupV1 {
        schema_version: "swarm-ai.settlement-event-lookup.v1".to_string(),
        settlement_id: settlement.settlement_id.clone(),
        settlement_path: path.display().to_string(),
        settlement,
        verification,
    }
}

fn settlement_resolution_lookup(
    resolution: SettlementResolutionV1,
    path: PathBuf,
) -> SettlementResolutionLookupV1 {
    let verification = verify_settlement_resolution(&resolution);
    SettlementResolutionLookupV1 {
        schema_version: "swarm-ai.settlement-resolution-lookup.v1".to_string(),
        resolution_id: resolution.resolution_id.clone(),
        resolution_path: path.display().to_string(),
        resolution,
        verification,
    }
}

fn is_settlement_receipt_ref(reference: &str) -> bool {
    reference.starts_with("bzz://") || reference.starts_with("local://")
}

fn verify_refund_source_matches(
    settlement: &SettlementEventV1,
    resolution: &SettlementResolutionV1,
    dispute: Option<&DisputeEvidenceV1>,
    issues: &mut Vec<MarketplaceVerificationIssueV1>,
    warnings: &mut Vec<MarketplaceVerificationIssueV1>,
) {
    if settlement.status != SettlementStatus::Refunded {
        issues.push(marketplace_issue(
            "$.settlement.status",
            "Refund record requires a refunded settlement",
        ));
    }
    if resolution.action != SettlementResolutionAction::Refund {
        issues.push(marketplace_issue(
            "$.resolution.action",
            "Refund record requires a refund settlement resolution",
        ));
    }
    if resolution.new_status != SettlementStatus::Refunded {
        issues.push(marketplace_issue(
            "$.resolution.newStatus",
            "Refund settlement resolution must end in refunded status",
        ));
    }
    if resolution.settlement_id.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.resolution.settlementId",
            "Refund resolution requires source settlementId",
        ));
    }
    if resolution.receipt_id != settlement.receipt_id {
        issues.push(marketplace_issue(
            "$.resolution.receiptId",
            "Refund resolution receiptId must match refunded settlement",
        ));
    }
    if (resolution.amount - settlement.amount).abs() > 0.000_000_1 {
        issues.push(marketplace_issue(
            "$.resolution.amount",
            "Refund resolution amount must match refunded settlement amount",
        ));
    }
    if resolution.currency != settlement.currency {
        issues.push(marketplace_issue(
            "$.resolution.currency",
            "Refund resolution currency must match refunded settlement currency",
        ));
    }
    if resolution.resolved_by.trim().is_empty() {
        issues.push(marketplace_issue(
            "$.resolution.resolvedBy",
            "Refund resolution requires resolvedBy",
        ));
    }
    if resolution.reason.trim().is_empty() {
        warnings.push(marketplace_issue(
            "$.resolution.reason",
            "Refund resolution reason is empty",
        ));
    }

    if let Some(dispute) = dispute {
        if dispute.dispute_id != resolution.dispute_id {
            issues.push(marketplace_issue(
                "$.dispute.disputeId",
                "Dispute id must match refund resolution disputeId",
            ));
        }
        if dispute.receipt_id != settlement.receipt_id {
            issues.push(marketplace_issue(
                "$.dispute.receiptId",
                "Dispute receiptId must match refunded settlement receiptId",
            ));
        }
        if dispute.request_id != settlement.request_id {
            issues.push(marketplace_issue(
                "$.dispute.requestId",
                "Dispute requestId must match refunded settlement requestId",
            ));
        }
        if dispute.package_ref != settlement.package_ref {
            issues.push(marketplace_issue(
                "$.dispute.packageRef",
                "Dispute packageRef must match refunded settlement packageRef",
            ));
        }
        if dispute.runner_id != settlement.runner_id {
            issues.push(marketplace_issue(
                "$.dispute.runnerId",
                "Dispute runnerId must match refunded settlement runnerId",
            ));
        }
    } else if !resolution.dispute_id.trim().is_empty() {
        warnings.push(marketplace_issue(
            "$.dispute",
            "Refund record was built without embedded dispute evidence; verify disputeId separately",
        ));
    }
}

fn verify_escrow_matches_authorization(
    escrow: &EscrowRecordV1,
    authorization: &PaymentAuthorizationV1,
    issues: &mut Vec<MarketplaceVerificationIssueV1>,
    warnings: &mut Vec<MarketplaceVerificationIssueV1>,
) {
    for (path, escrow_value, authorization_value, message) in [
        (
            "$.authorizationId",
            escrow.authorization_id.as_str(),
            authorization.authorization_id.as_str(),
            "Escrow authorizationId must match payment authorization",
        ),
        (
            "$.quoteId",
            escrow.quote_id.as_str(),
            authorization.quote_id.as_str(),
            "Escrow quoteId must match payment authorization",
        ),
        (
            "$.requestId",
            escrow.request_id.as_str(),
            authorization.request_id.as_str(),
            "Escrow requestId must match payment authorization",
        ),
        (
            "$.offerId",
            escrow.offer_id.as_str(),
            authorization.offer_id.as_str(),
            "Escrow offerId must match payment authorization",
        ),
        (
            "$.runnerId",
            escrow.runner_id.as_str(),
            authorization.runner_id.as_str(),
            "Escrow runnerId must match payment authorization",
        ),
        (
            "$.packageRef",
            escrow.package_ref.as_str(),
            authorization.package_ref.as_str(),
            "Escrow packageRef must match payment authorization",
        ),
        (
            "$.payer",
            escrow.payer.as_str(),
            authorization.payer.as_str(),
            "Escrow payer must match payment authorization",
        ),
        (
            "$.payee",
            escrow.payee.as_str(),
            authorization.payee.as_str(),
            "Escrow payee must match payment authorization",
        ),
        (
            "$.currency",
            escrow.currency.as_str(),
            authorization.currency.as_str(),
            "Escrow currency must match payment authorization",
        ),
        (
            "$.expiresAt",
            escrow.expires_at.as_str(),
            authorization.expires_at.as_str(),
            "Escrow expiresAt must match payment authorization",
        ),
    ] {
        if escrow_value != authorization_value {
            issues.push(marketplace_issue(path, message));
        }
    }
    if escrow.job_id != authorization.job_id {
        issues.push(marketplace_issue(
            "$.jobId",
            "Escrow jobId must match payment authorization",
        ));
    }
    if (escrow.amount - authorization.amount).abs() > 0.000_000_1 {
        issues.push(marketplace_issue(
            "$.amount",
            "Escrow amount must match payment authorization amount",
        ));
    }
    if escrow.asset != authorization.asset {
        issues.push(marketplace_issue(
            "$.asset",
            "Escrow asset must match payment authorization asset",
        ));
    }
    if escrow.adapter != authorization.adapter {
        issues.push(marketplace_issue(
            "$.adapter",
            "Escrow adapter must match payment authorization adapter",
        ));
    }
    if let Some(authorization_escrow_ref) = authorization.escrow_ref.as_deref() {
        if Some(authorization_escrow_ref) != escrow.escrow_ref.as_deref() {
            issues.push(marketplace_issue(
                "$.escrowRef",
                "Escrow ref must match payment authorization escrowRef",
            ));
        }
    } else {
        warnings.push(marketplace_issue(
            "$.authorization.escrowRef",
            "Payment authorization did not include escrowRef; link escrow by authorizationId",
        ));
    }
    if let (Some(escrow_payment_ref), Some(authorization_payment_ref)) = (
        escrow.payment_ref.as_deref(),
        authorization.payment_ref.as_deref(),
    ) && escrow_payment_ref != authorization_payment_ref
    {
        issues.push(marketplace_issue(
            "$.paymentRef",
            "Escrow paymentRef must match payment authorization paymentRef",
        ));
    }
}

fn verify_escrow_matches_quote(
    escrow: &EscrowRecordV1,
    quote: &ServiceQuoteV1,
    issues: &mut Vec<MarketplaceVerificationIssueV1>,
) {
    for (path, escrow_value, quote_value, message) in [
        (
            "$.quoteId",
            escrow.quote_id.as_str(),
            quote.quote_id.as_str(),
            "Escrow quoteId must match service quote",
        ),
        (
            "$.requestId",
            escrow.request_id.as_str(),
            quote.request_id.as_str(),
            "Escrow requestId must match service quote",
        ),
        (
            "$.offerId",
            escrow.offer_id.as_str(),
            quote.offer_id.as_str(),
            "Escrow offerId must match service quote",
        ),
        (
            "$.runnerId",
            escrow.runner_id.as_str(),
            quote.runner_id.as_str(),
            "Escrow runnerId must match service quote",
        ),
        (
            "$.packageRef",
            escrow.package_ref.as_str(),
            quote.package_ref.as_str(),
            "Escrow packageRef must match service quote",
        ),
        (
            "$.currency",
            escrow.currency.as_str(),
            quote.currency.as_str(),
            "Escrow currency must match service quote",
        ),
        (
            "$.expiresAt",
            escrow.expires_at.as_str(),
            quote.expires_at.as_str(),
            "Escrow expiresAt must match service quote",
        ),
    ] {
        if escrow_value != quote_value {
            issues.push(marketplace_issue(path, message));
        }
    }
    if let Some(quote_job_id) = quote.job_id.as_ref()
        && escrow.job_id.as_ref() != Some(quote_job_id)
    {
        issues.push(marketplace_issue(
            "$.jobId",
            "Escrow jobId must match service quote jobId",
        ));
    }
    if (escrow.amount - quote.estimated_cost).abs() > 0.000_000_1 {
        issues.push(marketplace_issue(
            "$.amount",
            "Escrow amount must match service quote estimatedCost",
        ));
    }
}

fn verify_escrow_can_release_for_settlement(
    escrow: &EscrowRecordV1,
    settlement: &SettlementEventV1,
    issues: &mut Vec<MarketplaceVerificationIssueV1>,
) {
    if !matches!(
        escrow.status,
        EscrowStatusV1::Locked | EscrowStatusV1::Disputed
    ) {
        issues.push(marketplace_issue(
            "$.escrow.status",
            "Only locked or disputed escrow records can be released",
        ));
    }
    if settlement.status != SettlementStatus::Settled {
        issues.push(marketplace_issue(
            "$.settlement.status",
            "Escrow release requires a settled settlement event",
        ));
    }
    if settlement
        .payment_authorization_id
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        != escrow.authorization_id
    {
        issues.push(marketplace_issue(
            "$.settlement.paymentAuthorizationId",
            "Settlement paymentAuthorizationId must match escrow authorizationId",
        ));
    }
    if settlement
        .quote_id
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        != escrow.quote_id
    {
        issues.push(marketplace_issue(
            "$.settlement.quoteId",
            "Settlement quoteId must match escrow quoteId",
        ));
    }
    if settlement.job_id != escrow.job_id {
        issues.push(marketplace_issue(
            "$.settlement.jobId",
            "Settlement jobId must match escrow jobId",
        ));
    }
    for (path, settlement_value, escrow_value, message) in [
        (
            "$.settlement.requestId",
            settlement.request_id.as_str(),
            escrow.request_id.as_str(),
            "Settlement requestId must match escrow requestId",
        ),
        (
            "$.settlement.packageRef",
            settlement.package_ref.as_str(),
            escrow.package_ref.as_str(),
            "Settlement packageRef must match escrow packageRef",
        ),
        (
            "$.settlement.runnerId",
            settlement.runner_id.as_str(),
            escrow.runner_id.as_str(),
            "Settlement runnerId must match escrow runnerId",
        ),
        (
            "$.settlement.payer",
            settlement.payer.as_str(),
            escrow.payer.as_str(),
            "Settlement payer must match escrow payer",
        ),
        (
            "$.settlement.payee",
            settlement.payee.as_str(),
            escrow.payee.as_str(),
            "Settlement payee must match escrow payee",
        ),
        (
            "$.settlement.currency",
            settlement.currency.as_str(),
            escrow.currency.as_str(),
            "Settlement currency must match escrow currency",
        ),
    ] {
        if settlement_value != escrow_value {
            issues.push(marketplace_issue(path, message));
        }
    }
    if (settlement.amount - escrow.amount).abs() > 0.000_000_1 {
        issues.push(marketplace_issue(
            "$.settlement.amount",
            "Settlement amount must match escrow amount",
        ));
    }
    if settlement.asset != escrow.asset {
        issues.push(marketplace_issue(
            "$.settlement.asset",
            "Settlement asset must match escrow asset",
        ));
    }
}

fn looks_like_marketplace_ref(reference: &str) -> bool {
    reference.starts_with("bzz://")
        || reference.starts_with("local://")
        || reference.starts_with("sha256://")
        || reference.starts_with("ipfs://")
        || reference.starts_with("https://")
}

fn is_legacy_listing_type(listing_type: &MarketplaceListingType) -> bool {
    matches!(
        listing_type,
        MarketplaceListingType::Package
            | MarketplaceListingType::Runner
            | MarketplaceListingType::Service
            | MarketplaceListingType::Validator
            | MarketplaceListingType::Benchmark
    )
}

fn marketplace_listing_kind_v2_from_v1(listing: &MarketplaceListingV1) -> MarketplaceListingKindV2 {
    match listing.listing_type {
        MarketplaceListingType::PackageSubscription => {
            MarketplaceListingKindV2::PackageSubscription
        }
        MarketplaceListingType::Package
        | MarketplaceListingType::PackageLicense
        | MarketplaceListingType::Runner
        | MarketplaceListingType::ContainerLeaseExperimental
        | MarketplaceListingType::FineTuningCapacity => {
            if matches!(listing.pricing.mode, PricingMode::Subscription) {
                MarketplaceListingKindV2::PackageSubscription
            } else {
                MarketplaceListingKindV2::PackageLicense
            }
        }
        MarketplaceListingType::VectorStoreService => MarketplaceListingKindV2::VectorStoreService,
        MarketplaceListingType::Service | MarketplaceListingType::HostedAiService => {
            if listing
                .details
                .get("packageKind")
                .and_then(Value::as_str)
                .map(|kind| kind == "vector_index" || kind == "rag_pipeline")
                .unwrap_or(false)
            {
                MarketplaceListingKindV2::VectorStoreService
            } else {
                MarketplaceListingKindV2::HostedInference
            }
        }
        MarketplaceListingType::RunnerCapacity | MarketplaceListingType::GpuCapacity => {
            MarketplaceListingKindV2::GpuCapacity
        }
        MarketplaceListingType::BatchCapacity => MarketplaceListingKindV2::BatchCapacity,
        MarketplaceListingType::ConfidentialRunner => MarketplaceListingKindV2::ConfidentialRunner,
        MarketplaceListingType::Validator | MarketplaceListingType::ValidatorService => {
            MarketplaceListingKindV2::ValidatorService
        }
        MarketplaceListingType::DatasetLicense => MarketplaceListingKindV2::DatasetLicense,
        MarketplaceListingType::Benchmark | MarketplaceListingType::BenchmarkBounty => {
            MarketplaceListingKindV2::BenchmarkBounty
        }
        MarketplaceListingType::ResearchGrant => MarketplaceListingKindV2::ResearchGrant,
    }
}

fn subject_type_for_listing_kind_v2(kind: &MarketplaceListingKindV2) -> &'static str {
    match kind {
        MarketplaceListingKindV2::PackageLicense
        | MarketplaceListingKindV2::PackageSubscription => "package",
        MarketplaceListingKindV2::HostedInference
        | MarketplaceListingKindV2::VectorStoreService => "service",
        MarketplaceListingKindV2::GpuCapacity | MarketplaceListingKindV2::ConfidentialRunner => {
            "compute_capacity"
        }
        MarketplaceListingKindV2::BatchCapacity => "batch_capacity",
        MarketplaceListingKindV2::ValidatorService => "validator_service",
        MarketplaceListingKindV2::DatasetLicense => "dataset",
        MarketplaceListingKindV2::BenchmarkBounty => "benchmark_bounty",
        MarketplaceListingKindV2::ResearchGrant => "research_grant",
    }
}

fn default_privacy_tiers_for_listing_kind_v2(kind: &MarketplaceListingKindV2) -> Vec<PrivacyTier> {
    match kind {
        MarketplaceListingKindV2::ConfidentialRunner => vec![PrivacyTier::TeeConfidential],
        MarketplaceListingKindV2::GpuCapacity
        | MarketplaceListingKindV2::BatchCapacity
        | MarketplaceListingKindV2::HostedInference
        | MarketplaceListingKindV2::ValidatorService
        | MarketplaceListingKindV2::VectorStoreService => {
            vec![PrivacyTier::Standard, PrivacyTier::NoLog]
        }
        MarketplaceListingKindV2::DatasetLicense
        | MarketplaceListingKindV2::PackageLicense
        | MarketplaceListingKindV2::PackageSubscription
        | MarketplaceListingKindV2::BenchmarkBounty
        | MarketplaceListingKindV2::ResearchGrant => {
            vec![PrivacyTier::Standard, PrivacyTier::LocalOnly]
        }
    }
}

fn default_verification_tiers_for_listing_kind_v2(
    kind: &MarketplaceListingKindV2,
    has_validation_refs: bool,
) -> Vec<IntegrityTier> {
    let mut tiers = vec![IntegrityTier::ReceiptOnly];
    if has_validation_refs
        || matches!(
            kind,
            MarketplaceListingKindV2::ValidatorService
                | MarketplaceListingKindV2::BenchmarkBounty
                | MarketplaceListingKindV2::ResearchGrant
                | MarketplaceListingKindV2::ConfidentialRunner
        )
    {
        tiers.push(IntegrityTier::ValidatorSpotCheck);
    }
    if matches!(kind, MarketplaceListingKindV2::ConfidentialRunner) {
        tiers.push(IntegrityTier::TeeAttested);
    }
    tiers
}

fn listing_requires_receipt(kind: &MarketplaceListingKindV2) -> bool {
    matches!(
        kind,
        MarketplaceListingKindV2::HostedInference
            | MarketplaceListingKindV2::GpuCapacity
            | MarketplaceListingKindV2::BatchCapacity
            | MarketplaceListingKindV2::ConfidentialRunner
            | MarketplaceListingKindV2::ValidatorService
            | MarketplaceListingKindV2::VectorStoreService
            | MarketplaceListingKindV2::BenchmarkBounty
            | MarketplaceListingKindV2::ResearchGrant
    )
}

fn settlement_model_for_pricing(mode: &PricingMode) -> &'static str {
    match mode {
        PricingMode::Free => "free",
        PricingMode::PayPerCall | PricingMode::PayPerToken => "direct-pay-per-call",
        PricingMode::Subscription => "subscription",
        PricingMode::Quote => "escrow-verified-job",
        PricingMode::StakeRewarded => "stake-rewarded",
    }
}

fn api_surfaces_for_package_kind(kind: &PackageKind) -> Vec<ApiSurface> {
    match kind {
        PackageKind::EmbeddingService => vec![ApiSurface::OpenAiEmbeddings],
        PackageKind::ImageGenerationService => vec![ApiSurface::OpenAiImages],
        PackageKind::ImageUnderstandingService => vec![ApiSurface::ImageUnderstanding],
        PackageKind::SpeechToTextService => vec![ApiSurface::SpeechToText],
        PackageKind::TextToSpeechService => vec![ApiSurface::TextToSpeech],
        PackageKind::RealtimeSessionService => vec![ApiSurface::OpenAiRealtime],
        PackageKind::VectorIndex | PackageKind::RagPipeline => {
            vec![ApiSurface::VectorSearch, ApiSurface::RagQuery]
        }
        PackageKind::EvalSuite | PackageKind::ScoringMethod => vec![ApiSurface::EvalRun],
        PackageKind::Service | PackageKind::ServiceDescriptor | PackageKind::ServiceAdapter => {
            vec![ApiSurface::HivemindNative]
        }
        _ => Vec::new(),
    }
}

fn modalities_for_package_kind(kind: &PackageKind) -> Vec<Modality> {
    match kind {
        PackageKind::Dataset => vec![Modality::Document, Modality::File],
        PackageKind::VectorIndex | PackageKind::RagPipeline => vec![Modality::VectorSearch],
        PackageKind::EmbeddingService => vec![Modality::Embedding, Modality::Text],
        PackageKind::ImageGenerationService | PackageKind::ImageUnderstandingService => {
            vec![Modality::Image]
        }
        PackageKind::SpeechToTextService | PackageKind::TextToSpeechService => {
            vec![Modality::Audio]
        }
        PackageKind::RealtimeSessionService => vec![Modality::Chat, Modality::Audio],
        PackageKind::Benchmark | PackageKind::EvalSuite | PackageKind::ScoringMethod => {
            vec![Modality::EvaluationData]
        }
        PackageKind::Tool | PackageKind::ToolPack => vec![Modality::ToolCall],
        _ => Vec::new(),
    }
}

fn parse_string_array(value: &Value) -> Option<Vec<String>> {
    Some(
        value
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .collect(),
    )
}

fn parse_api_surfaces(value: &Value) -> Option<Vec<ApiSurface>> {
    Some(
        value
            .as_array()?
            .iter()
            .cloned()
            .filter_map(|value| serde_json::from_value::<ApiSurface>(value).ok())
            .collect(),
    )
}

fn parse_modalities(value: &Value) -> Option<Vec<Modality>> {
    Some(
        value
            .as_array()?
            .iter()
            .cloned()
            .filter_map(|value| serde_json::from_value::<Modality>(value).ok())
            .collect(),
    )
}

fn parse_privacy_tiers(value: &Value) -> Option<Vec<PrivacyTier>> {
    Some(
        value
            .as_array()?
            .iter()
            .cloned()
            .filter_map(|value| serde_json::from_value::<PrivacyTier>(value).ok())
            .collect(),
    )
}

fn parse_integrity_tiers(value: &Value) -> Option<Vec<IntegrityTier>> {
    Some(
        value
            .as_array()?
            .iter()
            .cloned()
            .filter_map(|value| serde_json::from_value::<IntegrityTier>(value).ok())
            .collect(),
    )
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

fn marketplace_listing_signing_value(listing: &MarketplaceListingV1) -> Value {
    let mut value = serde_json::to_value(listing).expect("marketplace listing should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("listingId");
        object.remove("signature");
    }
    value
}

fn marketplace_listing_v2_signing_value(listing: &MarketplaceListingV2) -> Value {
    let mut value = serde_json::to_value(listing).expect("MarketplaceListingV2 should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("listingId");
        object.remove("signature");
    }
    value
}

fn hardware_resource_from_capability(capability: &RunnerCapabilityV1) -> HardwareResourceV1 {
    let vram_gb = capability
        .hardware
        .gpu_memory_mb
        .map(|memory_mb| memory_mb as f64 / 1024.0);
    HardwareResourceV1 {
        gpu_vendor: None,
        gpu_model: if capability.hardware.accelerator == "gpu" {
            Some("unspecified-gpu".to_string())
        } else {
            None
        },
        gpu_count: u32::from(capability.hardware.gpu_memory_mb.is_some()),
        vram_gb,
        cpu_cores: capability.hardware.cpu_threads,
        ram_gb: capability.memory.memory_mb as f64 / 1024.0,
        disk_gb: None,
        network_mbps: None,
        driver_version: None,
        runtime_versions: capability.engines.clone(),
    }
}

fn execution_modes_from_capability(
    capability: &RunnerCapabilityV1,
) -> Vec<HardwareExecutionModeV1> {
    let mut modes = vec![HardwareExecutionModeV1::PackageInference];
    if capability
        .supported_modalities
        .contains(&Modality::Embedding)
    {
        modes.push(HardwareExecutionModeV1::EmbeddingBatch);
        modes.push(HardwareExecutionModeV1::BatchInference);
    }
    if capability.supported_apis.contains(&ApiSurface::Batch) {
        modes.push(HardwareExecutionModeV1::BatchInference);
    }
    if capability.supported_apis.contains(&ApiSurface::FineTune) {
        modes.push(HardwareExecutionModeV1::FineTuneSmall);
    }
    if capability.supported_apis.contains(&ApiSurface::EvalRun) {
        modes.push(HardwareExecutionModeV1::EvaluationRun);
    }
    dedup_execution_modes(modes)
}

fn hardware_offer_price_table(capability: &RunnerCapabilityV1) -> Vec<RunnerPriceEntryV1> {
    if capability.price_table.is_empty() {
        return vec![RunnerPriceEntryV1 {
            price_model: PriceModel::PerSecond,
            unit: "second".to_string(),
            price: PriceV1 {
                amount: 0.0,
                currency: "quote-required".to_string(),
            },
        }];
    }
    capability.price_table.clone()
}

fn miner_trust_tier_for_capability(capability: &RunnerCapabilityV1) -> MinerTrustTierV1 {
    if capability
        .verification_tiers
        .contains(&IntegrityTier::ZkProofWhenSupported)
        || capability
            .privacy_tiers
            .contains(&PrivacyTier::FheEncrypted)
        || capability
            .privacy_tiers
            .contains(&PrivacyTier::FheEncryptedInference)
        || capability
            .privacy_tiers
            .contains(&PrivacyTier::ZkVerifiedInference)
        || capability
            .privacy_tiers
            .contains(&PrivacyTier::SplitTrustRedundant)
        || capability
            .privacy_tiers
            .contains(&PrivacyTier::MpcExperimental)
    {
        MinerTrustTierV1::Cryptographic
    } else if capability
        .verification_tiers
        .contains(&IntegrityTier::TeeAttested)
        || capability
            .privacy_tiers
            .contains(&PrivacyTier::TeeConfidential)
    {
        MinerTrustTierV1::Confidential
    } else if capability
        .verification_tiers
        .contains(&IntegrityTier::ValidatorSpotCheck)
        || capability
            .verification_tiers
            .contains(&IntegrityTier::DeterministicReplay)
    {
        MinerTrustTierV1::Verified
    } else {
        MinerTrustTierV1::Open
    }
}

fn dedup_execution_modes(mut values: Vec<HardwareExecutionModeV1>) -> Vec<HardwareExecutionModeV1> {
    let mut deduped = Vec::new();
    for value in values.drain(..) {
        if !deduped.contains(&value) {
            deduped.push(value);
        }
    }
    deduped
}

fn hardware_resource_offer_signing_value(offer: &HardwareResourceOfferV1) -> Value {
    let mut value = serde_json::to_value(offer).expect("hardware resource offer should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("offerId");
        object.remove("signature");
    }
    value
}

fn runner_offer_signing_value(offer: &RunnerOfferV1) -> Value {
    let mut value = serde_json::to_value(offer).expect("runner offer should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("offerId");
        object.remove("signature");
    }
    value
}

fn service_quote_signing_value(quote: &ServiceQuoteV1) -> Value {
    let mut value = serde_json::to_value(quote).expect("service quote should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("quoteId");
        object.remove("signature");
    }
    value
}

fn payment_authorization_job_id(quote: &ServiceQuoteV1) -> Option<String> {
    quote
        .job_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| quote_detail_string(quote, "jobId"))
        .or_else(|| {
            quote
                .details
                .get("jobOrder")
                .and_then(|job| job.get("jobId"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
}

fn quote_detail_string(quote: &ServiceQuoteV1, key: &str) -> Option<String> {
    quote
        .details
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn settlement_job_id(
    receipt: &ExecutionReceiptV1,
    quote: Option<&ServiceQuoteV1>,
    payment_authorization: Option<&PaymentAuthorizationV1>,
) -> Option<String> {
    quote
        .and_then(payment_authorization_job_id)
        .or_else(|| {
            payment_authorization.and_then(|authorization| {
                authorization
                    .job_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            })
        })
        .or_else(|| {
            let request_id = receipt.request_id.trim();
            (!request_id.is_empty()).then(|| format!("job-for-{request_id}"))
        })
}

fn settlement_evidence_refs(
    receipt: &ExecutionReceiptV1,
    quote: Option<&ServiceQuoteV1>,
    payment_authorization: Option<&PaymentAuthorizationV1>,
    receipt_ref: Option<&str>,
) -> Vec<String> {
    let mut evidence_refs = Vec::new();
    if let Some(receipt_ref) = receipt_ref {
        push_evidence_ref(&mut evidence_refs, receipt_ref);
    } else if !receipt.receipt_id.trim().is_empty() {
        push_evidence_ref(
            &mut evidence_refs,
            format!("local://receipt/{}", receipt.receipt_id),
        );
    }
    if let Some(quote) = quote {
        if !quote.quote_id.trim().is_empty() {
            push_evidence_ref(
                &mut evidence_refs,
                format!("local://quote/{}", quote.quote_id),
            );
        }
        if let Some(quote_ref) = quote_detail_string(quote, "quoteRef") {
            push_evidence_ref(&mut evidence_refs, quote_ref);
        }
        push_json_evidence_refs(&mut evidence_refs, quote.details.get("evidenceRefs"));
    }
    if let Some(authorization) = payment_authorization {
        if !authorization.authorization_id.trim().is_empty() {
            push_evidence_ref(
                &mut evidence_refs,
                format!(
                    "local://payment-authorization/{}",
                    authorization.authorization_id
                ),
            );
        }
        if let Some(payment_ref) = authorization.payment_ref.as_deref() {
            push_evidence_ref(&mut evidence_refs, payment_ref);
        }
        if let Some(escrow_ref) = authorization.escrow_ref.as_deref() {
            push_evidence_ref(&mut evidence_refs, escrow_ref);
        }
    }
    evidence_refs
}

fn push_json_evidence_refs(evidence_refs: &mut Vec<String>, value: Option<&Value>) {
    match value {
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(reference) = item.as_str() {
                    push_evidence_ref(evidence_refs, reference);
                }
            }
        }
        Some(Value::String(reference)) => push_evidence_ref(evidence_refs, reference),
        _ => {}
    }
}

fn merge_evidence_refs<'a>(
    evidence_refs: &mut Vec<String>,
    candidates: impl IntoIterator<Item = &'a String>,
) {
    for candidate in candidates {
        push_evidence_ref(evidence_refs, candidate);
    }
}

fn push_evidence_ref(evidence_refs: &mut Vec<String>, reference: impl AsRef<str>) {
    let reference = reference.as_ref().trim();
    if reference.is_empty() || evidence_refs.iter().any(|existing| existing == reference) {
        return;
    }
    evidence_refs.push(reference.to_string());
}

fn settlement_status_reason(
    status: SettlementStatus,
    payment_authorization: Option<&PaymentAuthorizationV1>,
    quote: Option<&ServiceQuoteV1>,
) -> String {
    match status {
        SettlementStatus::Settled if payment_authorization.is_some() => {
            "settled from verified receipt and payment authorization".to_string()
        }
        SettlementStatus::Settled if quote.is_some() => {
            "settled from receipt and service quote".to_string()
        }
        SettlementStatus::Settled => "settled from receipt billing estimate".to_string(),
        SettlementStatus::Authorized => "payment authorized".to_string(),
        SettlementStatus::PartiallySettled => "partially settled".to_string(),
        SettlementStatus::Refunded => "refunded".to_string(),
        SettlementStatus::Disputed => "dispute opened".to_string(),
        SettlementStatus::DisputeRejected => "dispute rejected".to_string(),
        SettlementStatus::Cancelled => "cancelled".to_string(),
        SettlementStatus::Failed => "failed".to_string(),
        SettlementStatus::Pending => "pending settlement".to_string(),
    }
}

fn settlement_resolution_reason(status: SettlementStatus, reason: &str) -> String {
    let label = settlement_status_reason(status, None, None);
    let reason = reason.trim();
    if reason.is_empty() {
        label
    } else {
        format!("{label}: {reason}")
    }
}

fn payment_authorization_signing_value(authorization: &PaymentAuthorizationV1) -> Value {
    let mut value =
        serde_json::to_value(authorization).expect("payment authorization should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("authorizationId");
        object.remove("signature");
    }
    value
}

fn escrow_record_signing_value(escrow: &EscrowRecordV1) -> Value {
    let mut value = serde_json::to_value(escrow).expect("escrow record should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("escrowId");
        object.remove("signature");
    }
    value
}

fn settlement_event_signing_value(settlement: &SettlementEventV1) -> Value {
    let mut value = serde_json::to_value(settlement).expect("settlement should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("settlementId");
        object.remove("signature");
    }
    value
}

fn settlement_resolution_signing_value(resolution: &SettlementResolutionV1) -> Value {
    let mut value =
        serde_json::to_value(resolution).expect("settlement resolution should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("resolutionId");
        object.remove("signature");
    }
    value
}

fn refund_record_signing_value(record: &RefundRecordV1) -> Value {
    let mut value = serde_json::to_value(record).expect("refund record should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("refundId");
        object.remove("signature");
    }
    value
}

fn slashing_record_signing_value(record: &SlashingRecordV1) -> Value {
    let mut value = serde_json::to_value(record).expect("slashing record should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("slashingId");
        object.remove("signature");
    }
    value
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

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("marketplace object should serialize");
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ExecutionMetrics, ExecutionOptions, ExecutionPrivacy, LicenseInfo, PackageKind,
        RegistryEntryV1, RunnerLimits, canonical_receipt_id, sign_receipt,
    };
    use hivemind_receipts::DisputeClaimKind;

    #[test]
    fn commercial_listing_requires_license() {
        let entry = registry_entry(LicenseType::Commercial);
        let listing = listing_from_registry_entry(&entry, "0xOwner").unwrap();

        assert_eq!(listing.schema_version, MARKETPLACE_LISTING_SCHEMA_VERSION);
        assert_eq!(listing.listing_type, MarketplaceListingType::PackageLicense);
        assert!(listing.requires_license);
        assert_eq!(listing.pricing.mode, PricingMode::Quote);
        assert!(listing.evidence_refs.iter().any(|reference| {
            reference.starts_with("bzz://") || reference.starts_with("sha256://")
        }));
        assert!(listing.reputation_ref.is_some());
        assert_eq!(
            listing.listing_id,
            canonical_marketplace_listing_id(&listing)
        );
        let expected_signature = expected_marketplace_listing_signature(&listing);
        assert_eq!(
            listing.signature.as_deref(),
            Some(expected_signature.as_str())
        );
        assert!(verify_marketplace_listing(&listing).valid);
    }

    #[test]
    fn marketplace_listing_v2_separates_package_license_contract() {
        let entry = registry_entry(LicenseType::Commercial);
        let listing = listing_from_registry_entry(&entry, "0xOwner").unwrap();
        let listing_v2 = marketplace_listing_v2_from_v1(&listing);
        let verification = verify_marketplace_listing_v2(&listing_v2);

        assert_eq!(
            listing_v2.schema_version,
            MARKETPLACE_LISTING_V2_SCHEMA_VERSION
        );
        assert_eq!(
            listing_v2.listing_type,
            MarketplaceListingKindV2::PackageLicense
        );
        assert_eq!(listing_v2.subject.subject_type, "package");
        assert_eq!(listing_v2.subject.subject_ref, "bzz://pkg");
        assert!(listing_v2.privacy_tiers.contains(&PrivacyTier::LocalOnly));
        assert!(
            listing_v2
                .verification_tiers
                .contains(&IntegrityTier::ValidatorSpotCheck)
        );
        assert_eq!(listing_v2.settlement_terms["requiresReceipt"], json!(false));
        assert!(verification.valid, "{verification:#?}");
    }

    #[test]
    fn marketplace_listing_v2_separates_vector_service_from_package_license() {
        let mut entry = registry_entry(LicenseType::Open);
        entry.kind = PackageKind::VectorIndex;
        entry.capabilities = vec!["vector.retrieve.general".to_string()];
        entry.modalities = vec![Modality::VectorSearch];
        entry.supported_apis = vec![ApiSurface::VectorSearch, ApiSurface::RagQuery];

        let listing_v2 = listing_v2_from_registry_entry(&entry, "0xOwner").unwrap();
        let verification = verify_marketplace_listing_v2(&listing_v2);

        assert_eq!(
            listing_v2.listing_type,
            MarketplaceListingKindV2::VectorStoreService
        );
        assert_eq!(listing_v2.subject.subject_type, "service");
        assert!(
            listing_v2
                .subject
                .api_surfaces
                .contains(&ApiSurface::VectorSearch)
        );
        assert!(
            listing_v2
                .subject
                .modalities
                .contains(&Modality::VectorSearch)
        );
        assert_eq!(listing_v2.settlement_terms["requiresReceipt"], json!(true));
        assert!(verification.valid, "{verification:#?}");
    }

    #[test]
    fn identity_signed_marketplace_listing_v2_verifies_and_detects_tampering() {
        let entry = registry_entry(LicenseType::Open);
        let listing = listing_from_registry_entry(&entry, "0xOwner").unwrap();
        let mut listing_v2 = marketplace_listing_v2_from_v1(&listing);
        let identity = hivemind_identity::identity_from_seed("0xOwner", b"owner-seed").unwrap();

        let envelope =
            sign_marketplace_listing_v2_with_identity(&mut listing_v2, &identity).unwrap();
        let verification = verify_marketplace_listing_v2(&listing_v2);

        assert_eq!(envelope.signer, listing_v2.seller);
        assert!(verification.valid, "{verification:#?}");
        listing_v2.title = "Tampered v2 listing".to_string();
        let tampered = verify_marketplace_listing_v2(&listing_v2);
        assert!(!tampered.valid);
        assert!(tampered.issues.iter().any(|issue| {
            issue.path == "$.listingId" || issue.path == "$.signature.payloadHash"
        }));
    }

    #[test]
    fn legacy_marketplace_listing_schema_version_still_verifies_without_v02_fields() {
        let entry = registry_entry(LicenseType::Open);
        let mut listing = listing_from_registry_entry(&entry, "0xOwner").unwrap();
        listing.schema_version = LEGACY_MARKETPLACE_LISTING_SCHEMA_VERSION.to_string();
        listing.listing_type = MarketplaceListingType::Package;
        listing.evidence_refs = Vec::new();
        listing.validation_report_refs = Vec::new();
        listing.reputation_ref = None;
        listing.details = json!({});
        sign_marketplace_listing(&mut listing);
        let mut serialized = serde_json::to_value(&listing).unwrap();
        let object = serialized.as_object_mut().unwrap();
        object.remove("evidenceRefs");
        object.remove("validationReportRefs");
        object.remove("reputationRef");
        object.remove("details");
        let listing: MarketplaceListingV1 = serde_json::from_value(serialized).unwrap();

        let verification = verify_marketplace_listing(&listing);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(
            verification.schema_version,
            MARKETPLACE_LISTING_VERIFICATION_SCHEMA_VERSION
        );
    }

    #[test]
    fn identity_signed_marketplace_listing_verifies() {
        let entry = registry_entry(LicenseType::Open);
        let mut listing = listing_from_registry_entry(&entry, "0xOwner").unwrap();
        let identity = hivemind_identity::identity_from_seed("0xOwner", b"owner-seed").unwrap();

        let envelope = sign_marketplace_listing_with_identity(&mut listing, &identity).unwrap();
        let verification = verify_marketplace_listing(&listing);

        assert_eq!(envelope.signer, listing.owner);
        assert!(
            listing
                .signature
                .as_deref()
                .unwrap()
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .as_deref()
                .unwrap()
                .starts_with("ed25519-payload-hash:")
        );
    }

    #[test]
    fn unsigned_marketplace_listing_remains_valid_with_warning() {
        let entry = registry_entry(LicenseType::Open);
        let mut listing = listing_from_registry_entry(&entry, "0xOwner").unwrap();
        listing.signature = None;

        let verification = verify_marketplace_listing(&listing);

        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signature")
        );
    }

    #[test]
    fn rejects_tampered_identity_signed_marketplace_listing() {
        let entry = registry_entry(LicenseType::Open);
        let mut listing = listing_from_registry_entry(&entry, "0xOwner").unwrap();
        let identity = hivemind_identity::identity_from_seed("0xOwner", b"owner-seed").unwrap();
        sign_marketplace_listing_with_identity(&mut listing, &identity).unwrap();
        listing.title = "Impostor listing".to_string();

        let verification = verify_marketplace_listing(&listing);

        assert!(!verification.valid);
        assert!(verification.issues.iter().any(|issue| {
            issue.path == "$.listingId" || issue.path == "$.signature.payloadHash"
        }));
    }

    #[test]
    fn quote_uses_offer_pricing_and_supports_package() {
        let descriptor = RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: "runner-1".to_string(),
            runner_type: RunnerType::RemoteGpu,
            targets: vec!["remote-openai-compatible".to_string()],
            engines: vec!["openai-compatible".to_string()],
            capabilities: vec!["embedding".to_string()],
            limits: RunnerLimits {
                max_memory_mb: 1024,
                max_input_bytes: 1024,
                max_concurrent_jobs: 1,
            },
            queue_depth: 0,
            warm_package_refs: Vec::new(),
        };
        let offer = offer_from_runner_descriptor(
            &descriptor,
            "bzz://descriptor",
            vec!["bzz://pkg".to_string()],
            RunnerPricingV1 {
                input_token_price: 0.01,
                output_token_price: 0.02,
                currency: "xDAI".to_string(),
            },
            RunnerServiceLevelV1 {
                p95_first_token_ms: 1200,
                availability_target: 0.99,
            },
            RunnerReputationV1 {
                validator_score: 0.9,
                completed_jobs: 42,
            },
        );
        assert_eq!(offer.schema_version, RUNNER_OFFER_SCHEMA_VERSION);
        assert_eq!(offer.identity.as_deref(), Some("local://runner/runner-1"));
        assert!(offer.public_key.is_some());
        assert!(offer.supported_apis.contains(&ApiSurface::OpenAiEmbeddings));
        assert!(offer.supported_modalities.contains(&Modality::Embedding));
        assert_eq!(offer.supported_package_kinds, vec!["model".to_string()]);
        assert_eq!(
            offer.supported_model_formats,
            vec!["remote-openai-compatible".to_string()]
        );
        assert_eq!(offer.engines, vec!["openai-compatible".to_string()]);
        assert_eq!(offer.hardware.as_ref().unwrap().gpu_memory_mb, Some(1024));
        assert_eq!(offer.memory.as_ref().unwrap().max_concurrent_jobs, 1);
        assert_eq!(offer.price_table.len(), 2);
        assert!(offer.privacy_tiers.contains(&PrivacyTier::NoLog));
        assert!(
            offer
                .verification_tiers
                .contains(&IntegrityTier::ValidatorSpotCheck)
        );
        assert!(offer.validator_score_ref.is_some());
        assert!(offer.terms_ref.is_some());
        assert!(offer.expires_at.is_some());
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "req-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: "hivemind/test".to_string(),
            package_version: "0.1.0".to_string(),
            preferred_artifact_group: None,
            task: "embedding".to_string(),
            input: json!({ "text": "hello paid world" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let quote = quote_execution(&request, &offer, Some(2)).unwrap();
        assert_eq!(quote.schema_version, SERVICE_QUOTE_SCHEMA_VERSION);
        assert_eq!(quote.job_id.as_deref(), Some("job-for-req-1"));
        assert_eq!(quote.listing_id.as_deref(), Some(offer.offer_id.as_str()));
        assert_eq!(
            quote.price,
            Some(PriceV1 {
                amount: 0.07,
                currency: "xDAI".to_string()
            })
        );
        assert_eq!(quote.price_model, Some(PriceModel::PerToken));
        assert_eq!(quote.privacy_mode, Some(PrivacyTier::NoLog));
        assert_eq!(
            quote.verification_mode,
            Some(IntegrityTier::ValidatorSpotCheck)
        );
        assert_eq!(quote.estimated_start_delay_ms, Some(0));
        assert_eq!(quote.estimated_time_to_first_output_ms, Some(1200));
        assert!(quote.estimated_completion_ms.unwrap() >= 1200);
        assert_eq!(quote.cache_hit_claim, Some(false));
        let timing = quote.quote_timing.as_ref().unwrap();
        assert_eq!(timing.schema_version, "hivemind.quote_timing.v1");
        assert!(timing.offer_matched);
        assert!(timing.privacy_matched);
        assert!(timing.verification_matched);
        assert!(quote.validation_support.contains(&"receipt".to_string()));
        assert!(
            quote
                .validation_support
                .contains(&"validator-spot-check".to_string())
        );
        assert_eq!(quote.estimated_input_tokens, 3);
        assert_eq!(quote.estimated_cost, 0.07);
        assert_eq!(offer.offer_id, canonical_runner_offer_id(&offer));
        let expected_offer_signature = expected_runner_offer_signature(&offer);
        assert_eq!(
            offer.signature.as_deref(),
            Some(expected_offer_signature.as_str())
        );
        assert_eq!(quote.quote_id, canonical_service_quote_id(&quote));
        let expected_quote_signature = expected_service_quote_signature(&quote);
        assert_eq!(
            quote.signature.as_deref(),
            Some(expected_quote_signature.as_str())
        );
        let offer_verification = verify_runner_offer(&offer);
        assert!(offer_verification.valid, "{offer_verification:#?}");
        assert_eq!(
            offer_verification.schema_version,
            RUNNER_OFFER_VERIFICATION_SCHEMA_VERSION
        );
        assert!(verify_service_quote(&quote, Some(&offer)).valid);
    }

    #[test]
    fn legacy_runner_offer_schema_version_still_verifies_without_v02_fields() {
        let mut offer = runner_offer("legacy-offer-runner", 0.01, 900, 0.91, 100);
        offer.schema_version = LEGACY_RUNNER_OFFER_SCHEMA_VERSION.to_string();
        offer.identity = None;
        offer.public_key = None;
        offer.supported_apis = Vec::new();
        offer.supported_modalities = Vec::new();
        offer.supported_package_kinds = Vec::new();
        offer.supported_model_formats = Vec::new();
        offer.engines = Vec::new();
        offer.hardware = None;
        offer.memory = None;
        offer.max_context_tokens = None;
        offer.max_batch_size = None;
        offer.streaming_modes = Vec::new();
        offer.price_table = Vec::new();
        offer.cache_claims = Vec::new();
        offer.privacy_tiers = Vec::new();
        offer.verification_tiers = Vec::new();
        offer.region_hint = None;
        offer.validator_score_ref = None;
        offer.terms_ref = None;
        offer.expires_at = None;
        sign_runner_offer(&mut offer);
        let mut serialized = serde_json::to_value(&offer).unwrap();
        let object = serialized.as_object_mut().unwrap();
        for field in [
            "identity",
            "publicKey",
            "supportedApis",
            "supportedModalities",
            "supportedPackageKinds",
            "supportedModelFormats",
            "engines",
            "hardware",
            "memory",
            "maxContextTokens",
            "maxBatchSize",
            "streamingModes",
            "priceTable",
            "cacheClaims",
            "privacyTiers",
            "verificationTiers",
            "regionHint",
            "validatorScoreRef",
            "termsRef",
            "expiresAt",
        ] {
            object.remove(field);
        }
        let offer: RunnerOfferV1 = serde_json::from_value(serialized).unwrap();

        let verification = verify_runner_offer(&offer);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(
            verification.schema_version,
            RUNNER_OFFER_VERIFICATION_SCHEMA_VERSION
        );
    }

    #[test]
    fn legacy_service_quote_schema_version_still_verifies_without_v02_fields() {
        let offer = runner_offer("legacy-quote-runner", 0.01, 900, 0.91, 100);
        let request = request("bzz://pkg", "embedding");
        let mut quote = quote_execution(&request, &offer, Some(2)).unwrap();
        quote.schema_version = LEGACY_SERVICE_QUOTE_SCHEMA_VERSION.to_string();
        quote.job_id = None;
        quote.listing_id = None;
        quote.price = None;
        quote.price_model = None;
        quote.privacy_mode = None;
        quote.verification_mode = None;
        quote.estimated_start_delay_ms = None;
        quote.estimated_time_to_first_output_ms = None;
        quote.estimated_completion_ms = None;
        quote.cache_hit_claim = None;
        quote.validation_support = Vec::new();
        quote.terms = json!({});
        quote.quote_timing = None;
        sign_service_quote(&mut quote);
        let mut serialized = serde_json::to_value(&quote).unwrap();
        let object = serialized.as_object_mut().unwrap();
        for field in [
            "jobId",
            "listingId",
            "price",
            "priceModel",
            "privacyMode",
            "verificationMode",
            "estimatedStartDelayMs",
            "estimatedTimeToFirstOutputMs",
            "estimatedCompletionMs",
            "cacheHitClaim",
            "validationSupport",
            "terms",
            "quoteTiming",
        ] {
            object.remove(field);
        }
        let quote: ServiceQuoteV1 = serde_json::from_value(serialized).unwrap();

        let verification = verify_service_quote(&quote, Some(&offer));

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(
            verification.schema_version,
            SERVICE_QUOTE_VERIFICATION_SCHEMA_VERSION
        );
    }

    #[test]
    fn quote_rejects_offer_that_cannot_satisfy_request_privacy() {
        let mut offer = runner_offer("standard-only-runner", 0.01, 900, 0.91, 100);
        offer.privacy_tiers = vec![PrivacyTier::Standard];
        sign_runner_offer(&mut offer);
        let request = request("bzz://pkg", "embedding");

        let quote = quote_execution(&request, &offer, Some(2));

        assert!(quote.is_none());
    }

    #[test]
    fn quote_verification_rejects_unsupported_privacy_claim() {
        let offer = runner_offer("quote-privacy-runner", 0.01, 900, 0.91, 100);
        let request = request("bzz://pkg", "embedding");
        let mut quote = quote_execution(&request, &offer, Some(2)).unwrap();
        quote.privacy_mode = Some(PrivacyTier::TeeConfidential);
        sign_service_quote(&mut quote);

        let verification = verify_service_quote(&quote, Some(&offer));

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.privacyMode")
        );
    }

    #[test]
    fn hardware_resource_offer_summarizes_runner_capacity() {
        let descriptor = RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: "miner-1".to_string(),
            runner_type: RunnerType::RemoteGpu,
            targets: vec!["cuda-vllm".to_string()],
            engines: vec!["vllm".to_string()],
            capabilities: vec!["chat".to_string(), "embedding".to_string()],
            limits: RunnerLimits {
                max_memory_mb: 24 * 1024,
                max_input_bytes: 128 * 1024,
                max_concurrent_jobs: 4,
            },
            queue_depth: 0,
            warm_package_refs: vec!["bzz://warm-model".to_string()],
        };

        let offer = default_hardware_resource_offer(&descriptor, "0xMiner");
        let verification = verify_hardware_resource_offer(&offer);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(offer.schema_version, HARDWARE_RESOURCE_OFFER_SCHEMA_VERSION);
        assert_eq!(
            verification.schema_version,
            HARDWARE_RESOURCE_OFFER_VERIFICATION_SCHEMA_VERSION
        );
        assert_eq!(offer.runner_id, "miner-1");
        assert_eq!(offer.operator, "0xMiner");
        assert_eq!(offer.hardware.gpu_count, 1);
        assert_eq!(offer.hardware.vram_gb, Some(24.0));
        assert_eq!(offer.availability.max_concurrent_jobs, 4);
        assert_eq!(offer.trust_tier, MinerTrustTierV1::Verified);
        assert!(
            offer
                .supported_execution_modes
                .contains(&HardwareExecutionModeV1::EmbeddingBatch)
        );
        assert!(offer.privacy_tiers.contains(&PrivacyTier::NoLog));
        assert!(
            offer
                .verification_tiers
                .contains(&IntegrityTier::ValidatorSpotCheck)
        );
        let expected_signature = expected_hardware_resource_offer_signature(&offer);
        assert_eq!(
            offer.signature.as_deref(),
            Some(expected_signature.as_str())
        );
    }

    #[test]
    fn legacy_hardware_resource_offer_schema_version_still_verifies() {
        let descriptor = RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: "legacy-miner".to_string(),
            runner_type: RunnerType::RemoteGpu,
            targets: vec!["cuda-vllm".to_string()],
            engines: vec!["vllm".to_string()],
            capabilities: vec!["chat".to_string()],
            limits: RunnerLimits {
                max_memory_mb: 16 * 1024,
                max_input_bytes: 128 * 1024,
                max_concurrent_jobs: 2,
            },
            queue_depth: 0,
            warm_package_refs: Vec::new(),
        };
        let mut offer = default_hardware_resource_offer(&descriptor, "0xLegacyMiner");
        offer.schema_version = LEGACY_HARDWARE_RESOURCE_OFFER_SCHEMA_VERSION.to_string();
        sign_hardware_resource_offer(&mut offer);

        let verification = verify_hardware_resource_offer(&offer);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(
            verification.schema_version,
            HARDWARE_RESOURCE_OFFER_VERIFICATION_SCHEMA_VERSION
        );
    }

    #[test]
    fn identity_signed_hardware_resource_offer_verifies_and_detects_tampering() {
        let descriptor = RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: "miner-identity".to_string(),
            runner_type: RunnerType::Marketplace,
            targets: vec!["cuda-vllm".to_string()],
            engines: vec!["vllm".to_string()],
            capabilities: vec!["embedding".to_string()],
            limits: RunnerLimits {
                max_memory_mb: 12 * 1024,
                max_input_bytes: 128 * 1024,
                max_concurrent_jobs: 2,
            },
            queue_depth: 0,
            warm_package_refs: Vec::new(),
        };
        let mut offer = default_hardware_resource_offer(&descriptor, "0xMiner");
        let identity = hivemind_identity::identity_from_seed("0xMiner", b"miner-seed").unwrap();

        let envelope = sign_hardware_resource_offer_with_identity(&mut offer, &identity).unwrap();
        let verification = verify_hardware_resource_offer(&offer);

        assert_eq!(envelope.signer, offer.operator);
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .as_deref()
                .unwrap()
                .starts_with("ed25519-payload-hash:")
        );

        offer.hardware.ram_gb = 0.0;
        let tampered = verify_hardware_resource_offer(&offer);
        assert!(!tampered.valid);
        assert!(tampered.issues.iter().any(|issue| {
            issue.path == "$.hardware.ramGb" || issue.path == "$.signature.payloadHash"
        }));
    }

    #[test]
    fn identity_signed_runner_offer_verifies() {
        let mut offer = runner_offer("runner-identity", 0.01, 900, 0.91, 100);
        let identity =
            hivemind_identity::identity_from_seed("runner-identity", b"runner-seed").unwrap();

        let envelope = sign_runner_offer_with_identity(&mut offer, &identity).unwrap();
        let verification = verify_runner_offer(&offer);

        assert_eq!(envelope.signer, offer.runner_id);
        assert!(
            offer
                .signature
                .as_deref()
                .unwrap()
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .as_deref()
                .unwrap()
                .starts_with("ed25519-payload-hash:")
        );
    }

    #[test]
    fn rejects_tampered_identity_signed_runner_offer() {
        let mut offer = runner_offer("runner-identity", 0.01, 900, 0.91, 100);
        let identity =
            hivemind_identity::identity_from_seed("runner-identity", b"runner-seed").unwrap();
        sign_runner_offer_with_identity(&mut offer, &identity).unwrap();
        offer.pricing.input_token_price = 99.0;

        let verification = verify_runner_offer(&offer);

        assert!(!verification.valid);
        assert!(
            verification.issues.iter().any(|issue| {
                issue.path == "$.offerId" || issue.path == "$.signature.payloadHash"
            })
        );
    }

    #[test]
    fn identity_signed_service_quote_verifies() {
        let offer = runner_offer("runner-identity", 0.01, 900, 0.91, 100);
        let request = request("bzz://pkg", "embedding");
        let mut quote = quote_execution(&request, &offer, Some(2)).unwrap();
        let identity =
            hivemind_identity::identity_from_seed("runner-identity", b"runner-seed").unwrap();

        let envelope = sign_service_quote_with_identity(&mut quote, &identity).unwrap();
        let verification = verify_service_quote(&quote, Some(&offer));

        assert_eq!(envelope.signer, quote.runner_id);
        assert!(
            quote
                .signature
                .as_deref()
                .unwrap()
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .as_deref()
                .unwrap()
                .starts_with("ed25519-payload-hash:")
        );
    }

    #[test]
    fn rejects_tampered_identity_signed_service_quote() {
        let offer = runner_offer("runner-identity", 0.01, 900, 0.91, 100);
        let request = request("bzz://pkg", "embedding");
        let mut quote = quote_execution(&request, &offer, Some(2)).unwrap();
        let identity =
            hivemind_identity::identity_from_seed("runner-identity", b"runner-seed").unwrap();
        sign_service_quote_with_identity(&mut quote, &identity).unwrap();
        quote.estimated_cost = 99.0;

        let verification = verify_service_quote(&quote, Some(&offer));

        assert!(!verification.valid);
        assert!(verification.issues.iter().any(|issue| {
            issue.path == "$.quoteId"
                || issue.path == "$.signature.payloadHash"
                || issue.path == "$.estimatedCost"
        }));
    }

    #[test]
    fn rejects_invalid_offer_and_tampered_quote() {
        let descriptor = RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: "runner-1".to_string(),
            runner_type: RunnerType::RemoteGpu,
            targets: vec!["remote-openai-compatible".to_string()],
            engines: vec!["openai-compatible".to_string()],
            capabilities: vec!["embedding".to_string()],
            limits: RunnerLimits {
                max_memory_mb: 1024,
                max_input_bytes: 1024,
                max_concurrent_jobs: 1,
            },
            queue_depth: 0,
            warm_package_refs: Vec::new(),
        };
        let mut offer = offer_from_runner_descriptor(
            &descriptor,
            "bzz://descriptor",
            vec!["bzz://pkg".to_string()],
            RunnerPricingV1 {
                input_token_price: 0.01,
                output_token_price: 0.02,
                currency: "xDAI".to_string(),
            },
            RunnerServiceLevelV1 {
                p95_first_token_ms: 1200,
                availability_target: 0.99,
            },
            RunnerReputationV1 {
                validator_score: 0.9,
                completed_jobs: 42,
            },
        );
        offer.pricing.input_token_price = -1.0;

        let verification = verify_runner_offer(&offer);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.pricing.inputTokenPrice")
        );

        offer.pricing.input_token_price = 0.01;
        let mut quote = quote(&receipt());
        quote.offer_id = offer.offer_id.clone();
        quote.runner_id = offer.runner_id.clone();
        quote.package_ref = "bzz://pkg".to_string();
        quote.estimated_input_tokens = 3;
        quote.estimated_output_tokens = 2;
        quote.estimated_cost = 999.0;

        let verification = verify_service_quote(&quote, Some(&offer));

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.estimatedCost")
        );
    }

    #[test]
    fn shortlist_prefers_reputation_for_quality_policy() {
        let low_quality = runner_offer("cheap-runner", 0.001, 800, 0.45, 4);
        let high_quality = runner_offer("trusted-runner", 0.01, 900, 0.97, 1200);
        let high_quality_offer_id = high_quality.offer_id.clone();
        let request = MarketplaceShortlistRequestV1 {
            schema_version: MARKETPLACE_SHORTLIST_REQUEST_SCHEMA_VERSION.to_string(),
            package_ref: "bzz://pkg".to_string(),
            task: "embedding".to_string(),
            api_surface: Some(ApiSurface::OpenAiEmbeddings),
            modality: Some(Modality::Embedding),
            estimated_input_tokens: 10,
            estimated_output_tokens: 5,
            required_privacy_tier: Some(PrivacyTier::NoLog),
            required_verification_tier: Some(IntegrityTier::ReceiptOnly),
            policy_mode: PolicyMode::QualityFirst,
            max_results: 5,
            include_rejected: false,
        };

        let shortlist = shortlist_runner_offers(&request, &[low_quality, high_quality]);

        assert_eq!(
            shortlist.selected_offer_id.as_deref(),
            Some(high_quality_offer_id.as_str())
        );
        assert_eq!(shortlist.rankings[0].runner_id, "trusted-runner");
    }

    #[test]
    fn shortlist_prefers_low_cost_for_cost_policy() {
        let cheap = runner_offer("cheap-runner", 0.001, 1_100, 0.80, 20);
        let expensive = runner_offer("expensive-runner", 0.10, 300, 0.99, 10_000);
        let request = MarketplaceShortlistRequestV1 {
            schema_version: MARKETPLACE_SHORTLIST_REQUEST_SCHEMA_VERSION.to_string(),
            package_ref: "bzz://pkg".to_string(),
            task: "embedding".to_string(),
            api_surface: Some(ApiSurface::OpenAiEmbeddings),
            modality: Some(Modality::Embedding),
            estimated_input_tokens: 10,
            estimated_output_tokens: 5,
            required_privacy_tier: Some(PrivacyTier::NoLog),
            required_verification_tier: Some(IntegrityTier::ReceiptOnly),
            policy_mode: PolicyMode::CostFirst,
            max_results: 5,
            include_rejected: false,
        };

        let shortlist = shortlist_runner_offers(&request, &[expensive, cheap]);

        assert_eq!(shortlist.rankings[0].runner_id, "cheap-runner");
        assert!(shortlist.rankings[0].estimated_cost < shortlist.rankings[1].estimated_cost);
    }

    #[test]
    fn shortlist_rejects_unsupported_offer_when_requested() {
        let offer = runner_offer("other-runner", 0.001, 800, 0.9, 50);
        let request = MarketplaceShortlistRequestV1 {
            schema_version: MARKETPLACE_SHORTLIST_REQUEST_SCHEMA_VERSION.to_string(),
            package_ref: "bzz://other".to_string(),
            task: "chat".to_string(),
            api_surface: Some(ApiSurface::OpenAiChatCompletions),
            modality: Some(Modality::Chat),
            estimated_input_tokens: 10,
            estimated_output_tokens: 5,
            required_privacy_tier: Some(PrivacyTier::NoLog),
            required_verification_tier: Some(IntegrityTier::ReceiptOnly),
            policy_mode: PolicyMode::Balanced,
            max_results: 5,
            include_rejected: true,
        };

        let shortlist = shortlist_runner_offers(&request, &[offer]);

        assert!(shortlist.selected_offer_id.is_none());
        assert_eq!(shortlist.rankings.len(), 1);
        assert!(!shortlist.rankings[0].eligible);
        assert!(
            shortlist.rankings[0]
                .reasons
                .iter()
                .any(|reason| reason.contains("packageRef"))
        );
        assert!(
            shortlist.rankings[0]
                .reasons
                .iter()
                .any(|reason| reason.contains("task"))
        );
    }

    #[test]
    fn shortlist_enforces_privacy_api_modality_and_verification_filters() {
        let mut offer = runner_offer("standard-runner", 0.001, 800, 0.9, 50);
        offer.supported_apis = vec![ApiSurface::HivemindNative];
        offer.supported_modalities = vec![Modality::Text];
        offer.privacy_tiers = vec![PrivacyTier::Standard];
        offer.verification_tiers = vec![IntegrityTier::ReceiptOnly];
        sign_runner_offer(&mut offer);
        let request = MarketplaceShortlistRequestV1 {
            schema_version: MARKETPLACE_SHORTLIST_REQUEST_SCHEMA_VERSION.to_string(),
            package_ref: "bzz://pkg".to_string(),
            task: "embedding".to_string(),
            api_surface: Some(ApiSurface::OpenAiEmbeddings),
            modality: Some(Modality::Embedding),
            estimated_input_tokens: 10,
            estimated_output_tokens: 5,
            required_privacy_tier: Some(PrivacyTier::TeeConfidential),
            required_verification_tier: Some(IntegrityTier::ValidatorSpotCheck),
            policy_mode: PolicyMode::Balanced,
            max_results: 5,
            include_rejected: true,
        };

        let shortlist = shortlist_runner_offers(&request, &[offer]);

        assert_eq!(
            shortlist.schema_version,
            MARKETPLACE_SHORTLIST_SCHEMA_VERSION
        );
        assert_eq!(
            shortlist.required_privacy_tier,
            Some(PrivacyTier::TeeConfidential)
        );
        assert_eq!(
            shortlist.required_verification_tier,
            Some(IntegrityTier::ValidatorSpotCheck)
        );
        assert!(shortlist.selected_offer_id.is_none());
        assert_eq!(shortlist.rankings.len(), 1);
        let ranking = &shortlist.rankings[0];
        assert_eq!(ranking.schema_version, RUNNER_OFFER_SCORE_SCHEMA_VERSION);
        assert!(!ranking.eligible);
        assert!(ranking.selected_privacy_tier.is_none());
        assert!(ranking.selected_verification_tier.is_none());
        assert!(
            ranking
                .reasons
                .iter()
                .any(|reason| reason.contains("API surface"))
        );
        assert!(
            ranking
                .reasons
                .iter()
                .any(|reason| reason.contains("modality"))
        );
        assert!(
            ranking
                .reasons
                .iter()
                .any(|reason| reason.contains("privacy tier"))
        );
        assert!(
            ranking
                .reasons
                .iter()
                .any(|reason| reason.contains("verification tier"))
        );
    }

    #[test]
    fn authorizes_and_verifies_payment_for_quote() {
        let mut quote = quote(&receipt());
        quote.job_id = Some("job-payment-1".to_string());
        quote.details = json!({
            "jobId": "job-payment-1",
            "escrowRef": "local://escrow/payment-1",
            "cancellationRules": {
                "refundWindowSeconds": 60,
                "allowRequesterCancelBeforeCapture": true
            }
        });
        let authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-1".to_string()),
        );

        assert!(!authorization.authorization_id.is_empty());
        assert_eq!(
            authorization.schema_version,
            PAYMENT_AUTHORIZATION_SCHEMA_VERSION
        );
        assert_eq!(authorization.job_id.as_deref(), Some("job-payment-1"));
        assert_eq!(authorization.max_amount, Some(quote.estimated_cost));
        assert_eq!(authorization.asset.as_deref(), Some("xDAI"));
        assert_eq!(
            authorization.method.as_ref(),
            Some(&PaymentAdapterKind::LocalDev)
        );
        assert_eq!(
            authorization.escrow_ref.as_deref(),
            Some("local://escrow/payment-1")
        );
        assert_eq!(
            authorization.cancellation_rules["refundWindowSeconds"],
            json!(60)
        );
        assert_eq!(
            authorization.authorization_id,
            canonical_payment_authorization_id(&authorization)
        );
        assert_eq!(
            authorization.signature,
            expected_payment_authorization_signature(&authorization)
        );

        let verification = verify_payment_authorization(&authorization, Some(&quote));

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(
            verification.schema_version,
            PAYMENT_AUTHORIZATION_VERIFICATION_SCHEMA_VERSION
        );
        assert_eq!(verification.issues.len(), 0);
        assert_eq!(verification.expected_signature, authorization.signature);
    }

    #[test]
    fn service_quote_store_lists_and_gets_quotes() {
        let root = unique_temp_dir("hivemind-service-quote-store-test");
        let mut quote = quote(&receipt());
        quote.quote_timing = Some(test_quote_timing(13));
        sign_service_quote(&mut quote);

        let quote_path = write_service_quote(&root, &quote).unwrap();
        let summary = list_service_quotes(&root).unwrap();

        assert_eq!(summary.quote_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.with_quote_timing_count, 1);
        assert_eq!(summary.average_quote_elapsed_ms, Some(13.0));
        assert_eq!(summary.max_quote_elapsed_ms, Some(13));
        assert_eq!(summary.quote_cache_claim_sample_count, 1);
        assert_eq!(summary.quote_cache_hit_count, 0);
        assert_eq!(summary.quote_cache_miss_count, 1);
        assert_eq!(summary.quote_cache_hit_rate, Some(0.0));
        assert_eq!(summary.quotes[0].quote_id, quote.quote_id);
        assert_eq!(summary.quotes[0].quote_elapsed_ms, Some(13));
        assert_eq!(summary.quotes[0].cache_hit_claim, Some(false));
        assert_eq!(
            summary.quotes[0].quote_started_at.as_deref(),
            Some("2026-06-05T00:00:00Z")
        );
        assert_eq!(
            summary.quotes[0].quote_completed_at.as_deref(),
            Some("2026-06-05T00:00:00.013Z")
        );
        assert!(summary.quotes[0].verification.valid);

        let lookup = get_service_quote(&root, &quote.quote_id).unwrap().unwrap();
        assert_eq!(lookup.quote_path, quote_path.display().to_string());
        assert_eq!(lookup.quote.quote_id, quote.quote_id);
        assert!(lookup.verification.valid);
        assert!(get_service_quote(&root, "missing-quote").unwrap().is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_payment_authorization_schema_version_still_verifies() {
        let quote = quote(&receipt());
        let mut authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-1".to_string()),
        );
        authorization.schema_version = LEGACY_PAYMENT_AUTHORIZATION_SCHEMA_VERSION.to_string();
        authorization.job_id = None;
        authorization.max_amount = None;
        authorization.asset = None;
        authorization.method = None;
        authorization.escrow_ref = None;
        authorization.cancellation_rules = json!({});
        sign_payment_authorization(&mut authorization);
        authorization.authorization_id = canonical_payment_authorization_id(&authorization);
        let mut legacy_value = serde_json::to_value(&authorization).unwrap();
        legacy_value
            .as_object_mut()
            .unwrap()
            .remove("cancellationRules");
        let authorization: PaymentAuthorizationV1 = serde_json::from_value(legacy_value).unwrap();

        let verification = verify_payment_authorization(&authorization, Some(&quote));

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(
            verification.schema_version,
            PAYMENT_AUTHORIZATION_VERIFICATION_SCHEMA_VERSION
        );
    }

    #[test]
    fn identity_signed_payment_authorization_verifies() {
        let quote = quote(&receipt());
        let mut authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-1".to_string()),
        );
        let identity = hivemind_identity::identity_from_seed("0xUser", b"payer-seed").unwrap();

        let envelope =
            sign_payment_authorization_with_identity(&mut authorization, &identity).unwrap();
        let verification = verify_payment_authorization(&authorization, Some(&quote));

        assert_eq!(envelope.signer, authorization.payer);
        assert!(
            authorization
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
    fn identity_signed_payment_authorization_can_fund_settlement() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let quote = quote(&receipt);
        let mut authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-1".to_string()),
        );
        let identity = hivemind_identity::identity_from_seed("0xUser", b"payer-seed").unwrap();
        sign_payment_authorization_with_identity(&mut authorization, &identity).unwrap();

        let result = settlement_from_verified_receipt_with_payment(
            &receipt,
            Some(&quote),
            Some(&authorization),
            "0xUser",
            "runner-1",
            Some("bzz://receipt".to_string()),
        );

        assert!(result.verification.valid, "{result:#?}");
        assert!(result.settlement.is_some());
        assert!(
            result
                .verification
                .payment_authorization_verification
                .as_ref()
                .unwrap()
                .expected_signature
                .starts_with("ed25519-payload-hash:")
        );
    }

    #[test]
    fn rejects_tampered_payment_authorization() {
        let quote = quote(&receipt());
        let mut authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-1".to_string()),
        );
        authorization.amount = 99.0;

        let verification = verify_payment_authorization(&authorization, Some(&quote));

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signature")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.amount")
        );
    }

    #[test]
    fn rejects_tampered_identity_signed_payment_authorization() {
        let quote = quote(&receipt());
        let mut authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-1".to_string()),
        );
        let identity = hivemind_identity::identity_from_seed("0xUser", b"payer-seed").unwrap();
        sign_payment_authorization_with_identity(&mut authorization, &identity).unwrap();
        authorization.amount = 99.0;

        let verification = verify_payment_authorization(&authorization, Some(&quote));

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.authorizationId"
                    || issue.path == "$.signature.payloadHash")
        );
    }

    #[test]
    fn payment_authorization_must_match_quote() {
        let quote = quote(&receipt());
        let mut other_quote = quote.clone();
        other_quote.quote_id = "quote-2".to_string();
        let authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-1".to_string()),
        );

        let verification = verify_payment_authorization(&authorization, Some(&other_quote));

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.quoteId")
        );
    }

    #[test]
    fn payment_authorization_store_lists_and_gets_authorizations() {
        let root = unique_temp_dir("hivemind-payment-authorization-store-test");
        let quote = quote(&receipt());
        let authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-1".to_string()),
        );

        let authorization_path = write_payment_authorization(&root, &authorization).unwrap();
        let summary = list_payment_authorizations(&root).unwrap();
        let lookup = get_payment_authorization(&root, &authorization.authorization_id)
            .unwrap()
            .unwrap();
        let missing = get_payment_authorization(&root, "missing-authorization").unwrap();

        assert_eq!(summary.authorization_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(
            summary.authorizations[0].authorization_id,
            authorization.authorization_id
        );
        assert_eq!(
            summary.authorizations[0].max_amount,
            Some(authorization.amount)
        );
        assert_eq!(summary.authorizations[0].asset.as_deref(), Some("xDAI"));
        assert_eq!(
            summary.authorizations[0].method.as_ref(),
            Some(&PaymentAdapterKind::LocalDev)
        );
        assert_eq!(
            summary.authorizations[0].authorization_path,
            authorization_path.display().to_string()
        );
        assert_eq!(
            lookup.authorization.authorization_id,
            authorization.authorization_id
        );
        assert!(lookup.verification.valid);
        assert!(missing.is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn settlement_links_quote_and_receipt() {
        let receipt = ExecutionReceiptV1 {
            schema_version: "swarm-ai.receipt.v1".to_string(),
            receipt_id: "receipt-1".to_string(),
            request_id: "req-1".to_string(),
            package_id: "hivemind/test".to_string(),
            package_ref: "bzz://pkg".to_string(),
            artifact_group: "local".to_string(),
            package_manifest_hash: "0".repeat(64),
            runner_id: "runner-1".to_string(),
            route_id: None,
            input_hash: "in".to_string(),
            output_hash: "out".to_string(),
            privacy_mode: "hash-only".to_string(),
            started_at: "2026-05-22T00:00:00Z".to_string(),
            finished_at: "2026-05-22T00:00:01Z".to_string(),
            metrics: ExecutionMetrics::default(),
            billing: hivemind_core::receipt::BillingInfo {
                estimated_cost: 0.0,
                currency: "none".to_string(),
            },
            access: hivemind_core::receipt::AccessInfo {
                license_grant_id: None,
            },
            policy: None,
            signature: "unsigned".to_string(),
        };
        let quote = ServiceQuoteV1 {
            schema_version: "swarm-ai.service-quote.v1".to_string(),
            quote_id: "quote-1".to_string(),
            job_id: None,
            request_id: "req-1".to_string(),
            offer_id: "offer-1".to_string(),
            listing_id: None,
            runner_id: "runner-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            estimated_input_tokens: 1,
            estimated_output_tokens: 1,
            estimated_cost: 0.01,
            currency: "xDAI".to_string(),
            price: None,
            price_model: None,
            privacy_mode: None,
            verification_mode: None,
            estimated_start_delay_ms: None,
            estimated_time_to_first_output_ms: None,
            estimated_completion_ms: None,
            cache_hit_claim: None,
            validation_support: Vec::new(),
            settlement_model: SettlementModel::DirectPayPerCall,
            expires_at: "2026-05-22T00:05:00Z".to_string(),
            terms: json!({}),
            details: json!({}),
            quote_timing: None,
            signature: None,
        };

        let settlement =
            settlement_from_receipt(&receipt, Some(&quote), "0xUser", "runner-1", None);
        assert_eq!(settlement.quote_id, Some("quote-1".to_string()));
        assert_eq!(settlement.job_id.as_deref(), Some("job-for-req-1"));
        assert_eq!(settlement.receipt_id, "receipt-1");
        assert_eq!(settlement.amount, 0.01);
        assert_eq!(settlement.asset.as_deref(), Some("xDAI"));
        assert!(settlement.created_at.is_some());
        assert!(
            settlement
                .reason
                .as_deref()
                .unwrap()
                .contains("service quote")
        );
        assert!(
            settlement
                .evidence_refs
                .iter()
                .any(|reference| reference == "local://receipt/receipt-1")
        );
        assert!(
            settlement
                .evidence_refs
                .iter()
                .any(|reference| reference == "local://quote/quote-1")
        );
    }

    #[test]
    fn verified_settlement_links_payment_authorization() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let quote = quote(&receipt);
        let authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-1".to_string()),
        );

        let result = settlement_from_verified_receipt_with_payment(
            &receipt,
            Some(&quote),
            Some(&authorization),
            "0xUser",
            "runner-1",
            Some("bzz://receipt".to_string()),
        );

        assert!(result.verification.valid, "{result:#?}");
        let settlement = result.settlement.unwrap();
        assert_eq!(
            settlement.payment_authorization_id,
            Some(authorization.authorization_id)
        );
        assert_eq!(settlement.schema_version, SETTLEMENT_EVENT_SCHEMA_VERSION);
        assert_eq!(
            settlement.payment_ref,
            Some("local://payment/auth-1".to_string())
        );
        assert_eq!(
            settlement.settlement_id,
            canonical_settlement_event_id(&settlement)
        );
        let expected_signature = expected_settlement_event_signature(&settlement);
        assert_eq!(
            settlement.signature.as_deref(),
            Some(expected_signature.as_str())
        );
        let event_verification = verify_settlement_event(&settlement);
        assert!(event_verification.valid);
        assert_eq!(
            event_verification.schema_version,
            SETTLEMENT_EVENT_VERIFICATION_SCHEMA_VERSION
        );
        assert!(result.verification.expected_signature.is_some());
    }

    #[test]
    fn escrow_record_locks_authorization_and_releases_for_verified_settlement() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let quote = quote(&receipt);
        let authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-escrow-1".to_string()),
        );
        let escrow = create_escrow_record(
            &authorization,
            Some(&quote),
            "local-market-escrow",
            vec!["local://policy/escrow-v1".to_string()],
        );

        assert_eq!(escrow.schema_version, ESCROW_RECORD_SCHEMA_VERSION);
        assert_eq!(escrow.status, EscrowStatusV1::Locked);
        assert_eq!(escrow.authorization_id, authorization.authorization_id);
        assert_eq!(escrow.job_id, authorization.job_id);
        assert!(escrow.escrow_id.starts_with("escrow-"));
        assert_eq!(
            escrow.signature.as_deref(),
            Some(expected_escrow_record_signature(&escrow).as_str())
        );
        let escrow_verification = verify_escrow_record(&escrow, Some(&authorization), Some(&quote));
        assert!(escrow_verification.valid, "{escrow_verification:#?}");
        assert!(
            escrow_verification
                .payment_authorization_verification
                .as_ref()
                .unwrap()
                .valid
        );

        let settlement = settlement_from_verified_receipt_with_payment(
            &receipt,
            Some(&quote),
            Some(&authorization),
            "0xUser",
            "runner-1",
            Some("local://receipt/receipt-escrow-1".to_string()),
        )
        .settlement
        .unwrap();
        let release = release_escrow_for_settlement(&EscrowReleaseRequestV1 {
            schema_version: ESCROW_RELEASE_REQUEST_SCHEMA_VERSION.to_string(),
            escrow: escrow.clone(),
            settlement: settlement.clone(),
            released_by: "local-market-escrow".to_string(),
            reason: Some("receipt verified and settlement matched escrow".to_string()),
            evidence_refs: vec!["local://operator/release-approval".to_string()],
        });

        assert!(release.valid, "{release:#?}");
        assert!(release.settlement_verification.valid);
        let released = release.escrow.unwrap();
        assert_eq!(released.status, EscrowStatusV1::Released);
        assert_eq!(
            released.settlement_id.as_deref(),
            Some(settlement.settlement_id.as_str())
        );
        assert!(released.released_at.is_some());
        assert!(
            released.evidence_refs.iter().any(|reference| reference
                == &format!("local://settlement/{}", settlement.settlement_id))
        );
        assert!(verify_escrow_record(&released, None, None).valid);
    }

    #[test]
    fn escrow_release_rejects_mismatched_settlement() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let quote = quote(&receipt);
        let authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-escrow-2".to_string()),
        );
        let escrow = create_escrow_record(
            &authorization,
            Some(&quote),
            "local-market-escrow",
            Vec::new(),
        );
        let mut settlement = settlement_from_verified_receipt_with_payment(
            &receipt,
            Some(&quote),
            Some(&authorization),
            "0xUser",
            "runner-1",
            Some("local://receipt/receipt-escrow-2".to_string()),
        )
        .settlement
        .unwrap();
        settlement.amount += 1.0;

        let release = release_escrow_for_settlement(&EscrowReleaseRequestV1 {
            schema_version: ESCROW_RELEASE_REQUEST_SCHEMA_VERSION.to_string(),
            escrow,
            settlement,
            released_by: "local-market-escrow".to_string(),
            reason: None,
            evidence_refs: Vec::new(),
        });

        assert!(!release.valid);
        assert!(release.escrow.is_none());
        assert!(release.issues.iter().any(|issue| {
            issue.path == "$.settlement"
                || issue.path == "$.settlement.amount"
                || issue.path == "$.settlementId"
        }));
    }

    #[test]
    fn escrow_record_store_lists_and_gets_records() {
        let root = unique_temp_dir("hivemind-escrow-store-test");
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let quote = quote(&receipt);
        let authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-escrow-3".to_string()),
        );
        let escrow = create_escrow_record(
            &authorization,
            Some(&quote),
            "local-market-escrow",
            Vec::new(),
        );

        let escrow_path = write_escrow_record(&root, &escrow).unwrap();
        let summary = list_escrow_records(&root).unwrap();

        assert_eq!(
            summary.schema_version,
            "hivemind.escrow-record-store-summary.v1"
        );
        assert_eq!(summary.escrow_count, 1);
        assert_eq!(summary.locked_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.escrows[0].escrow_id, escrow.escrow_id);
        assert_eq!(
            summary.escrows[0].escrow_path,
            escrow_path.display().to_string()
        );
        assert!(summary.escrows[0].verification.valid);

        let lookup = get_escrow_record(&root, &escrow.escrow_id)
            .unwrap()
            .unwrap();
        assert_eq!(lookup.escrow_path, escrow_path.display().to_string());
        assert_eq!(lookup.escrow.escrow_id, escrow.escrow_id);
        assert!(lookup.verification.valid);
        assert!(
            get_escrow_record(&root, "missing-escrow")
                .unwrap()
                .is_none()
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_settlement_event_schema_version_still_verifies() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut settlement =
            settlement_from_verified_receipt(&receipt, None, "0xUser", "runner-1", None)
                .settlement
                .unwrap();
        settlement.schema_version = LEGACY_SETTLEMENT_EVENT_SCHEMA_VERSION.to_string();
        settlement.job_id = None;
        settlement.asset = None;
        settlement.reason = None;
        settlement.evidence_refs = Vec::new();
        settlement.created_at = None;
        sign_settlement_event(&mut settlement);
        let mut serialized = serde_json::to_value(&settlement).unwrap();
        let object = serialized.as_object_mut().unwrap();
        object.remove("jobId");
        object.remove("asset");
        object.remove("reason");
        object.remove("evidenceRefs");
        object.remove("createdAt");
        let settlement: SettlementEventV1 = serde_json::from_value(serialized).unwrap();

        let verification = verify_settlement_event(&settlement);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(
            verification.schema_version,
            SETTLEMENT_EVENT_VERIFICATION_SCHEMA_VERSION
        );
    }

    #[test]
    fn identity_signed_settlement_event_verifies() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut settlement =
            settlement_from_verified_receipt(&receipt, None, "0xUser", "runner-1", None)
                .settlement
                .unwrap();
        let identity = hivemind_identity::identity_from_seed("runner-1", b"runner-seed").unwrap();

        let envelope = sign_settlement_event_with_identity(&mut settlement, &identity).unwrap();
        let verification = verify_settlement_event(&settlement);

        assert_eq!(envelope.signer, settlement.payee);
        assert!(
            settlement
                .signature
                .as_deref()
                .unwrap()
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .as_deref()
                .unwrap()
                .starts_with("ed25519-payload-hash:")
        );
    }

    #[test]
    fn rejects_tampered_identity_signed_settlement_event() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut settlement =
            settlement_from_verified_receipt(&receipt, None, "0xUser", "runner-1", None)
                .settlement
                .unwrap();
        let identity = hivemind_identity::identity_from_seed("runner-1", b"runner-seed").unwrap();
        sign_settlement_event_with_identity(&mut settlement, &identity).unwrap();
        settlement.amount = 99.0;

        let verification = verify_settlement_event(&settlement);

        assert!(!verification.valid);
        assert!(verification.issues.iter().any(|issue| {
            issue.path == "$.settlementId" || issue.path == "$.signature.payloadHash"
        }));
    }

    #[test]
    fn verified_settlement_requires_valid_receipt() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();

        let result = settlement_from_verified_receipt(
            &receipt,
            None,
            "0xUser",
            "runner-1",
            Some("bzz://receipt".to_string()),
        );

        assert!(result.verification.valid, "{result:#?}");
        assert!(result.settlement.is_some());

        let mut tampered = receipt;
        tampered.output_hash = "1".repeat(64);
        let result = settlement_from_verified_receipt(&tampered, None, "0xUser", "runner-1", None);

        assert!(!result.verification.valid);
        assert!(result.settlement.is_none());
        assert!(
            result
                .verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.receipt")
        );
    }

    #[test]
    fn verified_settlement_rejects_mismatched_quote() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut quote = quote(&receipt);
        quote.runner_id = "other-runner".to_string();

        let result =
            settlement_from_verified_receipt(&receipt, Some(&quote), "0xUser", "runner-1", None);

        assert!(!result.verification.valid);
        assert!(result.settlement.is_none());
        assert!(
            result
                .verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.quote.runnerId")
        );
    }

    #[test]
    fn opens_dispute_and_refunds_settlement() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let quote = quote(&receipt);
        let settlement = settlement_from_verified_receipt(
            &receipt,
            Some(&quote),
            "0xUser",
            "runner-1",
            Some("bzz://receipt".to_string()),
        )
        .settlement
        .unwrap();
        let dispute = hivemind_receipts::create_dispute_evidence(
            receipt,
            "0xUser",
            DisputeClaimKind::OutputMismatch,
            "Output was incorrect",
            vec!["bzz://evidence".to_string()],
        );

        let disputed =
            open_settlement_dispute(&settlement, &dispute, "market-operator", "needs review");

        assert!(disputed.verification.valid, "{disputed:#?}");
        assert_eq!(
            disputed.updated_settlement.as_ref().unwrap().status,
            SettlementStatus::Disputed
        );

        let rejected = reject_settlement_dispute(
            disputed.updated_settlement.as_ref().unwrap(),
            &dispute,
            "market-operator",
            "claim rejected",
        );

        assert!(rejected.verification.valid, "{rejected:#?}");
        assert_eq!(
            rejected.updated_settlement.as_ref().unwrap().status,
            SettlementStatus::DisputeRejected
        );
        assert!(
            rejected
                .updated_settlement
                .as_ref()
                .unwrap()
                .reason
                .as_deref()
                .unwrap()
                .contains("claim rejected")
        );
        assert_eq!(
            rejected.resolution.as_ref().unwrap().action,
            SettlementResolutionAction::RejectDispute
        );

        let refund = refund_settlement(
            disputed.updated_settlement.as_ref().unwrap(),
            &dispute,
            "market-operator",
            "refund approved",
        );

        assert!(refund.verification.valid, "{refund:#?}");
        assert_eq!(
            refund.updated_settlement.as_ref().unwrap().status,
            SettlementStatus::Refunded
        );
        assert!(
            refund
                .updated_settlement
                .as_ref()
                .unwrap()
                .evidence_refs
                .iter()
                .any(|reference| reference == "bzz://evidence")
        );
        assert_eq!(
            refund.resolution.as_ref().unwrap().action,
            SettlementResolutionAction::Refund
        );
        assert!(disputed.verification.expected_signature.is_some());
        assert!(
            verify_settlement_resolution(disputed.resolution.as_ref().unwrap()).valid,
            "{disputed:#?}"
        );
        assert!(
            verify_settlement_event(disputed.updated_settlement.as_ref().unwrap()).valid,
            "{disputed:#?}"
        );
    }

    #[test]
    fn refund_record_builds_from_refunded_settlement_and_resolution() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let quote = quote(&receipt);
        let settlement = settlement_from_verified_receipt(
            &receipt,
            Some(&quote),
            "0xUser",
            "runner-1",
            Some("bzz://receipt".to_string()),
        )
        .settlement
        .unwrap();
        let dispute = hivemind_receipts::create_dispute_evidence(
            receipt,
            "0xUser",
            DisputeClaimKind::OutputMismatch,
            "Output was incorrect",
            vec!["bzz://evidence".to_string()],
        );
        let disputed =
            open_settlement_dispute(&settlement, &dispute, "market-operator", "needs review");
        let refund = refund_settlement(
            disputed.updated_settlement.as_ref().unwrap(),
            &dispute,
            "market-operator",
            "refund approved",
        );

        let result = build_refund_record(&RefundBuildRequestV1 {
            schema_version: REFUND_BUILD_REQUEST_SCHEMA_VERSION.to_string(),
            settlement: refund.updated_settlement.as_ref().unwrap().clone(),
            resolution: refund.resolution.as_ref().unwrap().clone(),
            dispute: Some(dispute.clone()),
            refunded_by: "market-operator".to_string(),
            refund_ref: Some("local://refund/refund-1".to_string()),
            reason: None,
            evidence_refs: vec!["local://operator/refund-approved".to_string()],
            occurred_at: Some("2026-06-05T00:00:00Z".to_string()),
        });

        assert!(result.verification.valid, "{result:#?}");
        assert!(result.settlement_verification.valid);
        assert!(result.resolution_verification.valid);
        assert!(result.dispute_verification.as_ref().unwrap().valid);
        let record = result.refund.unwrap();
        assert_eq!(record.schema_version, REFUND_RECORD_SCHEMA_VERSION);
        assert_eq!(
            record.settlement_id,
            refund.updated_settlement.unwrap().settlement_id
        );
        assert_eq!(
            record.resolution_id,
            refund.resolution.unwrap().resolution_id
        );
        assert_eq!(
            record.dispute_id.as_deref(),
            Some(dispute.dispute_id.as_str())
        );
        assert_eq!(record.refunded_by, "market-operator");
        assert_eq!(
            record.refund_ref.as_deref(),
            Some("local://refund/refund-1")
        );
        assert!(record.refund_id.starts_with("refund-"));
        assert_eq!(
            record.signature.as_deref(),
            Some(expected_refund_record_signature(&record).as_str())
        );
        assert!(
            record
                .evidence_refs
                .iter()
                .any(|reference| reference == "local://operator/refund-approved")
        );
        assert!(
            record
                .evidence_refs
                .iter()
                .any(|reference| reference == "bzz://evidence")
        );
        assert!(verify_refund_record(&record).valid);
    }

    #[test]
    fn refund_record_rejects_non_refund_resolution() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let quote = quote(&receipt);
        let settlement = settlement_from_verified_receipt(
            &receipt,
            Some(&quote),
            "0xUser",
            "runner-1",
            Some("bzz://receipt".to_string()),
        )
        .settlement
        .unwrap();
        let dispute = hivemind_receipts::create_dispute_evidence(
            receipt,
            "0xUser",
            DisputeClaimKind::OutputMismatch,
            "Output was incorrect",
            vec!["bzz://evidence".to_string()],
        );
        let disputed =
            open_settlement_dispute(&settlement, &dispute, "market-operator", "needs review");

        let result = build_refund_record(&RefundBuildRequestV1 {
            schema_version: REFUND_BUILD_REQUEST_SCHEMA_VERSION.to_string(),
            settlement: disputed.updated_settlement.as_ref().unwrap().clone(),
            resolution: disputed.resolution.as_ref().unwrap().clone(),
            dispute: Some(dispute),
            refunded_by: "market-operator".to_string(),
            refund_ref: None,
            reason: None,
            evidence_refs: Vec::new(),
            occurred_at: None,
        });

        assert!(!result.verification.valid);
        assert!(result.refund.is_none());
        assert!(result.verification.issues.iter().any(|issue| {
            issue.path == "$.settlement.status" || issue.path == "$.resolution.action"
        }));
    }

    #[test]
    fn refund_record_store_lists_and_gets_records() {
        let root = unique_temp_dir("hivemind-refund-store-test");
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let quote = quote(&receipt);
        let settlement = settlement_from_verified_receipt(
            &receipt,
            Some(&quote),
            "0xUser",
            "runner-1",
            Some("bzz://receipt".to_string()),
        )
        .settlement
        .unwrap();
        let dispute = hivemind_receipts::create_dispute_evidence(
            receipt,
            "0xUser",
            DisputeClaimKind::OutputMismatch,
            "Output was incorrect",
            vec!["bzz://evidence".to_string()],
        );
        let disputed =
            open_settlement_dispute(&settlement, &dispute, "market-operator", "needs review");
        let refund = refund_settlement(
            disputed.updated_settlement.as_ref().unwrap(),
            &dispute,
            "market-operator",
            "refund approved",
        );
        let record = build_refund_record(&RefundBuildRequestV1 {
            schema_version: REFUND_BUILD_REQUEST_SCHEMA_VERSION.to_string(),
            settlement: refund.updated_settlement.as_ref().unwrap().clone(),
            resolution: refund.resolution.as_ref().unwrap().clone(),
            dispute: Some(dispute),
            refunded_by: "market-operator".to_string(),
            refund_ref: Some("local://refund/refund-store-1".to_string()),
            reason: Some("refund approved".to_string()),
            evidence_refs: Vec::new(),
            occurred_at: Some("2026-06-05T00:00:00Z".to_string()),
        })
        .refund
        .unwrap();

        let refund_path = write_refund_record(&root, &record).unwrap();
        let summary = list_refund_records(&root).unwrap();

        assert_eq!(
            summary.schema_version,
            "hivemind.refund-record-store-summary.v1"
        );
        assert_eq!(summary.refund_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.total_refunded_amount, record.amount);
        assert_eq!(summary.currency_counts.get("xDAI"), Some(&1));
        assert_eq!(summary.refunds[0].refund_id, record.refund_id);
        assert_eq!(
            summary.refunds[0].refund_path,
            refund_path.display().to_string()
        );
        assert!(summary.refunds[0].verification.valid);

        let lookup = get_refund_record(&root, &record.refund_id)
            .unwrap()
            .unwrap();
        assert_eq!(lookup.refund_path, refund_path.display().to_string());
        assert_eq!(lookup.refund.refund_id, record.refund_id);
        assert!(lookup.verification.valid);
        assert!(
            get_refund_record(&root, "missing-refund")
                .unwrap()
                .is_none()
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn marketplace_audit_store_indexes_settlements_and_resolutions() {
        let root = unique_temp_dir("hivemind-marketplace-audit-test");
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let mut quote = quote(&receipt);
        quote.quote_timing = Some(test_quote_timing(13));
        sign_service_quote(&mut quote);
        let mut settlement = settlement_from_verified_receipt(
            &receipt,
            Some(&quote),
            "0xUser",
            "runner-1",
            Some("bzz://receipt".to_string()),
        )
        .settlement
        .unwrap();
        settlement.created_at = Some("2026-06-05T00:00:00.038Z".to_string());
        settlement.occurred_at = "2026-06-05T00:00:00.038Z".to_string();
        sign_settlement_event(&mut settlement);
        let dispute = hivemind_receipts::create_dispute_evidence(
            receipt,
            "0xUser",
            DisputeClaimKind::OutputMismatch,
            "Output was incorrect",
            vec!["bzz://evidence".to_string()],
        );
        let disputed =
            open_settlement_dispute(&settlement, &dispute, "market-operator", "needs review");
        let refund = refund_settlement(
            disputed.updated_settlement.as_ref().unwrap(),
            &dispute,
            "market-operator",
            "refund approved",
        );

        let quote_path = write_service_quote(&root, &quote).unwrap();
        let settlement_path = write_settlement_event(&root, &settlement).unwrap();
        write_settlement_event(&root, disputed.updated_settlement.as_ref().unwrap()).unwrap();
        write_settlement_event(&root, refund.updated_settlement.as_ref().unwrap()).unwrap();
        let dispute_resolution_path =
            write_settlement_resolution(&root, disputed.resolution.as_ref().unwrap()).unwrap();
        write_settlement_resolution(&root, refund.resolution.as_ref().unwrap()).unwrap();

        let summary = list_marketplace_audit(&root).unwrap();
        assert_eq!(summary.quote_count, 1);
        assert_eq!(summary.valid_quote_count, 1);
        assert_eq!(summary.quotes[0].quote_id, quote.quote_id);
        assert_eq!(summary.settlement_count, 3);
        assert_eq!(summary.valid_settlement_count, 3);
        assert_eq!(summary.resolution_count, 2);
        assert_eq!(summary.valid_resolution_count, 2);
        assert_eq!(summary.settlement_latency_sample_count, 1);
        assert_eq!(summary.average_quote_to_settlement_ms, Some(25.0));
        assert_eq!(summary.max_quote_to_settlement_ms, Some(25));
        assert_eq!(summary.quote_cache_claim_sample_count, 1);
        assert_eq!(summary.quote_cache_hit_count, 0);
        assert_eq!(summary.quote_cache_miss_count, 1);
        assert_eq!(summary.quote_cache_hit_rate, Some(0.0));
        assert!(
            summary
                .settlements
                .iter()
                .any(|entry| entry.status == SettlementStatus::Refunded)
        );

        let quote_lookup = get_service_quote(&root, &quote.quote_id).unwrap().unwrap();
        assert_eq!(quote_lookup.quote_path, quote_path.display().to_string());
        assert!(quote_lookup.verification.valid);
        let settlement_lookup = get_settlement_event(&root, &settlement.settlement_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            settlement_lookup.settlement_path,
            settlement_path.display().to_string()
        );
        assert!(settlement_lookup.verification.valid);
        let resolution_lookup =
            get_settlement_resolution(&root, &disputed.resolution.as_ref().unwrap().resolution_id)
                .unwrap()
                .unwrap();
        assert_eq!(
            resolution_lookup.resolution_path,
            dispute_resolution_path.display().to_string()
        );
        assert!(resolution_lookup.verification.valid);
        assert!(
            get_settlement_event(&root, "missing-settlement")
                .unwrap()
                .is_none()
        );
        assert!(
            get_settlement_resolution(&root, "missing-resolution")
                .unwrap()
                .is_none()
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn identity_signed_settlement_resolution_verifies() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let settlement =
            settlement_from_verified_receipt(&receipt, None, "0xUser", "runner-1", None)
                .settlement
                .unwrap();
        let dispute = hivemind_receipts::create_dispute_evidence(
            receipt,
            "0xUser",
            DisputeClaimKind::OutputMismatch,
            "Output was incorrect",
            vec!["bzz://evidence".to_string()],
        );
        let mut resolution =
            open_settlement_dispute(&settlement, &dispute, "market-operator", "needs review")
                .resolution
                .unwrap();
        let identity =
            hivemind_identity::identity_from_seed("market-operator", b"resolver-seed").unwrap();

        let envelope =
            sign_settlement_resolution_with_identity(&mut resolution, &identity).unwrap();
        let verification = verify_settlement_resolution(&resolution);

        assert_eq!(envelope.signer, resolution.resolved_by);
        assert!(
            resolution
                .signature
                .as_deref()
                .unwrap()
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .as_deref()
                .unwrap()
                .starts_with("ed25519-payload-hash:")
        );
    }

    #[test]
    fn rejects_tampered_identity_signed_settlement_resolution() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let settlement =
            settlement_from_verified_receipt(&receipt, None, "0xUser", "runner-1", None)
                .settlement
                .unwrap();
        let dispute = hivemind_receipts::create_dispute_evidence(
            receipt,
            "0xUser",
            DisputeClaimKind::OutputMismatch,
            "Output was incorrect",
            vec!["bzz://evidence".to_string()],
        );
        let mut resolution =
            open_settlement_dispute(&settlement, &dispute, "market-operator", "needs review")
                .resolution
                .unwrap();
        let identity =
            hivemind_identity::identity_from_seed("market-operator", b"resolver-seed").unwrap();
        sign_settlement_resolution_with_identity(&mut resolution, &identity).unwrap();
        resolution.reason = "changed after signing".to_string();

        let verification = verify_settlement_resolution(&resolution);

        assert!(!verification.valid);
        assert!(verification.issues.iter().any(|issue| {
            issue.path == "$.resolutionId" || issue.path == "$.signature.payloadHash"
        }));
    }

    #[test]
    fn rejects_dispute_for_wrong_receipt() {
        let mut base_receipt = receipt();
        sign_receipt(&mut base_receipt);
        base_receipt.receipt_id = canonical_receipt_id(&base_receipt).unwrap();
        let settlement =
            settlement_from_verified_receipt(&base_receipt, None, "0xUser", "runner-1", None)
                .settlement
                .unwrap();

        let mut other_receipt = receipt();
        other_receipt.request_id = "other-request".to_string();
        sign_receipt(&mut other_receipt);
        other_receipt.receipt_id = canonical_receipt_id(&other_receipt).unwrap();
        let dispute = hivemind_receipts::create_dispute_evidence(
            other_receipt,
            "0xUser",
            DisputeClaimKind::RunnerFailure,
            "Wrong receipt evidence",
            Vec::new(),
        );

        let result =
            open_settlement_dispute(&settlement, &dispute, "market-operator", "bad evidence");

        assert!(!result.verification.valid);
        assert!(result.updated_settlement.is_none());
        assert!(
            result
                .verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.dispute.receiptId")
        );
    }

    #[test]
    fn slashing_record_requires_disputed_settlement_and_failed_correctness_evidence() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let settlement = settlement_from_verified_receipt(
            &receipt,
            None,
            "0xUser",
            "runner-1",
            Some("bzz://receipt".to_string()),
        )
        .settlement
        .unwrap();
        let dispute = hivemind_receipts::create_dispute_evidence(
            receipt.clone(),
            "0xUser",
            DisputeClaimKind::OutputMismatch,
            "Output was incorrect",
            vec!["bzz://validator-report".to_string()],
        );
        let disputed =
            open_settlement_dispute(&settlement, &dispute, "market-operator", "needs review");
        let disputed_settlement = disputed.updated_settlement.unwrap();
        let request = SlashingBuildRequestV1 {
            schema_version: SLASHING_BUILD_REQUEST_SCHEMA_VERSION.to_string(),
            settlement: disputed_settlement.clone(),
            dispute: dispute.clone(),
            correctness_assessment: failed_correctness_assessment(&receipt),
            slashed_by: "market-operator".to_string(),
            amount: 0.001,
            currency: Some(disputed_settlement.currency.clone()),
            stake_ref: Some("local://stake/runner-1".to_string()),
            reason_kind: SlashingReasonKindV1::FakeOutput,
            reason: "validator evidence confirmed output mismatch".to_string(),
            evidence_refs: vec!["local://governance/slashing-policy-v1".to_string()],
            occurred_at: Some("2026-06-05T00:00:00Z".to_string()),
        };

        let result = build_slashing_record(&request);

        assert!(result.verification.valid, "{result:#?}");
        assert!(result.correctness_assessment_accepted);
        assert!(result.settlement_verification.valid);
        assert!(result.dispute_verification.valid);
        let slashing = result.slashing.unwrap();
        assert_eq!(slashing.settlement_id, disputed_settlement.settlement_id);
        assert_eq!(slashing.dispute_id, dispute.dispute_id);
        assert_eq!(slashing.slashed_party, "runner-1");
        assert_eq!(slashing.slashed_by, "market-operator");
        assert_eq!(
            slashing.failed_methods,
            vec!["validator-spot-check".to_string()]
        );
        assert!(slashing.slashing_id.starts_with("slashing-"));
        assert_eq!(
            slashing.signature.as_deref(),
            Some(expected_slashing_record_signature(&slashing).as_str())
        );
        assert!(verify_slashing_record(&slashing).valid);
    }

    #[test]
    fn slashing_record_rejects_missing_correctness_evidence() {
        let mut receipt = receipt();
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        let settlement = settlement_from_verified_receipt(
            &receipt,
            None,
            "0xUser",
            "runner-1",
            Some("bzz://receipt".to_string()),
        )
        .settlement
        .unwrap();
        let dispute = hivemind_receipts::create_dispute_evidence(
            receipt.clone(),
            "0xUser",
            DisputeClaimKind::OutputMismatch,
            "Output was incorrect",
            vec!["bzz://validator-report".to_string()],
        );
        let disputed =
            open_settlement_dispute(&settlement, &dispute, "market-operator", "needs review");
        let request = SlashingBuildRequestV1 {
            schema_version: SLASHING_BUILD_REQUEST_SCHEMA_VERSION.to_string(),
            settlement: disputed.updated_settlement.unwrap(),
            dispute,
            correctness_assessment: missing_correctness_assessment(&receipt),
            slashed_by: "market-operator".to_string(),
            amount: 0.001,
            currency: None,
            stake_ref: Some("local://stake/runner-1".to_string()),
            reason_kind: SlashingReasonKindV1::FakeOutput,
            reason: "attempted slash without failed validator evidence".to_string(),
            evidence_refs: Vec::new(),
            occurred_at: None,
        };

        let result = build_slashing_record(&request);

        assert!(!result.verification.valid);
        assert!(result.slashing.is_none());
        assert!(!result.correctness_assessment_accepted);
        assert!(result.verification.issues.iter().any(|issue| {
            issue.path == "$.correctnessAssessment"
                && issue
                    .message
                    .contains("missing evidence alone is not enough")
        }));
    }

    fn receipt() -> ExecutionReceiptV1 {
        ExecutionReceiptV1 {
            schema_version: "swarm-ai.receipt.v1".to_string(),
            receipt_id: String::new(),
            request_id: "req-1".to_string(),
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
            billing: hivemind_core::receipt::BillingInfo {
                estimated_cost: 0.0,
                currency: "none".to_string(),
            },
            access: hivemind_core::receipt::AccessInfo {
                license_grant_id: None,
            },
            policy: None,
            signature: String::new(),
        }
    }

    fn failed_correctness_assessment(
        receipt: &ExecutionReceiptV1,
    ) -> ReceiptCorrectnessAssessmentV1 {
        ReceiptCorrectnessAssessmentV1 {
            schema_version: hivemind_receipts::RECEIPT_CORRECTNESS_ASSESSMENT_SCHEMA_VERSION
                .to_string(),
            receipt_id: receipt.receipt_id.clone(),
            valid: false,
            assessed_integrity_tier: IntegrityTier::ValidatorSpotCheck,
            correctness_level: hivemind_receipts::ReceiptCorrectnessLevelV1::Failed,
            receipt_verification: correctness_receipt_verification(receipt),
            evidence_count: 1,
            accepted_evidence_count: 0,
            validation_refs: vec!["bzz://validator-report".to_string()],
            satisfied_methods: Vec::new(),
            missing_methods: Vec::new(),
            failed_methods: vec![
                hivemind_receipts::ReceiptCorrectnessEvidenceMethodV1::ValidatorSpotCheck,
            ],
            issues: vec![hivemind_receipts::ReceiptVerificationIssueV1 {
                path: "$.validationEvidence[0].status".to_string(),
                message: "Validation evidence reported failure".to_string(),
            }],
            warnings: Vec::new(),
            assessed_at: "2026-06-05T00:00:00Z".to_string(),
        }
    }

    fn missing_correctness_assessment(
        receipt: &ExecutionReceiptV1,
    ) -> ReceiptCorrectnessAssessmentV1 {
        ReceiptCorrectnessAssessmentV1 {
            schema_version: hivemind_receipts::RECEIPT_CORRECTNESS_ASSESSMENT_SCHEMA_VERSION
                .to_string(),
            receipt_id: receipt.receipt_id.clone(),
            valid: false,
            assessed_integrity_tier: IntegrityTier::ValidatorSpotCheck,
            correctness_level: hivemind_receipts::ReceiptCorrectnessLevelV1::Unverified,
            receipt_verification: correctness_receipt_verification(receipt),
            evidence_count: 0,
            accepted_evidence_count: 0,
            validation_refs: Vec::new(),
            satisfied_methods: Vec::new(),
            missing_methods: vec![
                hivemind_receipts::ReceiptCorrectnessEvidenceMethodV1::ValidatorSpotCheck,
            ],
            failed_methods: Vec::new(),
            issues: vec![hivemind_receipts::ReceiptVerificationIssueV1 {
                path: "$.validationEvidence".to_string(),
                message: "Missing required correctness evidence method validator-spot-check"
                    .to_string(),
            }],
            warnings: Vec::new(),
            assessed_at: "2026-06-05T00:00:00Z".to_string(),
        }
    }

    fn correctness_receipt_verification(
        receipt: &ExecutionReceiptV1,
    ) -> hivemind_receipts::ExecutionReceiptV2VerificationV1 {
        hivemind_receipts::ExecutionReceiptV2VerificationV1 {
            schema_version: "hivemind.execution_receipt_v2_verification.v1".to_string(),
            receipt_id: receipt.receipt_id.clone(),
            valid: true,
            issues: Vec::new(),
            warnings: Vec::new(),
            signature_verified: true,
            source_receipt_valid: Some(true),
            expected_signature: Some(receipt.signature.clone()),
            verified_at: "2026-06-05T00:00:00Z".to_string(),
        }
    }

    fn request(package_ref: &str, task: &str) -> ExecutionRequestV1 {
        ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "req-1".to_string(),
            package_ref: package_ref.to_string(),
            package_id: "hivemind/test".to_string(),
            package_version: "0.1.0".to_string(),
            preferred_artifact_group: None,
            task: task.to_string(),
            input: json!({ "text": "hello paid world" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        }
    }

    fn quote(receipt: &ExecutionReceiptV1) -> ServiceQuoteV1 {
        ServiceQuoteV1 {
            schema_version: SERVICE_QUOTE_SCHEMA_VERSION.to_string(),
            quote_id: "quote-1".to_string(),
            job_id: Some("job-quote-1".to_string()),
            request_id: receipt.request_id.clone(),
            offer_id: "offer-1".to_string(),
            listing_id: Some("offer-1".to_string()),
            runner_id: receipt.runner_id.clone(),
            package_ref: receipt.package_ref.clone(),
            estimated_input_tokens: 1,
            estimated_output_tokens: 1,
            estimated_cost: 0.01,
            currency: "xDAI".to_string(),
            price: Some(PriceV1 {
                amount: 0.01,
                currency: "xDAI".to_string(),
            }),
            price_model: Some(PriceModel::PerToken),
            privacy_mode: Some(PrivacyTier::NoLog),
            verification_mode: Some(IntegrityTier::ReceiptOnly),
            estimated_start_delay_ms: Some(0),
            estimated_time_to_first_output_ms: Some(1000),
            estimated_completion_ms: Some(1010),
            cache_hit_claim: Some(false),
            validation_support: vec!["receipt".to_string()],
            settlement_model: SettlementModel::DirectPayPerCall,
            expires_at: (Utc::now() + chrono::Duration::minutes(5))
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            terms: json!({}),
            details: json!({}),
            quote_timing: None,
            signature: None,
        }
    }

    fn test_quote_timing(elapsed_ms: u64) -> ServiceQuoteTimingV1 {
        ServiceQuoteTimingV1 {
            schema_version: "hivemind.quote_timing.v1".to_string(),
            started_at: "2026-06-05T00:00:00Z".to_string(),
            completed_at: "2026-06-05T00:00:00.013Z".to_string(),
            elapsed_ms,
            offer_matched: true,
            privacy_matched: true,
            verification_matched: true,
        }
    }

    fn runner_offer(
        runner_id: &str,
        token_price: f64,
        p95_first_token_ms: u64,
        validator_score: f64,
        completed_jobs: u64,
    ) -> RunnerOfferV1 {
        let descriptor = RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: runner_id.to_string(),
            runner_type: RunnerType::Marketplace,
            targets: vec!["remote-openai-compatible".to_string()],
            engines: vec!["openai-compatible".to_string()],
            capabilities: vec!["embedding".to_string()],
            limits: RunnerLimits {
                max_memory_mb: 1024,
                max_input_bytes: 1024,
                max_concurrent_jobs: 1,
            },
            queue_depth: 0,
            warm_package_refs: Vec::new(),
        };
        offer_from_runner_descriptor(
            &descriptor,
            format!("bzz://descriptor/{runner_id}"),
            vec!["bzz://pkg".to_string()],
            RunnerPricingV1 {
                input_token_price: token_price,
                output_token_price: token_price,
                currency: "xDAI".to_string(),
            },
            RunnerServiceLevelV1 {
                p95_first_token_ms,
                availability_target: 0.99,
            },
            RunnerReputationV1 {
                validator_score,
                completed_jobs,
            },
        )
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

    fn registry_entry(license_type: LicenseType) -> RegistryEntryV1 {
        RegistryEntryV1 {
            schema_version: "swarm-ai.registry.entry.v1".to_string(),
            package_id: "hivemind/test".to_string(),
            name: "Test".to_string(),
            kind: PackageKind::Model,
            latest_version: "0.1.0".to_string(),
            stable_version: "0.1.0".to_string(),
            package_refs: vec![hivemind_core::registry::RegistryPackageRef {
                version: "0.1.0".to_string(),
                package_ref: "bzz://pkg".to_string(),
                manifest_hash: "0".repeat(64),
                published_at: "2026-05-22T00:00:00Z".to_string(),
            }],
            publisher: hivemind_core::registry::RegistryPublisher {
                address: "0xPublisher".to_string(),
                display_name: "Publisher".to_string(),
                publisher_profile_ref: None,
            },
            capabilities: vec!["embedding".to_string()],
            modalities: vec![
                hivemind_core::Modality::Embedding,
                hivemind_core::Modality::Text,
            ],
            supported_apis: vec![
                hivemind_core::ApiSurface::HivemindNative,
                hivemind_core::ApiSurface::OpenAiEmbeddings,
                hivemind_core::ApiSurface::HuggingFaceInference,
            ],
            targets: vec!["local-mock".to_string()],
            engines: vec!["rust-mock".to_string()],
            license: LicenseInfo {
                license_type,
                name: Some("Example".to_string()),
                url: None,
            },
            trust: hivemind_core::registry::RegistryTrust {
                signature_verified: false,
                validator_score: Some(0.8),
                download_count_approx: 0,
                curated: false,
            },
            privacy_tiers: vec![
                hivemind_core::PrivacyTier::Standard,
                hivemind_core::PrivacyTier::LocalOnly,
                hivemind_core::PrivacyTier::NoLog,
                hivemind_core::PrivacyTier::RedactedInput,
            ],
            verification_tiers: vec![hivemind_core::IntegrityTier::ReceiptOnly],
            browser_runnable: false,
            gpu_required: false,
            min_memory_mb: Some(1),
            min_vram_mb: None,
            price_hint: None,
            marketplace_listings: Vec::new(),
            runner_offer_refs: Vec::new(),
            hardware_resource_offer_refs: Vec::new(),
            permissions: Vec::new(),
            policy_summary: hivemind_core::registry::RegistryPolicySummaryV1 {
                risk_level: hivemind_core::policy::RiskLevel::Low,
                decision: hivemind_core::PolicyDecision::Allow,
                permission_count: 0,
                code_execution: "none".to_string(),
                reasons: vec!["Package requests no elevated permissions".to_string()],
            },
            benchmark_scores: Vec::new(),
            approx_artifact_bytes: 1,
        }
    }
}
