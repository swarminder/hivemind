use chrono::{DateTime, SecondsFormat, Utc};
use hivemind_core::{
    ExecutionReceiptV1, ExecutionRequestV1, LicenseType, PolicyMode, RegistryEntryV1,
    RunnerDescriptorV1, RunnerType, canonicalize_json, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use hivemind_receipts::{DisputeEvidenceV1, DisputeEvidenceVerificationV1, ReceiptVerificationV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

const DEV_RUNNER_OFFER_SIGNATURE_PREFIX: &str = "dev-runner-offer-signature-v1";
const DEV_SERVICE_QUOTE_SIGNATURE_PREFIX: &str = "dev-service-quote-signature-v1";
const DEV_MARKETPLACE_LISTING_SIGNATURE_PREFIX: &str = "dev-marketplace-listing-signature-v1";
const DEV_SETTLEMENT_EVENT_SIGNATURE_PREFIX: &str = "dev-settlement-event-signature-v1";
const DEV_SETTLEMENT_RESOLUTION_SIGNATURE_PREFIX: &str = "dev-settlement-resolution-signature-v1";
const DEV_PAYMENT_SIGNATURE_PREFIX: &str = "dev-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MarketplaceListingType {
    Package,
    Runner,
    Service,
    Validator,
    Benchmark,
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
#[serde(rename_all = "kebab-case")]
pub enum SettlementStatus {
    Pending,
    Settled,
    Refunded,
    Disputed,
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
    #[serde(rename = "runnerType")]
    pub runner_type: RunnerType,
    #[serde(rename = "runnerDescriptorRef")]
    pub runner_descriptor_ref: String,
    #[serde(rename = "supportedPackageRefs")]
    pub supported_package_refs: Vec<String>,
    #[serde(rename = "supportedCapabilities")]
    pub supported_capabilities: Vec<String>,
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
    #[serde(rename = "estimatedInputTokens")]
    pub estimated_input_tokens: u64,
    #[serde(rename = "estimatedOutputTokens")]
    pub estimated_output_tokens: u64,
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
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "offerId")]
    pub offer_id: String,
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
    #[serde(rename = "settlementModel")]
    pub settlement_model: SettlementModel,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(default)]
    pub details: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
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
pub struct PaymentAuthorizationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "authorizationId")]
    pub authorization_id: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
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
    pub status: PaymentAuthorizationStatus,
    #[serde(rename = "paymentRef", default)]
    pub payment_ref: Option<String>,
    #[serde(rename = "authorizedAt")]
    pub authorized_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
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
    pub status: PaymentAuthorizationStatus,
    #[serde(rename = "paymentRef", default)]
    pub payment_ref: Option<String>,
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
pub struct SettlementEventV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "settlementId")]
    pub settlement_id: String,
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
    pub status: SettlementStatus,
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
pub struct SettlementAuditEntryV1 {
    #[serde(rename = "settlementId")]
    pub settlement_id: String,
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
    pub status: SettlementStatus,
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

pub fn listing_from_registry_entry(
    entry: &RegistryEntryV1,
    owner: impl Into<String>,
) -> Option<MarketplaceListingV1> {
    let package_ref = entry.package_refs.first()?.package_ref.clone();
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
        schema_version: "swarm-ai.marketplace.listing.v1".to_string(),
        listing_id: String::new(),
        listing_type: MarketplaceListingType::Package,
        owner: owner.into(),
        package_id: entry.package_id.clone(),
        package_ref: Some(package_ref),
        title: entry.name.clone(),
        description_ref: None,
        pricing,
        terms_ref: entry.license.url.clone(),
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
    let signature = listing
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if listing.schema_version != "swarm-ai.marketplace.listing.v1" {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.marketplace.listing.v1",
        ));
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
        schema_version: "swarm-ai.marketplace-listing-verification.v1".to_string(),
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
    let mut offer = RunnerOfferV1 {
        schema_version: "swarm-ai.runner-offer.v1".to_string(),
        offer_id: String::new(),
        runner_id: descriptor.runner_id.clone(),
        runner_type: descriptor.runner_type.clone(),
        runner_descriptor_ref: runner_descriptor_ref.into(),
        supported_package_refs,
        supported_capabilities: descriptor.capabilities.clone(),
        pricing,
        service_level,
        reputation,
        signature: None,
    };
    sign_runner_offer(&mut offer);
    offer
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
    let signature = offer
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if offer.schema_version != "swarm-ai.runner-offer.v1" {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.runner-offer.v1",
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
        } else if !package_ref.starts_with("bzz://") {
            warnings.push(marketplace_issue(
                format!("$.supportedPackageRefs[{index}]"),
                "Supported package ref is not a bzz:// reference",
            ));
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
        schema_version: "swarm-ai.runner-offer-verification.v1".to_string(),
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
        schema_version: "swarm-ai.marketplace-shortlist-request.v1".to_string(),
        package_ref: request.package_ref.clone(),
        task: request.task.clone(),
        estimated_input_tokens,
        estimated_output_tokens: estimated_input_tokens,
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
        schema_version: "swarm-ai.marketplace-shortlist.v1".to_string(),
        package_ref: request.package_ref.clone(),
        task: request.task.clone(),
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

    if request.schema_version != "swarm-ai.marketplace-shortlist-request.v1" {
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
    let score = if eligible {
        match request.policy_mode {
            PolicyMode::PrivacyFirst => reputation_score * 3.0 + cost_score * 3.0 + speed_score,
            PolicyMode::SpeedFirst => speed_score * 10.0 + reputation_score * 2.0 + cost_score,
            PolicyMode::CostFirst => cost_score * 10.0 + reputation_score * 2.0 + speed_score,
            PolicyMode::QualityFirst => reputation_score * 10.0 + speed_score + cost_score,
            PolicyMode::Balanced => reputation_score * 4.0 + speed_score * 3.0 + cost_score * 3.0,
            PolicyMode::Developer => reputation_score + speed_score + cost_score,
        }
    } else {
        -1.0
    };

    if reasons.is_empty() {
        reasons.push(format!(
            "Eligible offer scored for {:?} policy using cost, speed, availability, and validator reputation",
            request.policy_mode
        ));
    }

    RunnerOfferScoreV1 {
        schema_version: "swarm-ai.runner-offer-score.v1".to_string(),
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
    let mut quote = ServiceQuoteV1 {
        schema_version: "swarm-ai.service-quote.v1".to_string(),
        quote_id: String::new(),
        request_id: request.request_id.clone(),
        offer_id: offer.offer_id.clone(),
        runner_id: offer.runner_id.clone(),
        package_ref: request.package_ref.clone(),
        estimated_input_tokens,
        estimated_output_tokens,
        estimated_cost,
        currency: offer.pricing.currency.clone(),
        settlement_model,
        expires_at,
        details: json!({
            "runnerType": offer.runner_type,
            "pricing": offer.pricing,
            "serviceLevel": offer.service_level,
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
    let signature = quote
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if quote.schema_version != "swarm-ai.service-quote.v1" {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.service-quote.v1",
        ));
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
        let cost = quote.estimated_input_tokens as f64 * offer.pricing.input_token_price
            + quote.estimated_output_tokens as f64 * offer.pricing.output_token_price;
        expected_cost = Some(cost);
        if (quote.estimated_cost - cost).abs() > 0.000_000_1 {
            issues.push(marketplace_issue(
                "$.estimatedCost",
                "Quote estimated cost does not match runner offer pricing",
            ));
        }
    }

    ServiceQuoteVerificationV1 {
        schema_version: "swarm-ai.service-quote-verification.v1".to_string(),
        quote_id: quote.quote_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_cost,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn authorize_payment(
    quote: &ServiceQuoteV1,
    payer: impl Into<String>,
    payee: impl Into<String>,
    adapter: PaymentAdapterKind,
    payment_ref: Option<String>,
) -> PaymentAuthorizationV1 {
    let mut authorization = PaymentAuthorizationV1 {
        schema_version: "swarm-ai.payment-authorization.v1".to_string(),
        authorization_id: String::new(),
        quote_id: quote.quote_id.clone(),
        request_id: quote.request_id.clone(),
        offer_id: quote.offer_id.clone(),
        runner_id: quote.runner_id.clone(),
        package_ref: quote.package_ref.clone(),
        payer: payer.into(),
        payee: payee.into(),
        amount: quote.estimated_cost,
        currency: quote.currency.clone(),
        adapter,
        status: PaymentAuthorizationStatus::Authorized,
        payment_ref,
        authorized_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        expires_at: quote.expires_at.clone(),
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

    if authorization.schema_version != "swarm-ai.payment-authorization.v1" {
        issues.push(marketplace_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.payment-authorization.v1",
        ));
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
        if authorization.currency != quote.currency {
            issues.push(marketplace_issue(
                "$.currency",
                "Payment authorization currency must match service quote",
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
        schema_version: "swarm-ai.payment-authorization-verification.v1".to_string(),
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
        schema_version: "swarm-ai.settlement-event.v1".to_string(),
        settlement_id: String::new(),
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
        currency,
        status: SettlementStatus::Settled,
        occurred_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
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
    let signature = settlement
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if settlement.schema_version != "swarm-ai.settlement-event.v1" {
        issues.push(settlement_issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.settlement-event.v1",
        ));
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
        schema_version: "swarm-ai.settlement-event-verification.v1".to_string(),
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
        SettlementStatus::Settled,
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
    Ok(MarketplaceAuditSummaryV1 {
        schema_version: "swarm-ai.marketplace-audit-summary.v1".to_string(),
        root: audit_dir.display().to_string(),
        settlement_count: settlements.len(),
        valid_settlement_count,
        invalid_settlement_count: settlements.len().saturating_sub(valid_settlement_count),
        resolution_count: resolutions.len(),
        valid_resolution_count,
        invalid_resolution_count: resolutions.len().saturating_sub(valid_resolution_count),
        settlements,
        resolutions,
    })
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
        let updated_settlement = settlement_with_status(settlement, new_status.clone());
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
) -> SettlementEventV1 {
    let mut updated = settlement.clone();
    updated.status = status;
    updated.occurred_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    updated.settlement_id.clear();
    updated.signature = None;
    sign_settlement_event(&mut updated);
    updated
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

fn payment_authorization_index_entry(
    authorization: &PaymentAuthorizationV1,
    authorization_path: String,
) -> PaymentAuthorizationIndexEntryV1 {
    let verification = verify_payment_authorization(authorization, None);
    PaymentAuthorizationIndexEntryV1 {
        authorization_id: authorization.authorization_id.clone(),
        quote_id: authorization.quote_id.clone(),
        request_id: authorization.request_id.clone(),
        offer_id: authorization.offer_id.clone(),
        runner_id: authorization.runner_id.clone(),
        package_ref: authorization.package_ref.clone(),
        payer: authorization.payer.clone(),
        payee: authorization.payee.clone(),
        amount: authorization.amount,
        currency: authorization.currency.clone(),
        adapter: authorization.adapter.clone(),
        status: authorization.status.clone(),
        payment_ref: authorization.payment_ref.clone(),
        authorized_at: authorization.authorized_at.clone(),
        expires_at: authorization.expires_at.clone(),
        authorization_path,
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

fn marketplace_settlements_dir(audit_dir: &Path) -> PathBuf {
    audit_dir.join("settlements")
}

fn marketplace_resolutions_dir(audit_dir: &Path) -> PathBuf {
    audit_dir.join("resolutions")
}

fn settlement_audit_entry(
    settlement: &SettlementEventV1,
    settlement_path: String,
) -> SettlementAuditEntryV1 {
    let verification = verify_settlement_event(settlement);
    SettlementAuditEntryV1 {
        settlement_id: settlement.settlement_id.clone(),
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
        status: settlement.status.clone(),
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

fn looks_like_marketplace_ref(reference: &str) -> bool {
    reference.starts_with("bzz://") || reference.starts_with("local://")
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

fn payment_authorization_signing_value(authorization: &PaymentAuthorizationV1) -> Value {
    let mut value =
        serde_json::to_value(authorization).expect("payment authorization should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("authorizationId");
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

        assert!(listing.requires_license);
        assert_eq!(listing.pricing.mode, PricingMode::Quote);
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
        assert!(verify_runner_offer(&offer).valid);
        assert!(verify_service_quote(&quote, Some(&offer)).valid);
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
            schema_version: "swarm-ai.marketplace-shortlist-request.v1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            task: "embedding".to_string(),
            estimated_input_tokens: 10,
            estimated_output_tokens: 5,
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
            schema_version: "swarm-ai.marketplace-shortlist-request.v1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            task: "embedding".to_string(),
            estimated_input_tokens: 10,
            estimated_output_tokens: 5,
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
            schema_version: "swarm-ai.marketplace-shortlist-request.v1".to_string(),
            package_ref: "bzz://other".to_string(),
            task: "chat".to_string(),
            estimated_input_tokens: 10,
            estimated_output_tokens: 5,
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
    fn authorizes_and_verifies_payment_for_quote() {
        let quote = quote(&receipt());
        let authorization = authorize_payment(
            &quote,
            "0xUser",
            "runner-1",
            PaymentAdapterKind::LocalDev,
            Some("local://payment/auth-1".to_string()),
        );

        assert!(!authorization.authorization_id.is_empty());
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
        assert_eq!(verification.issues.len(), 0);
        assert_eq!(verification.expected_signature, authorization.signature);
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
            request_id: "req-1".to_string(),
            offer_id: "offer-1".to_string(),
            runner_id: "runner-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            estimated_input_tokens: 1,
            estimated_output_tokens: 1,
            estimated_cost: 0.01,
            currency: "xDAI".to_string(),
            settlement_model: SettlementModel::DirectPayPerCall,
            expires_at: "2026-05-22T00:05:00Z".to_string(),
            details: json!({}),
            signature: None,
        };

        let settlement =
            settlement_from_receipt(&receipt, Some(&quote), "0xUser", "runner-1", None);
        assert_eq!(settlement.quote_id, Some("quote-1".to_string()));
        assert_eq!(settlement.receipt_id, "receipt-1");
        assert_eq!(settlement.amount, 0.01);
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
        assert!(verify_settlement_event(&settlement).valid);
        assert!(result.verification.expected_signature.is_some());
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
            SettlementStatus::Settled
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
    fn marketplace_audit_store_indexes_settlements_and_resolutions() {
        let root = unique_temp_dir("hivemind-marketplace-audit-test");
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

        let settlement_path = write_settlement_event(&root, &settlement).unwrap();
        write_settlement_event(&root, disputed.updated_settlement.as_ref().unwrap()).unwrap();
        write_settlement_event(&root, refund.updated_settlement.as_ref().unwrap()).unwrap();
        let dispute_resolution_path =
            write_settlement_resolution(&root, disputed.resolution.as_ref().unwrap()).unwrap();
        write_settlement_resolution(&root, refund.resolution.as_ref().unwrap()).unwrap();

        let summary = list_marketplace_audit(&root).unwrap();
        assert_eq!(summary.settlement_count, 3);
        assert_eq!(summary.valid_settlement_count, 3);
        assert_eq!(summary.resolution_count, 2);
        assert_eq!(summary.valid_resolution_count, 2);
        assert!(
            summary
                .settlements
                .iter()
                .any(|entry| entry.status == SettlementStatus::Refunded)
        );

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
            schema_version: "swarm-ai.service-quote.v1".to_string(),
            quote_id: "quote-1".to_string(),
            request_id: receipt.request_id.clone(),
            offer_id: "offer-1".to_string(),
            runner_id: receipt.runner_id.clone(),
            package_ref: receipt.package_ref.clone(),
            estimated_input_tokens: 1,
            estimated_output_tokens: 1,
            estimated_cost: 0.01,
            currency: "xDAI".to_string(),
            settlement_model: SettlementModel::DirectPayPerCall,
            expires_at: (Utc::now() + chrono::Duration::minutes(5))
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            details: json!({}),
            signature: None,
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
