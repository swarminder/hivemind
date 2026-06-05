use anyhow::{Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{Duration, SecondsFormat, Utc};
use hivemind_core::{
    AccessDecision, AiRequestV1, AiResponseV1, ApiSurface, CandidateRoute, ErrorCode,
    ExecutionLeaseRequestV1, ExecutionRequestV1, ExecutionResponseV1, ExecutionStatus,
    INTERFACE_VERSION, IntegrityTier, JOB_QUOTE_SCHEMA_VERSION, JobOrderV1, JobQuoteV1,
    LicenseType, Modality, PackageKind, PolicyMode, PriceV1, PrivacyTier, RegistryEntryV1,
    RegistryQueryV1, RegistrySearchResponse, RouteDecision, RoutePlanV1, RunnerCapabilityV1,
    RunnerType, StreamingEventType, SwarmAiErrorV1, TrustPolicyV1,
    ai_response_from_execution_response, ai_workload_from_ai_request, canonical_job_order_id,
    canonical_job_quote_id, canonical_receipt_id, execution_lease_from_quote,
    execution_lease_from_request, execution_receipt_v2_from_v1, execution_request_from_ai_request,
    job_order_from_execution_request, job_quote_from_runner_capability, sign_receipt,
    streaming_event, task_envelope_from_ai_request, verify_ai_workload, verify_task_envelope,
};
use hivemind_marketplace::{
    HardwareResourceOfferV1, MarketplaceListingV1, RunnerOfferV1, default_local_runner_offer,
    listing_from_registry_entry, quote_execution,
};
use hivemind_registry::{
    IndexedPackage, RegistrySnapshotV1, build_registry_shards, find_package,
    load_hardware_resource_offers, load_marketplace_listings,
    load_packages_with_all_metadata_feeds_marketplace_and_offers, load_runner_offers,
    public_registry_snapshot,
    rebuild_registry_snapshot_with_all_sources_marketplace_offers_and_governance,
    registry_package_lookup, registry_package_lookup_for_request,
    registry_shard_manifest_for_shards, search_registry,
};
use hivemind_router::{
    AiExecutionPlanV1, MinerCapacityInputV1, RouteAttemptV1, RouteExecutionTraceV1,
    RoutePlannerReportV1, RoutePlannerRequestV1, RunnerReputationSummaryV1,
    plan_routes_with_trust_policy, planner_report_with_trust_policy,
};
use hivemind_storage::StorageProvider;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub host: String,
    pub port: u16,
    pub package_dir: PathBuf,
    pub package_audit_dir: PathBuf,
    pub compatibility_dir: PathBuf,
    pub record_dir: PathBuf,
    pub validation_dir: PathBuf,
    pub evaluation_dir: PathBuf,
    pub access_grant_dir: PathBuf,
    pub access_revocation_dir: PathBuf,
    pub receipt_dir: PathBuf,
    pub dispute_dir: PathBuf,
    pub job_dir: PathBuf,
    pub governance_dir: PathBuf,
    pub research_dir: PathBuf,
    pub eval_dir: PathBuf,
    pub vector_dir: PathBuf,
    pub workflow_dir: PathBuf,
    pub batch_dir: PathBuf,
    pub fine_tune_dir: PathBuf,
    pub realtime_dir: PathBuf,
    pub media_dir: PathBuf,
    pub moderation_dir: PathBuf,
    pub miner_dir: PathBuf,
    pub marketplace_listing_dir: PathBuf,
    pub marketplace_runner_offer_dir: PathBuf,
    pub marketplace_hardware_offer_dir: PathBuf,
    pub marketplace_payment_dir: PathBuf,
    pub marketplace_audit_dir: PathBuf,
    pub storage_dir: PathBuf,
    pub storage_audit_dir: PathBuf,
    pub runner_cache_dir: PathBuf,
    pub trust_policy_dir: PathBuf,
    pub feed_dir: PathBuf,
    pub stream_event_dir: PathBuf,
    pub route_trace_dir: PathBuf,
    pub static_dir: PathBuf,
    pub registry_audit_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct AppState {
    packages: Arc<Vec<IndexedPackage>>,
    registry_snapshot: Arc<RegistrySnapshotV1>,
    package_audit_dir: Arc<PathBuf>,
    compatibility_dir: Arc<PathBuf>,
    registry_audit_dir: Arc<PathBuf>,
    record_dir: Arc<PathBuf>,
    validation_dir: Arc<PathBuf>,
    evaluation_dir: Arc<PathBuf>,
    access_grant_dir: Arc<PathBuf>,
    access_revocation_dir: Arc<PathBuf>,
    receipt_dir: Arc<PathBuf>,
    dispute_dir: Arc<PathBuf>,
    job_dir: Arc<PathBuf>,
    governance_dir: Arc<PathBuf>,
    research_dir: Arc<PathBuf>,
    eval_dir: Arc<PathBuf>,
    vector_dir: Arc<PathBuf>,
    workflow_dir: Arc<PathBuf>,
    batch_dir: Arc<PathBuf>,
    fine_tune_dir: Arc<PathBuf>,
    realtime_dir: Arc<PathBuf>,
    media_dir: Arc<PathBuf>,
    moderation_dir: Arc<PathBuf>,
    miner_dir: Arc<PathBuf>,
    marketplace_listing_dir: Arc<PathBuf>,
    marketplace_runner_offer_dir: Arc<PathBuf>,
    marketplace_hardware_offer_dir: Arc<PathBuf>,
    marketplace_payment_dir: Arc<PathBuf>,
    marketplace_audit_dir: Arc<PathBuf>,
    storage_dir: Arc<PathBuf>,
    storage_audit_dir: Arc<PathBuf>,
    runner_cache_dir: Arc<PathBuf>,
    trust_policy_dir: Arc<PathBuf>,
    feed_dir: Arc<PathBuf>,
    stream_event_dir: Arc<PathBuf>,
    route_trace_dir: Arc<PathBuf>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    #[serde(rename = "interfaceVersion")]
    interface_version: &'static str,
    packages: usize,
}

#[derive(Debug, Deserialize)]
struct RevokeAccessGrantRequest {
    grant: hivemind_core::AccessGrantV1,
    #[serde(rename = "revokedBy")]
    revoked_by: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct RevokeAccessGrantResponse {
    revocation: hivemind_core::AccessGrantRevocationV1,
    verification: hivemind_access::AccessGrantRevocationVerificationV1,
}

#[derive(Debug, Deserialize)]
struct VerifyAccessRevocationRequest {
    revocation: hivemind_core::AccessGrantRevocationV1,
    #[serde(default)]
    grant: Option<hivemind_core::AccessGrantV1>,
}

#[derive(Debug, Deserialize)]
struct AccessPolicyProjectRequest {
    #[serde(rename = "licensePolicy")]
    license_policy: hivemind_core::LicensePolicyV1,
    #[serde(default)]
    context: hivemind_core::AccessPolicyV1Context,
}

#[derive(Debug, Deserialize)]
struct RequestPaidAccessRequest {
    listing: hivemind_marketplace::MarketplaceListingV2,
    requester: String,
    #[serde(rename = "requestedUse", default)]
    requested_use: Option<String>,
    #[serde(rename = "assetRef", default)]
    asset_ref: Option<String>,
    #[serde(default)]
    amount: Option<f64>,
    #[serde(default)]
    currency: Option<String>,
    #[serde(rename = "expiresAt", default)]
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AttachAccessGrantToJobRequest {
    #[serde(rename = "jobOrder")]
    job_order: hivemind_core::JobOrderV1,
    grant: hivemind_core::AccessGrantV2,
}

#[derive(Debug, Deserialize)]
struct CompatibilityPackageCertificationRequest {
    #[serde(rename = "schemaVersion", default)]
    schema_version: Option<String>,
    #[serde(rename = "packageRef", default)]
    package_ref: Option<String>,
    #[serde(rename = "packageId", default)]
    package_id: Option<String>,
    #[serde(rename = "componentType", default = "default_component_type")]
    component_type: String,
    #[serde(rename = "implementationName", default)]
    implementation_name: Option<String>,
    #[serde(rename = "componentVersion", default)]
    component_version: Option<String>,
    #[serde(rename = "supportedSchemas", default)]
    supported_schemas: Vec<String>,
    #[serde(default)]
    warnings: Vec<String>,
    #[serde(default)]
    identity: Option<hivemind_identity::IdentityKeypairV1>,
    #[serde(default)]
    store: bool,
}

#[derive(Debug, Serialize)]
struct CompatibilityPackageCertificationResponse {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    #[serde(rename = "packageId")]
    package_id: String,
    #[serde(rename = "packageRef")]
    package_ref: String,
    #[serde(rename = "packageRoot")]
    package_root: String,
    report: hivemind_sdk::CompatibilityReportV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    certification: Option<hivemind_sdk::CompatibilityCertificationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verification: Option<hivemind_sdk::SdkVerificationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    store: Option<hivemind_sdk::CompatibilityCertificationWriteResultV1>,
}

#[derive(Debug, Deserialize)]
struct CompatibilityCertificationVerificationRequest {
    #[serde(rename = "schemaVersion", default)]
    schema_version: Option<String>,
    certification: hivemind_sdk::CompatibilityCertificationV1,
    #[serde(rename = "expectedSigner", default)]
    expected_signer: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RoutePlannerBody {
    Planner(RoutePlannerRequestV1),
    Execution(ExecutionRequestV1),
}

#[derive(Debug, Deserialize, Default)]
struct TrustPolicyPresetRequest {
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    sign: bool,
}

#[derive(Debug, Serialize)]
struct TrustPolicyEnvelopeResponse {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    #[serde(rename = "trustPolicy")]
    trust_policy: TrustPolicyV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    verification: hivemind_core::TrustPolicyVerificationV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    store: Option<hivemind_policy::TrustPolicyWriteResultV1>,
}

#[derive(Debug, Clone)]
struct CompatibilityRoutingControls {
    policy_mode: PolicyMode,
    max_marketplace_results: usize,
    trust_policy: Option<TrustPolicyV1>,
}

impl Default for CompatibilityRoutingControls {
    fn default() -> Self {
        Self {
            policy_mode: PolicyMode::Balanced,
            max_marketplace_results: 3,
            trust_policy: None,
        }
    }
}

fn default_component_type() -> String {
    "package".to_string()
}

#[derive(Debug, Deserialize)]
struct VerifyMinerProfileRequest {
    profile: hivemind_miner::MinerProfileV1,
    #[serde(rename = "hardwareOffer", default)]
    hardware_offer: Option<hivemind_marketplace::HardwareResourceOfferV1>,
}

#[derive(Debug, Deserialize)]
struct VerifyMinerHeartbeatRequest {
    heartbeat: hivemind_miner::MinerHeartbeatV1,
    #[serde(default)]
    profile: Option<hivemind_miner::MinerProfileV1>,
}

#[derive(Debug, Deserialize)]
struct VerifyMinerBenchmarkRequest {
    benchmark: hivemind_miner::MinerBenchmarkResultV1,
    #[serde(default)]
    profile: Option<hivemind_miner::MinerProfileV1>,
    #[serde(rename = "hardwareOffer", default)]
    hardware_offer: Option<hivemind_marketplace::HardwareResourceOfferV1>,
}

#[derive(Debug, Deserialize)]
struct MinerOnboardingRequest {
    profile: hivemind_miner::MinerProfileV1,
    #[serde(rename = "hardwareOffer")]
    hardware_offer: hivemind_marketplace::HardwareResourceOfferV1,
    #[serde(default)]
    benchmarks: Vec<hivemind_miner::MinerBenchmarkResultV1>,
}

#[derive(Debug, Deserialize)]
struct CreateDisputeRequest {
    receipt: hivemind_core::ExecutionReceiptV1,
    claimant: String,
    #[serde(rename = "claimKind")]
    claim_kind: hivemind_receipts::DisputeClaimKind,
    summary: String,
    #[serde(rename = "evidenceRefs", default)]
    evidence_refs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CreateDisputeResponse {
    #[serde(rename = "disputePath")]
    dispute_path: String,
    evidence: hivemind_receipts::DisputeEvidenceV1,
    verification: hivemind_receipts::DisputeEvidenceVerificationV1,
}

#[derive(Debug, Deserialize)]
struct MarketplaceSettleRequest {
    receipt: hivemind_core::ExecutionReceiptV1,
    #[serde(default)]
    quote: Option<hivemind_marketplace::ServiceQuoteV1>,
    #[serde(rename = "paymentAuthorization", default)]
    payment_authorization: Option<hivemind_marketplace::PaymentAuthorizationV1>,
    payer: String,
    payee: String,
    #[serde(rename = "receiptRef", default)]
    receipt_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MarketplaceVerifyQuoteRequest {
    quote: hivemind_marketplace::ServiceQuoteV1,
    #[serde(default)]
    offer: Option<hivemind_marketplace::RunnerOfferV1>,
}

#[derive(Debug, Deserialize)]
struct MarketplaceAuthorizePaymentRequest {
    quote: hivemind_marketplace::ServiceQuoteV1,
    payer: String,
    payee: String,
    #[serde(default)]
    adapter: Option<hivemind_marketplace::PaymentAdapterKind>,
    #[serde(rename = "paymentRef", default)]
    payment_ref: Option<String>,
}

#[derive(Debug, Serialize)]
struct MarketplaceAuthorizePaymentResponse {
    authorization: hivemind_marketplace::PaymentAuthorizationV1,
    verification: hivemind_marketplace::PaymentAuthorizationVerificationV1,
}

#[derive(Debug, Deserialize)]
struct MarketplaceCreateEscrowRequest {
    authorization: hivemind_marketplace::PaymentAuthorizationV1,
    #[serde(default)]
    quote: Option<hivemind_marketplace::ServiceQuoteV1>,
    #[serde(default)]
    custodian: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    evidence_refs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct MarketplaceCreateEscrowResponse {
    escrow: hivemind_marketplace::EscrowRecordV1,
    verification: hivemind_marketplace::EscrowRecordVerificationV1,
}

#[derive(Debug, Deserialize)]
struct MarketplaceVerifyEscrowRequest {
    escrow: hivemind_marketplace::EscrowRecordV1,
    #[serde(default)]
    authorization: Option<hivemind_marketplace::PaymentAuthorizationV1>,
    #[serde(default)]
    quote: Option<hivemind_marketplace::ServiceQuoteV1>,
}

#[derive(Debug, Deserialize)]
struct MarketplaceVerifyPaymentRequest {
    authorization: hivemind_marketplace::PaymentAuthorizationV1,
    #[serde(default)]
    quote: Option<hivemind_marketplace::ServiceQuoteV1>,
}

#[derive(Debug, Deserialize, Default)]
struct HivemindPackagesQuery {
    #[serde(default)]
    kind: Option<PackageKind>,
    #[serde(default)]
    capability: Option<String>,
    #[serde(default)]
    modality: Option<Modality>,
    #[serde(rename = "apiSurface", default)]
    api_surface: Option<ApiSurface>,
    #[serde(default)]
    publisher: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    engine: Option<String>,
    #[serde(rename = "licenseType", default)]
    license_type: Option<String>,
    #[serde(rename = "privacyTier", default)]
    privacy_tier: Option<PrivacyTier>,
    #[serde(rename = "verificationTier", default)]
    verification_tier: Option<IntegrityTier>,
    #[serde(rename = "maxArtifactBytes", default)]
    max_artifact_bytes: Option<u64>,
    #[serde(rename = "minArtifactBytes", default)]
    min_artifact_bytes: Option<u64>,
    #[serde(rename = "browserRunnable", default)]
    browser_runnable: Option<bool>,
    #[serde(rename = "gpuRequired", default)]
    gpu_required: Option<bool>,
    #[serde(rename = "minValidatorScore", default)]
    min_validator_score: Option<f64>,
    #[serde(rename = "minBenchmarkScore", default)]
    min_benchmark_score: Option<f64>,
    #[serde(rename = "maxPriceAmount", default)]
    max_price_amount: Option<f64>,
    #[serde(rename = "maxPriceCurrency", default)]
    max_price_currency: Option<String>,
    #[serde(rename = "pageSize", default)]
    page_size: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct JobStreamQuery {
    #[serde(default)]
    format: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ReceiptRedactionQuery {
    #[serde(default)]
    profile: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct HivemindPackageSelectorRequest {
    #[serde(rename = "schemaVersion", default)]
    schema_version: Option<String>,
    #[serde(rename = "packageId", default)]
    package_id: Option<String>,
    #[serde(rename = "packageRef", default)]
    package_ref: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    requester: Option<String>,
    #[serde(rename = "requestedUse", default)]
    requested_use: Option<String>,
    #[serde(rename = "runnerId", default)]
    runner_id: Option<String>,
    #[serde(rename = "accessGrant", default)]
    access_grant: Option<hivemind_core::AccessGrantV1>,
    #[serde(rename = "accessRevocationList", default)]
    access_revocation_list: Option<hivemind_core::AccessRevocationListV1>,
}

#[derive(Debug, Serialize)]
struct HivemindResolveResponse {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    #[serde(rename = "selectedPackageId")]
    selected_package_id: String,
    #[serde(rename = "selectedPackageRef")]
    selected_package_ref: String,
    #[serde(rename = "manifestHash")]
    manifest_hash: String,
    lookup: hivemind_registry::RegistryPackageLookupV1,
}

#[derive(Debug, Serialize)]
struct HivemindPolicyEvaluationResponse {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    #[serde(rename = "packageId")]
    package_id: String,
    #[serde(rename = "packageRef")]
    package_ref: String,
    #[serde(rename = "runnerId", default)]
    runner_id: Option<String>,
    #[serde(rename = "executionAllowed")]
    execution_allowed: bool,
    #[serde(rename = "policyInspection")]
    policy_inspection: hivemind_policy::PolicyInspectionV1,
    #[serde(rename = "accessEvaluation")]
    access_evaluation: hivemind_core::AccessEvaluationV1,
}

#[derive(Debug, Deserialize)]
struct ResearchReproduceRequest {
    experiment: hivemind_research::ResearchExperimentV1,
    #[serde(default)]
    runner: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResearchCreateRunRequest {
    experiment: hivemind_research::ResearchExperimentV1,
    requester: String,
    runner: String,
    #[serde(default)]
    status: Option<hivemind_research::ResearchRunStatusV1>,
    #[serde(rename = "receiptRefs", default)]
    receipt_refs: Vec<String>,
    #[serde(rename = "evaluationResultRefs", default)]
    evaluation_result_refs: Vec<String>,
    #[serde(rename = "validationReportRefs", default)]
    validation_report_refs: Vec<String>,
    #[serde(rename = "outputRefs", default)]
    output_refs: Vec<String>,
    #[serde(default)]
    notes: Vec<String>,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct ResearchVerifyRunRequest {
    run: hivemind_research::ResearchExperimentRunV1,
    #[serde(default)]
    experiment: Option<hivemind_research::ResearchExperimentV1>,
}

#[derive(Debug, Serialize)]
struct ResearchCreateRunResponse {
    #[serde(rename = "runPath")]
    run_path: String,
    run: hivemind_research::ResearchExperimentRunV1,
    verification: hivemind_research::ResearchExperimentRunVerificationV1,
}

#[derive(Debug, Deserialize)]
struct MarketplaceSettlementResolutionRequest {
    settlement: hivemind_marketplace::SettlementEventV1,
    dispute: hivemind_receipts::DisputeEvidenceV1,
    #[serde(rename = "resolvedBy")]
    resolved_by: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct DownloadReceiptRequest {
    #[serde(rename = "receiptRef")]
    receipt_ref: String,
}

#[derive(Debug, Deserialize)]
struct DownloadValidationReportRequest {
    #[serde(rename = "reportRef")]
    report_ref: String,
}

#[derive(Debug, Deserialize)]
struct ValidationReputationRequest {
    #[serde(rename = "subjectType")]
    subject_type: hivemind_validator::ReputationSubjectType,
    #[serde(rename = "subjectId")]
    subject_id: String,
}

#[derive(Debug, Serialize)]
struct IntegrityEvidenceCreateResponse {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    #[serde(rename = "evidencePath")]
    evidence_path: String,
    evidence: hivemind_validator::IntegrityEvidenceV1,
    verification: hivemind_validator::IntegrityEvidenceVerificationV1,
    #[serde(rename = "validationReportV2")]
    validation_report_v2: hivemind_validator::ValidationReportV2,
}

#[derive(Debug, Deserialize)]
struct StorageReferenceRequest {
    #[serde(rename = "ref")]
    reference: String,
}

#[derive(Debug, Deserialize)]
struct StorageInspectRequest {
    #[serde(rename = "ref")]
    reference: String,
    #[serde(default)]
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StorageFeedCreateRequest {
    topic: String,
    owner: String,
}

#[derive(Debug, Deserialize)]
struct StorageFeedUpdateRequest {
    topic: String,
    owner: String,
    #[serde(rename = "ref")]
    reference: String,
}

#[derive(Debug, Deserialize)]
struct StorageFeedResolveRequest {
    #[serde(rename = "feedRef")]
    feed_ref: String,
}

pub async fn serve(config: ServeConfig) -> Result<()> {
    let packages = load_packages_with_all_metadata_feeds_marketplace_and_offers(
        &config.package_dir,
        Some(&config.record_dir),
        Some(&config.feed_dir),
        Some(&config.validation_dir),
        Some(&config.evaluation_dir),
        Some(&config.marketplace_listing_dir),
        Some(&config.marketplace_runner_offer_dir),
        Some(&config.marketplace_hardware_offer_dir),
    )
        .with_context(|| {
        format!(
            "failed to load packages from {} with publication records from {}, feeds from {}, validation reports from {}, evaluation results from {}, marketplace listings from {}, runner offers from {}, and hardware offers from {}",
            config.package_dir.display(),
            config.record_dir.display(),
            config.feed_dir.display(),
            config.validation_dir.display(),
            config.evaluation_dir.display(),
            config.marketplace_listing_dir.display(),
            config.marketplace_runner_offer_dir.display(),
            config.marketplace_hardware_offer_dir.display()
        )
    })?;
    let registry_snapshot =
        rebuild_registry_snapshot_with_all_sources_marketplace_offers_and_governance(
            &config.package_dir,
            Some(&config.record_dir),
            Some(&config.feed_dir),
            Some(&config.validation_dir),
            Some(&config.evaluation_dir),
            Some(&config.marketplace_listing_dir),
            Some(&config.marketplace_runner_offer_dir),
            Some(&config.marketplace_hardware_offer_dir),
            Some(&config.governance_dir),
        )
        .with_context(|| {
            format!(
                "failed to build registry snapshot from {}, {}, {}, {}, {}, {}, {}, {}, and {}",
                config.package_dir.display(),
                config.record_dir.display(),
                config.feed_dir.display(),
                config.validation_dir.display(),
                config.evaluation_dir.display(),
                config.marketplace_listing_dir.display(),
                config.marketplace_runner_offer_dir.display(),
                config.marketplace_hardware_offer_dir.display(),
                config.governance_dir.display()
            )
        })?;
    let state = AppState {
        packages: Arc::new(packages),
        registry_snapshot: Arc::new(registry_snapshot),
        package_audit_dir: Arc::new(config.package_audit_dir),
        compatibility_dir: Arc::new(config.compatibility_dir),
        registry_audit_dir: Arc::new(config.registry_audit_dir),
        record_dir: Arc::new(config.record_dir),
        validation_dir: Arc::new(config.validation_dir),
        evaluation_dir: Arc::new(config.evaluation_dir),
        access_grant_dir: Arc::new(config.access_grant_dir),
        access_revocation_dir: Arc::new(config.access_revocation_dir),
        receipt_dir: Arc::new(config.receipt_dir),
        dispute_dir: Arc::new(config.dispute_dir),
        job_dir: Arc::new(config.job_dir),
        governance_dir: Arc::new(config.governance_dir),
        research_dir: Arc::new(config.research_dir),
        eval_dir: Arc::new(config.eval_dir),
        vector_dir: Arc::new(config.vector_dir),
        workflow_dir: Arc::new(config.workflow_dir),
        batch_dir: Arc::new(config.batch_dir),
        fine_tune_dir: Arc::new(config.fine_tune_dir),
        realtime_dir: Arc::new(config.realtime_dir),
        media_dir: Arc::new(config.media_dir),
        moderation_dir: Arc::new(config.moderation_dir),
        miner_dir: Arc::new(config.miner_dir),
        marketplace_listing_dir: Arc::new(config.marketplace_listing_dir),
        marketplace_runner_offer_dir: Arc::new(config.marketplace_runner_offer_dir),
        marketplace_hardware_offer_dir: Arc::new(config.marketplace_hardware_offer_dir),
        marketplace_payment_dir: Arc::new(config.marketplace_payment_dir),
        marketplace_audit_dir: Arc::new(config.marketplace_audit_dir),
        storage_dir: Arc::new(config.storage_dir),
        storage_audit_dir: Arc::new(config.storage_audit_dir),
        runner_cache_dir: Arc::new(config.runner_cache_dir),
        trust_policy_dir: Arc::new(config.trust_policy_dir),
        feed_dir: Arc::new(config.feed_dir),
        stream_event_dir: Arc::new(config.stream_event_dir),
        route_trace_dir: Arc::new(config.route_trace_dir),
    };
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .with_context(|| format!("invalid listen address {}:{}", config.host, config.port))?;
    let app = router(state, config.static_dir);
    let listener = TcpListener::bind(addr).await?;
    info!("serving Hivemind API and UI on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

fn router(state: AppState, static_dir: PathBuf) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/errors/catalog", get(error_catalog))
        .route("/v1/packages/validate", post(validate_manifest))
        .route("/v1/packages/project-v2", post(project_package_manifest_v2))
        .route("/v1/packages/project-v3", post(project_package_manifest_v3))
        .route("/v1/packages/project-v4", post(project_package_manifest_v4))
        .route("/v1/ai/workload", post(hivemind_ai_workload))
        .route("/v1/ai/task-envelope", post(hivemind_ai_task_envelope))
        .route(
            "/v1/compatibility/supported-schemas",
            get(compatibility_supported_schemas),
        )
        .route(
            "/v1/compatibility/certify-package",
            post(compatibility_certify_package),
        )
        .route(
            "/v1/compatibility/verify-certification",
            post(compatibility_verify_certification),
        )
        .route(
            "/v1/compatibility/certifications",
            get(compatibility_certifications),
        )
        .route(
            "/v1/compatibility/certifications/{certification_id}",
            get(compatibility_certification_by_id),
        )
        .route("/v1/access/verify-grant", post(verify_access_grant))
        .route("/v1/access/sign-grant-v2", post(sign_access_grant_v2))
        .route("/v1/access/verify-grant-v2", post(verify_access_grant_v2))
        .route("/v1/access/sign-grant-v3", post(sign_access_grant_v3))
        .route("/v1/access/verify-grant-v3", post(verify_access_grant_v3))
        .route("/v1/access/policy/project", post(project_access_policy))
        .route("/v1/access/policy/verify", post(verify_access_policy))
        .route(
            "/v1/access/policy/project-v2",
            post(project_access_policy_v2),
        )
        .route("/v1/access/policy/verify-v2", post(verify_access_policy_v2))
        .route("/v1/access/request-paid-access", post(request_paid_access))
        .route(
            "/v1/access/attach-grant-to-job",
            post(attach_access_grant_to_job),
        )
        .route("/v1/access/grants", get(access_grants))
        .route("/v1/access/grants/{grant_id}", get(access_grant_by_id))
        .route("/v1/access/revoke-grant", post(revoke_access_grant))
        .route("/v1/access/revocations", get(access_revocations))
        .route(
            "/v1/access/revocations/{revocation_id}",
            get(access_revocation_by_id),
        )
        .route(
            "/v1/access/verify-revocation",
            post(verify_access_revocation),
        )
        .route(
            "/v1/access/verify-revocation-list",
            post(verify_access_revocation_list),
        )
        .route("/v1/registry/search", post(search))
        .route("/v1/registry/package", post(registry_package_request))
        .route(
            "/v1/registry/packages/{*package_id}",
            get(registry_package_by_id),
        )
        .route("/v1/registry/snapshot", get(registry_snapshot))
        .route(
            "/v1/registry/snapshot/verification",
            get(registry_snapshot_verification),
        )
        .route(
            "/v1/registry/snapshot/verify",
            post(registry_snapshot_verify),
        )
        .route("/v1/registry/shards", get(registry_shards))
        .route(
            "/v1/registry/shards/manifest",
            get(registry_shards_manifest),
        )
        .route(
            "/v1/registry/shards/manifest/compare",
            post(registry_shard_manifest_compare),
        )
        .route("/v1/registry/shards/verify", post(registry_shards_verify))
        .route(
            "/v1/registry/shards/manifest/verify",
            post(registry_shard_manifest_verify),
        )
        .route("/v1/storage/status", get(storage_status))
        .route("/v1/storage/providers/v3", get(storage_providers_v3))
        .route("/v1/storage/providers/v4", get(storage_providers_v4))
        .route("/v1/storage/cache", get(storage_cache))
        .route("/v1/storage/inspect", post(storage_inspect))
        .route("/v1/storage/pin", post(storage_pin))
        .route("/v1/storage/unpin", post(storage_unpin))
        .route("/v1/storage/feed/create", post(storage_feed_create))
        .route("/v1/storage/feed/update", post(storage_feed_update))
        .route("/v1/storage/feed/resolve", post(storage_feed_resolve))
        .route("/v1/browser-storage/providers", get(storage_providers_v3))
        .route(
            "/v1/browser-storage/providers/v4",
            get(storage_providers_v4),
        )
        .route(
            "/v1/browser-storage/consent/verify",
            post(browser_storage_verify_consent),
        )
        .route(
            "/v1/browser-storage/session/verify",
            post(browser_storage_verify_session),
        )
        .route(
            "/v1/browser-storage/receipt/verify",
            post(browser_storage_verify_receipt),
        )
        .route(
            "/v1/browser-storage/sponsorship/verify",
            post(browser_storage_verify_sponsorship),
        )
        .route(
            "/v1/browser-storage/security/assess",
            post(browser_storage_security_assess),
        )
        .route(
            "/v1/browser-storage/security/verify",
            post(browser_storage_security_verify),
        )
        .route("/v1/policy/catalog", get(policy_catalog))
        .route("/v1/policy/inspect", post(policy_inspect))
        .route("/v1/policy/inspect-v2", post(policy_inspect_v2))
        .route("/v1/policy/privacy/tiers", get(policy_privacy_tiers))
        .route("/v1/policy/privacy/assess", post(policy_privacy_assess))
        .route("/v1/policy/trust", get(policy_trust_records))
        .route("/v1/policy/trust/local-only", post(policy_trust_local_only))
        .route(
            "/v1/policy/trust/open-marketplace",
            post(policy_trust_open_marketplace),
        )
        .route("/v1/policy/trust/sign", post(policy_trust_sign))
        .route("/v1/policy/trust/verify", post(policy_trust_verify))
        .route("/v1/policy/trust/{policy_id}", get(policy_trust_by_id))
        .route("/v1/receipts", get(receipts))
        .route("/v1/receipts/audit", get(receipts_audit))
        .route("/v1/receipts/batches", get(batch_receipts))
        .route("/v1/receipts/batches/audit", get(batch_receipts_audit))
        .route(
            "/v1/receipts/batches/{batch_receipt_id}",
            get(batch_receipt_by_id),
        )
        .route("/v1/receipts/verify", post(verify_receipt))
        .route("/v1/receipts/verify-v2", post(verify_receipt_v2))
        .route(
            "/v1/receipts/assess-correctness",
            post(assess_receipt_correctness),
        )
        .route("/v1/receipts/verify-batch", post(verify_batch_receipt))
        .route("/v1/receipts/verify-partial", post(verify_partial_receipt))
        .route(
            "/v1/receipts/verify-redaction",
            post(verify_redacted_receipt),
        )
        .route(
            "/v1/receipts/partials/{stream_key}",
            get(receipt_partials_by_stream_key),
        )
        .route("/v1/receipts/upload", post(upload_receipt))
        .route("/v1/receipts/download", post(download_receipt))
        .route("/v1/receipts/disputes", get(disputes))
        .route("/v1/receipts/dispute", post(create_dispute))
        .route("/v1/receipts/verify-dispute", post(verify_dispute))
        .route("/v1/receipts/disputes/{dispute_id}", get(dispute_by_id))
        .route(
            "/v1/receipts/{receipt_id}/redacted",
            get(receipt_redaction_by_id),
        )
        .route("/v1/receipts/{receipt_id}/v2", get(receipt_v2_by_id))
        .route("/v1/receipts/{receipt_id}", get(receipt_by_id))
        .route("/v1/observability/snapshot", get(operational_snapshot))
        .route("/v1/publisher/publications", get(publisher_publications))
        .route(
            "/v1/publisher/publications/{publication_id}",
            get(publisher_publication_by_id),
        )
        .route("/v1/publisher/verify", post(publisher_verify))
        .route("/v1/publisher/feeds", get(publisher_feeds))
        .route(
            "/v1/publisher/feeds/{*feed_key}",
            get(publisher_feed_by_key),
        )
        .route("/v1/publisher/feed/update", post(publisher_feed_update))
        .route("/v1/publisher/feed/resolve", post(publisher_feed_resolve))
        .route("/v1/validator/methods", get(validator_methods))
        .route("/v1/validator/reports", get(validator_reports))
        .route(
            "/v1/validator/integrity-evidence",
            get(validator_integrity_evidence).post(validator_create_integrity_evidence),
        )
        .route(
            "/v1/validator/integrity-evidence/{evidence_id}",
            get(validator_integrity_evidence_by_id),
        )
        .route(
            "/v1/validator/reports/{report_id}/v2",
            get(validator_report_v2_by_id),
        )
        .route(
            "/v1/validator/reports/{report_id}",
            get(validator_report_by_id),
        )
        .route(
            "/v1/validator/reputation",
            post(validator_reputation_profile),
        )
        .route(
            "/v1/validator/reputation/v2",
            post(validator_reputation_profile_v2),
        )
        .route("/v1/validator/verify-report", post(validator_verify_report))
        .route(
            "/v1/validator/verify-integrity-evidence",
            post(validator_verify_integrity_evidence),
        )
        .route("/v1/validator/upload-report", post(validator_upload_report))
        .route(
            "/v1/validator/download-report",
            post(validator_download_report),
        )
        .route("/v1/benchmarks/evaluations", get(benchmark_evaluations))
        .route(
            "/v1/benchmarks/evaluations-v2",
            get(benchmark_evaluations_v2),
        )
        .route(
            "/v1/benchmarks/evaluations-v2/from-v1",
            post(benchmark_create_evaluation_v2_from_v1),
        )
        .route("/v1/benchmarks/leaderboard", get(benchmark_leaderboard))
        .route("/v1/research/leaderboard", get(benchmark_leaderboard))
        .route("/v1/research/evaluations-v2", get(benchmark_evaluations_v2))
        .route(
            "/v1/research/evaluations-v2/from-v1",
            post(benchmark_create_evaluation_v2_from_v1),
        )
        .route(
            "/v1/benchmarks/challenge-commitments",
            get(benchmark_challenge_commitments).post(benchmark_create_challenge_commitment),
        )
        .route(
            "/v1/benchmarks/suites",
            get(benchmark_suites).post(benchmark_create_suite),
        )
        .route(
            "/v1/benchmarks/packs/from-suite",
            post(benchmark_pack_from_suite),
        )
        .route("/v1/benchmarks/verify-pack", post(benchmark_verify_pack))
        .route(
            "/v1/research/challenge-commitments",
            get(benchmark_challenge_commitments).post(benchmark_create_challenge_commitment),
        )
        .route(
            "/v1/research/benchmark-suites",
            get(benchmark_suites).post(benchmark_create_suite),
        )
        .route(
            "/v1/research/benchmark-packs/from-suite",
            post(benchmark_pack_from_suite),
        )
        .route(
            "/v1/research/verify-benchmark-pack",
            post(benchmark_verify_pack),
        )
        .route(
            "/v1/benchmarks/evaluations/{evaluation_id}",
            get(benchmark_evaluation_by_id),
        )
        .route(
            "/v1/benchmarks/evaluations/{evaluation_id}/v2",
            get(benchmark_evaluation_v1_as_v2_by_id),
        )
        .route(
            "/v1/benchmarks/evaluations-v2/{evaluation_id}",
            get(benchmark_evaluation_v2_by_id),
        )
        .route(
            "/v1/research/evaluations-v2/{evaluation_id}",
            get(benchmark_evaluation_v2_by_id),
        )
        .route(
            "/v1/benchmarks/suites/{suite_id}",
            get(benchmark_suite_by_id),
        )
        .route(
            "/v1/research/benchmark-suites/{suite_id}",
            get(benchmark_suite_by_id),
        )
        .route(
            "/v1/benchmarks/challenge-commitments/{commitment_id}",
            get(benchmark_challenge_commitment_by_id),
        )
        .route(
            "/v1/research/challenge-commitments/{commitment_id}",
            get(benchmark_challenge_commitment_by_id),
        )
        .route(
            "/v1/benchmarks/verify-evaluation",
            post(benchmark_verify_evaluation),
        )
        .route(
            "/v1/benchmarks/verify-evaluation-v2",
            post(benchmark_verify_evaluation_v2),
        )
        .route(
            "/v1/research/verify-evaluation-v2",
            post(benchmark_verify_evaluation_v2),
        )
        .route("/v1/benchmarks/verify-suite", post(benchmark_verify_suite))
        .route(
            "/v1/research/verify-benchmark-suite",
            post(benchmark_verify_suite),
        )
        .route(
            "/v1/benchmarks/verify-challenge-commitment",
            post(benchmark_verify_challenge_commitment),
        )
        .route(
            "/v1/research/verify-challenge-commitment",
            post(benchmark_verify_challenge_commitment),
        )
        .route("/v1/evals/verify-manifest", post(eval_verify_manifest))
        .route("/v1/evals/verify-run", post(eval_verify_run))
        .route("/v1/evals/plan", post(eval_plan))
        .route("/v1/evals/records", get(eval_records))
        .route("/v1/evals/records/{record_id}", get(eval_record_by_id))
        .route("/v1/miner/verify-profile", post(miner_verify_profile))
        .route("/v1/miner/verify-heartbeat", post(miner_verify_heartbeat))
        .route("/v1/miner/verify-benchmark", post(miner_verify_benchmark))
        .route("/v1/miner/onboarding-plan", post(miner_onboarding_plan))
        .route("/v1/miner/dashboard", post(miner_dashboard))
        .route("/v1/miner/records", get(miner_records))
        .route("/v1/miner/records/{record_id}", get(miner_record_by_id))
        .route(
            "/v1/research/verify-experiment",
            post(research_verify_experiment),
        )
        .route("/v1/research/reproduce", post(research_reproduce))
        .route(
            "/v1/research/runs",
            get(research_runs).post(research_create_run),
        )
        .route("/v1/research/verify-run", post(research_verify_run))
        .route("/v1/research/runs/{run_id}", get(research_run_by_id))
        .route(
            "/v1/research/verify-evaluation-run-v2",
            post(research_verify_evaluation_run_v2),
        )
        .route(
            "/v1/research/verify-result-record",
            post(research_verify_result_record),
        )
        .route(
            "/v1/research/reproducibility-bundles/from-experiment",
            post(research_create_reproducibility_bundle),
        )
        .route(
            "/v1/research/verify-reproducibility-bundle",
            post(research_verify_reproducibility_bundle),
        )
        .route("/v1/research/experiments", get(research_experiments))
        .route(
            "/v1/research/experiments/{experiment_id}",
            get(research_experiment_by_id),
        )
        .route("/v1/vector/verify-store", post(vector_verify_store))
        .route(
            "/v1/vector/verify-document-collection",
            post(vector_verify_document_collection),
        )
        .route("/v1/vector/verify-chunk-set", post(vector_verify_chunk_set))
        .route(
            "/v1/vector/verify-embedding-set",
            post(vector_verify_embedding_set),
        )
        .route("/v1/vector/verify-index-v2", post(vector_verify_index_v2))
        .route("/v1/vector/retrieval-plan", post(vector_retrieval_plan))
        .route(
            "/v1/vector/verify-rag-pipeline-v2",
            post(vector_verify_rag_pipeline_v2),
        )
        .route(
            "/v1/vector/verify-citation-trace",
            post(vector_verify_citation_trace),
        )
        .route("/v1/vector/search-plan", post(vector_search_plan))
        .route("/v1/vector/stores", get(vector_stores))
        .route(
            "/v1/vector/stores/{vector_store_id}",
            get(vector_store_by_id),
        )
        .route("/v1/workflows/verify-tool", post(workflow_verify_tool))
        .route(
            "/v1/workflows/verify-workflow",
            post(workflow_verify_workflow),
        )
        .route("/v1/workflows/plan", post(workflow_plan))
        .route("/v1/workflows/records", get(workflow_records))
        .route(
            "/v1/workflows/records/{record_id}",
            get(workflow_record_by_id),
        )
        .route("/v1/batch/verify-job", post(batch_verify_job))
        .route("/v1/batch/plan", post(batch_plan))
        .route("/v1/batch/jobs", get(batch_jobs))
        .route("/v1/batch/jobs/{batch_id}", get(batch_job_by_id))
        .route("/v1/fine-tune/verify-job", post(fine_tune_verify_job))
        .route("/v1/fine-tune/plan", post(fine_tune_plan))
        .route("/v1/fine-tune/jobs", get(fine_tune_jobs))
        .route(
            "/v1/fine-tune/jobs/{fine_tune_job_id}",
            get(fine_tune_job_by_id),
        )
        .route("/v1/realtime/verify-session", post(realtime_verify_session))
        .route("/v1/realtime/plan", post(realtime_plan))
        .route("/v1/realtime/native-sessions", get(realtime_sessions))
        .route(
            "/v1/realtime/native-sessions/{session_id}",
            get(realtime_session_by_id),
        )
        .route("/v1/media/verify-job", post(media_verify_job))
        .route("/v1/media/plan", post(media_plan))
        .route("/v1/media/jobs", get(media_jobs))
        .route("/v1/media/jobs/{media_job_id}", get(media_job_by_id))
        .route(
            "/v1/moderation/verify-policy",
            post(moderation_verify_policy),
        )
        .route(
            "/v1/moderation/verify-request",
            post(moderation_verify_request),
        )
        .route("/v1/moderation/plan", post(moderation_plan))
        .route("/v1/moderation/records", get(moderation_records))
        .route(
            "/v1/moderation/records/{record_id}",
            get(moderation_record_by_id),
        )
        .route(
            "/v1/governance/verify-policy",
            post(governance_verify_policy),
        )
        .route(
            "/v1/governance/verify-schema-release",
            post(governance_verify_schema_release),
        )
        .route(
            "/v1/governance/verify-advisory",
            post(governance_verify_advisory),
        )
        .route(
            "/v1/governance/verify-readiness",
            post(governance_verify_readiness),
        )
        .route(
            "/v1/governance/security-response-plan",
            post(governance_security_response_plan),
        )
        .route("/v1/governance/records", get(governance_records))
        .route(
            "/v1/governance/records/{record_id}",
            get(governance_record_by_id),
        )
        .route("/v1/browser/capabilities", get(browser_capabilities))
        .route("/v1/browser/assess", post(browser_assess))
        .route("/v1/browser/execute", post(browser_execute))
        .route("/v1/remote/capabilities", get(remote_capabilities))
        .route("/v1/remote/health", get(remote_health))
        .route("/v1/remote/prepare", post(remote_prepare))
        .route("/v1/remote/execute", post(remote_execute))
        .route("/v1/remote/cancel", post(remote_cancel))
        .route(
            "/v1/browser-swarm/descriptor",
            get(browser_swarm_descriptor),
        )
        .route("/v1/browser-swarm/status", get(browser_swarm_status))
        .route(
            "/v1/browser-swarm/compatibility",
            get(browser_swarm_compatibility),
        )
        .route("/v1/browser-swarm/file", post(browser_swarm_file))
        .route("/v1/browser-swarm/manifest", post(browser_swarm_manifest))
        .route("/v1/swarm-ai/capabilities", get(capabilities))
        .route("/v1/swarm-ai/errors/catalog", get(error_catalog))
        .route(
            "/v1/swarm-ai/compatibility/supported-schemas",
            get(compatibility_supported_schemas),
        )
        .route(
            "/v1/swarm-ai/compatibility/certify-package",
            post(compatibility_certify_package),
        )
        .route(
            "/v1/swarm-ai/compatibility/verify-certification",
            post(compatibility_verify_certification),
        )
        .route(
            "/v1/swarm-ai/compatibility/certifications",
            get(compatibility_certifications),
        )
        .route(
            "/v1/swarm-ai/compatibility/certifications/{certification_id}",
            get(compatibility_certification_by_id),
        )
        .route("/v1/swarm-ai/route", post(route))
        .route("/v1/swarm-ai/route-report", post(route_report))
        .route("/v1/swarm-ai/route-traces", get(route_traces))
        .route(
            "/v1/swarm-ai/route-traces/{request_id}",
            get(route_trace_by_request_id),
        )
        .route("/v1/swarm-ai/route-decisions", get(route_decisions))
        .route(
            "/v1/swarm-ai/route-decisions/{request_id}",
            get(route_decision_by_request_id),
        )
        .route(
            "/v1/swarm-ai/observability/snapshot",
            get(operational_snapshot),
        )
        .route("/v1/swarm-ai/execute", post(execute))
        .route("/v1/swarm-ai/ai/plan", post(hivemind_ai_plan))
        .route("/v1/swarm-ai/ai/workload", post(hivemind_ai_workload))
        .route(
            "/v1/swarm-ai/ai/task-envelope",
            post(hivemind_ai_task_envelope),
        )
        .route(
            "/v1/swarm-ai/storage/providers/v3",
            get(storage_providers_v3),
        )
        .route(
            "/v1/swarm-ai/storage/providers/v4",
            get(storage_providers_v4),
        )
        .route(
            "/v1/swarm-ai/browser-storage/providers",
            get(storage_providers_v3),
        )
        .route(
            "/v1/swarm-ai/browser-storage/providers/v4",
            get(storage_providers_v4),
        )
        .route(
            "/v1/swarm-ai/browser-storage/consent/verify",
            post(browser_storage_verify_consent),
        )
        .route(
            "/v1/swarm-ai/browser-storage/session/verify",
            post(browser_storage_verify_session),
        )
        .route(
            "/v1/swarm-ai/browser-storage/receipt/verify",
            post(browser_storage_verify_receipt),
        )
        .route(
            "/v1/swarm-ai/browser-storage/sponsorship/verify",
            post(browser_storage_verify_sponsorship),
        )
        .route(
            "/v1/swarm-ai/browser-storage/security/assess",
            post(browser_storage_security_assess),
        )
        .route(
            "/v1/swarm-ai/browser-storage/security/verify",
            post(browser_storage_security_verify),
        )
        .route(
            "/v1/swarm-ai/access/sign-grant-v2",
            post(sign_access_grant_v2),
        )
        .route(
            "/v1/swarm-ai/access/verify-grant-v2",
            post(verify_access_grant_v2),
        )
        .route(
            "/v1/swarm-ai/access/sign-grant-v3",
            post(sign_access_grant_v3),
        )
        .route(
            "/v1/swarm-ai/access/verify-grant-v3",
            post(verify_access_grant_v3),
        )
        .route(
            "/v1/swarm-ai/access/policy/project-v2",
            post(project_access_policy_v2),
        )
        .route(
            "/v1/swarm-ai/access/policy/verify-v2",
            post(verify_access_policy_v2),
        )
        .route(
            "/v1/swarm-ai/access/request-paid-access",
            post(request_paid_access),
        )
        .route(
            "/v1/swarm-ai/access/attach-grant-to-job",
            post(attach_access_grant_to_job),
        )
        .route(
            "/v1/swarm-ai/ai/verify-request",
            post(hivemind_ai_verify_request),
        )
        .route(
            "/v1/swarm-ai/ai/sign-request",
            post(hivemind_ai_sign_request),
        )
        .route(
            "/v1/swarm-ai/ai/verify-response",
            post(hivemind_ai_verify_response),
        )
        .route(
            "/v1/swarm-ai/ai/sign-response",
            post(hivemind_ai_sign_response),
        )
        .route("/v1/swarm-ai/ai", post(hivemind_ai_execute))
        .route("/v1/swarm-ai/jobs", get(hivemind_jobs))
        .route("/v1/swarm-ai/jobs/{job_id}", get(hivemind_job_by_id))
        .route(
            "/v1/swarm-ai/jobs/{job_id}/timeline",
            get(hivemind_job_timeline),
        )
        .route(
            "/v1/swarm-ai/jobs/{job_id}/lifecycle",
            get(hivemind_job_lifecycle),
        )
        .route(
            "/v1/swarm-ai/jobs/{job_id}/evidence",
            post(hivemind_link_job_evidence),
        )
        .route("/v1/swarm-ai/jobs/audit", post(hivemind_audit_jobs))
        .route(
            "/v1/swarm-ai/jobs/lifecycle-audit",
            post(hivemind_audit_job_lifecycles),
        )
        .route("/v1/swarm-ai/jobs/expire", post(hivemind_expire_jobs))
        .route("/v1/swarm-ai/jobs/quote", post(swarm_ai_job_quote))
        .route("/v1/swarm-ai/jobs/lease", post(hivemind_lease))
        .route(
            "/v1/swarm-ai/jobs/{job_id}/cancel",
            post(hivemind_cancel_job),
        )
        .route(
            "/v1/swarm-ai/jobs/{job_id}/stream",
            get(hivemind_job_stream),
        )
        .route(
            "/v1/swarm-ai/jobs/{job_id}/partial-receipts",
            get(hivemind_job_partial_receipts),
        )
        .route("/v1/swarm-ai/receipts", get(receipts))
        .route("/v1/swarm-ai/receipts/audit", get(receipts_audit))
        .route("/v1/swarm-ai/receipts/verify-v2", post(verify_receipt_v2))
        .route(
            "/v1/swarm-ai/receipts/assess-correctness",
            post(assess_receipt_correctness),
        )
        .route("/v1/swarm-ai/receipts/batches", get(batch_receipts))
        .route(
            "/v1/swarm-ai/receipts/batches/audit",
            get(batch_receipts_audit),
        )
        .route(
            "/v1/swarm-ai/receipts/batches/{batch_receipt_id}",
            get(batch_receipt_by_id),
        )
        .route(
            "/v1/swarm-ai/receipts/partials/{stream_key}",
            get(receipt_partials_by_stream_key),
        )
        .route(
            "/v1/swarm-ai/receipt/{receipt_id}/v2",
            get(receipt_v2_by_id),
        )
        .route(
            "/v1/swarm-ai/receipt/{receipt_id}/redacted",
            get(receipt_redaction_by_id),
        )
        .route("/v1/swarm-ai/receipt/{receipt_id}", get(receipt_by_id))
        .route("/v1/swarm-ai/cache", get(local_runner_cache))
        .route(
            "/v1/swarm-ai/cache/{*package_ref}",
            delete(clear_local_runner_cache),
        )
        .route("/v1/chat/completions", post(openai_chat_completions))
        .route("/v1/responses", post(openai_responses))
        .route("/v1/anthropic/messages", post(anthropic_messages))
        .route("/v1/gemini/generateContent", post(gemini_generate_content))
        .route(
            "/v1/gemini/generateContent/{*model_id}",
            post(gemini_generate_content_for_model),
        )
        .route(
            "/v1/gemini/live/sessions",
            post(gemini_live_sessions_create),
        )
        .route(
            "/v1/gemini/live/sessions/{session_id}",
            get(gemini_live_session_by_id),
        )
        .route("/v1/huggingface/inference", post(huggingface_inference))
        .route(
            "/v1/huggingface/inference/{*model_id}",
            post(huggingface_inference_for_model),
        )
        .route("/v1/files", post(openai_files_create))
        .route("/v1/files/{file_id}", get(openai_file_by_id))
        .route("/v1/batches", post(openai_batches_create))
        .route("/v1/batches/{batch_id}", get(openai_batch_by_id))
        .route("/v1/fine_tuning/jobs", post(openai_fine_tuning_jobs_create))
        .route(
            "/v1/fine_tuning/jobs/{fine_tune_job_id}",
            get(openai_fine_tuning_job_by_id),
        )
        .route(
            "/v1/realtime/sessions",
            post(openai_realtime_sessions_create),
        )
        .route(
            "/v1/realtime/sessions/{session_id}",
            get(openai_realtime_session_by_id),
        )
        .route("/v1/evals", post(openai_evals_create))
        .route("/v1/evals/{eval_id}", get(openai_eval_by_id))
        .route("/v1/evals/{eval_id}/runs", post(openai_eval_runs_create))
        .route(
            "/v1/evals/{eval_id}/runs/{eval_run_id}",
            get(openai_eval_run_by_id),
        )
        .route("/v1/images/generations", post(openai_images_generations))
        .route("/v1/images/edits", post(openai_images_edits))
        .route(
            "/v1/audio/transcriptions",
            post(openai_audio_transcriptions),
        )
        .route("/v1/audio/speech", post(openai_audio_speech))
        .route("/v1/vector_stores", post(openai_vector_stores_create))
        .route(
            "/v1/vector_stores/{vector_store_id}",
            get(openai_vector_store_by_id),
        )
        .route(
            "/v1/vector_stores/{vector_store_id}/search",
            post(openai_vector_store_search),
        )
        .route("/v1/models", get(openai_models))
        .route("/v1/models/{*model_id}", get(openai_model_by_id))
        .route("/v1/embeddings", post(openai_embeddings))
        .route("/v1/moderations", post(openai_moderations))
        .route("/v1/hivemind/resolve", post(hivemind_resolve))
        .route("/v1/hivemind/errors/catalog", get(error_catalog))
        .route(
            "/v1/hivemind/compatibility/supported-schemas",
            get(compatibility_supported_schemas),
        )
        .route(
            "/v1/hivemind/compatibility/certify-package",
            post(compatibility_certify_package),
        )
        .route(
            "/v1/hivemind/compatibility/verify-certification",
            post(compatibility_verify_certification),
        )
        .route(
            "/v1/hivemind/compatibility/certifications",
            get(compatibility_certifications),
        )
        .route(
            "/v1/hivemind/compatibility/certifications/{certification_id}",
            get(compatibility_certification_by_id),
        )
        .route("/v1/hivemind/ai/plan", post(hivemind_ai_plan))
        .route("/v1/hivemind/ai/workload", post(hivemind_ai_workload))
        .route(
            "/v1/hivemind/ai/task-envelope",
            post(hivemind_ai_task_envelope),
        )
        .route(
            "/v1/hivemind/storage/providers/v3",
            get(storage_providers_v3),
        )
        .route(
            "/v1/hivemind/storage/providers/v4",
            get(storage_providers_v4),
        )
        .route(
            "/v1/hivemind/browser-storage/providers",
            get(storage_providers_v3),
        )
        .route(
            "/v1/hivemind/browser-storage/providers/v4",
            get(storage_providers_v4),
        )
        .route(
            "/v1/hivemind/browser-storage/consent/verify",
            post(browser_storage_verify_consent),
        )
        .route(
            "/v1/hivemind/browser-storage/session/verify",
            post(browser_storage_verify_session),
        )
        .route(
            "/v1/hivemind/browser-storage/receipt/verify",
            post(browser_storage_verify_receipt),
        )
        .route(
            "/v1/hivemind/browser-storage/sponsorship/verify",
            post(browser_storage_verify_sponsorship),
        )
        .route(
            "/v1/hivemind/browser-storage/security/assess",
            post(browser_storage_security_assess),
        )
        .route(
            "/v1/hivemind/browser-storage/security/verify",
            post(browser_storage_security_verify),
        )
        .route(
            "/v1/hivemind/access/sign-grant-v2",
            post(sign_access_grant_v2),
        )
        .route(
            "/v1/hivemind/access/verify-grant-v2",
            post(verify_access_grant_v2),
        )
        .route(
            "/v1/hivemind/access/sign-grant-v3",
            post(sign_access_grant_v3),
        )
        .route(
            "/v1/hivemind/access/verify-grant-v3",
            post(verify_access_grant_v3),
        )
        .route(
            "/v1/hivemind/access/policy/project-v2",
            post(project_access_policy_v2),
        )
        .route(
            "/v1/hivemind/access/policy/verify-v2",
            post(verify_access_policy_v2),
        )
        .route(
            "/v1/hivemind/access/request-paid-access",
            post(request_paid_access),
        )
        .route(
            "/v1/hivemind/access/attach-grant-to-job",
            post(attach_access_grant_to_job),
        )
        .route(
            "/v1/hivemind/ai/verify-request",
            post(hivemind_ai_verify_request),
        )
        .route(
            "/v1/hivemind/ai/sign-request",
            post(hivemind_ai_sign_request),
        )
        .route(
            "/v1/hivemind/ai/verify-response",
            post(hivemind_ai_verify_response),
        )
        .route(
            "/v1/hivemind/ai/sign-response",
            post(hivemind_ai_sign_response),
        )
        .route("/v1/hivemind/ai", post(hivemind_ai_execute))
        .route(
            "/v1/hivemind/policy/evaluate",
            post(hivemind_policy_evaluate),
        )
        .route("/v1/hivemind/packages", get(hivemind_packages))
        .route("/v1/hivemind/runners/v2", get(hivemind_runners_v2))
        .route("/v1/hivemind/runners", get(hivemind_runners))
        .route("/v1/hivemind/route-traces", get(route_traces))
        .route(
            "/v1/hivemind/route-traces/{request_id}",
            get(route_trace_by_request_id),
        )
        .route("/v1/hivemind/route-decisions", get(route_decisions))
        .route(
            "/v1/hivemind/route-decisions/{request_id}",
            get(route_decision_by_request_id),
        )
        .route(
            "/v1/hivemind/observability/snapshot",
            get(operational_snapshot),
        )
        .route(
            "/v1/hivemind/jobs",
            get(hivemind_jobs).post(hivemind_create_job),
        )
        .route("/v1/hivemind/jobs/{job_id}", get(hivemind_job_by_id))
        .route(
            "/v1/hivemind/jobs/{job_id}/timeline",
            get(hivemind_job_timeline),
        )
        .route(
            "/v1/hivemind/jobs/{job_id}/lifecycle",
            get(hivemind_job_lifecycle),
        )
        .route(
            "/v1/hivemind/jobs/{job_id}/evidence",
            post(hivemind_link_job_evidence),
        )
        .route("/v1/hivemind/jobs/audit", post(hivemind_audit_jobs))
        .route(
            "/v1/hivemind/jobs/lifecycle-audit",
            post(hivemind_audit_job_lifecycles),
        )
        .route("/v1/hivemind/jobs/expire", post(hivemind_expire_jobs))
        .route(
            "/v1/hivemind/jobs/{job_id}/quotes",
            post(hivemind_job_quotes),
        )
        .route("/v1/hivemind/leases", post(hivemind_lease))
        .route(
            "/v1/hivemind/jobs/{job_id}/cancel",
            post(hivemind_cancel_job),
        )
        .route(
            "/v1/hivemind/jobs/{job_id}/stream",
            get(hivemind_job_stream),
        )
        .route(
            "/v1/hivemind/jobs/{job_id}/partial-receipts",
            get(hivemind_job_partial_receipts),
        )
        .route("/v1/hivemind/receipts", get(receipts))
        .route("/v1/hivemind/receipts/audit", get(receipts_audit))
        .route("/v1/hivemind/receipts/verify-v2", post(verify_receipt_v2))
        .route(
            "/v1/hivemind/receipts/assess-correctness",
            post(assess_receipt_correctness),
        )
        .route("/v1/hivemind/receipts/batches", get(batch_receipts))
        .route(
            "/v1/hivemind/receipts/batches/audit",
            get(batch_receipts_audit),
        )
        .route(
            "/v1/hivemind/receipts/batches/{batch_receipt_id}",
            get(batch_receipt_by_id),
        )
        .route(
            "/v1/hivemind/receipts/partials/{stream_key}",
            get(receipt_partials_by_stream_key),
        )
        .route(
            "/v1/hivemind/receipts/{receipt_id}/v2",
            get(receipt_v2_by_id),
        )
        .route(
            "/v1/hivemind/receipts/{receipt_id}/redacted",
            get(receipt_redaction_by_id),
        )
        .route("/v1/hivemind/receipts/{receipt_id}", get(receipt_by_id))
        .route(
            "/v1/hivemind/validations/{report_id}",
            get(hivemind_validation_by_id),
        )
        .route("/v1/hivemind/validator/methods", get(validator_methods))
        .route(
            "/v1/hivemind/validations/{report_id}/v2",
            get(validator_report_v2_by_id),
        )
        .route(
            "/v1/hivemind/integrity-evidence",
            get(validator_integrity_evidence).post(validator_create_integrity_evidence),
        )
        .route(
            "/v1/hivemind/integrity-evidence/{evidence_id}",
            get(validator_integrity_evidence_by_id),
        )
        .route(
            "/v1/hivemind/verify-integrity-evidence",
            post(validator_verify_integrity_evidence),
        )
        .route(
            "/v1/hivemind/marketplace/listings",
            get(hivemind_marketplace_listings),
        )
        .route(
            "/v1/hivemind/marketplace/listings/v2",
            get(hivemind_marketplace_listings_v2),
        )
        .route("/v1/marketplace/listings", get(marketplace_listings))
        .route("/v1/marketplace/listings/v2", get(marketplace_listings_v2))
        .route(
            "/v1/marketplace/listing/project-v2",
            post(marketplace_project_listing_v2),
        )
        .route(
            "/v1/marketplace/verify-listing",
            post(marketplace_verify_listing),
        )
        .route(
            "/v1/marketplace/verify-listing-v2",
            post(marketplace_verify_listing_v2),
        )
        .route("/v1/marketplace/offers", get(marketplace_offers))
        .route(
            "/v1/marketplace/hardware-offers",
            get(marketplace_hardware_offers),
        )
        .route("/v1/marketplace/shortlist", post(marketplace_shortlist))
        .route(
            "/v1/marketplace/verify-offer",
            post(marketplace_verify_offer),
        )
        .route(
            "/v1/marketplace/verify-hardware-offer",
            post(marketplace_verify_hardware_offer),
        )
        .route("/v1/marketplace/quote", post(marketplace_quote))
        .route("/v1/marketplace/quotes", get(marketplace_quotes))
        .route(
            "/v1/marketplace/quotes/{quote_id}",
            get(marketplace_service_quote_by_id),
        )
        .route(
            "/v1/marketplace/verify-quote",
            post(marketplace_verify_quote),
        )
        .route(
            "/v1/marketplace/authorize-payment",
            post(marketplace_authorize_payment),
        )
        .route(
            "/v1/marketplace/verify-payment",
            post(marketplace_verify_payment),
        )
        .route("/v1/marketplace/payments", get(marketplace_payments))
        .route(
            "/v1/marketplace/payments/{authorization_id}",
            get(marketplace_payment_by_id),
        )
        .route(
            "/v1/marketplace/create-escrow",
            post(marketplace_create_escrow),
        )
        .route(
            "/v1/marketplace/verify-escrow",
            post(marketplace_verify_escrow),
        )
        .route(
            "/v1/marketplace/release-escrow",
            post(marketplace_release_escrow),
        )
        .route("/v1/marketplace/escrows", get(marketplace_escrows))
        .route(
            "/v1/marketplace/escrows/{escrow_id}",
            get(marketplace_escrow_by_id),
        )
        .route("/v1/marketplace/audit", get(marketplace_audit))
        .route(
            "/v1/marketplace/settlements/{settlement_id}",
            get(marketplace_settlement_by_id),
        )
        .route(
            "/v1/marketplace/resolutions/{resolution_id}",
            get(marketplace_resolution_by_id),
        )
        .route("/v1/marketplace/settle", post(marketplace_settle))
        .route(
            "/v1/marketplace/verify-settlement",
            post(marketplace_verify_settlement),
        )
        .route(
            "/v1/marketplace/dispute-settlement",
            post(marketplace_dispute_settlement),
        )
        .route(
            "/v1/marketplace/refund-settlement",
            post(marketplace_refund_settlement),
        )
        .route(
            "/v1/marketplace/reject-dispute",
            post(marketplace_reject_dispute),
        )
        .route(
            "/v1/marketplace/refund-record",
            post(marketplace_refund_record),
        )
        .route(
            "/v1/marketplace/verify-refund-record",
            post(marketplace_verify_refund_record),
        )
        .route("/v1/marketplace/refunds", get(marketplace_refunds))
        .route(
            "/v1/marketplace/refunds/{refund_id}",
            get(marketplace_refund_by_id),
        )
        .route("/v1/marketplace/slash", post(marketplace_slash))
        .route(
            "/v1/marketplace/verify-slashing",
            post(marketplace_verify_slashing),
        )
        .route(
            "/v1/marketplace/verify-resolution",
            post(marketplace_verify_resolution),
        )
        .fallback_service(ServeDir::new(static_dir).append_index_html_on_directories(true))
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        interface_version: INTERFACE_VERSION,
        packages: state.packages.len(),
    })
}

async fn error_catalog() -> Json<hivemind_core::StandardErrorCatalogV1> {
    Json(hivemind_core::standard_error_catalog())
}

async fn validate_manifest(
    State(state): State<AppState>,
    Json(value): Json<Value>,
) -> Json<hivemind_core::ValidationReport> {
    let (report, audit_record) =
        hivemind_package::validate_manifest_value_with_audit(&value, "api:/v1/packages/validate");
    if let Err(error) = hivemind_package::write_package_validation_audit_record(
        &state.package_audit_dir,
        &audit_record,
    ) {
        warn!("failed to write package validation audit record: {error}");
    }
    Json(report)
}

async fn project_package_manifest_v2(
    Json(manifest): Json<hivemind_core::PackageManifestV1>,
) -> Json<hivemind_core::PackageManifestV2> {
    Json(hivemind_core::package_manifest_v2_from_v1(&manifest))
}

async fn project_package_manifest_v3(
    Json(manifest): Json<hivemind_core::PackageManifestV1>,
) -> Json<hivemind_core::PackageManifestV3> {
    Json(hivemind_core::package_manifest_v3_from_v1(&manifest))
}

async fn project_package_manifest_v4(
    Json(manifest): Json<hivemind_core::PackageManifestV1>,
) -> Json<hivemind_core::PackageManifestV4> {
    Json(hivemind_core::package_manifest_v4_from_v1(&manifest))
}

async fn hivemind_ai_workload(Json(request): Json<AiRequestV1>) -> Json<Value> {
    let workload = ai_workload_from_ai_request(&request);
    let verification = verify_ai_workload(&workload);
    Json(json!({
        "schemaVersion": "hivemind.ai-workload-projection.v1",
        "workload": workload,
        "verification": verification
    }))
}

async fn hivemind_ai_task_envelope(Json(request): Json<AiRequestV1>) -> Json<Value> {
    let task_envelope = task_envelope_from_ai_request(&request);
    let verification = verify_task_envelope(&task_envelope);
    Json(json!({
        "schemaVersion": "hivemind.task-envelope-projection.v1",
        "taskEnvelope": task_envelope,
        "verification": verification
    }))
}

async fn compatibility_supported_schemas() -> Json<Value> {
    Json(json!({
        "schemaVersion": "swarm-ai.compatibility-supported-schemas.v1",
        "supportedSchemas": hivemind_sdk::package_certification_supported_schemas()
    }))
}

async fn compatibility_certify_package(
    State(state): State<AppState>,
    Json(request): Json<CompatibilityPackageCertificationRequest>,
) -> impl IntoResponse {
    match compatibility_certification_response(&state, request) {
        Ok(response) => (StatusCode::OK, Json(json!(response))).into_response(),
        Err((status, error)) => (status, Json(json!(error))).into_response(),
    }
}

async fn compatibility_verify_certification(
    Json(request): Json<CompatibilityCertificationVerificationRequest>,
) -> Json<hivemind_sdk::SdkVerificationV1> {
    let _schema_version = request.schema_version.as_deref();
    Json(hivemind_sdk::verify_compatibility_certification(
        &request.certification,
        request.expected_signer.as_deref(),
    ))
}

async fn compatibility_certifications(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_sdk::list_compatibility_certifications(&state.compatibility_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list compatibility certifications: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn compatibility_certification_by_id(
    State(state): State<AppState>,
    Path(certification_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_sdk::get_compatibility_certification(&state.compatibility_dir, &certification_id)
    {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Compatibility certification was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read compatibility certification: {error}"),
            )),
        )
            .into_response(),
    }
}

fn compatibility_certification_response(
    state: &AppState,
    request: CompatibilityPackageCertificationRequest,
) -> Result<CompatibilityPackageCertificationResponse, (StatusCode, Value)> {
    let _schema_version = request.schema_version.as_deref();
    let package_ref = request.package_ref.as_deref().unwrap_or_default().trim();
    let package_id = request.package_id.as_deref().unwrap_or_default().trim();
    if package_ref.is_empty() && package_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            json_error(
                ErrorCode::InvalidRequest,
                "compatibility certification requires packageRef or packageId",
            ),
        ));
    }

    let Some(indexed) = find_package(&state.packages, package_ref, package_id) else {
        return Err((
            StatusCode::NOT_FOUND,
            json_error(
                ErrorCode::PackageNotFound,
                "Package is not in the local registry",
            ),
        ));
    };

    let resolved_ref = if package_ref.is_empty() {
        indexed
            .entry
            .package_refs
            .first()
            .map(|reference| reference.package_ref.clone())
            .unwrap_or_else(|| indexed.package.package_ref.clone())
    } else {
        package_ref.to_string()
    };
    let package = package_for_request(indexed, &resolved_ref);
    if package.root.as_os_str().is_empty() || !package.root.exists() {
        return Err((
            StatusCode::BAD_REQUEST,
            json_error(
                ErrorCode::InvalidRequest,
                "The selected package does not have a readable local package root",
            ),
        ));
    }

    let report = hivemind_sdk::certify_package_dir(&package.root).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            json_error(
                ErrorCode::InvalidManifest,
                &format!("Failed to certify package: {error}"),
            ),
        )
    })?;

    let mut certification = None;
    let mut verification = None;
    let mut store = None;
    if let Some(identity) = request.identity {
        let mut declared_schemas = hivemind_sdk::package_certification_supported_schemas();
        declared_schemas.extend(request.supported_schemas);
        let mut signed = hivemind_sdk::compatibility_certification_from_report(
            &report,
            request.component_type,
            request
                .implementation_name
                .unwrap_or_else(|| package.manifest.package_id.clone()),
            request
                .component_version
                .unwrap_or_else(|| package.manifest.version.clone()),
            declared_schemas,
            request.warnings,
        );
        hivemind_sdk::sign_compatibility_certification(&mut signed, &identity).map_err(
            |error| {
                (
                    StatusCode::BAD_REQUEST,
                    json_error(
                        ErrorCode::InvalidRequest,
                        &format!("Failed to sign compatibility certification: {error}"),
                    ),
                )
            },
        )?;
        let signed_verification = hivemind_sdk::verify_compatibility_certification(
            &signed,
            Some(identity.subject.as_str()),
        );
        if request.store {
            if !signed_verification.valid {
                return Err((
                    StatusCode::BAD_REQUEST,
                    json_error(
                        ErrorCode::InvalidRequest,
                        "Signed compatibility certification failed verification and was not stored",
                    ),
                ));
            }
            store = Some(
                hivemind_sdk::write_compatibility_certification(&state.compatibility_dir, &signed)
                    .map_err(|error| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            json_error(
                                ErrorCode::ExecutionFailed,
                                &format!("Failed to store compatibility certification: {error}"),
                            ),
                        )
                    })?,
            );
        }
        certification = Some(signed);
        verification = Some(signed_verification);
    }

    Ok(CompatibilityPackageCertificationResponse {
        schema_version: "swarm-ai.compatibility-package-certification-response.v1".to_string(),
        package_id: package.manifest.package_id,
        package_ref: resolved_ref,
        package_root: package.root.display().to_string(),
        report,
        certification,
        verification,
        store,
    })
}

async fn project_access_policy(
    Json(request): Json<AccessPolicyProjectRequest>,
) -> Json<hivemind_core::AccessPolicyV1> {
    Json(
        hivemind_core::access_policy_from_license_policy_with_context(
            &request.license_policy,
            request.context,
        ),
    )
}

async fn verify_access_policy(
    Json(policy): Json<hivemind_core::AccessPolicyV1>,
) -> Json<hivemind_core::AccessPolicyVerificationV1> {
    Json(hivemind_core::verify_access_policy(&policy))
}

async fn project_access_policy_v2(
    Json(request): Json<AccessPolicyProjectRequest>,
) -> Json<hivemind_core::AccessPolicyV2> {
    Json(
        hivemind_core::access_policy_v2_from_license_policy_with_context(
            &request.license_policy,
            request.context,
        ),
    )
}

async fn verify_access_policy_v2(
    Json(policy): Json<hivemind_core::AccessPolicyV2>,
) -> Json<hivemind_core::AccessPolicyV2VerificationV1> {
    Json(hivemind_core::verify_access_policy_v2(&policy))
}

async fn request_paid_access(Json(request): Json<RequestPaidAccessRequest>) -> impl IntoResponse {
    let listing_verification =
        hivemind_marketplace::verify_marketplace_listing_v2(&request.listing);
    if !listing_verification.valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                "Marketplace listing v2 is not valid for paid access",
            )),
        )
            .into_response();
    }
    let policy = match access_policy_v2_for_marketplace_listing(&request.listing) {
        Ok(policy) => policy,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json_error(ErrorCode::InvalidRequest, &error)),
            )
                .into_response();
        }
    };
    let listing_ref = Some(format!(
        "local://marketplace/listings/{}",
        request.listing.listing_id
    ));
    let requester = request.requester;
    let requested_use = request
        .requested_use
        .unwrap_or_else(|| requested_use_for_marketplace_listing(&request.listing).to_string());
    let asset_ref = request
        .asset_ref
        .or_else(|| Some(request.listing.subject.subject_ref.clone()));
    let amount = request
        .amount
        .or(Some(request.listing.price_model.base_price));
    let currency = request
        .currency
        .or_else(|| Some(request.listing.price_model.currency.clone()));
    let expires_at = request
        .expires_at
        .or_else(|| request.listing.expires_at.clone());
    let evidence_refs = request.listing.evidence_refs.clone();
    let quote = hivemind_core::paid_access_quote_with_listing_ref(
        &policy,
        requester,
        requested_use,
        asset_ref,
        amount,
        currency,
        expires_at,
        listing_ref,
        evidence_refs,
    );
    (StatusCode::OK, Json(json!(quote))).into_response()
}

async fn attach_access_grant_to_job(
    Json(request): Json<AttachAccessGrantToJobRequest>,
) -> Json<hivemind_core::JobAccessAttachmentV1> {
    Json(hivemind_core::attach_access_grant_v2_to_job_order(
        &request.job_order,
        &request.grant,
    ))
}

async fn verify_access_grant(
    Json(grant): Json<hivemind_core::AccessGrantV1>,
) -> Json<hivemind_access::AccessGrantVerificationV1> {
    Json(hivemind_access::verify_access_grant(&grant))
}

async fn sign_access_grant_v2(
    Json(mut grant): Json<hivemind_core::AccessGrantV2>,
) -> impl IntoResponse {
    match hivemind_access::sign_access_grant_v2(&mut grant) {
        Ok(_) => (StatusCode::OK, Json(json!(grant))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to sign access grant v2: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn verify_access_grant_v2(
    Json(grant): Json<hivemind_core::AccessGrantV2>,
) -> Json<hivemind_access::AccessGrantV2VerificationV1> {
    Json(hivemind_access::verify_access_grant_v2(&grant))
}

async fn sign_access_grant_v3(
    Json(mut grant): Json<hivemind_core::AccessGrantV3>,
) -> impl IntoResponse {
    match hivemind_access::sign_access_grant_v3(&mut grant) {
        Ok(_) => (StatusCode::OK, Json(json!(grant))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to sign access grant v3: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn verify_access_grant_v3(
    Json(grant): Json<hivemind_core::AccessGrantV3>,
) -> Json<hivemind_access::AccessGrantV3VerificationV1> {
    Json(hivemind_access::verify_access_grant_v3(&grant))
}

async fn access_grants(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_access::list_access_grants(state.access_grant_dir.as_ref().as_path()) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list access grants: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn access_grant_by_id(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_access::get_access_grant(state.access_grant_dir.as_ref().as_path(), &grant_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Access grant was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read access grant: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn revoke_access_grant(
    State(state): State<AppState>,
    Json(request): Json<RevokeAccessGrantRequest>,
) -> impl IntoResponse {
    let revocation =
        hivemind_access::revoke_access_grant(&request.grant, request.revoked_by, request.reason);
    let verification =
        hivemind_access::verify_access_grant_revocation(&revocation, Some(&request.grant));
    if verification.valid
        && let Err(error) = hivemind_access::write_access_grant_revocation(
            state.access_revocation_dir.as_ref().as_path(),
            &revocation,
        )
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to store access revocation: {error}"),
            )),
        )
            .into_response();
    }
    (
        StatusCode::OK,
        Json(json!(RevokeAccessGrantResponse {
            revocation,
            verification,
        })),
    )
        .into_response()
}

async fn access_revocations(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_access::list_access_grant_revocations(
        state.access_revocation_dir.as_ref().as_path(),
    ) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list access revocations: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn access_revocation_by_id(
    State(state): State<AppState>,
    Path(revocation_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_access::get_access_grant_revocation(
        state.access_revocation_dir.as_ref().as_path(),
        &revocation_id,
    ) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Access revocation was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read access revocation: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn verify_access_revocation(
    Json(request): Json<VerifyAccessRevocationRequest>,
) -> Json<hivemind_access::AccessGrantRevocationVerificationV1> {
    Json(hivemind_access::verify_access_grant_revocation(
        &request.revocation,
        request.grant.as_ref(),
    ))
}

async fn verify_access_revocation_list(
    Json(revocation_list): Json<hivemind_core::AccessRevocationListV1>,
) -> Json<hivemind_access::AccessRevocationListVerificationV1> {
    Json(hivemind_access::verify_access_revocation_list(
        &revocation_list,
    ))
}

async fn search(
    State(state): State<AppState>,
    Json(query): Json<RegistryQueryV1>,
) -> Json<RegistrySearchResponse> {
    let requested_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let started = Instant::now();
    let response = search_registry(&state.packages, &query);
    let elapsed_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    let completed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let audit_record = hivemind_registry::registry_search_audit_record(
        &query,
        &response,
        hivemind_registry::RegistrySearchRetrievalModeV1::LocalCache,
        state.packages.len(),
        elapsed_ms,
        requested_at,
        completed_at,
    );
    if let Err(error) = hivemind_registry::write_registry_search_audit_record(
        &state.registry_audit_dir,
        &audit_record,
    ) {
        warn!("failed to write registry search audit record: {error}");
    }
    Json(response)
}

async fn registry_package_by_id(
    State(state): State<AppState>,
    Path(package_id): Path<String>,
) -> impl IntoResponse {
    let package_id = package_id.trim_start_matches('/');
    match registry_package_lookup(&state.packages, &state.registry_snapshot, "", package_id) {
        Some(lookup) if lookup.entry.license.license_type != LicenseType::Private => {
            (StatusCode::OK, Json(json!(lookup))).into_response()
        }
        Some(_) | None => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Package is not in the public registry",
            )),
        )
            .into_response(),
    }
}

async fn registry_package_request(
    State(state): State<AppState>,
    Json(request): Json<hivemind_registry::RegistryPackageLookupRequestV1>,
) -> impl IntoResponse {
    match registry_package_lookup_for_request(&state.packages, &state.registry_snapshot, &request) {
        Some(lookup) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Package is not in the registry or is not authorized",
            )),
        )
            .into_response(),
    }
}

async fn registry_snapshot(State(state): State<AppState>) -> Json<RegistrySnapshotV1> {
    Json(public_registry_snapshot(&state.registry_snapshot))
}

async fn registry_snapshot_verification(
    State(state): State<AppState>,
) -> Json<hivemind_registry::RegistrySnapshotVerificationV1> {
    let public = public_registry_snapshot(&state.registry_snapshot);
    Json(hivemind_registry::verify_registry_snapshot(&public))
}

async fn registry_snapshot_verify(
    Json(snapshot): Json<RegistrySnapshotV1>,
) -> Json<hivemind_registry::RegistrySnapshotVerificationV1> {
    Json(hivemind_registry::verify_registry_snapshot(&snapshot))
}

async fn hivemind_packages(
    State(state): State<AppState>,
    Query(query): Query<HivemindPackagesQuery>,
) -> Json<RegistrySearchResponse> {
    let public = public_registry_snapshot(&state.registry_snapshot);
    let mut entries: Vec<_> = public
        .entries
        .into_iter()
        .filter(|entry| registry_entry_matches_package_query(entry, &query))
        .collect();
    entries.sort_by(|left, right| left.package_id.cmp(&right.package_id));

    let start = query
        .cursor
        .as_deref()
        .and_then(|cursor| cursor.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let page_size = query.page_size.unwrap_or(100).clamp(1, 100);
    let total = entries.len();
    let entries: Vec<_> = entries.into_iter().skip(start).take(page_size).collect();
    let next_cursor = (start + entries.len() < total).then(|| (start + entries.len()).to_string());

    Json(RegistrySearchResponse {
        schema_version: "swarm-ai.registry.search.response.v1".to_string(),
        entries,
        next_cursor,
        total_approx: total,
    })
}

async fn registry_shards(
    State(state): State<AppState>,
) -> Json<Vec<hivemind_registry::RegistryShardV1>> {
    let public = public_registry_snapshot(&state.registry_snapshot);
    Json(build_registry_shards(&public))
}

async fn registry_shards_manifest(
    State(state): State<AppState>,
) -> Json<hivemind_registry::RegistryShardManifestV1> {
    let public = public_registry_snapshot(&state.registry_snapshot);
    let shards = build_registry_shards(&public);
    Json(registry_shard_manifest_for_shards(&public, &shards))
}

async fn registry_shards_verify(
    State(state): State<AppState>,
    Json(request): Json<hivemind_registry::RegistryShardVerificationRequestV1>,
) -> Json<hivemind_registry::RegistryShardVerificationV1> {
    let public = public_registry_snapshot(&state.registry_snapshot);
    Json(hivemind_registry::verify_registry_shard_set(
        &public,
        request.shards,
        request
            .shard_source
            .unwrap_or_else(|| "request".to_string()),
    ))
}

async fn registry_shard_manifest_compare(
    State(state): State<AppState>,
    Json(request): Json<hivemind_registry::RegistryShardManifestComparisonRequestV1>,
) -> Json<hivemind_registry::RegistryShardManifestComparisonV1> {
    let public = public_registry_snapshot(&state.registry_snapshot);
    Json(hivemind_registry::compare_registry_shard_manifest(
        &public,
        &request.manifest,
        request
            .shard_source
            .unwrap_or_else(|| "request".to_string()),
    ))
}

async fn registry_shard_manifest_verify(
    State(state): State<AppState>,
    Json(request): Json<hivemind_registry::RegistryShardManifestVerificationRequestV1>,
) -> Json<hivemind_registry::RegistryShardManifestVerificationV1> {
    let public = public_registry_snapshot(&state.registry_snapshot);
    Json(hivemind_registry::verify_registry_shard_manifest_set(
        &public,
        &request.manifest,
        request.shards,
        request
            .shard_source
            .unwrap_or_else(|| "request".to_string()),
    ))
}

async fn storage_status(State(state): State<AppState>) -> Json<hivemind_storage::StorageStatusV1> {
    let storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    Json(storage.get_status())
}

async fn storage_providers_v3() -> Json<Value> {
    Json(json!({
        "schemaVersion": "hivemind.storage-provider-catalog.v3",
        "providers": hivemind_storage::default_storage_provider_descriptors_v3(),
    }))
}

async fn storage_providers_v4() -> Json<hivemind_storage::BrowserSwarmProviderCatalogV4> {
    Json(hivemind_storage::browser_swarm_provider_catalog_v4())
}

async fn browser_storage_verify_consent(
    Json(consent): Json<hivemind_storage::BrowserStorageConsentV1>,
) -> Json<hivemind_storage::StorageContractVerificationV1> {
    Json(hivemind_storage::verify_browser_storage_consent(&consent))
}

async fn browser_storage_verify_session(
    Json(session): Json<hivemind_storage::BrowserStorageSessionV1>,
) -> Json<hivemind_storage::StorageContractVerificationV1> {
    Json(hivemind_storage::verify_browser_storage_session(&session))
}

async fn browser_storage_verify_receipt(
    Json(receipt): Json<hivemind_storage::StorageEventReceiptV1>,
) -> Json<hivemind_storage::StorageContractVerificationV1> {
    Json(hivemind_storage::verify_storage_event_receipt(&receipt))
}

async fn browser_storage_verify_sponsorship(
    Json(sponsorship): Json<hivemind_storage::StorageSponsorshipV1>,
) -> Json<hivemind_storage::StorageContractVerificationV1> {
    Json(hivemind_storage::verify_storage_sponsorship(&sponsorship))
}

async fn browser_storage_security_assess(
    Json(request): Json<hivemind_storage::BrowserStorageSecurityAssessmentRequestV1>,
) -> Json<hivemind_storage::BrowserStorageSecurityAssessmentV1> {
    Json(hivemind_storage::assess_browser_storage_security(request))
}

async fn browser_storage_security_verify(
    Json(assessment): Json<hivemind_storage::BrowserStorageSecurityAssessmentV1>,
) -> Json<hivemind_storage::StorageContractVerificationV1> {
    Json(hivemind_storage::verify_browser_storage_security_assessment(&assessment))
}

async fn storage_cache(State(state): State<AppState>) -> impl IntoResponse {
    let storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    match storage.cache_summary() {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json_error_value(&error))).into_response(),
    }
}

async fn storage_inspect(
    State(state): State<AppState>,
    Json(request): Json<StorageInspectRequest>,
) -> impl IntoResponse {
    let storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    if let Some(path) = request.path {
        return match storage.download_file(&request.reference, &path) {
            Ok(response) => {
                let preview = text_preview(&response.bytes);
                (
                    StatusCode::OK,
                    Json(json!({
                        "schemaVersion": "swarm-ai.storage.inspect-download.v1",
                        "ref": response.reference,
                        "path": response.path,
                        "contentType": response.content_type,
                        "sizeBytes": response.size_bytes,
                        "sha256": response.sha256,
                        "metrics": response.metrics,
                        "textPreview": preview
                    })),
                )
                    .into_response()
            }
            Err(error) => (StatusCode::BAD_REQUEST, Json(json_error_value(&error))).into_response(),
        };
    }

    match storage.inspect(&request.reference) {
        Ok(inspection) => (StatusCode::OK, Json(json!(inspection))).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json_error_value(&error))).into_response(),
    }
}

async fn storage_pin(
    State(state): State<AppState>,
    Json(request): Json<StorageReferenceRequest>,
) -> impl IntoResponse {
    let mut storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    match storage.pin(&request.reference) {
        Ok(result) => (StatusCode::OK, Json(json!(result))).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json_error_value(&error))).into_response(),
    }
}

async fn storage_unpin(
    State(state): State<AppState>,
    Json(request): Json<StorageReferenceRequest>,
) -> impl IntoResponse {
    let mut storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    match storage.unpin(&request.reference) {
        Ok(result) => (StatusCode::OK, Json(json!(result))).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json_error_value(&error))).into_response(),
    }
}

async fn storage_feed_create(
    State(state): State<AppState>,
    Json(request): Json<StorageFeedCreateRequest>,
) -> impl IntoResponse {
    let mut storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    match storage.create_feed(&request.topic, &request.owner) {
        Ok(pointer) => (StatusCode::OK, Json(json!(pointer))).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json_error_value(&error))).into_response(),
    }
}

async fn storage_feed_update(
    State(state): State<AppState>,
    Json(request): Json<StorageFeedUpdateRequest>,
) -> impl IntoResponse {
    let mut storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    match storage.update_feed(&request.topic, &request.owner, &request.reference) {
        Ok(update) => (StatusCode::OK, Json(json!(update))).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json_error_value(&error))).into_response(),
    }
}

async fn storage_feed_resolve(
    State(state): State<AppState>,
    Json(request): Json<StorageFeedResolveRequest>,
) -> impl IntoResponse {
    let storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    match storage.resolve_feed(&request.feed_ref) {
        Ok(resolution) => (StatusCode::OK, Json(json!(resolution))).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json_error_value(&error))).into_response(),
    }
}

async fn policy_catalog() -> Json<Vec<hivemind_policy::PermissionDefinitionV1>> {
    Json(hivemind_policy::permission_catalog())
}

async fn policy_privacy_tiers() -> Json<hivemind_core::PrivacyTierCatalogV1> {
    Json(hivemind_core::privacy_tier_catalog())
}

async fn policy_privacy_assess(
    Json(request): Json<hivemind_core::PrivacyRequirementAssessmentRequestV1>,
) -> Json<hivemind_core::PrivacyRequirementAssessmentV1> {
    Json(hivemind_core::assess_privacy_requirement(&request))
}

async fn policy_inspect(
    Json(manifest): Json<hivemind_core::PackageManifestV1>,
) -> Json<hivemind_policy::PolicyInspectionV1> {
    Json(hivemind_policy::inspect_package_policy(
        &manifest,
        format!("local://manifest/{}", manifest.package_id),
        None,
    ))
}

async fn policy_inspect_v2(
    Json(manifest): Json<hivemind_core::PackageManifestV1>,
) -> Json<hivemind_policy::RiskInspectionReportV1> {
    Json(hivemind_policy::inspect_package_policy_v2(
        &manifest,
        format!("local://manifest/{}", manifest.package_id),
        None,
    ))
}

async fn policy_trust_records(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_policy::list_trust_policy_records(state.trust_policy_dir.as_ref().as_path()) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list trust policies: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn policy_trust_by_id(
    State(state): State<AppState>,
    Path(policy_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_policy::get_trust_policy_record(
        state.trust_policy_dir.as_ref().as_path(),
        &policy_id,
    ) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                &format!("Trust policy {policy_id} not found"),
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to load trust policy {policy_id}: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn policy_trust_local_only(
    State(state): State<AppState>,
    Json(request): Json<TrustPolicyPresetRequest>,
) -> impl IntoResponse {
    trust_policy_envelope_response(
        state.trust_policy_dir.as_ref().as_path(),
        TrustPolicyV1::local_only(trust_policy_owner(request.owner)),
        request.sign,
    )
}

async fn policy_trust_open_marketplace(
    State(state): State<AppState>,
    Json(request): Json<TrustPolicyPresetRequest>,
) -> impl IntoResponse {
    trust_policy_envelope_response(
        state.trust_policy_dir.as_ref().as_path(),
        TrustPolicyV1::open_marketplace(trust_policy_owner(request.owner)),
        request.sign,
    )
}

async fn policy_trust_sign(
    State(state): State<AppState>,
    Json(policy): Json<TrustPolicyV1>,
) -> impl IntoResponse {
    trust_policy_envelope_response(state.trust_policy_dir.as_ref().as_path(), policy, true)
}

async fn policy_trust_verify(
    Json(policy): Json<TrustPolicyV1>,
) -> Json<hivemind_core::TrustPolicyVerificationV1> {
    Json(hivemind_core::verify_trust_policy(&policy))
}

fn trust_policy_envelope_response(
    trust_dir: &FsPath,
    policy: TrustPolicyV1,
    sign: bool,
) -> Response {
    match trust_policy_envelope(policy, sign) {
        Ok(mut response) => {
            if response.verification.valid {
                match hivemind_policy::write_trust_policy_record(trust_dir, &response.trust_policy)
                {
                    Ok(store) => response.store = Some(store),
                    Err(error) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json_error(
                                ErrorCode::ExecutionFailed,
                                &format!("Failed to store trust policy: {error}"),
                            )),
                        )
                            .into_response();
                    }
                }
            }
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error)),
        )
            .into_response(),
    }
}

fn trust_policy_envelope(
    mut policy: TrustPolicyV1,
    sign: bool,
) -> std::result::Result<TrustPolicyEnvelopeResponse, String> {
    let signature = if sign {
        Some(
            hivemind_core::sign_trust_policy(&mut policy)
                .map_err(|error| format!("failed to sign trust policy: {error}"))?,
        )
    } else {
        None
    };
    let verification = hivemind_core::verify_trust_policy(&policy);
    Ok(TrustPolicyEnvelopeResponse {
        schema_version: "swarm-ai.trust-policy-envelope.v1".to_string(),
        trust_policy: policy,
        signature,
        verification,
        store: None,
    })
}

fn trust_policy_owner(owner: Option<String>) -> String {
    owner
        .map(|owner| owner.trim().to_string())
        .filter(|owner| !owner.is_empty())
        .unwrap_or_else(|| "local-dev".to_string())
}

async fn receipts(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_receipts::list_receipts(&state.receipt_dir) {
        Ok(mut summary) => {
            enrich_receipt_summary_from_job_store(&mut summary, state.job_dir.as_ref().as_path());
            (StatusCode::OK, Json(summary)).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list receipts: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn receipts_audit(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_receipts::list_receipts(&state.receipt_dir) {
        Ok(mut summary) => {
            enrich_receipt_summary_from_job_store(&mut summary, state.job_dir.as_ref().as_path());
            let audit = hivemind_receipts::audit_receipt_store(&summary);
            (StatusCode::OK, Json(audit)).into_response()
        }
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to audit receipts: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn batch_receipts(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_receipts::list_batch_receipts(&state.receipt_dir) {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list batch receipts: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn batch_receipts_audit(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_receipts::audit_batch_receipts_dir(&state.receipt_dir) {
        Ok(audit) => (StatusCode::OK, Json(audit)).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to audit batch receipts: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn batch_receipt_by_id(
    State(state): State<AppState>,
    Path(batch_receipt_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_receipts::get_batch_receipt(&state.receipt_dir, &batch_receipt_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Batch receipt was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read batch receipt: {error}"),
            )),
        )
            .into_response(),
    }
}

fn enrich_receipt_summary_from_job_store(
    summary: &mut hivemind_receipts::ReceiptStoreSummaryV1,
    job_dir: &FsPath,
) {
    let Ok(job_summary) = hivemind_jobs::list_job_records(job_dir) else {
        return;
    };
    let mut jobs_by_receipt = BTreeMap::new();
    for job in job_summary.jobs {
        let Some(receipt_id) = job.receipt_id else {
            continue;
        };
        let Ok(Some(lookup)) = hivemind_jobs::get_job_record(job_dir, &job.job_id) else {
            continue;
        };
        jobs_by_receipt.insert(receipt_id, lookup.record);
    }
    for entry in &mut summary.receipts {
        let Some(record) = jobs_by_receipt.get(&entry.receipt_id) else {
            continue;
        };
        enrich_receipt_index_entry_from_job_record(entry, record);
    }
}

fn enrich_receipt_index_entry_from_job_record(
    entry: &mut hivemind_receipts::ReceiptIndexEntryV1,
    record: &hivemind_jobs::JobRecordV1,
) {
    entry.job_id = Some(record.job_id.clone());
    entry.requester = Some(record.job_order.requester.clone());
    entry.lease_id = record.lease.as_ref().map(|lease| lease.lease_id.clone());
    entry.quote_id = record
        .lease
        .as_ref()
        .map(|lease| lease.quote_id.clone())
        .or_else(|| record.quotes.first().map(|quote| quote.quote_id.clone()));
    entry.settlement_ref = receipt_settlement_ref(record);
    entry.settlement_status = Some(receipt_settlement_status(record));
}

fn receipt_settlement_status(
    record: &hivemind_jobs::JobRecordV1,
) -> hivemind_receipts::ReceiptSettlementStatusV1 {
    if let Some(status) = json_path_str(&record.metadata, &["settlementResolution", "newStatus"])
        .or_else(|| json_path_str(&record.metadata, &["settlementEvent", "status"]))
        .or_else(|| json_path_str(&record.metadata, &["settlement", "status"]))
    {
        return receipt_settlement_status_from_str(status);
    }
    if json_path_str(&record.metadata, &["dispute", "disputeId"]).is_some()
        || json_path_str(&record.metadata, &["dispute", "disputeRef"]).is_some()
    {
        return hivemind_receipts::ReceiptSettlementStatusV1::Disputed;
    }
    if record.job_order.settlement_method == "free-local-dev" {
        return hivemind_receipts::ReceiptSettlementStatusV1::NotRequired;
    }
    if receipt_settlement_ref(record).is_some() {
        return hivemind_receipts::ReceiptSettlementStatusV1::Settled;
    }
    let lifecycle = hivemind_jobs::job_production_lifecycle(record);
    if lifecycle.ready_for_settlement {
        return hivemind_receipts::ReceiptSettlementStatusV1::ReadyForSettlement;
    }
    if matches!(
        record.status,
        hivemind_jobs::JobRecordStatusV1::Failed | hivemind_jobs::JobRecordStatusV1::Cancelled
    ) {
        return hivemind_receipts::ReceiptSettlementStatusV1::Blocked;
    }
    hivemind_receipts::ReceiptSettlementStatusV1::Pending
}

fn receipt_settlement_status_from_str(value: &str) -> hivemind_receipts::ReceiptSettlementStatusV1 {
    match value {
        "authorized" => hivemind_receipts::ReceiptSettlementStatusV1::Authorized,
        "settled" => hivemind_receipts::ReceiptSettlementStatusV1::Settled,
        "partially_settled" | "partially-settled" => {
            hivemind_receipts::ReceiptSettlementStatusV1::PartiallySettled
        }
        "refunded" => hivemind_receipts::ReceiptSettlementStatusV1::Refunded,
        "disputed" => hivemind_receipts::ReceiptSettlementStatusV1::Disputed,
        "dispute_rejected" | "dispute-rejected" => {
            hivemind_receipts::ReceiptSettlementStatusV1::DisputeRejected
        }
        "cancelled" | "canceled" => hivemind_receipts::ReceiptSettlementStatusV1::Cancelled,
        "failed" => hivemind_receipts::ReceiptSettlementStatusV1::Failed,
        _ => hivemind_receipts::ReceiptSettlementStatusV1::Pending,
    }
}

fn receipt_settlement_ref(record: &hivemind_jobs::JobRecordV1) -> Option<String> {
    json_path_str(&record.metadata, &["settlementResolution", "settlementRef"])
        .or_else(|| json_path_str(&record.metadata, &["settlementEvent", "settlementRef"]))
        .or_else(|| json_path_str(&record.metadata, &["settlement", "settlementRef"]))
        .or_else(|| json_path_str(&record.metadata, &["settlementStore", "settlementRef"]))
        .map(str::to_string)
        .or_else(|| {
            record
                .lease
                .as_ref()
                .map(|lease| lease.settlement_ref.clone())
                .filter(|settlement_ref| !settlement_ref.trim().is_empty())
        })
}

async fn receipt_by_id(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_receipts::get_receipt(&state.receipt_dir, &receipt_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Receipt was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read receipt: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn receipt_v2_by_id(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_receipts::get_receipt(&state.receipt_dir, &receipt_id) {
        Ok(Some(lookup)) => {
            let context = receipt_v2_context_from_job_store(
                state.job_dir.as_ref().as_path(),
                &lookup.receipt,
            );
            let receipt = execution_receipt_v2_from_v1(&lookup.receipt, context);
            (StatusCode::OK, Json(json!(receipt))).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Receipt was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read receipt: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn receipt_redaction_by_id(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
    Query(query): Query<ReceiptRedactionQuery>,
) -> impl IntoResponse {
    let policy = match receipt_redaction_policy_from_query(query.profile.as_deref()) {
        Ok(policy) => policy,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json_error(ErrorCode::InvalidRequest, &message)),
            )
                .into_response();
        }
    };
    match hivemind_receipts::get_receipt(&state.receipt_dir, &receipt_id) {
        Ok(Some(lookup)) => {
            let redacted = hivemind_receipts::redact_receipt(&lookup.receipt, policy);
            (StatusCode::OK, Json(json!(redacted))).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Receipt was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read receipt: {error}"),
            )),
        )
            .into_response(),
    }
}

fn receipt_redaction_policy_from_query(
    profile: Option<&str>,
) -> std::result::Result<hivemind_receipts::ReceiptRedactionPolicyV1, String> {
    Ok(hivemind_receipts::receipt_redaction_policy(
        receipt_redaction_profile_from_str(profile.unwrap_or("public-audit"))?,
    ))
}

fn receipt_redaction_profile_from_str(
    value: &str,
) -> std::result::Result<hivemind_receipts::ReceiptRedactionProfileV1, String> {
    match value.trim() {
        "" | "public" | "public-audit" => {
            Ok(hivemind_receipts::ReceiptRedactionProfileV1::PublicAudit)
        }
        "settlement" | "settlement-audit" => {
            Ok(hivemind_receipts::ReceiptRedactionProfileV1::SettlementAudit)
        }
        "internal" | "internal-audit" => {
            Ok(hivemind_receipts::ReceiptRedactionProfileV1::InternalAudit)
        }
        other => Err(format!(
            "unknown receipt redaction profile {other}; expected public-audit, settlement-audit, or internal-audit"
        )),
    }
}

fn receipt_v2_context_from_job_store(
    job_dir: &FsPath,
    receipt: &hivemind_core::ExecutionReceiptV1,
) -> hivemind_core::ExecutionReceiptV2Context {
    let Ok(summary) = hivemind_jobs::list_job_records(job_dir) else {
        return receipt_v2_context_from_receipt(receipt);
    };
    for entry in summary.jobs {
        if entry.receipt_id.as_deref() != Some(receipt.receipt_id.as_str()) {
            continue;
        }
        let Ok(Some(lookup)) = hivemind_jobs::get_job_record(job_dir, &entry.job_id) else {
            continue;
        };
        let record = lookup.record;
        let lease_context =
            record
                .lease
                .as_ref()
                .map(|lease| hivemind_core::ExecutionReceiptLeaseContextV2 {
                    quote_id: Some(lease.quote_id.clone()),
                    allowed_input_refs: lease.allowed_input_refs.clone(),
                    allowed_input_hashes: lease.allowed_input_hashes.clone(),
                    allowed_package_refs: lease.allowed_package_refs.clone(),
                    max_cost: Some(lease.max_cost.clone()),
                    start_after: lease.start_after.clone(),
                    deadline: Some(lease.deadline.clone()),
                    settlement_ref: Some(lease.settlement_ref.clone()),
                });
        return hivemind_core::ExecutionReceiptV2Context {
            job_id: Some(record.job_id.clone()),
            lease_id: record.lease.as_ref().map(|lease| lease.lease_id.clone()),
            lease_context,
            requester: Some(record.job_order.requester.clone()),
            api_surface: Some(record.job_order.api_surface.clone()),
            input_modalities: record
                .job_order
                .modalities
                .iter()
                .map(modality_label)
                .collect(),
            output_modalities: output_modalities_for_task(&record.job_order.task),
            verification_mode: Some(record.job_order.required_verification_tier.clone()),
            route_decision_ref: json_path_str(
                &record.metadata,
                &["routeDecisionStore", "decisionRef"],
            )
            .map(str::to_string)
            .or_else(|| {
                record
                    .selected_route_id
                    .as_ref()
                    .map(|route_id| format!("local://route/{route_id}"))
            }),
            trace_ref: json_path_str(&record.metadata, &["routeTraceStore", "traceRef"])
                .map(str::to_string)
                .or_else(|| {
                    record
                        .selected_route_id
                        .as_ref()
                        .map(|route_id| format!("local://route/{route_id}"))
                }),
            tool_call_refs: Vec::new(),
            retrieval_refs: Vec::new(),
            attestation_ref: None,
            proof_refs: Vec::new(),
            status: record.execution_status.clone(),
            error: record.error.clone(),
        };
    }
    receipt_v2_context_from_receipt(receipt)
}

fn receipt_v2_context_from_receipt(
    receipt: &hivemind_core::ExecutionReceiptV1,
) -> hivemind_core::ExecutionReceiptV2Context {
    hivemind_core::ExecutionReceiptV2Context {
        route_decision_ref: receipt
            .route_id
            .as_ref()
            .map(|route_id| format!("local://route/{route_id}")),
        trace_ref: receipt
            .route_id
            .as_ref()
            .map(|route_id| format!("local://route/{route_id}")),
        ..Default::default()
    }
}

fn modality_label(modality: &hivemind_core::Modality) -> String {
    serde_json::to_value(modality)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{modality:?}"))
}

fn output_modalities_for_task(task: &str) -> Vec<String> {
    match task {
        "embedding" => vec!["embedding".to_string()],
        "classification" => vec!["structured_output".to_string()],
        "chat" => vec!["text".to_string()],
        "image" | "image_generation" => vec!["image".to_string()],
        "speech_to_text" => vec!["text".to_string()],
        "text_to_speech" => vec!["audio".to_string()],
        _ => vec!["json".to_string()],
    }
}

async fn verify_receipt(
    Json(receipt): Json<hivemind_core::ExecutionReceiptV1>,
) -> Json<hivemind_receipts::ReceiptVerificationV1> {
    Json(hivemind_receipts::verify_receipt(&receipt))
}

async fn verify_receipt_v2(
    Json(request): Json<hivemind_receipts::ExecutionReceiptV2VerificationRequestV1>,
) -> Json<hivemind_receipts::ExecutionReceiptV2VerificationV1> {
    Json(hivemind_receipts::verify_execution_receipt_v2_request(
        &request,
    ))
}

async fn assess_receipt_correctness(
    Json(request): Json<hivemind_receipts::ReceiptCorrectnessAssessmentRequestV1>,
) -> Json<hivemind_receipts::ReceiptCorrectnessAssessmentV1> {
    Json(hivemind_receipts::assess_receipt_correctness(&request))
}

async fn verify_batch_receipt(
    Json(receipt): Json<hivemind_receipts::BatchReceiptV1>,
) -> Json<hivemind_receipts::BatchReceiptVerificationV1> {
    Json(hivemind_receipts::verify_batch_receipt(&receipt))
}

async fn verify_partial_receipt(
    Json(receipt): Json<hivemind_receipts::PartialReceiptV1>,
) -> Json<hivemind_receipts::PartialReceiptVerificationV1> {
    Json(hivemind_receipts::verify_partial_receipt(&receipt))
}

async fn verify_redacted_receipt(
    Json(redacted): Json<hivemind_receipts::RedactedReceiptV1>,
) -> Json<hivemind_receipts::RedactedReceiptVerificationV1> {
    Json(hivemind_receipts::verify_redacted_receipt(&redacted))
}

async fn receipt_partials_by_stream_key(
    State(state): State<AppState>,
    Path(stream_key): Path<String>,
) -> impl IntoResponse {
    partial_receipts_by_stream_key_response(&state, &stream_key)
}

fn partial_receipts_by_stream_key_response(state: &AppState, stream_key: &str) -> Response {
    match hivemind_streams::read_stream_events(
        state.stream_event_dir.as_ref().as_path(),
        stream_key,
    ) {
        Ok(Some(events)) => {
            let summary = hivemind_receipts::partial_receipt_stream_summary(stream_key, &events);
            (StatusCode::OK, Json(json!(summary))).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Stream events were not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to read stream events: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn upload_receipt(
    State(state): State<AppState>,
    Json(receipt): Json<hivemind_core::ExecutionReceiptV1>,
) -> impl IntoResponse {
    let mut storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    match hivemind_receipts::upload_receipt(&mut storage, &receipt) {
        Ok(upload) => {
            persist_storage_transfer_audit(
                state.storage_audit_dir.as_ref().as_path(),
                "local",
                hivemind_storage::StorageTransferDirectionV1::Upload,
                &upload.receipt_ref,
                None,
                Some(upload.storage.content_type.clone()),
                upload.storage.size_bytes,
                upload.storage.metrics.as_ref(),
            );
            (StatusCode::OK, Json(json!(upload))).into_response()
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to upload receipt: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn download_receipt(
    State(state): State<AppState>,
    Json(request): Json<DownloadReceiptRequest>,
) -> impl IntoResponse {
    let storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    match hivemind_receipts::download_receipt(&storage, &request.receipt_ref) {
        Ok(download) => {
            persist_storage_transfer_audit(
                state.storage_audit_dir.as_ref().as_path(),
                "local",
                hivemind_storage::StorageTransferDirectionV1::Download,
                &download.receipt_ref,
                None,
                Some(download.storage.content_type.clone()),
                download.storage.size_bytes,
                download.storage.metrics.as_ref(),
            );
            (StatusCode::OK, Json(json!(download))).into_response()
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::PackageNotFound,
                &format!("Failed to download receipt: {error}"),
            )),
        )
            .into_response(),
    }
}

fn persist_storage_transfer_audit(
    storage_audit_dir: &FsPath,
    provider: &str,
    direction: hivemind_storage::StorageTransferDirectionV1,
    reference: &str,
    path: Option<String>,
    content_type: Option<String>,
    size_bytes: usize,
    metrics: Option<&hivemind_storage::StorageTransferMetricsV1>,
) {
    let Some(metrics) = metrics.cloned() else {
        return;
    };
    let record = hivemind_storage::storage_transfer_audit_record(
        provider,
        direction,
        reference,
        path,
        content_type,
        size_bytes,
        metrics,
    );
    if let Err(error) =
        hivemind_storage::write_storage_transfer_audit_record(storage_audit_dir, &record)
    {
        warn!("failed to persist storage transfer audit record: {error}");
    }
}

async fn disputes(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_receipts::list_dispute_evidence(&state.dispute_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list dispute evidence: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn dispute_by_id(
    State(state): State<AppState>,
    Path(dispute_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_receipts::get_dispute_evidence(&state.dispute_dir, &dispute_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Dispute evidence was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read dispute evidence: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn create_dispute(
    State(state): State<AppState>,
    Json(request): Json<CreateDisputeRequest>,
) -> impl IntoResponse {
    let evidence = hivemind_receipts::create_dispute_evidence(
        request.receipt,
        request.claimant,
        request.claim_kind,
        request.summary,
        request.evidence_refs,
    );
    let verification = hivemind_receipts::verify_dispute_evidence(&evidence);
    match hivemind_receipts::write_dispute_evidence(&state.dispute_dir, &evidence) {
        Ok(dispute_path) => (
            StatusCode::OK,
            Json(json!(CreateDisputeResponse {
                dispute_path: dispute_path.display().to_string(),
                evidence,
                verification,
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to store dispute evidence: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn verify_dispute(
    Json(evidence): Json<hivemind_receipts::DisputeEvidenceV1>,
) -> Json<hivemind_receipts::DisputeEvidenceVerificationV1> {
    Json(hivemind_receipts::verify_dispute_evidence(&evidence))
}

async fn publisher_publications(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_publisher::list_publication_records(state.record_dir.as_ref().as_path()) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list publication records: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn publisher_publication_by_id(
    State(state): State<AppState>,
    Path(publication_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_publisher::get_publication_record(
        state.record_dir.as_ref().as_path(),
        &publication_id,
    ) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Publication record was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read publication record: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn publisher_verify(
    Json(record): Json<hivemind_publisher::PublicationRecordV1>,
) -> Json<hivemind_publisher::PublicationVerificationV1> {
    Json(hivemind_publisher::verify_publication_record(&record))
}

async fn publisher_feeds(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_publisher::list_feed_pointers(state.feed_dir.as_ref().as_path()) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list publisher feeds: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn publisher_feed_by_key(
    State(state): State<AppState>,
    Path(feed_key): Path<String>,
) -> impl IntoResponse {
    let Some((package_id, channel)) = feed_key.rsplit_once('/') else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                "Feed lookup path must be {packageId}/{channel}",
            )),
        )
            .into_response();
    };
    match hivemind_publisher::get_feed_pointer(
        state.feed_dir.as_ref().as_path(),
        package_id,
        channel,
    ) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Publisher feed pointer was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read publisher feed pointer: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn publisher_feed_update(
    State(state): State<AppState>,
    Json(record): Json<hivemind_publisher::PublicationRecordV1>,
) -> impl IntoResponse {
    let verification = hivemind_publisher::verify_publication_record(&record);
    if !verification.valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "verification": verification,
                "feedUpdates": []
            })),
        )
            .into_response();
    }
    match hivemind_publisher::write_feed_updates(&state.feed_dir, &record) {
        Ok(feed_updates) => (
            StatusCode::OK,
            Json(json!({
                "verification": verification,
                "feedUpdates": feed_updates
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to update publisher feeds: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn publisher_feed_resolve(
    State(state): State<AppState>,
    Json(request): Json<hivemind_publisher::FeedResolveRequestV1>,
) -> impl IntoResponse {
    match hivemind_publisher::resolve_feed(&state.feed_dir, &request.package_id, &request.channel) {
        Ok(resolution) => (StatusCode::OK, Json(json!(resolution))).into_response(),
        Err(error) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                &format!("Failed to resolve publisher feed: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn validator_reports(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_validator::list_validation_reports(state.validation_dir.as_ref().as_path()) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list validation reports: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn validator_methods() -> Json<hivemind_validator::ValidationMethodRegistryV1> {
    Json(hivemind_validator::validation_method_registry())
}

async fn validator_report_by_id(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
) -> impl IntoResponse {
    validator_report_lookup_response(&state, &report_id)
}

async fn validator_report_v2_by_id(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
) -> impl IntoResponse {
    validator_report_v2_lookup_response(&state, &report_id)
}

async fn validator_reputation_profile(
    State(state): State<AppState>,
    Json(request): Json<ValidationReputationRequest>,
) -> impl IntoResponse {
    match hivemind_validator::reputation_profile_from_store(
        state.validation_dir.as_ref().as_path(),
        request.subject_type,
        request.subject_id,
    ) {
        Ok(profile) => (StatusCode::OK, Json(json!(profile))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to build reputation profile: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn validator_reputation_profile_v2(
    State(state): State<AppState>,
    Json(request): Json<ValidationReputationRequest>,
) -> impl IntoResponse {
    match hivemind_validator::reputation_profile_v2_from_store(
        state.validation_dir.as_ref().as_path(),
        request.subject_type,
        request.subject_id,
    ) {
        Ok(profile) => (StatusCode::OK, Json(json!(profile))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to build v2 reputation profile: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn validator_verify_report(
    Json(report): Json<hivemind_validator::ValidationReportV1>,
) -> Json<hivemind_validator::ValidationReportVerificationV1> {
    Json(hivemind_validator::verify_validation_report(&report))
}

async fn validator_create_integrity_evidence(
    State(state): State<AppState>,
    Json(request): Json<hivemind_validator::IntegrityEvidenceInitOptionsV1>,
) -> impl IntoResponse {
    let evidence = hivemind_validator::create_integrity_evidence(request);
    let verification = hivemind_validator::verify_integrity_evidence(&evidence);
    if !verification.valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": json_error(ErrorCode::InvalidRequest, "Integrity evidence is not valid"),
                "verification": verification
            })),
        )
            .into_response();
    }
    let evidence_dir = validator_integrity_evidence_dir(&state);
    match hivemind_validator::write_integrity_evidence(&evidence_dir, &evidence) {
        Ok(path) => (
            StatusCode::OK,
            Json(json!(IntegrityEvidenceCreateResponse {
                schema_version: "hivemind.integrity_evidence_create_response.v1".to_string(),
                evidence_path: path.display().to_string(),
                validation_report_v2:
                    hivemind_validator::validation_report_v2_from_integrity_evidence(&evidence),
                evidence,
                verification,
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::ExecutionFailed, &error.to_string())),
        )
            .into_response(),
    }
}

async fn validator_verify_integrity_evidence(
    Json(evidence): Json<hivemind_validator::IntegrityEvidenceV1>,
) -> Json<Value> {
    Json(json!({
        "verification": hivemind_validator::verify_integrity_evidence(&evidence),
        "validationReportV2": hivemind_validator::validation_report_v2_from_integrity_evidence(&evidence)
    }))
}

async fn validator_integrity_evidence(State(state): State<AppState>) -> impl IntoResponse {
    let evidence_dir = validator_integrity_evidence_dir(&state);
    match hivemind_validator::list_integrity_evidence(&evidence_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn validator_integrity_evidence_by_id(
    State(state): State<AppState>,
    Path(evidence_id): Path<String>,
) -> impl IntoResponse {
    let evidence_dir = validator_integrity_evidence_dir(&state);
    match hivemind_validator::get_integrity_evidence(&evidence_dir, &evidence_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Integrity evidence was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn validator_upload_report(
    State(state): State<AppState>,
    Json(report): Json<hivemind_validator::ValidationReportV1>,
) -> impl IntoResponse {
    let mut storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    match hivemind_validator::upload_validation_report(&mut storage, &report) {
        Ok(upload) => {
            persist_storage_transfer_audit(
                state.storage_audit_dir.as_ref().as_path(),
                "local",
                hivemind_storage::StorageTransferDirectionV1::Upload,
                &upload.report_ref,
                None,
                Some(upload.storage.content_type.clone()),
                upload.storage.size_bytes,
                upload.storage.metrics.as_ref(),
            );
            (StatusCode::OK, Json(json!(upload))).into_response()
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to upload validation report: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn validator_download_report(
    State(state): State<AppState>,
    Json(request): Json<DownloadValidationReportRequest>,
) -> impl IntoResponse {
    let storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    match hivemind_validator::download_validation_report(&storage, &request.report_ref) {
        Ok(download) => {
            persist_storage_transfer_audit(
                state.storage_audit_dir.as_ref().as_path(),
                "local",
                hivemind_storage::StorageTransferDirectionV1::Download,
                &download.report_ref,
                None,
                Some(download.storage.content_type.clone()),
                download.storage.size_bytes,
                download.storage.metrics.as_ref(),
            );
            (StatusCode::OK, Json(json!(download))).into_response()
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::PackageNotFound,
                &format!("Failed to download validation report: {error}"),
            )),
        )
            .into_response(),
    }
}

fn validator_integrity_evidence_dir(state: &AppState) -> PathBuf {
    state.validation_dir.join("integrity")
}

async fn benchmark_evaluations(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_benchmarks::list_evaluation_results(state.evaluation_dir.as_ref().as_path()) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list evaluation results: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_leaderboard(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_benchmarks::evaluation_leaderboard(state.evaluation_dir.as_ref().as_path()) {
        Ok(leaderboard) => (StatusCode::OK, Json(json!(leaderboard))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to build evaluation leaderboard: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_evaluation_by_id(
    State(state): State<AppState>,
    Path(evaluation_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_benchmarks::get_evaluation_result(
        state.evaluation_dir.as_ref().as_path(),
        &evaluation_id,
    ) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Evaluation result was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read evaluation result: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_verify_evaluation(
    Json(result): Json<hivemind_benchmarks::EvaluationResultV1>,
) -> Json<hivemind_benchmarks::EvaluationResultVerificationV1> {
    Json(hivemind_benchmarks::verify_evaluation_result(&result))
}

async fn benchmark_evaluations_v2(State(state): State<AppState>) -> impl IntoResponse {
    let results_dir = benchmark_evaluations_v2_dir(&state);
    match hivemind_benchmarks::list_evaluation_results_v2(&results_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list evaluation result v2 records: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_evaluation_v2_by_id(
    State(state): State<AppState>,
    Path(evaluation_id): Path<String>,
) -> impl IntoResponse {
    let results_dir = benchmark_evaluations_v2_dir(&state);
    match hivemind_benchmarks::get_evaluation_result_v2(&results_dir, &evaluation_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Evaluation result v2 was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read evaluation result v2: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_evaluation_v1_as_v2_by_id(
    State(state): State<AppState>,
    Path(evaluation_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_benchmarks::get_evaluation_result(
        state.evaluation_dir.as_ref().as_path(),
        &evaluation_id,
    ) {
        Ok(Some(lookup)) => {
            let evaluation = hivemind_benchmarks::evaluation_result_v2_from_v1(
                &lookup.evaluation,
                hivemind_benchmarks::EvaluationResultV2ContextV1::default(),
            );
            let verification = hivemind_benchmarks::verify_evaluation_result_v2(&evaluation);
            (
                StatusCode::OK,
                Json(json!({
                    "schemaVersion": "hivemind.evaluation_result_v2_projection_response.v1",
                    "source": lookup,
                    "evaluation": evaluation,
                    "verification": verification
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Evaluation result was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read evaluation result: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_create_evaluation_v2_from_v1(
    State(state): State<AppState>,
    Json(request): Json<hivemind_benchmarks::EvaluationResultV2ProjectionRequestV1>,
) -> impl IntoResponse {
    let evaluation =
        hivemind_benchmarks::evaluation_result_v2_from_v1(&request.result, request.context);
    let verification = hivemind_benchmarks::verify_evaluation_result_v2(&evaluation);
    if !verification.valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": json_error(ErrorCode::InvalidRequest, "Evaluation result v2 is not valid"),
                "verification": verification
            })),
        )
            .into_response();
    }
    let results_dir = benchmark_evaluations_v2_dir(&state);
    match hivemind_benchmarks::write_evaluation_result_v2(&results_dir, &evaluation) {
        Ok(path) => (
            StatusCode::OK,
            Json(json!({
                "schemaVersion": "hivemind.evaluation_result_v2_create_response.v1",
                "resultPath": path.display().to_string(),
                "evaluation": evaluation,
                "verification": verification
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to write evaluation result v2: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_verify_evaluation_v2(
    Json(result): Json<hivemind_benchmarks::EvaluationResultV2>,
) -> Json<hivemind_benchmarks::EvaluationResultV2VerificationV1> {
    Json(hivemind_benchmarks::verify_evaluation_result_v2(&result))
}

fn benchmark_evaluations_v2_dir(state: &AppState) -> PathBuf {
    state.evaluation_dir.join("v2")
}

async fn benchmark_create_suite(
    State(state): State<AppState>,
    Json(request): Json<hivemind_benchmarks::BenchmarkSuiteInitOptionsV1>,
) -> impl IntoResponse {
    let suite = hivemind_benchmarks::create_benchmark_suite(request);
    let verification = hivemind_benchmarks::verify_benchmark_suite(&suite);
    if !verification.valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": json_error(ErrorCode::InvalidRequest, "Benchmark suite is not valid"),
                "verification": verification
            })),
        )
            .into_response();
    }
    let suites_dir = benchmark_suites_dir(&state);
    match hivemind_benchmarks::write_benchmark_suite(&suites_dir, &suite) {
        Ok(path) => (
            StatusCode::OK,
            Json(json!({
                "schemaVersion": "hivemind.benchmark_suite_create_response.v1",
                "suitePath": path.display().to_string(),
                "suite": suite,
                "verification": verification
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to write benchmark suite: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_suites(State(state): State<AppState>) -> impl IntoResponse {
    let suites_dir = benchmark_suites_dir(&state);
    match hivemind_benchmarks::list_benchmark_suites(&suites_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to list benchmark suites: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_suite_by_id(
    State(state): State<AppState>,
    Path(suite_id): Path<String>,
) -> impl IntoResponse {
    let suites_dir = benchmark_suites_dir(&state);
    match hivemind_benchmarks::get_benchmark_suite(&suites_dir, &suite_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Benchmark suite was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read benchmark suite: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_verify_suite(
    Json(suite): Json<hivemind_benchmarks::BenchmarkSuiteV1>,
) -> Json<hivemind_benchmarks::BenchmarkSuiteVerificationV1> {
    Json(hivemind_benchmarks::verify_benchmark_suite(&suite))
}

async fn benchmark_pack_from_suite(
    Json(request): Json<hivemind_benchmarks::BenchmarkPackProjectionRequestV1>,
) -> Json<hivemind_benchmarks::BenchmarkPackProjectionV1> {
    Json(hivemind_benchmarks::benchmark_pack_projection(request))
}

async fn benchmark_verify_pack(
    Json(pack): Json<hivemind_benchmarks::BenchmarkPackV1>,
) -> Json<hivemind_benchmarks::BenchmarkPackVerificationV1> {
    Json(hivemind_benchmarks::verify_benchmark_pack(&pack))
}

fn benchmark_suites_dir(state: &AppState) -> PathBuf {
    state.evaluation_dir.join("suites")
}

async fn benchmark_create_challenge_commitment(
    State(state): State<AppState>,
    Json(request): Json<hivemind_benchmarks::ChallengeCommitmentInitOptionsV1>,
) -> impl IntoResponse {
    let commitment = hivemind_benchmarks::create_challenge_commitment(request);
    let verification = hivemind_benchmarks::verify_challenge_commitment(&commitment);
    if !verification.valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": json_error(ErrorCode::InvalidRequest, "Challenge commitment is not valid"),
                "verification": verification
            })),
        )
            .into_response();
    }
    let commitments_dir = benchmark_challenge_commitments_dir(&state);
    match hivemind_benchmarks::write_challenge_commitment(&commitments_dir, &commitment) {
        Ok(path) => (
            StatusCode::OK,
            Json(json!({
                "schemaVersion": "hivemind.challenge_commitment_create_response.v1",
                "commitmentPath": path.display().to_string(),
                "commitment": commitment,
                "verification": verification
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to write challenge commitment: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_challenge_commitments(State(state): State<AppState>) -> impl IntoResponse {
    let commitments_dir = benchmark_challenge_commitments_dir(&state);
    match hivemind_benchmarks::list_challenge_commitments(&commitments_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to list challenge commitments: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_challenge_commitment_by_id(
    State(state): State<AppState>,
    Path(commitment_id): Path<String>,
) -> impl IntoResponse {
    let commitments_dir = benchmark_challenge_commitments_dir(&state);
    match hivemind_benchmarks::get_challenge_commitment(&commitments_dir, &commitment_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Challenge commitment was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read challenge commitment: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn benchmark_verify_challenge_commitment(
    Json(commitment): Json<hivemind_benchmarks::ChallengeCommitmentV1>,
) -> Json<hivemind_benchmarks::ChallengeCommitmentVerificationV1> {
    Json(hivemind_benchmarks::verify_challenge_commitment(
        &commitment,
    ))
}

fn benchmark_challenge_commitments_dir(state: &AppState) -> PathBuf {
    state.evaluation_dir.join("challenges")
}

async fn eval_verify_manifest(
    Json(manifest): Json<hivemind_evals::EvalManifestV1>,
) -> Json<hivemind_evals::EvalManifestVerificationV1> {
    Json(hivemind_evals::verify_eval_manifest(&manifest))
}

async fn eval_verify_run(
    Json(run): Json<hivemind_evals::EvalRunV1>,
) -> Json<hivemind_evals::EvalRunVerificationV1> {
    Json(hivemind_evals::verify_eval_run(&run))
}

async fn eval_plan(
    Json(request): Json<hivemind_evals::EvalRunPlanningRequestV1>,
) -> Json<hivemind_evals::EvalRunPlanV1> {
    Json(hivemind_evals::eval_run_plan(
        &request.manifest,
        &request.run,
    ))
}

async fn eval_records(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_evals::list_eval_records(&state.eval_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn eval_record_by_id(
    State(state): State<AppState>,
    Path(record_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_evals::get_eval_record(&state.eval_dir, &record_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Eval record was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn miner_verify_profile(
    Json(request): Json<VerifyMinerProfileRequest>,
) -> Json<hivemind_miner::MinerProfileVerificationV1> {
    Json(hivemind_miner::verify_miner_profile(
        &request.profile,
        request.hardware_offer.as_ref(),
    ))
}

async fn miner_verify_heartbeat(
    Json(request): Json<VerifyMinerHeartbeatRequest>,
) -> Json<hivemind_miner::MinerHeartbeatVerificationV1> {
    Json(hivemind_miner::verify_miner_heartbeat(
        &request.heartbeat,
        request.profile.as_ref(),
    ))
}

async fn miner_verify_benchmark(
    Json(request): Json<VerifyMinerBenchmarkRequest>,
) -> Json<hivemind_miner::MinerBenchmarkVerificationV1> {
    Json(hivemind_miner::verify_miner_benchmark_result(
        &request.benchmark,
        request.profile.as_ref(),
        request.hardware_offer.as_ref(),
    ))
}

async fn miner_onboarding_plan(
    Json(request): Json<MinerOnboardingRequest>,
) -> Json<hivemind_miner::MinerOnboardingPlanV1> {
    Json(hivemind_miner::miner_onboarding_plan(
        &request.profile,
        &request.hardware_offer,
        &request.benchmarks,
    ))
}

async fn miner_dashboard(
    Json(input): Json<hivemind_miner::MinerDashboardInputV1>,
) -> Json<hivemind_miner::MinerDashboardSummaryV1> {
    Json(hivemind_miner::miner_dashboard_summary(input))
}

async fn miner_records(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_miner::list_miner_records(&state.miner_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn miner_record_by_id(
    State(state): State<AppState>,
    Path(record_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_miner::get_miner_record(&state.miner_dir, &record_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Miner record was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn research_verify_experiment(
    Json(experiment): Json<hivemind_research::ResearchExperimentV1>,
) -> Json<hivemind_research::ResearchExperimentVerificationV1> {
    Json(hivemind_research::verify_research_experiment(&experiment))
}

async fn research_reproduce(
    Json(request): Json<ResearchReproduceRequest>,
) -> Json<hivemind_research::ResearchReproductionPlanV1> {
    Json(hivemind_research::reproduction_plan(
        &request.experiment,
        request.runner.unwrap_or_else(|| "local".to_string()),
    ))
}

async fn research_create_run(
    State(state): State<AppState>,
    Json(request): Json<ResearchCreateRunRequest>,
) -> impl IntoResponse {
    let run = hivemind_research::create_research_experiment_run(
        &request.experiment,
        hivemind_research::ResearchExperimentRunInitOptionsV1 {
            requester: request.requester,
            runner: request.runner,
            status: request.status,
            receipt_refs: request.receipt_refs,
            evaluation_result_refs: request.evaluation_result_refs,
            validation_report_refs: request.validation_report_refs,
            output_refs: request.output_refs,
            cost: None,
            notes: request.notes,
            metadata: request.metadata,
        },
    );
    let verification =
        hivemind_research::verify_research_experiment_run(&run, Some(&request.experiment));
    if !verification.valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": json_error(ErrorCode::InvalidRequest, "Research run is not valid"),
                "run": run,
                "verification": verification
            })),
        )
            .into_response();
    }
    match hivemind_research::write_research_experiment_run(&state.research_dir, &run) {
        Ok(path) => (
            StatusCode::OK,
            Json(json!(ResearchCreateRunResponse {
                run_path: path.display().to_string(),
                run,
                verification,
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(ErrorCode::ExecutionFailed, &error.to_string())),
        )
            .into_response(),
    }
}

async fn research_verify_run(
    Json(request): Json<ResearchVerifyRunRequest>,
) -> Json<hivemind_research::ResearchExperimentRunVerificationV1> {
    Json(hivemind_research::verify_research_experiment_run(
        &request.run,
        request.experiment.as_ref(),
    ))
}

async fn research_verify_evaluation_run_v2(
    Json(run): Json<hivemind_research::EvaluationRunV2>,
) -> Json<hivemind_research::EvaluationRunV2VerificationV1> {
    Json(hivemind_research::verify_evaluation_run_v2(&run))
}

async fn research_verify_result_record(
    Json(record): Json<hivemind_research::ResearchResultRecordV1>,
) -> Json<hivemind_research::ResearchResultRecordVerificationV1> {
    Json(hivemind_research::verify_research_result_record(&record))
}

async fn research_create_reproducibility_bundle(
    Json(request): Json<hivemind_research::ReproducibilityBundleInitOptionsV1>,
) -> impl IntoResponse {
    let bundle = hivemind_research::create_reproducibility_bundle(request);
    let verification = hivemind_research::verify_reproducibility_bundle(&bundle);
    let status = if verification.valid {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (
        status,
        Json(json!({
            "schemaVersion": "hivemind.reproducibility_bundle_create_response.v1",
            "bundle": bundle,
            "verification": verification
        })),
    )
        .into_response()
}

async fn research_verify_reproducibility_bundle(
    Json(bundle): Json<hivemind_research::ReproducibilityBundleV1>,
) -> Json<hivemind_research::ReproducibilityBundleVerificationV1> {
    Json(hivemind_research::verify_reproducibility_bundle(&bundle))
}

async fn research_runs(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_research::list_research_experiment_runs(&state.research_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn research_run_by_id(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_research::get_research_experiment_run(&state.research_dir, &run_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Research run was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn research_experiments(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_research::list_research_experiments(&state.research_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn research_experiment_by_id(
    State(state): State<AppState>,
    Path(experiment_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_research::get_research_experiment(&state.research_dir, &experiment_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Research experiment was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn vector_verify_store(
    Json(manifest): Json<hivemind_vector::VectorStoreManifestV1>,
) -> Json<hivemind_vector::VectorStoreVerificationV1> {
    Json(hivemind_vector::verify_vector_store_manifest(&manifest))
}

async fn vector_verify_document_collection(
    Json(manifest): Json<hivemind_vector::DocumentCollectionManifestV1>,
) -> Json<hivemind_vector::KnowledgeAssetVerificationV1> {
    Json(hivemind_vector::verify_document_collection_manifest(
        &manifest,
    ))
}

async fn vector_verify_chunk_set(
    Json(manifest): Json<hivemind_vector::ChunkSetManifestV1>,
) -> Json<hivemind_vector::KnowledgeAssetVerificationV1> {
    Json(hivemind_vector::verify_chunk_set_manifest(&manifest))
}

async fn vector_verify_embedding_set(
    Json(manifest): Json<hivemind_vector::EmbeddingSetManifestV1>,
) -> Json<hivemind_vector::KnowledgeAssetVerificationV1> {
    Json(hivemind_vector::verify_embedding_set_manifest(&manifest))
}

async fn vector_verify_index_v2(
    Json(manifest): Json<hivemind_vector::VectorIndexManifestV2>,
) -> Json<hivemind_vector::KnowledgeAssetVerificationV1> {
    Json(hivemind_vector::verify_vector_index_manifest_v2(&manifest))
}

async fn vector_retrieval_plan(
    Json(request): Json<hivemind_vector::RetrievalPlanningRequestV1>,
) -> Json<hivemind_vector::RetrievalPlanV1> {
    Json(hivemind_vector::retrieval_plan(&request))
}

async fn vector_verify_rag_pipeline_v2(
    Json(manifest): Json<hivemind_vector::RagPipelineManifestV2>,
) -> Json<hivemind_vector::KnowledgeAssetVerificationV1> {
    Json(hivemind_vector::verify_rag_pipeline_manifest_v2(&manifest))
}

async fn vector_verify_citation_trace(
    Json(trace): Json<hivemind_vector::CitationTraceV1>,
) -> Json<hivemind_vector::KnowledgeAssetVerificationV1> {
    Json(hivemind_vector::verify_citation_trace(&trace))
}

async fn vector_search_plan(
    Json(request): Json<hivemind_vector::VectorSearchPlanningRequestV1>,
) -> Json<hivemind_vector::VectorSearchPlanV1> {
    Json(hivemind_vector::vector_search_plan(
        &request.manifest,
        &request.request,
    ))
}

async fn vector_stores(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_vector::list_vector_store_manifests(&state.vector_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn vector_store_by_id(
    State(state): State<AppState>,
    Path(vector_store_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_vector::get_vector_store_manifest(&state.vector_dir, &vector_store_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Vector store manifest was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn workflow_verify_tool(
    Json(tool): Json<hivemind_workflow::ToolManifestV1>,
) -> Json<hivemind_workflow::ToolManifestVerificationV1> {
    Json(hivemind_workflow::verify_tool_manifest(&tool))
}

async fn workflow_verify_workflow(
    Json(workflow): Json<hivemind_workflow::WorkflowManifestV1>,
) -> Json<hivemind_workflow::WorkflowManifestVerificationV1> {
    Json(hivemind_workflow::verify_workflow_manifest(&workflow))
}

async fn workflow_plan(
    Json(request): Json<hivemind_workflow::WorkflowPlanRequestV1>,
) -> Json<hivemind_workflow::WorkflowPlanV1> {
    Json(hivemind_workflow::workflow_plan(&request.workflow))
}

async fn workflow_records(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_workflow::list_workflow_records(&state.workflow_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn workflow_record_by_id(
    State(state): State<AppState>,
    Path(record_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_workflow::get_workflow_record(&state.workflow_dir, &record_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Workflow record was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn batch_verify_job(
    Json(job): Json<hivemind_batch::BatchJobV1>,
) -> Json<hivemind_batch::BatchJobVerificationV1> {
    Json(hivemind_batch::verify_batch_job(&job))
}

async fn batch_plan(
    Json(job): Json<hivemind_batch::BatchJobV1>,
) -> Json<hivemind_batch::BatchExecutionPlanV1> {
    Json(hivemind_batch::batch_execution_plan(&job))
}

async fn batch_jobs(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_batch::list_batch_jobs(&state.batch_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn batch_job_by_id(
    State(state): State<AppState>,
    Path(batch_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_batch::get_batch_job(&state.batch_dir, &batch_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Batch job was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn fine_tune_verify_job(
    Json(job): Json<hivemind_fine_tune::FineTuneJobV1>,
) -> Json<hivemind_fine_tune::FineTuneJobVerificationV1> {
    Json(hivemind_fine_tune::verify_fine_tune_job(&job))
}

async fn fine_tune_plan(
    Json(job): Json<hivemind_fine_tune::FineTuneJobV1>,
) -> Json<hivemind_fine_tune::FineTuneExecutionPlanV1> {
    Json(hivemind_fine_tune::fine_tune_execution_plan(&job))
}

async fn fine_tune_jobs(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_fine_tune::list_fine_tune_jobs(&state.fine_tune_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn fine_tune_job_by_id(
    State(state): State<AppState>,
    Path(fine_tune_job_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_fine_tune::get_fine_tune_job(&state.fine_tune_dir, &fine_tune_job_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Fine-tune job was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn realtime_verify_session(
    Json(session): Json<hivemind_realtime::RealtimeSessionV1>,
) -> Json<hivemind_realtime::RealtimeSessionVerificationV1> {
    Json(hivemind_realtime::verify_realtime_session(&session))
}

async fn realtime_plan(
    Json(session): Json<hivemind_realtime::RealtimeSessionV1>,
) -> Json<hivemind_realtime::RealtimeConnectionPlanV1> {
    Json(hivemind_realtime::realtime_connection_plan(&session))
}

async fn realtime_sessions(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_realtime::list_realtime_sessions(&state.realtime_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn realtime_session_by_id(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_realtime::get_realtime_session(&state.realtime_dir, &session_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Realtime session was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn media_verify_job(
    Json(job): Json<hivemind_media::MediaJobV1>,
) -> Json<hivemind_media::MediaJobVerificationV1> {
    Json(hivemind_media::verify_media_job(&job))
}

async fn media_plan(
    Json(job): Json<hivemind_media::MediaJobV1>,
) -> Json<hivemind_media::MediaExecutionPlanV1> {
    Json(hivemind_media::media_execution_plan(&job))
}

async fn media_jobs(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_media::list_media_jobs(&state.media_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn media_job_by_id(
    State(state): State<AppState>,
    Path(media_job_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_media::get_media_job(&state.media_dir, &media_job_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Media job was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn moderation_verify_policy(
    Json(policy): Json<hivemind_moderation::ModerationPolicyManifestV1>,
) -> Json<hivemind_moderation::ModerationPolicyVerificationV1> {
    Json(hivemind_moderation::verify_moderation_policy(&policy))
}

async fn moderation_verify_request(
    Json(request): Json<hivemind_moderation::ModerationRequestV1>,
) -> Json<hivemind_moderation::ModerationRequestVerificationV1> {
    Json(hivemind_moderation::verify_moderation_request(&request))
}

async fn moderation_plan(
    Json(request): Json<hivemind_moderation::ModerationPlanRequestV1>,
) -> Json<hivemind_moderation::ModerationPlanV1> {
    Json(hivemind_moderation::moderation_plan_from_request(&request))
}

async fn moderation_records(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_moderation::list_moderation_records(&state.moderation_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn moderation_record_by_id(
    State(state): State<AppState>,
    Path(record_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_moderation::get_moderation_record(&state.moderation_dir, &record_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Moderation record was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn governance_verify_policy(
    Json(policy): Json<hivemind_governance::GovernancePolicyManifestV1>,
) -> Json<hivemind_governance::GovernancePolicyVerificationV1> {
    Json(hivemind_governance::verify_governance_policy(&policy))
}

async fn governance_verify_schema_release(
    Json(release): Json<hivemind_governance::SchemaReleaseV1>,
) -> Json<hivemind_governance::SchemaReleaseVerificationV1> {
    Json(hivemind_governance::verify_schema_release(&release))
}

async fn governance_verify_advisory(
    Json(advisory): Json<hivemind_governance::SecurityAdvisoryV1>,
) -> Json<hivemind_governance::SecurityAdvisoryVerificationV1> {
    Json(hivemind_governance::verify_security_advisory(&advisory))
}

async fn governance_verify_readiness(
    Json(readiness): Json<hivemind_governance::ComponentReadinessV1>,
) -> Json<hivemind_governance::ComponentReadinessVerificationV1> {
    Json(hivemind_governance::verify_component_readiness(&readiness))
}

async fn governance_security_response_plan(
    Json(advisory): Json<hivemind_governance::SecurityAdvisoryV1>,
) -> Json<hivemind_governance::SecurityResponsePlanV1> {
    Json(hivemind_governance::security_response_plan(&advisory))
}

async fn governance_records(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_governance::list_governance_records(&state.governance_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn governance_record_by_id(
    State(state): State<AppState>,
    Path(record_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_governance::get_governance_record(&state.governance_dir, &record_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Governance record was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn browser_capabilities() -> Json<hivemind_browser_runner::BrowserCapabilitiesV1> {
    Json(hivemind_browser_runner::default_browser_capabilities())
}

async fn browser_assess(
    Json(manifest): Json<hivemind_core::PackageManifestV1>,
) -> Json<hivemind_browser_runner::BrowserRunAssessmentV1> {
    Json(hivemind_browser_runner::assess_package(
        &manifest,
        &hivemind_browser_runner::default_browser_capabilities(),
        None,
    ))
}

async fn browser_execute(
    State(state): State<AppState>,
    Json(request): Json<ExecutionRequestV1>,
) -> impl IntoResponse {
    let Some(package) = find_package(&state.packages, &request.package_ref, &request.package_id)
    else {
        let response = ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::PackageNotFound,
                "Package is not in the local registry",
            ),
            Default::default(),
        );
        return (StatusCode::NOT_FOUND, Json(response)).into_response();
    };
    let package = package_for_request(package, &request.package_ref);
    let response = hivemind_browser_runner::execute_manifest_with_hash(
        &package.manifest,
        package.package_ref.clone(),
        package.manifest_hash.clone(),
        request,
        &hivemind_browser_runner::default_browser_capabilities(),
    );
    (StatusCode::OK, Json(response)).into_response()
}

async fn remote_capabilities() -> Json<hivemind_core::RunnerCapabilityV1> {
    Json(hivemind_core::runner_capability_from_descriptor(
        &hivemind_remote_runner::default_descriptor(),
    ))
}

async fn remote_health() -> Json<hivemind_remote_runner::RemoteRunnerHealthV1> {
    Json(hivemind_remote_runner::health(
        &hivemind_remote_runner::default_descriptor(),
        &[],
    ))
}

async fn remote_prepare(
    State(state): State<AppState>,
    Json(request): Json<ExecutionRequestV1>,
) -> impl IntoResponse {
    let Some(package) = find_package(&state.packages, &request.package_ref, &request.package_id)
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Package is not in the local registry",
            )),
        )
            .into_response();
    };
    let package = package_for_request(package, &request.package_ref);
    match hivemind_remote_runner::prepare_manifest(
        &package.manifest,
        package.package_ref,
        package.manifest_hash,
        &hivemind_remote_runner::default_descriptor(),
        request.preferred_artifact_group.as_deref(),
    ) {
        Ok(prepared) => (StatusCode::OK, Json(json!(prepared))).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!(error))).into_response(),
    }
}

async fn remote_execute(
    State(state): State<AppState>,
    Json(request): Json<ExecutionRequestV1>,
) -> impl IntoResponse {
    let Some(package) = find_package(&state.packages, &request.package_ref, &request.package_id)
    else {
        let response = ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::PackageNotFound,
                "Package is not in the local registry",
            ),
            Default::default(),
        );
        return (StatusCode::NOT_FOUND, Json(response)).into_response();
    };
    let package = package_for_request(package, &request.package_ref);
    let response = hivemind_remote_runner::execute_manifest_with_hash(
        &package.manifest,
        package.package_ref,
        package.manifest_hash,
        request,
        &hivemind_remote_runner::default_descriptor(),
    );
    (StatusCode::OK, Json(response)).into_response()
}

async fn remote_cancel(
    Json(request): Json<hivemind_remote_runner::RemoteCancelRequestV1>,
) -> Json<hivemind_remote_runner::RemoteCancelResultV1> {
    Json(hivemind_remote_runner::cancel(request))
}

async fn browser_swarm_descriptor() -> Json<hivemind_weeb3_adapter::Weeb3AdapterDescriptorV1> {
    Json(hivemind_weeb3_adapter::descriptor())
}

async fn browser_swarm_status(
    State(state): State<AppState>,
) -> Json<hivemind_weeb3_adapter::BrowserSwarmStatusV1> {
    let mut provider = browser_swarm_provider(&state.storage_dir);
    Json(provider.start())
}

async fn browser_swarm_compatibility(
    State(state): State<AppState>,
) -> Json<hivemind_weeb3_adapter::BrowserSwarmCompatibilityReportV1> {
    let mut provider = browser_swarm_provider(&state.storage_dir);
    provider.start();
    Json(provider.compatibility_report())
}

async fn browser_swarm_file(
    State(state): State<AppState>,
    Json(request): Json<hivemind_weeb3_adapter::BrowserSwarmRetrieveRequestV1>,
) -> impl IntoResponse {
    let Some(path) = request.path.as_deref() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                "browser-swarm file retrieval requires path",
            )),
        )
            .into_response();
    };
    let mut provider = browser_swarm_provider(&state.storage_dir);
    provider.start();
    match provider.download_file_with_report(&request.reference, path) {
        Ok((response, retrieval)) => (
            StatusCode::OK,
            Json(json!(hivemind_weeb3_adapter::encode_file_result(
                response, retrieval
            ))),
        )
            .into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!(error))).into_response(),
    }
}

async fn browser_swarm_manifest(
    State(state): State<AppState>,
    Json(request): Json<hivemind_weeb3_adapter::BrowserSwarmRetrieveRequestV1>,
) -> impl IntoResponse {
    let mut provider = browser_swarm_provider(&state.storage_dir);
    provider.start();
    match provider.download_manifest_with_report(&request.reference) {
        Ok((manifest, retrieval)) => (
            StatusCode::OK,
            Json(json!(
                hivemind_weeb3_adapter::BrowserSwarmManifestResultV1 {
                    schema_version: "swarm-ai.browser-swarm-manifest-result.v1".to_string(),
                    manifest,
                    retrieval,
                }
            )),
        )
            .into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!(error))).into_response(),
    }
}

async fn capabilities() -> Json<hivemind_core::RunnerCapabilityV1> {
    Json(hivemind_core::runner_capability_from_descriptor(
        &hivemind_local_runner::descriptor(),
    ))
}

async fn local_runner_cache(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_local_runner::list_cache(&state.runner_cache_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list local runner cache: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn clear_local_runner_cache(
    State(state): State<AppState>,
    Path(package_ref): Path<String>,
) -> impl IntoResponse {
    match hivemind_local_runner::clear_cache(&state.runner_cache_dir, &package_ref) {
        Ok(result) => (StatusCode::OK, Json(json!(result))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to clear local runner cache: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn marketplace_listings(State(state): State<AppState>) -> Json<Vec<MarketplaceListingV1>> {
    Json(marketplace_listings_from_packages_and_store(
        state.packages.as_ref().as_slice(),
        state.marketplace_listing_dir.as_ref().as_path(),
    ))
}

async fn marketplace_listings_v2(
    State(state): State<AppState>,
) -> Json<Vec<hivemind_marketplace::MarketplaceListingV2>> {
    Json(
        marketplace_listings_from_packages_and_store(
            state.packages.as_ref().as_slice(),
            state.marketplace_listing_dir.as_ref().as_path(),
        )
        .iter()
        .map(hivemind_marketplace::marketplace_listing_v2_from_v1)
        .collect(),
    )
}

async fn marketplace_project_listing_v2(
    Json(listing): Json<hivemind_marketplace::MarketplaceListingV1>,
) -> Json<hivemind_marketplace::MarketplaceListingV2> {
    Json(hivemind_marketplace::marketplace_listing_v2_from_v1(
        &listing,
    ))
}

async fn marketplace_verify_listing(
    Json(listing): Json<hivemind_marketplace::MarketplaceListingV1>,
) -> Json<hivemind_marketplace::MarketplaceListingVerificationV1> {
    Json(hivemind_marketplace::verify_marketplace_listing(&listing))
}

async fn marketplace_verify_listing_v2(
    Json(listing): Json<hivemind_marketplace::MarketplaceListingV2>,
) -> Json<hivemind_marketplace::MarketplaceListingV2VerificationV1> {
    Json(hivemind_marketplace::verify_marketplace_listing_v2(
        &listing,
    ))
}

fn access_policy_v2_for_marketplace_listing(
    listing: &hivemind_marketplace::MarketplaceListingV2,
) -> Result<hivemind_core::AccessPolicyV2, String> {
    if let Ok(policy) =
        serde_json::from_value::<hivemind_core::AccessPolicyV2>(listing.access_policy.clone())
    {
        let verification = hivemind_core::verify_access_policy_v2(&policy);
        if verification.valid {
            return Ok(policy);
        }
    }
    let package_ref = listing.subject.subject_ref.trim();
    if package_ref.is_empty() {
        return Err("Marketplace listing subjectRef is required for paid access".to_string());
    }
    let license_type = license_type_for_marketplace_paid_access(listing);
    let requires_access_grant =
        listing.price_model.base_price > 0.0 || !matches!(license_type, LicenseType::Open);
    let license_policy = hivemind_core::LicensePolicyV1 {
        schema_version: "swarm-ai.license-policy.v1".to_string(),
        package_id: listing
            .subject
            .package_id
            .clone()
            .unwrap_or_else(|| format!("marketplace/{}", listing.listing_id)),
        package_ref: package_ref.to_string(),
        license_type: license_type.clone(),
        allowed_uses: allowed_uses_for_marketplace_listing(listing),
        restricted_uses: vec!["redistribution".to_string()],
        requires_access_grant,
        terms_ref: listing.description_ref.clone(),
        access_control: hivemind_core::AccessControlV1 {
            mode: if requires_access_grant {
                hivemind_core::AccessControlMode::EncryptedRef
            } else {
                hivemind_core::AccessControlMode::None
            },
            act_ref: None,
        },
    };
    let mut policy = hivemind_core::access_policy_v2_from_license_policy(&license_policy);
    let settlement_ref = json_path_str(&listing.settlement_terms, &["settlementRef"])
        .or_else(|| json_path_str(&listing.settlement_terms, &["settlement", "settlementRef"]))
        .map(str::to_string);
    policy.payment_requirement.required = listing.price_model.base_price > 0.0
        || matches!(
            listing.price_model.mode,
            hivemind_marketplace::PricingMode::PayPerCall
                | hivemind_marketplace::PricingMode::PayPerToken
                | hivemind_marketplace::PricingMode::Subscription
                | hivemind_marketplace::PricingMode::Quote
        );
    policy.payment_requirement.asset = Some(listing.price_model.currency.clone());
    policy.payment_requirement.amount = Some(listing.price_model.base_price);
    policy.payment_requirement.settlement_ref = settlement_ref.clone();
    policy.settlement_ref = settlement_ref;
    policy.evidence_refs = listing.evidence_refs.clone();
    policy.policy_id = hivemind_core::canonical_access_policy_v2_id(&policy)
        .map_err(|error| format!("Failed to canonicalize listing access policy: {error}"))?;
    Ok(policy)
}

fn license_type_for_marketplace_paid_access(
    listing: &hivemind_marketplace::MarketplaceListingV2,
) -> LicenseType {
    if matches!(
        listing.listing_type,
        hivemind_marketplace::MarketplaceListingKindV2::PackageSubscription
    ) || matches!(
        listing.price_model.mode,
        hivemind_marketplace::PricingMode::Subscription
    ) {
        LicenseType::Subscription
    } else if listing.price_model.base_price <= 0.0
        && matches!(
            listing.price_model.mode,
            hivemind_marketplace::PricingMode::Free
        )
    {
        LicenseType::Open
    } else {
        LicenseType::Commercial
    }
}

fn allowed_uses_for_marketplace_listing(
    listing: &hivemind_marketplace::MarketplaceListingV2,
) -> Vec<String> {
    match listing.listing_type {
        hivemind_marketplace::MarketplaceListingKindV2::DatasetLicense => {
            vec!["research".to_string(), "validation".to_string()]
        }
        hivemind_marketplace::MarketplaceListingKindV2::BenchmarkBounty
        | hivemind_marketplace::MarketplaceListingKindV2::ResearchGrant => {
            vec!["research".to_string(), "validation".to_string()]
        }
        _ => vec![
            "commercial".to_string(),
            "runner-service".to_string(),
            "validation".to_string(),
        ],
    }
}

fn requested_use_for_marketplace_listing(
    listing: &hivemind_marketplace::MarketplaceListingV2,
) -> &'static str {
    match listing.listing_type {
        hivemind_marketplace::MarketplaceListingKindV2::DatasetLicense
        | hivemind_marketplace::MarketplaceListingKindV2::BenchmarkBounty
        | hivemind_marketplace::MarketplaceListingKindV2::ResearchGrant => "research",
        _ => "commercial",
    }
}

async fn marketplace_offers(State(state): State<AppState>) -> Json<Vec<RunnerOfferV1>> {
    Json(marketplace_offers_from_packages_and_store(
        state.packages.as_ref().as_slice(),
        state.marketplace_runner_offer_dir.as_ref().as_path(),
    ))
}

async fn marketplace_hardware_offers(
    State(state): State<AppState>,
) -> Json<Vec<HardwareResourceOfferV1>> {
    Json(hardware_resource_offers_from_store(
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    ))
}

async fn marketplace_shortlist(
    State(state): State<AppState>,
    Json(request): Json<hivemind_marketplace::MarketplaceShortlistRequestV1>,
) -> Json<hivemind_marketplace::MarketplaceShortlistV1> {
    let offers = marketplace_offers_from_packages_and_store(
        state.packages.as_ref().as_slice(),
        state.marketplace_runner_offer_dir.as_ref().as_path(),
    );
    Json(hivemind_marketplace::shortlist_runner_offers(
        &request, &offers,
    ))
}

async fn marketplace_verify_offer(
    Json(offer): Json<hivemind_marketplace::RunnerOfferV1>,
) -> Json<hivemind_marketplace::RunnerOfferVerificationV1> {
    Json(hivemind_marketplace::verify_runner_offer(&offer))
}

async fn marketplace_verify_hardware_offer(
    Json(offer): Json<hivemind_marketplace::HardwareResourceOfferV1>,
) -> Json<hivemind_marketplace::HardwareResourceOfferVerificationV1> {
    Json(hivemind_marketplace::verify_hardware_resource_offer(&offer))
}

async fn marketplace_quote(
    State(state): State<AppState>,
    Json(request): Json<ExecutionRequestV1>,
) -> impl IntoResponse {
    let offers = marketplace_offers_from_packages_and_store(
        state.packages.as_ref().as_slice(),
        state.marketplace_runner_offer_dir.as_ref().as_path(),
    );
    let Some(offer) = marketplace_offer_for_quote(&state.packages, &offers, &request) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                "No marketplace offer supports this request",
            )),
        )
            .into_response();
    };
    let Some(quote) = quote_execution(&request, &offer, None) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                "No marketplace offer supports this request",
            )),
        )
            .into_response();
    };
    (StatusCode::OK, Json(quote)).into_response()
}

async fn hivemind_runners() -> Json<Vec<RunnerCapabilityV1>> {
    Json(runner_capabilities())
}

async fn hivemind_runners_v2() -> Json<Vec<hivemind_core::RunnerCapabilityV2>> {
    Json(
        runner_capabilities()
            .iter()
            .map(hivemind_core::runner_capability_v2_from_v1)
            .collect(),
    )
}

async fn hivemind_resolve(
    State(state): State<AppState>,
    Json(request): Json<HivemindPackageSelectorRequest>,
) -> impl IntoResponse {
    let lookup_request = registry_lookup_request_from_hivemind_selector(&request);
    match registry_package_lookup_for_request(
        &state.packages,
        &state.registry_snapshot,
        &lookup_request,
    ) {
        Some(lookup) => {
            let response = HivemindResolveResponse {
                schema_version: "swarm-ai.hivemind.resolve.v1".to_string(),
                selected_package_id: lookup.package_id.clone(),
                selected_package_ref: lookup.local_package_ref.clone(),
                manifest_hash: lookup.manifest_hash.clone(),
                lookup,
            };
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Package could not be resolved or is not authorized",
            )),
        )
            .into_response(),
    }
}

async fn hivemind_policy_evaluate(
    State(state): State<AppState>,
    Json(request): Json<HivemindPackageSelectorRequest>,
) -> impl IntoResponse {
    let lookup_request = registry_lookup_request_from_hivemind_selector(&request);
    let Some(lookup) = registry_package_lookup_for_request(
        &state.packages,
        &state.registry_snapshot,
        &lookup_request,
    ) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Package could not be resolved or is not authorized",
            )),
        )
            .into_response();
    };

    let runner_id = request
        .runner_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let requester = request
        .requester
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("api-requester");
    let requested_use = request
        .requested_use
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("personal");
    let policy_inspection = hivemind_policy::inspect_package_policy(
        &lookup.manifest,
        lookup.local_package_ref.clone(),
        runner_id.clone(),
    );
    let access_evaluation = hivemind_access::evaluate_execution_access_with_revocations(
        &lookup.manifest,
        &lookup.local_package_ref,
        "api-policy-evaluation",
        requester,
        requested_use,
        runner_id.as_deref(),
        request.access_grant.as_ref(),
        request.access_revocation_list.as_ref(),
    );
    let execution_allowed = matches!(
        policy_inspection.policy_decision.decision,
        hivemind_core::PolicyDecision::Allow
    ) && matches!(access_evaluation.decision, AccessDecision::Granted);
    let response = HivemindPolicyEvaluationResponse {
        schema_version: "swarm-ai.hivemind.policy-evaluation.v1".to_string(),
        package_id: lookup.package_id,
        package_ref: lookup.local_package_ref,
        runner_id,
        execution_allowed,
        policy_inspection,
        access_evaluation,
    };
    (StatusCode::OK, Json(json!(response))).into_response()
}

async fn hivemind_jobs(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_jobs::list_job_records(state.job_dir.as_ref().as_path()) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list jobs: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn hivemind_job_by_id(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_jobs::get_job_record(state.job_dir.as_ref().as_path(), &job_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(ErrorCode::PackageNotFound, "Job was not found")),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read job: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn hivemind_job_timeline(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_jobs::get_job_record(state.job_dir.as_ref().as_path(), &job_id) {
        Ok(Some(lookup)) => (
            StatusCode::OK,
            Json(json!(hivemind_jobs::job_lifecycle_timeline(&lookup.record))),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(ErrorCode::PackageNotFound, "Job was not found")),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read job timeline: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn hivemind_job_lifecycle(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_jobs::get_job_record(state.job_dir.as_ref().as_path(), &job_id) {
        Ok(Some(lookup)) => (
            StatusCode::OK,
            Json(json!(hivemind_jobs::job_production_lifecycle(
                &lookup.record
            ))),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(ErrorCode::PackageNotFound, "Job was not found")),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read job lifecycle: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn hivemind_link_job_evidence(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Json(request): Json<hivemind_jobs::JobEvidenceLinkRequestV1>,
) -> impl IntoResponse {
    if request.job_id != job_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                "Path jobId does not match evidence link request",
            )),
        )
            .into_response();
    }
    match hivemind_jobs::link_job_evidence(
        state.job_dir.as_ref().as_path(),
        &request,
        hivemind_jobs::now_timestamp(),
    ) {
        Ok(Some(result)) => (StatusCode::OK, Json(json!(result))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(ErrorCode::PackageNotFound, "Job was not found")),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to link job evidence: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn hivemind_expire_jobs(
    State(state): State<AppState>,
    Json(request): Json<hivemind_jobs::JobExpirationSweepRequestV1>,
) -> impl IntoResponse {
    match hivemind_jobs::expire_stale_job_records(state.job_dir.as_ref().as_path(), &request) {
        Ok(result) => (StatusCode::OK, Json(json!(result))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to expire stale jobs: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn hivemind_audit_jobs(
    State(state): State<AppState>,
    Json(request): Json<hivemind_jobs::JobStoreAuditRequestV1>,
) -> impl IntoResponse {
    match hivemind_jobs::audit_job_store(state.job_dir.as_ref().as_path(), &request) {
        Ok(result) => (StatusCode::OK, Json(json!(result))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to audit jobs: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn hivemind_audit_job_lifecycles(
    State(state): State<AppState>,
    Json(request): Json<hivemind_jobs::JobStoreAuditRequestV1>,
) -> impl IntoResponse {
    match hivemind_jobs::audit_job_production_lifecycles(state.job_dir.as_ref().as_path(), &request)
    {
        Ok(result) => (StatusCode::OK, Json(json!(result))).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to audit job production lifecycles: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn hivemind_create_job(
    State(state): State<AppState>,
    Json(request): Json<ExecutionRequestV1>,
) -> impl IntoResponse {
    let order = job_order_from_execution_request(&request, "local-dev", ApiSurface::HivemindNative);
    let record =
        hivemind_jobs::job_record_from_order(order.clone(), hivemind_jobs::now_timestamp());
    match hivemind_jobs::upsert_job_record(state.job_dir.as_ref().as_path(), record) {
        Ok(_) => (StatusCode::OK, Json(json!(order))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to store job: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn hivemind_job_quotes(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Json(order): Json<JobOrderV1>,
) -> impl IntoResponse {
    if order.job_id != job_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                "Path jobId does not match job order",
            )),
        )
            .into_response();
    }
    quote_response_with_job_store(state.job_dir.as_ref().as_path(), order)
}

async fn swarm_ai_job_quote(
    State(state): State<AppState>,
    Json(order): Json<JobOrderV1>,
) -> impl IntoResponse {
    quote_response_with_job_store(state.job_dir.as_ref().as_path(), order)
}

async fn hivemind_lease(
    State(state): State<AppState>,
    Json(request): Json<ExecutionLeaseRequestV1>,
) -> impl IntoResponse {
    match execution_lease_from_request(&request) {
        Ok(lease) => {
            let record = hivemind_jobs::job_record_with_lease(
                &request,
                lease.clone(),
                hivemind_jobs::now_timestamp(),
            );
            match hivemind_jobs::upsert_job_record(state.job_dir.as_ref().as_path(), record) {
                Ok(_) => (StatusCode::OK, Json(json!(lease))).into_response(),
                Err(error) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json_error(
                        ErrorCode::ExecutionFailed,
                        &format!("Failed to store job lease: {error}"),
                    )),
                )
                    .into_response(),
            }
        }
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!(error))).into_response(),
    }
}

async fn hivemind_cancel_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Json(request): Json<hivemind_jobs::JobCancellationRequestV1>,
) -> impl IntoResponse {
    if request.job_id != job_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                "Path jobId does not match cancellation request",
            )),
        )
            .into_response();
    }
    let mut result = match hivemind_jobs::cancel_job_record(
        state.job_dir.as_ref().as_path(),
        &request,
        hivemind_jobs::now_timestamp(),
    ) {
        Ok(Some(result)) => result,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json_error(ErrorCode::PackageNotFound, "Job was not found")),
            )
                .into_response();
        }
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json_error(
                    ErrorCode::InvalidRequest,
                    &format!("Failed to cancel job: {error}"),
                )),
            )
                .into_response();
        }
    };
    if result.transitioned {
        persist_job_cancellation_stream_event(
            state.job_dir.as_ref().as_path(),
            state.stream_event_dir.as_ref().as_path(),
            &mut result,
        );
    }
    (StatusCode::OK, Json(json!(result))).into_response()
}

async fn hivemind_job_stream(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
    Query(query): Query<JobStreamQuery>,
) -> impl IntoResponse {
    let events = match hivemind_streams::read_stream_events(
        state.stream_event_dir.as_ref().as_path(),
        &job_id,
    ) {
        Ok(Some(events)) => events,
        Ok(None) => development_job_stream_events(&job_id),
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json_error(
                    ErrorCode::ExecutionFailed,
                    &format!("Failed to read stream events: {error}"),
                )),
            )
                .into_response();
        }
    };
    if wants_sse(query.format.as_deref()) {
        return native_stream_event_response(&events, &job_id);
    }
    Json(events).into_response()
}

async fn hivemind_job_partial_receipts(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> impl IntoResponse {
    partial_receipts_by_stream_key_response(&state, &job_id)
}

fn development_job_stream_events(job_id: &str) -> Vec<hivemind_core::StreamingEventV1> {
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    vec![streaming_event(
        job_id.to_string(),
        Some(job_id.to_string()),
        0,
        StreamingEventType::Heartbeat,
        timestamp,
        json!({
            "status": "no-live-stream-store",
            "message": "This development endpoint exposes the StreamingEventV1 contract; live stream persistence is not enabled."
        }),
    )]
}

fn wants_sse(format: Option<&str>) -> bool {
    format
        .map(str::trim)
        .map(|format| {
            format.eq_ignore_ascii_case("sse")
                || format.eq_ignore_ascii_case("event-stream")
                || format.eq_ignore_ascii_case("text/event-stream")
        })
        .unwrap_or(false)
}

async fn hivemind_validation_by_id(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
) -> impl IntoResponse {
    validator_report_lookup_response(&state, &report_id)
}

async fn hivemind_marketplace_listings(
    State(state): State<AppState>,
) -> Json<Vec<MarketplaceListingV1>> {
    Json(marketplace_listings_from_packages_and_store(
        state.packages.as_ref().as_slice(),
        state.marketplace_listing_dir.as_ref().as_path(),
    ))
}

async fn hivemind_marketplace_listings_v2(
    State(state): State<AppState>,
) -> Json<Vec<hivemind_marketplace::MarketplaceListingV2>> {
    Json(
        marketplace_listings_from_packages_and_store(
            state.packages.as_ref().as_slice(),
            state.marketplace_listing_dir.as_ref().as_path(),
        )
        .iter()
        .map(hivemind_marketplace::marketplace_listing_v2_from_v1)
        .collect(),
    )
}

fn registry_lookup_request_from_hivemind_selector(
    request: &HivemindPackageSelectorRequest,
) -> hivemind_registry::RegistryPackageLookupRequestV1 {
    let mut package_ref = trim_optional_string(request.package_ref.as_deref());
    let mut package_id = trim_optional_string(request.package_id.as_deref());
    if package_ref.is_none()
        && package_id.is_none()
        && let Some(model) = trim_optional_string(request.model.as_deref())
    {
        if looks_like_storage_ref(&model) {
            package_ref = Some(model);
        } else {
            package_id = Some(model);
        }
    }

    hivemind_registry::RegistryPackageLookupRequestV1 {
        schema_version: request
            .schema_version
            .clone()
            .unwrap_or_else(|| "swarm-ai.registry.package-lookup-request.v1".to_string()),
        package_id,
        package_ref,
        requester: trim_optional_string(request.requester.as_deref()),
        requested_use: trim_optional_string(request.requested_use.as_deref()),
        runner_id: trim_optional_string(request.runner_id.as_deref()),
        access_grant: request.access_grant.clone(),
        access_revocation_list: request.access_revocation_list.clone(),
    }
}

fn validator_report_lookup_response(state: &AppState, report_id: &str) -> axum::response::Response {
    match hivemind_validator::get_validation_report(
        state.validation_dir.as_ref().as_path(),
        report_id,
    ) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Validation report was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read validation report: {error}"),
            )),
        )
            .into_response(),
    }
}

fn validator_report_v2_lookup_response(
    state: &AppState,
    report_id: &str,
) -> axum::response::Response {
    match hivemind_validator::get_validation_report(
        state.validation_dir.as_ref().as_path(),
        report_id,
    ) {
        Ok(Some(lookup)) => {
            let report_v2 = hivemind_validator::validation_report_v2_from_v1(&lookup.report);
            (StatusCode::OK, Json(json!(report_v2))).into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Validation report was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read validation report: {error}"),
            )),
        )
            .into_response(),
    }
}

fn marketplace_listings_from_packages(packages: &[IndexedPackage]) -> Vec<MarketplaceListingV1> {
    packages
        .iter()
        .filter(|package| package.entry.license.license_type != LicenseType::Private)
        .filter_map(|package| listing_from_registry_entry(&package.entry, "local-market"))
        .collect()
}

fn marketplace_listings_from_packages_and_store(
    packages: &[IndexedPackage],
    listing_dir: &FsPath,
) -> Vec<MarketplaceListingV1> {
    let mut listings = marketplace_listings_from_packages(packages);
    if let Ok(stored) = load_marketplace_listings(listing_dir) {
        listings.extend(stored);
    }
    let mut by_id = BTreeMap::new();
    for listing in listings {
        by_id.insert(listing.listing_id.clone(), listing);
    }
    by_id.into_values().collect()
}

fn trim_optional_string(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn looks_like_storage_ref(value: &str) -> bool {
    value.starts_with("bzz://")
        || value.starts_with("local://")
        || value.starts_with("ipfs://")
        || value.starts_with("sha256://")
        || value.starts_with("https://")
}

fn quote_response_with_job_store(job_dir: &FsPath, order: JobOrderV1) -> axum::response::Response {
    let quotes = quotes_for_job_order(&order);
    if quotes.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::UnsupportedTarget,
                "No discovered runner can satisfy this job order",
            )),
        )
            .into_response();
    }
    let record = hivemind_jobs::job_record_with_quotes(
        order,
        quotes.clone(),
        hivemind_jobs::now_timestamp(),
    );
    match hivemind_jobs::upsert_job_record(job_dir, record) {
        Ok(_) => (StatusCode::OK, Json(json!(quotes))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to store job quotes: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn marketplace_verify_quote(
    Json(request): Json<MarketplaceVerifyQuoteRequest>,
) -> Json<hivemind_marketplace::ServiceQuoteVerificationV1> {
    Json(hivemind_marketplace::verify_service_quote(
        &request.quote,
        request.offer.as_ref(),
    ))
}

async fn marketplace_quotes(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_marketplace::list_service_quotes(state.marketplace_audit_dir.as_ref().as_path())
    {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list marketplace service quotes: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn marketplace_service_quote_by_id(
    State(state): State<AppState>,
    Path(quote_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_marketplace::get_service_quote(
        state.marketplace_audit_dir.as_ref().as_path(),
        &quote_id,
    ) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Marketplace service quote was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read marketplace service quote: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn marketplace_authorize_payment(
    State(state): State<AppState>,
    Json(request): Json<MarketplaceAuthorizePaymentRequest>,
) -> impl IntoResponse {
    let authorization = hivemind_marketplace::authorize_payment(
        &request.quote,
        request.payer,
        request.payee,
        request
            .adapter
            .unwrap_or(hivemind_marketplace::PaymentAdapterKind::LocalDev),
        request.payment_ref,
    );
    let verification =
        hivemind_marketplace::verify_payment_authorization(&authorization, Some(&request.quote));
    let status = if verification.valid {
        if let Err(error) = hivemind_marketplace::write_payment_authorization(
            state.marketplace_payment_dir.as_ref().as_path(),
            &authorization,
        ) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json_error(
                    ErrorCode::ExecutionFailed,
                    &format!("Failed to store payment authorization: {error}"),
                )),
            )
                .into_response();
        }
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (
        status,
        Json(json!(MarketplaceAuthorizePaymentResponse {
            authorization,
            verification,
        })),
    )
        .into_response()
}

async fn marketplace_payments(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_marketplace::list_payment_authorizations(
        state.marketplace_payment_dir.as_ref().as_path(),
    ) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list payment authorizations: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn marketplace_payment_by_id(
    State(state): State<AppState>,
    Path(authorization_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_marketplace::get_payment_authorization(
        state.marketplace_payment_dir.as_ref().as_path(),
        &authorization_id,
    ) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Payment authorization was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read payment authorization: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn marketplace_verify_payment(
    Json(request): Json<MarketplaceVerifyPaymentRequest>,
) -> Json<hivemind_marketplace::PaymentAuthorizationVerificationV1> {
    Json(hivemind_marketplace::verify_payment_authorization(
        &request.authorization,
        request.quote.as_ref(),
    ))
}

async fn marketplace_create_escrow(
    State(state): State<AppState>,
    Json(request): Json<MarketplaceCreateEscrowRequest>,
) -> impl IntoResponse {
    let escrow = hivemind_marketplace::create_escrow_record(
        &request.authorization,
        request.quote.as_ref(),
        request
            .custodian
            .unwrap_or_else(|| "local-market-escrow".to_string()),
        request.evidence_refs,
    );
    let verification = hivemind_marketplace::verify_escrow_record(
        &escrow,
        Some(&request.authorization),
        request.quote.as_ref(),
    );
    let status = if verification.valid {
        let escrows_dir = marketplace_escrows_dir(&state);
        if let Err(error) = hivemind_marketplace::write_escrow_record(&escrows_dir, &escrow) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json_error(
                    ErrorCode::ExecutionFailed,
                    &format!("Failed to store escrow record: {error}"),
                )),
            )
                .into_response();
        }
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (
        status,
        Json(json!(MarketplaceCreateEscrowResponse {
            escrow,
            verification,
        })),
    )
        .into_response()
}

async fn marketplace_verify_escrow(
    Json(request): Json<MarketplaceVerifyEscrowRequest>,
) -> Json<hivemind_marketplace::EscrowRecordVerificationV1> {
    Json(hivemind_marketplace::verify_escrow_record(
        &request.escrow,
        request.authorization.as_ref(),
        request.quote.as_ref(),
    ))
}

async fn marketplace_release_escrow(
    State(state): State<AppState>,
    Json(request): Json<hivemind_marketplace::EscrowReleaseRequestV1>,
) -> impl IntoResponse {
    let result = hivemind_marketplace::release_escrow_for_settlement(&request);
    let status = if result.valid {
        if let Some(escrow) = &result.escrow {
            let escrows_dir = marketplace_escrows_dir(&state);
            if let Err(error) = hivemind_marketplace::write_escrow_record(&escrows_dir, escrow) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json_error(
                        ErrorCode::ExecutionFailed,
                        &format!("Failed to store released escrow record: {error}"),
                    )),
                )
                    .into_response();
            }
        }
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, Json(json!(result))).into_response()
}

async fn marketplace_escrows(State(state): State<AppState>) -> impl IntoResponse {
    let escrows_dir = marketplace_escrows_dir(&state);
    match hivemind_marketplace::list_escrow_records(&escrows_dir) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list escrow records: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn marketplace_escrow_by_id(
    State(state): State<AppState>,
    Path(escrow_id): Path<String>,
) -> impl IntoResponse {
    let escrows_dir = marketplace_escrows_dir(&state);
    match hivemind_marketplace::get_escrow_record(&escrows_dir, &escrow_id) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Escrow record was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read escrow record: {error}"),
            )),
        )
            .into_response(),
    }
}

fn marketplace_escrows_dir(state: &AppState) -> PathBuf {
    state.marketplace_payment_dir.as_ref().join("escrows")
}

async fn marketplace_audit(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_marketplace::list_marketplace_audit(
        state.marketplace_audit_dir.as_ref().as_path(),
    ) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list marketplace audit records: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn marketplace_settlement_by_id(
    State(state): State<AppState>,
    Path(settlement_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_marketplace::get_settlement_event(
        state.marketplace_audit_dir.as_ref().as_path(),
        &settlement_id,
    ) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Settlement was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read settlement: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn marketplace_resolution_by_id(
    State(state): State<AppState>,
    Path(resolution_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_marketplace::get_settlement_resolution(
        state.marketplace_audit_dir.as_ref().as_path(),
        &resolution_id,
    ) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Settlement resolution was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read settlement resolution: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn marketplace_settle(
    State(state): State<AppState>,
    Json(request): Json<MarketplaceSettleRequest>,
) -> impl IntoResponse {
    let result = hivemind_marketplace::settlement_from_verified_receipt_with_payment(
        &request.receipt,
        request.quote.as_ref(),
        request.payment_authorization.as_ref(),
        request.payer,
        request.payee,
        request.receipt_ref,
    );
    let status = if result.verification.valid {
        if let Some(settlement) = &result.settlement
            && let Err(error) = hivemind_marketplace::write_settlement_event(
                state.marketplace_audit_dir.as_ref().as_path(),
                settlement,
            )
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json_error(
                    ErrorCode::ExecutionFailed,
                    &format!("Failed to store settlement audit record: {error}"),
                )),
            )
                .into_response();
        }
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, Json(json!(result))).into_response()
}

async fn marketplace_verify_settlement(
    Json(settlement): Json<hivemind_marketplace::SettlementEventV1>,
) -> Json<hivemind_marketplace::SettlementEventVerificationV1> {
    Json(hivemind_marketplace::verify_settlement_event(&settlement))
}

async fn marketplace_dispute_settlement(
    State(state): State<AppState>,
    Json(request): Json<MarketplaceSettlementResolutionRequest>,
) -> impl IntoResponse {
    let result = hivemind_marketplace::open_settlement_dispute(
        &request.settlement,
        &request.dispute,
        request.resolved_by,
        request.reason,
    );
    settlement_resolution_response(result, state.marketplace_audit_dir.as_ref().as_path())
}

async fn marketplace_refund_settlement(
    State(state): State<AppState>,
    Json(request): Json<MarketplaceSettlementResolutionRequest>,
) -> impl IntoResponse {
    let result = hivemind_marketplace::refund_settlement(
        &request.settlement,
        &request.dispute,
        request.resolved_by,
        request.reason,
    );
    settlement_resolution_response(result, state.marketplace_audit_dir.as_ref().as_path())
}

async fn marketplace_reject_dispute(
    State(state): State<AppState>,
    Json(request): Json<MarketplaceSettlementResolutionRequest>,
) -> impl IntoResponse {
    let result = hivemind_marketplace::reject_settlement_dispute(
        &request.settlement,
        &request.dispute,
        request.resolved_by,
        request.reason,
    );
    settlement_resolution_response(result, state.marketplace_audit_dir.as_ref().as_path())
}

async fn marketplace_refund_record(
    State(state): State<AppState>,
    Json(request): Json<hivemind_marketplace::RefundBuildRequestV1>,
) -> impl IntoResponse {
    let result = hivemind_marketplace::build_refund_record(&request);
    let status = if result.verification.valid {
        if let Some(refund) = &result.refund
            && let Err(error) = hivemind_marketplace::write_refund_record(
                state.marketplace_audit_dir.as_ref().as_path(),
                refund,
            )
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json_error(
                    ErrorCode::ExecutionFailed,
                    &format!("Failed to store refund record: {error}"),
                )),
            )
                .into_response();
        }
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, Json(json!(result))).into_response()
}

async fn marketplace_verify_refund_record(
    Json(record): Json<hivemind_marketplace::RefundRecordV1>,
) -> Json<hivemind_marketplace::RefundRecordVerificationV1> {
    Json(hivemind_marketplace::verify_refund_record(&record))
}

async fn marketplace_refunds(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_marketplace::list_refund_records(state.marketplace_audit_dir.as_ref().as_path())
    {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list refund records: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn marketplace_refund_by_id(
    State(state): State<AppState>,
    Path(refund_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_marketplace::get_refund_record(
        state.marketplace_audit_dir.as_ref().as_path(),
        &refund_id,
    ) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Refund record was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read refund record: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn marketplace_slash(
    Json(request): Json<hivemind_marketplace::SlashingBuildRequestV1>,
) -> impl IntoResponse {
    let result = hivemind_marketplace::build_slashing_record(&request);
    let status = if result.verification.valid {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, Json(json!(result))).into_response()
}

async fn marketplace_verify_slashing(
    Json(record): Json<hivemind_marketplace::SlashingRecordV1>,
) -> Json<hivemind_marketplace::SlashingRecordVerificationV1> {
    Json(hivemind_marketplace::verify_slashing_record(&record))
}

async fn marketplace_verify_resolution(
    Json(resolution): Json<hivemind_marketplace::SettlementResolutionV1>,
) -> Json<hivemind_marketplace::SettlementResolutionVerificationV1> {
    Json(hivemind_marketplace::verify_settlement_resolution(
        &resolution,
    ))
}

fn settlement_resolution_response(
    result: hivemind_marketplace::SettlementResolutionResultV1,
    marketplace_audit_dir: &std::path::Path,
) -> axum::response::Response {
    let status = if result.verification.valid {
        if let Some(settlement) = &result.updated_settlement
            && let Err(error) =
                hivemind_marketplace::write_settlement_event(marketplace_audit_dir, settlement)
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json_error(
                    ErrorCode::ExecutionFailed,
                    &format!("Failed to store settlement audit record: {error}"),
                )),
            )
                .into_response();
        }
        if let Some(resolution) = &result.resolution
            && let Err(error) =
                hivemind_marketplace::write_settlement_resolution(marketplace_audit_dir, resolution)
        {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json_error(
                    ErrorCode::ExecutionFailed,
                    &format!("Failed to store settlement resolution audit record: {error}"),
                )),
            )
                .into_response();
        }
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    (status, Json(json!(result))).into_response()
}

async fn route(
    State(state): State<AppState>,
    Json(body): Json<RoutePlannerBody>,
) -> impl IntoResponse {
    let (request, policy_mode, max_marketplace_results, trust_policy) =
        route_planner_body_parts(body);
    if let Some(message) = invalid_trust_policy_message(trust_policy.as_ref()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &message)),
        )
            .into_response();
    }
    let Some(package) = find_package(&state.packages, &request.package_ref, &request.package_id)
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Package is not in the local registry",
            )),
        )
            .into_response();
    };
    let package = package_for_request(package, &request.package_ref);

    let offers = marketplace_offers_for_route_request(&state, &request.package_ref);
    let miner_capacity = route_miner_capacity_inputs(
        state.miner_dir.as_ref().as_path(),
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    );
    let runner_reputation =
        runner_reputation_summaries(&state.registry_snapshot.validation_reports);
    let plan = plan_routes_with_trust_policy(
        &request,
        &package,
        &routing_runners(),
        &offers,
        &miner_capacity,
        policy_mode,
        max_marketplace_results,
        &runner_reputation,
        trust_policy.as_ref(),
    );
    (StatusCode::OK, Json(json!(plan))).into_response()
}

async fn route_report(
    State(state): State<AppState>,
    Json(body): Json<RoutePlannerBody>,
) -> impl IntoResponse {
    let (request, policy_mode, max_marketplace_results, trust_policy) =
        route_planner_body_parts(body);
    if let Some(message) = invalid_trust_policy_message(trust_policy.as_ref()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &message)),
        )
            .into_response();
    }
    let Some(package) = find_package(&state.packages, &request.package_ref, &request.package_id)
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Package is not in the local registry",
            )),
        )
            .into_response();
    };
    let package = package_for_request(package, &request.package_ref);
    let offers = marketplace_offers_for_route_request(&state, &request.package_ref);
    let miner_capacity = route_miner_capacity_inputs(
        state.miner_dir.as_ref().as_path(),
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    );
    let runner_reputation =
        runner_reputation_summaries(&state.registry_snapshot.validation_reports);
    let report = planner_report_with_trust_policy(
        &request,
        &package,
        &routing_runners(),
        &offers,
        &miner_capacity,
        policy_mode,
        max_marketplace_results,
        &runner_reputation,
        trust_policy.as_ref(),
    );
    (StatusCode::OK, Json(json!(report))).into_response()
}

async fn route_traces(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_router::list_route_execution_traces(state.route_trace_dir.as_ref().as_path()) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list route traces: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn route_trace_by_request_id(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_router::get_route_execution_trace(
        state.route_trace_dir.as_ref().as_path(),
        &request_id,
    ) {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Route trace was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read route trace: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn route_decisions(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_router::list_route_decisions(state.route_trace_dir.as_ref().as_path()) {
        Ok(summary) => (StatusCode::OK, Json(json!(summary))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to list route decisions: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn route_decision_by_request_id(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_router::get_route_decision(state.route_trace_dir.as_ref().as_path(), &request_id)
    {
        Ok(Some(lookup)) => (StatusCode::OK, Json(json!(lookup))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json_error(
                ErrorCode::PackageNotFound,
                "Route decision was not found",
            )),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(
                ErrorCode::InvalidRequest,
                &format!("Failed to read route decision: {error}"),
            )),
        )
            .into_response(),
    }
}

async fn operational_snapshot(State(state): State<AppState>) -> impl IntoResponse {
    let mut request = hivemind_observability::OperationalMetricSnapshotRequestV1::local_stores(
        state.job_dir.as_ref().clone(),
        state.receipt_dir.as_ref().clone(),
        state.route_trace_dir.as_ref().clone(),
        state.marketplace_audit_dir.as_ref().clone(),
    );
    request.storage_audit_dir = Some(state.storage_audit_dir.as_ref().clone());
    request.stream_dir = Some(state.stream_event_dir.as_ref().clone());
    request.package_validation_audit_dir = Some(state.package_audit_dir.as_ref().clone());
    request.registry_search_audit_dir = Some(state.registry_audit_dir.as_ref().clone());
    request.validation_report_dir = Some(state.validation_dir.as_ref().clone());
    request.miner_dir = Some(state.miner_dir.as_ref().clone());
    request.governance_dir = Some(state.governance_dir.as_ref().clone());
    match hivemind_observability::operational_snapshot_from_local_stores(&request) {
        Ok(snapshot) => (StatusCode::OK, Json(json!(snapshot))).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json_error(
                ErrorCode::ExecutionFailed,
                &format!("Failed to build operational snapshot: {error}"),
            )),
        )
            .into_response(),
    }
}

fn route_planner_body_parts(
    body: RoutePlannerBody,
) -> (ExecutionRequestV1, PolicyMode, usize, Option<TrustPolicyV1>) {
    match body {
        RoutePlannerBody::Execution(request) => (request, PolicyMode::Balanced, 3, None),
        RoutePlannerBody::Planner(request) => (
            request.request,
            request.policy_mode,
            request.max_marketplace_results,
            request.trust_policy,
        ),
    }
}

fn invalid_trust_policy_message(policy: Option<&TrustPolicyV1>) -> Option<String> {
    policy.and_then(|policy| validate_trust_policy_for_request(policy).err())
}

fn validate_trust_policy_for_request(policy: &TrustPolicyV1) -> std::result::Result<(), String> {
    let verification = hivemind_core::verify_trust_policy(policy);
    if verification.valid {
        return Ok(());
    }
    Err(format!(
        "trust policy {} failed verification: {}",
        verification.policy_id,
        validation_issues_summary(&verification.issues)
    ))
}

fn validation_issues_summary(issues: &[hivemind_core::ValidationIssue]) -> String {
    if issues.is_empty() {
        return "no issue details were reported".to_string();
    }
    issues
        .iter()
        .map(|issue| format!("{}: {}", issue.path, issue.message))
        .collect::<Vec<_>>()
        .join("; ")
}

fn compatibility_routing_controls(
    metadata: &Option<Value>,
) -> Result<CompatibilityRoutingControls, String> {
    compatibility_routing_controls_from_value(metadata.as_ref())
}

fn compatibility_routing_controls_from_value(
    metadata: Option<&Value>,
) -> Result<CompatibilityRoutingControls, String> {
    let mut controls = CompatibilityRoutingControls::default();
    if let Some(value) = metadata_control_value(metadata, &["policyMode", "policy_mode"]) {
        controls.policy_mode = serde_json::from_value(value.clone())
            .map_err(|error| format!("metadata policyMode is invalid: {error}"))?;
    }
    if let Some(value) = metadata_control_value(
        metadata,
        &["maxMarketplaceResults", "max_marketplace_results"],
    ) {
        let Some(max) = value.as_u64() else {
            return Err(
                "metadata maxMarketplaceResults must be a non-negative integer".to_string(),
            );
        };
        controls.max_marketplace_results = max as usize;
    }
    if let Some(value) = metadata_control_value(metadata, &["trustPolicy", "trust_policy"]) {
        let trust_policy: TrustPolicyV1 = serde_json::from_value(value.clone())
            .map_err(|error| format!("metadata trustPolicy is invalid: {error}"))?;
        validate_trust_policy_for_request(&trust_policy)
            .map_err(|message| format!("metadata trustPolicy is invalid: {message}"))?;
        controls.trust_policy = Some(trust_policy);
    }
    Ok(controls)
}

fn metadata_control_value<'a>(metadata: Option<&'a Value>, keys: &[&str]) -> Option<&'a Value> {
    let metadata = metadata?;
    for key in keys {
        if let Some(value) = metadata.get(*key) {
            return Some(value);
        }
    }
    if let Some(hivemind) = metadata.get("hivemind") {
        for key in keys {
            if let Some(value) = hivemind.get(*key) {
                return Some(value);
            }
        }
    }
    None
}

fn route_miner_capacity_inputs(
    miner_dir: &FsPath,
    hardware_offer_dir: &FsPath,
) -> Vec<MinerCapacityInputV1> {
    let mut benchmarks_by_miner: BTreeMap<String, Vec<hivemind_miner::MinerBenchmarkResultV1>> =
        BTreeMap::new();
    let mut profile_offers: BTreeMap<String, hivemind_marketplace::HardwareResourceOfferV1> =
        BTreeMap::new();
    let mut latest_by_runner: BTreeMap<String, (String, MinerCapacityInputV1)> = BTreeMap::new();

    if let Ok(summary) = hivemind_miner::list_miner_records(miner_dir) {
        for record in &summary.records {
            let Ok(Some(lookup)) = hivemind_miner::get_miner_record(miner_dir, &record.record_id)
            else {
                continue;
            };
            if let Some(benchmark) = lookup.benchmark {
                benchmarks_by_miner
                    .entry(benchmark.miner_id.clone())
                    .or_default()
                    .push(benchmark);
            } else if let (Some(profile), Some(hardware_offer)) =
                (lookup.profile, lookup.hardware_offer)
            {
                profile_offers.insert(profile.runner_id, hardware_offer);
            }
        }

        for record in &summary.records {
            if record.record_type != hivemind_miner::MinerRecordType::Heartbeat {
                continue;
            }
            let Ok(Some(lookup)) = hivemind_miner::get_miner_record(miner_dir, &record.record_id)
            else {
                continue;
            };
            let (Some(heartbeat), Some(hardware_offer)) = (lookup.heartbeat, lookup.hardware_offer)
            else {
                continue;
            };
            let benchmarks = benchmarks_by_miner
                .get(&heartbeat.miner_id)
                .cloned()
                .unwrap_or_default();
            let input = MinerCapacityInputV1 {
                schema_version: "swarm-ai.miner-capacity-input.v1".to_string(),
                hardware_offer,
                heartbeat: Some(heartbeat.clone()),
                benchmarks,
            };
            let observed_at = heartbeat.observed_at.clone();
            latest_by_runner
                .entry(heartbeat.runner_id.clone())
                .and_modify(|(existing_observed_at, existing_input)| {
                    if observed_at > *existing_observed_at {
                        *existing_observed_at = observed_at.clone();
                        *existing_input = input.clone();
                    }
                })
                .or_insert((observed_at, input));
        }
    }

    for (runner_id, hardware_offer) in profile_offers {
        if latest_by_runner.contains_key(&runner_id) {
            continue;
        }
        latest_by_runner.insert(
            runner_id,
            (
                String::new(),
                MinerCapacityInputV1 {
                    schema_version: "swarm-ai.miner-capacity-input.v1".to_string(),
                    hardware_offer,
                    heartbeat: None,
                    benchmarks: Vec::new(),
                },
            ),
        );
    }

    if let Ok(hardware_offers) = load_hardware_resource_offers(hardware_offer_dir) {
        for hardware_offer in hardware_offers {
            if latest_by_runner.contains_key(&hardware_offer.runner_id) {
                continue;
            }
            latest_by_runner.insert(
                hardware_offer.runner_id.clone(),
                (
                    String::new(),
                    miner_capacity_input_from_hardware_offer(hardware_offer),
                ),
            );
        }
    }

    latest_by_runner
        .into_values()
        .map(|(_, input)| input)
        .collect()
}

fn miner_capacity_input_from_hardware_offer(
    hardware_offer: hivemind_marketplace::HardwareResourceOfferV1,
) -> MinerCapacityInputV1 {
    MinerCapacityInputV1 {
        schema_version: "swarm-ai.miner-capacity-input.v1".to_string(),
        hardware_offer,
        heartbeat: None,
        benchmarks: Vec::new(),
    }
}

async fn execute(
    State(state): State<AppState>,
    Json(body): Json<RoutePlannerBody>,
) -> impl IntoResponse {
    let (request, policy_mode, max_marketplace_results, trust_policy) =
        route_planner_body_parts(body);
    if let Some(message) = invalid_trust_policy_message(trust_policy.as_ref()) {
        let response = ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(ErrorCode::InvalidRequest, message),
            Default::default(),
        );
        return (StatusCode::BAD_REQUEST, Json(response)).into_response();
    }
    let Some(package) = find_package(&state.packages, &request.package_ref, &request.package_id)
    else {
        let response = ExecutionResponseV1 {
            schema_version: "swarm-ai.execution.response.v1".to_string(),
            request_id: request.request_id,
            status: ExecutionStatus::Failed,
            output: json!({}),
            metrics: Default::default(),
            receipt_ref: None,
            error: Some(SwarmAiErrorV1::new(
                ErrorCode::PackageNotFound,
                "Package is not in the local registry",
            )),
            metadata: json!({}),
        };
        return (StatusCode::NOT_FOUND, Json(response)).into_response();
    };

    let package = package_for_request(package, &request.package_ref);
    let offers = marketplace_offers_for_route_request(&state, &request.package_ref);
    let miner_capacity = route_miner_capacity_inputs(
        state.miner_dir.as_ref().as_path(),
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    );
    let runner_reputation =
        runner_reputation_summaries(&state.registry_snapshot.validation_reports);
    let report = planner_report_with_trust_policy(
        &request,
        &package,
        &routing_runners(),
        &offers,
        &miner_capacity,
        policy_mode,
        max_marketplace_results,
        &runner_reputation,
        trust_policy.as_ref(),
    );
    let response = execute_with_route_fallback(request, package, report).await;
    let mut response = response;
    persist_response_route_decision(state.route_trace_dir.as_ref().as_path(), &mut response);
    persist_response_route_trace(state.route_trace_dir.as_ref().as_path(), &mut response);
    persist_response_receipt(state.receipt_dir.as_ref().as_path(), &mut response);
    persist_response_marketplace_audit(
        state.marketplace_payment_dir.as_ref().as_path(),
        state.marketplace_audit_dir.as_ref().as_path(),
        &mut response,
    );
    attach_partial_receipt_stream_event(&mut response);
    persist_response_stream_events(state.stream_event_dir.as_ref().as_path(), &mut response);
    persist_response_job_record(state.job_dir.as_ref().as_path(), &mut response);
    (StatusCode::OK, Json(response)).into_response()
}

async fn hivemind_ai_plan(
    State(state): State<AppState>,
    Json(request): Json<AiRequestV1>,
) -> impl IntoResponse {
    let Some((indexed, package_ref)) = package_for_ai_request(&state.packages, &request) else {
        let response = AiResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::PackageNotFound,
                "AI request packageSelector did not resolve to a local package",
            ),
        );
        return (StatusCode::NOT_FOUND, Json(json!(response))).into_response();
    };
    let package = package_for_request(indexed, &package_ref);
    let execution_request = match execution_request_from_ai_request(
        &request,
        &package.package_ref,
        &package.manifest.package_id,
        &package.manifest.version,
    ) {
        Ok(request) => request,
        Err(error) => {
            let response = AiResponseV1::failed(request.request_id, error);
            return (StatusCode::BAD_REQUEST, Json(json!(response))).into_response();
        }
    };
    let controls = match compatibility_routing_controls_from_value(Some(&request.metadata)) {
        Ok(controls) => controls,
        Err(message) => {
            let response = AiResponseV1::failed(
                request.request_id,
                SwarmAiErrorV1::new(ErrorCode::InvalidRequest, message),
            );
            return (StatusCode::BAD_REQUEST, Json(json!(response))).into_response();
        }
    };
    let offers = marketplace_offers_for_route_request(&state, &execution_request.package_ref);
    let miner_capacity = route_miner_capacity_inputs(
        state.miner_dir.as_ref().as_path(),
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    );
    let runner_reputation =
        runner_reputation_summaries(&state.registry_snapshot.validation_reports);
    let report = planner_report_with_trust_policy(
        &execution_request,
        &package,
        &routing_runners(),
        &offers,
        &miner_capacity,
        controls.policy_mode,
        controls.max_marketplace_results,
        &runner_reputation,
        controls.trust_policy.as_ref(),
    );
    let plan = AiExecutionPlanV1::from_report(
        request,
        execution_request,
        package.package_ref,
        package.manifest.package_id,
        report,
    );
    (StatusCode::OK, Json(json!(plan))).into_response()
}

async fn hivemind_ai_verify_request(
    Json(request): Json<AiRequestV1>,
) -> Json<hivemind_core::AiRequestVerificationV1> {
    Json(hivemind_core::verify_ai_request(&request))
}

async fn hivemind_ai_sign_request(Json(mut request): Json<AiRequestV1>) -> impl IntoResponse {
    match hivemind_core::sign_ai_request(&mut request) {
        Ok(signature) => {
            let verification = hivemind_core::verify_ai_request(&request);
            (
                StatusCode::OK,
                Json(json!({
                    "schemaVersion": "hivemind.ai_request_sign_response.v1",
                    "signature": signature,
                    "request": request,
                    "verification": verification
                })),
            )
                .into_response()
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn hivemind_ai_verify_response(
    Json(response): Json<AiResponseV1>,
) -> Json<hivemind_core::AiResponseVerificationV1> {
    Json(hivemind_core::verify_ai_response(&response))
}

async fn hivemind_ai_sign_response(Json(mut response): Json<AiResponseV1>) -> impl IntoResponse {
    match hivemind_core::sign_ai_response(&mut response) {
        Ok(signature) => {
            let verification = hivemind_core::verify_ai_response(&response);
            (
                StatusCode::OK,
                Json(json!({
                    "schemaVersion": "hivemind.ai_response_sign_response.v1",
                    "signature": signature,
                    "response": response,
                    "verification": verification
                })),
            )
                .into_response()
        }
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json_error(ErrorCode::InvalidRequest, &error.to_string())),
        )
            .into_response(),
    }
}

async fn hivemind_ai_execute(
    State(state): State<AppState>,
    Json(request): Json<AiRequestV1>,
) -> impl IntoResponse {
    let Some((indexed, package_ref)) = package_for_ai_request(&state.packages, &request) else {
        let response = AiResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::PackageNotFound,
                "AI request packageSelector did not resolve to a local package",
            ),
        );
        return (StatusCode::NOT_FOUND, Json(json!(response))).into_response();
    };
    let package = package_for_request(indexed, &package_ref);
    let execution_request = match execution_request_from_ai_request(
        &request,
        &package.package_ref,
        &package.manifest.package_id,
        &package.manifest.version,
    ) {
        Ok(request) => request,
        Err(error) => {
            let response = AiResponseV1::failed(request.request_id, error);
            return (StatusCode::BAD_REQUEST, Json(json!(response))).into_response();
        }
    };
    let controls = match compatibility_routing_controls_from_value(Some(&request.metadata)) {
        Ok(controls) => controls,
        Err(message) => {
            let response = AiResponseV1::failed(
                request.request_id,
                SwarmAiErrorV1::new(ErrorCode::InvalidRequest, message),
            );
            return (StatusCode::BAD_REQUEST, Json(json!(response))).into_response();
        }
    };
    let runner_reputation =
        runner_reputation_summaries(&state.registry_snapshot.validation_reports);
    let miner_capacity = route_miner_capacity_inputs(
        state.miner_dir.as_ref().as_path(),
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    );
    let execution_response = execute_with_controlled_routing(
        execution_request,
        package,
        state.marketplace_runner_offer_dir.as_ref().as_path(),
        &runner_reputation,
        &miner_capacity,
        &controls,
        state.job_dir.as_ref().as_path(),
        state.receipt_dir.as_ref().as_path(),
        state.marketplace_payment_dir.as_ref().as_path(),
        state.marketplace_audit_dir.as_ref().as_path(),
        state.route_trace_dir.as_ref().as_path(),
        state.stream_event_dir.as_ref().as_path(),
    )
    .await;
    let mut response = ai_response_from_execution_response(&execution_response);
    response.metadata["aiRequest"] = json!({
        "requestId": request.request_id,
        "apiSurface": request.api_surface,
        "packageSelector": request.package_selector,
    });
    (StatusCode::OK, Json(json!(response))).into_response()
}

async fn openai_models(
    State(state): State<AppState>,
) -> Json<hivemind_openai_compat::OpenAiModelListV1> {
    let public = public_registry_snapshot(&state.registry_snapshot);
    Json(hivemind_openai_compat::model_list_from_registry_entries(
        &public.entries,
    ))
}

async fn openai_model_by_id(
    State(state): State<AppState>,
    Path(model_id): Path<String>,
) -> impl IntoResponse {
    let model_id = model_id.trim_start_matches('/');
    let public = public_registry_snapshot(&state.registry_snapshot);
    let Some(entry) = public
        .entries
        .iter()
        .find(|entry| registry_entry_matches_model_id(entry, model_id))
    else {
        return openai_error_response(
            StatusCode::NOT_FOUND,
            "model_not_found",
            format!("Model {model_id} is not in the public registry"),
        );
    };

    (
        StatusCode::OK,
        Json(json!(hivemind_openai_compat::model_from_registry_entry(
            entry
        ))),
    )
        .into_response()
}

async fn openai_chat_completions(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::ChatCompletionRequestV1>,
) -> impl IntoResponse {
    let Some((indexed, package_ref)) = package_for_model(&state.packages, &request.model) else {
        return openai_error_response(
            StatusCode::NOT_FOUND,
            "model_not_found",
            format!("Model {} is not in the local registry", request.model),
        );
    };
    let package = package_for_request(indexed, &package_ref);
    let request_id = format!("chatcmpl-{}", uuid::Uuid::new_v4());
    let execution_request = hivemind_openai_compat::chat_request_to_execution(
        &request,
        &package.package_ref,
        &package.manifest.package_id,
        &package.manifest.version,
        &request_id,
    );
    let runner_reputation =
        runner_reputation_summaries(&state.registry_snapshot.validation_reports);
    let controls = match compatibility_routing_controls(&request.metadata) {
        Ok(controls) => controls,
        Err(message) => {
            return openai_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                message,
            );
        }
    };
    let miner_capacity = route_miner_capacity_inputs(
        state.miner_dir.as_ref().as_path(),
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    );
    let response = execute_with_controlled_routing(
        execution_request,
        package,
        state.marketplace_runner_offer_dir.as_ref().as_path(),
        &runner_reputation,
        &miner_capacity,
        &controls,
        state.job_dir.as_ref().as_path(),
        state.receipt_dir.as_ref().as_path(),
        state.marketplace_payment_dir.as_ref().as_path(),
        state.marketplace_audit_dir.as_ref().as_path(),
        state.route_trace_dir.as_ref().as_path(),
        state.stream_event_dir.as_ref().as_path(),
    )
    .await;
    if response.status != ExecutionStatus::Succeeded {
        return openai_error_from_execution(&response);
    }

    let created = unix_timestamp();
    if request.stream {
        let body = hivemind_openai_compat::chat_completion_stream_body_from_execution(
            &request, &response, request_id, created,
        );
        return compatibility_event_stream_response(body, &response);
    }

    let completion = hivemind_openai_compat::chat_completion_from_execution(
        &request, &response, request_id, created,
    );
    compatibility_json_response(StatusCode::OK, completion, &response)
}

async fn openai_responses(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::OpenAiResponsesRequestV1>,
) -> impl IntoResponse {
    let Some((indexed, package_ref)) = package_for_model(&state.packages, &request.model) else {
        return openai_error_response(
            StatusCode::NOT_FOUND,
            "model_not_found",
            format!("Model {} is not in the local registry", request.model),
        );
    };
    let package = package_for_request(indexed, &package_ref);
    let request_id = format!("resp-{}", uuid::Uuid::new_v4());
    let execution_request = hivemind_openai_compat::responses_request_to_execution(
        &request,
        &package.package_ref,
        &package.manifest.package_id,
        &package.manifest.version,
        &request_id,
    );
    let runner_reputation =
        runner_reputation_summaries(&state.registry_snapshot.validation_reports);
    let controls = match compatibility_routing_controls(&request.metadata) {
        Ok(controls) => controls,
        Err(message) => {
            return openai_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                message,
            );
        }
    };
    let miner_capacity = route_miner_capacity_inputs(
        state.miner_dir.as_ref().as_path(),
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    );
    let response = execute_with_controlled_routing(
        execution_request,
        package,
        state.marketplace_runner_offer_dir.as_ref().as_path(),
        &runner_reputation,
        &miner_capacity,
        &controls,
        state.job_dir.as_ref().as_path(),
        state.receipt_dir.as_ref().as_path(),
        state.marketplace_payment_dir.as_ref().as_path(),
        state.marketplace_audit_dir.as_ref().as_path(),
        state.route_trace_dir.as_ref().as_path(),
        state.stream_event_dir.as_ref().as_path(),
    )
    .await;
    if response.status != ExecutionStatus::Succeeded {
        return openai_error_from_execution(&response);
    }

    let created = unix_timestamp();
    if request.stream {
        let body = hivemind_openai_compat::responses_stream_body_from_execution(
            &request, &response, request_id, created,
        );
        return compatibility_event_stream_response(body, &response);
    }

    let provider_response = hivemind_openai_compat::responses_response_from_execution(
        &request, &response, request_id, created,
    );
    compatibility_json_response(StatusCode::OK, provider_response, &response)
}

async fn anthropic_messages(
    State(state): State<AppState>,
    Json(request): Json<hivemind_provider_compat::AnthropicMessageRequestV1>,
) -> impl IntoResponse {
    let Some((indexed, package_ref)) = package_for_model(&state.packages, &request.model) else {
        return anthropic_error_response(
            StatusCode::NOT_FOUND,
            "not_found_error",
            format!("Model {} is not in the local registry", request.model),
        );
    };
    let package = package_for_request(indexed, &package_ref);
    let request_id = format!("msg-{}", uuid::Uuid::new_v4());
    let execution_request = hivemind_provider_compat::anthropic_messages_to_execution(
        &request,
        &package.package_ref,
        &package.manifest.package_id,
        &package.manifest.version,
        &request_id,
    );
    let runner_reputation =
        runner_reputation_summaries(&state.registry_snapshot.validation_reports);
    let controls = match compatibility_routing_controls_from_value(Some(&request.metadata)) {
        Ok(controls) => controls,
        Err(message) => {
            return anthropic_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                message,
            );
        }
    };
    let miner_capacity = route_miner_capacity_inputs(
        state.miner_dir.as_ref().as_path(),
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    );
    let response = execute_with_controlled_routing(
        execution_request,
        package,
        state.marketplace_runner_offer_dir.as_ref().as_path(),
        &runner_reputation,
        &miner_capacity,
        &controls,
        state.job_dir.as_ref().as_path(),
        state.receipt_dir.as_ref().as_path(),
        state.marketplace_payment_dir.as_ref().as_path(),
        state.marketplace_audit_dir.as_ref().as_path(),
        state.route_trace_dir.as_ref().as_path(),
        state.stream_event_dir.as_ref().as_path(),
    )
    .await;
    if response.status != ExecutionStatus::Succeeded {
        return anthropic_error_from_execution(&response);
    }

    let message =
        hivemind_provider_compat::anthropic_message_from_execution(&request, &response, request_id);
    compatibility_json_response(StatusCode::OK, message, &response)
}

async fn gemini_generate_content(
    State(state): State<AppState>,
    Json(request): Json<hivemind_provider_compat::GeminiGenerateContentRequestV1>,
) -> impl IntoResponse {
    let Some(model) = hivemind_provider_compat::gemini_model_from_request(&request) else {
        return gemini_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "Gemini compatibility requests must include a model or use the path-model endpoint",
        );
    };
    gemini_generate_content_response(state, model, request).await
}

async fn gemini_generate_content_for_model(
    State(state): State<AppState>,
    Path(model_id): Path<String>,
    Json(mut request): Json<hivemind_provider_compat::GeminiGenerateContentRequestV1>,
) -> impl IntoResponse {
    let model = model_id.trim().trim_matches('/').to_string();
    if model.is_empty() {
        return gemini_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            "Gemini compatibility path must include a model id",
        );
    }
    request.model = Some(model.clone());
    gemini_generate_content_response(state, model, request).await
}

async fn gemini_generate_content_response(
    state: AppState,
    model: String,
    request: hivemind_provider_compat::GeminiGenerateContentRequestV1,
) -> axum::response::Response {
    let Some((indexed, package_ref)) = package_for_model(&state.packages, &model) else {
        return gemini_error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            format!("Model {model} is not in the local registry"),
        );
    };
    let package = package_for_request(indexed, &package_ref);
    let request_id = format!("gemini-{}", uuid::Uuid::new_v4());
    let execution_request = hivemind_provider_compat::gemini_generate_content_to_execution(
        &request,
        &model,
        &package.package_ref,
        &package.manifest.package_id,
        &package.manifest.version,
        &request_id,
    );
    let runner_reputation =
        runner_reputation_summaries(&state.registry_snapshot.validation_reports);
    let controls = match compatibility_routing_controls_from_value(Some(&request.metadata)) {
        Ok(controls) => controls,
        Err(message) => {
            return gemini_error_response(StatusCode::BAD_REQUEST, "INVALID_ARGUMENT", message);
        }
    };
    let miner_capacity = route_miner_capacity_inputs(
        state.miner_dir.as_ref().as_path(),
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    );
    let response = execute_with_controlled_routing(
        execution_request,
        package,
        state.marketplace_runner_offer_dir.as_ref().as_path(),
        &runner_reputation,
        &miner_capacity,
        &controls,
        state.job_dir.as_ref().as_path(),
        state.receipt_dir.as_ref().as_path(),
        state.marketplace_payment_dir.as_ref().as_path(),
        state.marketplace_audit_dir.as_ref().as_path(),
        state.route_trace_dir.as_ref().as_path(),
        state.stream_event_dir.as_ref().as_path(),
    )
    .await;
    if response.status != ExecutionStatus::Succeeded {
        return gemini_error_from_execution(&response);
    }

    let generated = hivemind_provider_compat::gemini_generate_content_from_execution(
        model, &request, &response,
    );
    compatibility_json_response(StatusCode::OK, generated, &response)
}

async fn gemini_live_sessions_create(
    State(state): State<AppState>,
    Json(request): Json<hivemind_provider_compat::GeminiLiveSessionCreateRequestV1>,
) -> impl IntoResponse {
    let record = hivemind_provider_compat::gemini_live_session_record_from_request(
        &request,
        "gemini-compat",
    );
    let verification = hivemind_realtime::verify_realtime_session(&record.session);
    if !verification.valid {
        return gemini_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            format!(
                "Gemini Live session is invalid: {}",
                validation_issue_summary(&verification.issues)
            ),
        );
    }

    match write_provider_record(
        &state.storage_dir,
        "gemini",
        "live-sessions",
        &record.session.session_id,
        &record,
    ) {
        Ok(_) => {
            let response = hivemind_provider_compat::gemini_live_session_from_record(&record);
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Err(error) => gemini_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            format!("Failed to store Gemini Live session: {error}"),
        ),
    }
}

async fn gemini_live_session_by_id(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    match read_provider_record::<hivemind_provider_compat::GeminiLiveSessionRecordV1>(
        &state.storage_dir,
        "gemini",
        "live-sessions",
        &session_id,
    ) {
        Ok(Some(record)) => {
            let response = hivemind_provider_compat::gemini_live_session_from_record(&record);
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Ok(None) => gemini_error_response(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            format!("Gemini Live session {session_id} was not found"),
        ),
        Err(error) => gemini_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_ARGUMENT",
            format!("Failed to read Gemini Live session: {error}"),
        ),
    }
}

async fn huggingface_inference(
    State(state): State<AppState>,
    Json(request): Json<hivemind_provider_compat::HuggingFaceInferenceRequestV1>,
) -> impl IntoResponse {
    let Some(model) = hivemind_provider_compat::huggingface_model_from_request(&request) else {
        return huggingface_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Hugging Face compatibility requests must include a model or use the path-model endpoint",
        );
    };
    huggingface_inference_response(state, model, request).await
}

async fn huggingface_inference_for_model(
    State(state): State<AppState>,
    Path(model_id): Path<String>,
    Json(mut request): Json<hivemind_provider_compat::HuggingFaceInferenceRequestV1>,
) -> impl IntoResponse {
    let model = model_id.trim().trim_matches('/').to_string();
    if model.is_empty() {
        return huggingface_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Hugging Face compatibility path must include a model id",
        );
    }
    request.model = Some(model.clone());
    huggingface_inference_response(state, model, request).await
}

async fn huggingface_inference_response(
    state: AppState,
    model: String,
    request: hivemind_provider_compat::HuggingFaceInferenceRequestV1,
) -> axum::response::Response {
    let Some((indexed, package_ref)) = package_for_model(&state.packages, &model) else {
        return huggingface_error_response(
            StatusCode::NOT_FOUND,
            "model_not_found",
            format!("Model {model} is not in the local registry"),
        );
    };
    let package = package_for_request(indexed, &package_ref);
    let request_id = format!("hf-{}", uuid::Uuid::new_v4());
    let execution_request = hivemind_provider_compat::huggingface_inference_to_execution(
        &request,
        &model,
        &package.package_ref,
        &package.manifest.package_id,
        &package.manifest.version,
        &request_id,
    );
    let runner_reputation =
        runner_reputation_summaries(&state.registry_snapshot.validation_reports);
    let controls = match compatibility_routing_controls_from_value(Some(&request.metadata)) {
        Ok(controls) => controls,
        Err(message) => {
            return huggingface_error_response(StatusCode::BAD_REQUEST, "invalid_request", message);
        }
    };
    let miner_capacity = route_miner_capacity_inputs(
        state.miner_dir.as_ref().as_path(),
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    );
    let response = execute_with_controlled_routing(
        execution_request,
        package,
        state.marketplace_runner_offer_dir.as_ref().as_path(),
        &runner_reputation,
        &miner_capacity,
        &controls,
        state.job_dir.as_ref().as_path(),
        state.receipt_dir.as_ref().as_path(),
        state.marketplace_payment_dir.as_ref().as_path(),
        state.marketplace_audit_dir.as_ref().as_path(),
        state.route_trace_dir.as_ref().as_path(),
        state.stream_event_dir.as_ref().as_path(),
    )
    .await;
    if response.status != ExecutionStatus::Succeeded {
        return huggingface_error_from_execution(&response);
    }

    let generated =
        hivemind_provider_compat::huggingface_inference_from_execution(model, &request, &response);
    compatibility_json_response(StatusCode::OK, generated, &response)
}

async fn openai_files_create(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::OpenAiFileCreateRequestV1>,
) -> impl IntoResponse {
    let file_id = hivemind_openai_compat::openai_file_id_from_create_request(&request);
    let file = hivemind_openai_compat::openai_file_from_create_request(
        &request,
        &file_id,
        unix_timestamp(),
    );
    match write_openai_record(&state.storage_dir, "files", &file_id, &file) {
        Ok(_) => (StatusCode::OK, Json(json!(file))).into_response(),
        Err(error) => openai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "file_store_failed",
            format!("Failed to store file metadata: {error}"),
        ),
    }
}

async fn openai_file_by_id(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
) -> impl IntoResponse {
    match read_openai_record::<hivemind_openai_compat::OpenAiFileV1>(
        &state.storage_dir,
        "files",
        &file_id,
    ) {
        Ok(Some(file)) => (StatusCode::OK, Json(json!(file))).into_response(),
        Ok(None) => openai_error_response(
            StatusCode::NOT_FOUND,
            "file_not_found",
            format!("File {file_id} was not found"),
        ),
        Err(error) => openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!("Failed to read file metadata: {error}"),
        ),
    }
}

async fn openai_batches_create(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::OpenAiBatchCreateRequestV1>,
) -> impl IntoResponse {
    let job = hivemind_openai_compat::batch_job_from_openai_request(&request, "openai-compat");
    let verification = hivemind_batch::verify_batch_job(&job);
    if !verification.valid {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!(
                "Batch job is invalid: {}",
                validation_issue_summary(&verification.issues)
            ),
        );
    }

    match write_openai_record(&state.storage_dir, "batches", &job.batch_id, &job) {
        Ok(_) => {
            let response = hivemind_openai_compat::openai_batch_from_job(&job, unix_timestamp());
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Err(error) => openai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "batch_store_failed",
            format!("Failed to store batch job: {error}"),
        ),
    }
}

async fn openai_batch_by_id(
    State(state): State<AppState>,
    Path(batch_id): Path<String>,
) -> impl IntoResponse {
    match read_openai_record::<hivemind_batch::BatchJobV1>(&state.storage_dir, "batches", &batch_id)
    {
        Ok(Some(job)) => {
            let response = hivemind_openai_compat::openai_batch_from_job(&job, unix_timestamp());
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Ok(None) => openai_error_response(
            StatusCode::NOT_FOUND,
            "batch_not_found",
            format!("Batch {batch_id} was not found"),
        ),
        Err(error) => openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!("Failed to read batch job: {error}"),
        ),
    }
}

async fn openai_fine_tuning_jobs_create(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::OpenAiFineTuningCreateRequestV1>,
) -> impl IntoResponse {
    let job = hivemind_openai_compat::fine_tune_job_from_openai_request(&request, "openai-compat");
    let verification = hivemind_fine_tune::verify_fine_tune_job(&job);
    if !verification.valid {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!(
                "Fine-tuning job is invalid: {}",
                validation_issue_summary(&verification.issues)
            ),
        );
    }

    match write_openai_record(
        &state.storage_dir,
        "fine-tuning-jobs",
        &job.fine_tune_job_id,
        &job,
    ) {
        Ok(_) => {
            let response =
                hivemind_openai_compat::openai_fine_tuning_job_from_job(&job, unix_timestamp());
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Err(error) => openai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "fine_tune_job_store_failed",
            format!("Failed to store fine-tuning job: {error}"),
        ),
    }
}

async fn openai_fine_tuning_job_by_id(
    State(state): State<AppState>,
    Path(fine_tune_job_id): Path<String>,
) -> impl IntoResponse {
    match read_openai_record::<hivemind_fine_tune::FineTuneJobV1>(
        &state.storage_dir,
        "fine-tuning-jobs",
        &fine_tune_job_id,
    ) {
        Ok(Some(job)) => {
            let response =
                hivemind_openai_compat::openai_fine_tuning_job_from_job(&job, unix_timestamp());
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Ok(None) => openai_error_response(
            StatusCode::NOT_FOUND,
            "fine_tune_job_not_found",
            format!("Fine-tuning job {fine_tune_job_id} was not found"),
        ),
        Err(error) => openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!("Failed to read fine-tuning job: {error}"),
        ),
    }
}

async fn openai_realtime_sessions_create(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::OpenAiRealtimeSessionCreateRequestV1>,
) -> impl IntoResponse {
    let record = hivemind_openai_compat::realtime_session_record_from_openai_request(
        &request,
        "openai-compat",
    );
    let verification = hivemind_realtime::verify_realtime_session(&record.session);
    if !verification.valid {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!(
                "Realtime session is invalid: {}",
                validation_issue_summary(&verification.issues)
            ),
        );
    }

    match write_openai_record(
        &state.storage_dir,
        "realtime-sessions",
        &record.session.session_id,
        &record,
    ) {
        Ok(_) => {
            let response = hivemind_openai_compat::openai_realtime_session_from_record(
                &record,
                unix_timestamp(),
            );
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Err(error) => openai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "realtime_session_store_failed",
            format!("Failed to store realtime session: {error}"),
        ),
    }
}

async fn openai_realtime_session_by_id(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    match read_openai_record::<hivemind_openai_compat::OpenAiRealtimeSessionRecordV1>(
        &state.storage_dir,
        "realtime-sessions",
        &session_id,
    ) {
        Ok(Some(record)) => {
            let response = hivemind_openai_compat::openai_realtime_session_from_record(
                &record,
                unix_timestamp(),
            );
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Ok(None) => openai_error_response(
            StatusCode::NOT_FOUND,
            "realtime_session_not_found",
            format!("Realtime session {session_id} was not found"),
        ),
        Err(error) => openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!("Failed to read realtime session: {error}"),
        ),
    }
}

async fn openai_evals_create(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::OpenAiEvalCreateRequestV1>,
) -> impl IntoResponse {
    let record =
        hivemind_openai_compat::eval_manifest_record_from_openai_request(&request, "openai-compat");
    let verification = hivemind_evals::verify_eval_manifest(&record.manifest);
    if !verification.valid {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!(
                "Eval manifest is invalid: {}",
                validation_issue_summary(&verification.issues)
            ),
        );
    }

    match write_openai_record(
        &state.storage_dir,
        "evals",
        &record.manifest.eval_id,
        &record,
    ) {
        Ok(_) => {
            let response =
                hivemind_openai_compat::openai_eval_from_record(&record, unix_timestamp());
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Err(error) => openai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "eval_store_failed",
            format!("Failed to store eval manifest: {error}"),
        ),
    }
}

async fn openai_eval_by_id(
    State(state): State<AppState>,
    Path(eval_id): Path<String>,
) -> impl IntoResponse {
    match read_openai_record::<hivemind_openai_compat::OpenAiEvalRecordV1>(
        &state.storage_dir,
        "evals",
        &eval_id,
    ) {
        Ok(Some(record)) => {
            let response =
                hivemind_openai_compat::openai_eval_from_record(&record, unix_timestamp());
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Ok(None) => openai_error_response(
            StatusCode::NOT_FOUND,
            "eval_not_found",
            format!("Eval {eval_id} was not found"),
        ),
        Err(error) => openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!("Failed to read eval manifest: {error}"),
        ),
    }
}

async fn openai_eval_runs_create(
    State(state): State<AppState>,
    Path(eval_id): Path<String>,
    Json(request): Json<hivemind_openai_compat::OpenAiEvalRunCreateRequestV1>,
) -> impl IntoResponse {
    let eval_record = match read_openai_record::<hivemind_openai_compat::OpenAiEvalRecordV1>(
        &state.storage_dir,
        "evals",
        &eval_id,
    ) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return openai_error_response(
                StatusCode::NOT_FOUND,
                "eval_not_found",
                format!("Eval {eval_id} was not found"),
            );
        }
        Err(error) => {
            return openai_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                format!("Failed to read eval manifest: {error}"),
            );
        }
    };
    let record = hivemind_openai_compat::eval_run_record_from_openai_request(
        &eval_id,
        &request,
        "openai-compat",
    );
    let plan = hivemind_evals::eval_run_plan(&eval_record.manifest, &record.run);
    if !plan.valid {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!(
                "Eval run is invalid: {}",
                validation_issue_summary(&plan.issues)
            ),
        );
    }

    match write_openai_record(
        &state.storage_dir,
        "eval-runs",
        &record.run.eval_run_id,
        &record,
    ) {
        Ok(_) => {
            let response = hivemind_openai_compat::openai_eval_run_from_record(
                &record,
                Some(&eval_record.manifest),
                unix_timestamp(),
            );
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Err(error) => openai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "eval_run_store_failed",
            format!("Failed to store eval run: {error}"),
        ),
    }
}

async fn openai_eval_run_by_id(
    State(state): State<AppState>,
    Path((eval_id, eval_run_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let record = match read_openai_record::<hivemind_openai_compat::OpenAiEvalRunRecordV1>(
        &state.storage_dir,
        "eval-runs",
        &eval_run_id,
    ) {
        Ok(Some(record)) if record.eval_id == eval_id => record,
        Ok(Some(_)) | Ok(None) => {
            return openai_error_response(
                StatusCode::NOT_FOUND,
                "eval_run_not_found",
                format!("Eval run {eval_run_id} was not found for eval {eval_id}"),
            );
        }
        Err(error) => {
            return openai_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                format!("Failed to read eval run: {error}"),
            );
        }
    };
    let eval_record = match read_openai_record::<hivemind_openai_compat::OpenAiEvalRecordV1>(
        &state.storage_dir,
        "evals",
        &eval_id,
    ) {
        Ok(record) => record,
        Err(error) => {
            return openai_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                format!("Failed to read eval manifest: {error}"),
            );
        }
    };
    let response = hivemind_openai_compat::openai_eval_run_from_record(
        &record,
        eval_record.as_ref().map(|record| &record.manifest),
        unix_timestamp(),
    );
    (StatusCode::OK, Json(json!(response))).into_response()
}

async fn openai_images_generations(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::OpenAiImageGenerationRequestV1>,
) -> impl IntoResponse {
    let job =
        hivemind_openai_compat::media_job_from_openai_image_generation(&request, "openai-compat");
    let verification = hivemind_media::verify_media_job(&job);
    if !verification.valid {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!(
                "Image generation job is invalid: {}",
                validation_issue_summary(&verification.issues)
            ),
        );
    }

    match write_openai_record(&state.storage_dir, "media-jobs", &job.media_job_id, &job) {
        Ok(_) => {
            let response = hivemind_openai_compat::openai_image_generation_from_media_job(
                &request,
                &job,
                unix_timestamp(),
            );
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Err(error) => openai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "media_job_store_failed",
            format!("Failed to store image generation job: {error}"),
        ),
    }
}

async fn openai_images_edits(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::OpenAiImageEditRequestV1>,
) -> impl IntoResponse {
    let job = hivemind_openai_compat::media_job_from_openai_image_edit(&request, "openai-compat");
    let verification = hivemind_media::verify_media_job(&job);
    if !verification.valid {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!(
                "Image edit job is invalid: {}",
                validation_issue_summary(&verification.issues)
            ),
        );
    }

    match write_openai_record(&state.storage_dir, "media-jobs", &job.media_job_id, &job) {
        Ok(_) => {
            let response = hivemind_openai_compat::openai_image_edit_from_media_job(
                &request,
                &job,
                unix_timestamp(),
            );
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Err(error) => openai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "media_job_store_failed",
            format!("Failed to store image edit job: {error}"),
        ),
    }
}

async fn openai_audio_transcriptions(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::OpenAiAudioTranscriptionRequestV1>,
) -> impl IntoResponse {
    let job = hivemind_openai_compat::media_job_from_openai_audio_transcription(
        &request,
        "openai-compat",
    );
    let verification = hivemind_media::verify_media_job(&job);
    if !verification.valid {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!(
                "Audio transcription job is invalid: {}",
                validation_issue_summary(&verification.issues)
            ),
        );
    }

    match write_openai_record(&state.storage_dir, "media-jobs", &job.media_job_id, &job) {
        Ok(_) => {
            let response =
                hivemind_openai_compat::openai_audio_transcription_from_media_job(&request, &job);
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Err(error) => openai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "media_job_store_failed",
            format!("Failed to store audio transcription job: {error}"),
        ),
    }
}

async fn openai_audio_speech(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::OpenAiAudioSpeechRequestV1>,
) -> impl IntoResponse {
    let job = hivemind_openai_compat::media_job_from_openai_audio_speech(&request, "openai-compat");
    let verification = hivemind_media::verify_media_job(&job);
    if !verification.valid {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!(
                "Audio speech job is invalid: {}",
                validation_issue_summary(&verification.issues)
            ),
        );
    }

    match write_openai_record(&state.storage_dir, "media-jobs", &job.media_job_id, &job) {
        Ok(_) => {
            let response =
                hivemind_openai_compat::openai_audio_speech_from_media_job(&request, &job);
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Err(error) => openai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "media_job_store_failed",
            format!("Failed to store audio speech job: {error}"),
        ),
    }
}

async fn openai_vector_stores_create(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::OpenAiVectorStoreCreateRequestV1>,
) -> impl IntoResponse {
    let manifest = hivemind_openai_compat::vector_store_manifest_from_openai_request(
        &request,
        "openai-compat",
    );
    let verification = hivemind_vector::verify_vector_store_manifest(&manifest);
    if !verification.valid {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!(
                "Vector store manifest is invalid: {}",
                validation_issue_summary(&verification.issues)
            ),
        );
    }

    match write_openai_record(
        &state.storage_dir,
        "vector-stores",
        &manifest.vector_store_id,
        &manifest,
    ) {
        Ok(_) => {
            let response = hivemind_openai_compat::openai_vector_store_from_manifest(
                &manifest,
                unix_timestamp(),
                request.metadata,
            );
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Err(error) => openai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "vector_store_failed",
            format!("Failed to store vector store manifest: {error}"),
        ),
    }
}

async fn openai_vector_store_by_id(
    State(state): State<AppState>,
    Path(vector_store_id): Path<String>,
) -> impl IntoResponse {
    match read_openai_record::<hivemind_vector::VectorStoreManifestV1>(
        &state.storage_dir,
        "vector-stores",
        &vector_store_id,
    ) {
        Ok(Some(manifest)) => {
            let response = hivemind_openai_compat::openai_vector_store_from_manifest(
                &manifest,
                unix_timestamp(),
                None,
            );
            (StatusCode::OK, Json(json!(response))).into_response()
        }
        Ok(None) => openai_error_response(
            StatusCode::NOT_FOUND,
            "vector_store_not_found",
            format!("Vector store {vector_store_id} was not found"),
        ),
        Err(error) => openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!("Failed to read vector store manifest: {error}"),
        ),
    }
}

async fn openai_vector_store_search(
    State(state): State<AppState>,
    Path(vector_store_id): Path<String>,
    Json(request): Json<hivemind_openai_compat::OpenAiVectorStoreSearchRequestV1>,
) -> impl IntoResponse {
    let manifest = match read_openai_record::<hivemind_vector::VectorStoreManifestV1>(
        &state.storage_dir,
        "vector-stores",
        &vector_store_id,
    ) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => {
            return openai_error_response(
                StatusCode::NOT_FOUND,
                "vector_store_not_found",
                format!("Vector store {vector_store_id} was not found"),
            );
        }
        Err(error) => {
            return openai_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                format!("Failed to read vector store manifest: {error}"),
            );
        }
    };

    let requester = request.user.as_deref().unwrap_or("openai-compat");
    let native_request =
        hivemind_openai_compat::vector_search_request_from_openai(&manifest, &request, requester);
    let plan = hivemind_vector::vector_search_plan(&manifest, &native_request);
    if !plan.valid {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            format!(
                "Vector search request is invalid: {}",
                validation_issue_summary(&plan.issues)
            ),
        );
    }
    let response = hivemind_openai_compat::openai_vector_search_response_from_plan(&request, &plan);
    (StatusCode::OK, Json(json!(response))).into_response()
}

async fn openai_embeddings(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::EmbeddingRequestV1>,
) -> impl IntoResponse {
    let Some((indexed, package_ref)) = package_for_model(&state.packages, &request.model) else {
        return openai_error_response(
            StatusCode::NOT_FOUND,
            "model_not_found",
            format!("Model {} is not in the local registry", request.model),
        );
    };
    let package = package_for_request(indexed, &package_ref);
    let request_id = format!("embd-{}", uuid::Uuid::new_v4());
    let execution_requests = hivemind_openai_compat::embedding_requests_to_executions(
        &request,
        &package.package_ref,
        &package.manifest.package_id,
        &package.manifest.version,
        request_id,
    );
    if execution_requests.is_empty() {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "Embedding input must contain at least one item",
        );
    }

    let runner_reputation =
        runner_reputation_summaries(&state.registry_snapshot.validation_reports);
    let controls = match compatibility_routing_controls(&request.metadata) {
        Ok(controls) => controls,
        Err(message) => {
            return openai_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                message,
            );
        }
    };
    let miner_capacity = route_miner_capacity_inputs(
        state.miner_dir.as_ref().as_path(),
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    );
    let mut responses = Vec::with_capacity(execution_requests.len());
    for execution_request in execution_requests {
        let response = execute_with_controlled_routing(
            execution_request,
            package.clone(),
            state.marketplace_runner_offer_dir.as_ref().as_path(),
            &runner_reputation,
            &miner_capacity,
            &controls,
            state.job_dir.as_ref().as_path(),
            state.receipt_dir.as_ref().as_path(),
            state.marketplace_payment_dir.as_ref().as_path(),
            state.marketplace_audit_dir.as_ref().as_path(),
            state.route_trace_dir.as_ref().as_path(),
            state.stream_event_dir.as_ref().as_path(),
        )
        .await;
        if response.status != ExecutionStatus::Succeeded {
            return openai_error_from_execution(&response);
        }
        responses.push(response);
    }

    let embedding =
        hivemind_openai_compat::embedding_response_from_executions(&request, &responses);
    compatibility_json_response(StatusCode::OK, embedding, &responses[0])
}

async fn openai_moderations(
    State(state): State<AppState>,
    Json(request): Json<hivemind_openai_compat::OpenAiModerationRequestV1>,
) -> impl IntoResponse {
    let Some((indexed, package_ref)) = package_for_model(&state.packages, &request.model) else {
        return openai_error_response(
            StatusCode::NOT_FOUND,
            "model_not_found",
            format!("Model {} is not in the local registry", request.model),
        );
    };
    let package = package_for_request(indexed, &package_ref);
    let request_id = format!("modr-{}", uuid::Uuid::new_v4());
    let execution_requests = hivemind_openai_compat::moderation_requests_to_executions(
        &request,
        &package.package_ref,
        &package.manifest.package_id,
        &package.manifest.version,
        request_id.clone(),
    );
    if execution_requests.is_empty() {
        return openai_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "Moderation input must contain at least one item",
        );
    }

    let runner_reputation =
        runner_reputation_summaries(&state.registry_snapshot.validation_reports);
    let controls = match compatibility_routing_controls(&request.metadata) {
        Ok(controls) => controls,
        Err(message) => {
            return openai_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                message,
            );
        }
    };
    let miner_capacity = route_miner_capacity_inputs(
        state.miner_dir.as_ref().as_path(),
        state.marketplace_hardware_offer_dir.as_ref().as_path(),
    );
    let mut responses = Vec::with_capacity(execution_requests.len());
    for execution_request in execution_requests {
        let response = execute_with_controlled_routing(
            execution_request,
            package.clone(),
            state.marketplace_runner_offer_dir.as_ref().as_path(),
            &runner_reputation,
            &miner_capacity,
            &controls,
            state.job_dir.as_ref().as_path(),
            state.receipt_dir.as_ref().as_path(),
            state.marketplace_payment_dir.as_ref().as_path(),
            state.marketplace_audit_dir.as_ref().as_path(),
            state.route_trace_dir.as_ref().as_path(),
            state.stream_event_dir.as_ref().as_path(),
        )
        .await;
        if response.status != ExecutionStatus::Succeeded {
            return openai_error_from_execution(&response);
        }
        responses.push(response);
    }

    let moderation = hivemind_openai_compat::moderation_response_from_executions(
        &request, &responses, request_id,
    );
    compatibility_json_response(StatusCode::OK, moderation, &responses[0])
}

async fn execute_with_controlled_routing(
    request: ExecutionRequestV1,
    package: hivemind_package::LocalPackage,
    marketplace_runner_offer_dir: &FsPath,
    runner_reputation: &[RunnerReputationSummaryV1],
    miner_capacity: &[MinerCapacityInputV1],
    controls: &CompatibilityRoutingControls,
    job_dir: &FsPath,
    receipt_dir: &FsPath,
    marketplace_payment_dir: &FsPath,
    marketplace_audit_dir: &FsPath,
    route_trace_dir: &FsPath,
    stream_event_dir: &FsPath,
) -> ExecutionResponseV1 {
    let offers =
        marketplace_offers_for_package_ref(marketplace_runner_offer_dir, &request.package_ref);
    let report = planner_report_with_trust_policy(
        &request,
        &package,
        &routing_runners(),
        &offers,
        miner_capacity,
        controls.policy_mode.clone(),
        controls.max_marketplace_results,
        runner_reputation,
        controls.trust_policy.as_ref(),
    );
    let mut response = execute_with_route_fallback(request, package, report).await;
    persist_response_route_decision(route_trace_dir, &mut response);
    persist_response_route_trace(route_trace_dir, &mut response);
    persist_response_receipt(receipt_dir, &mut response);
    persist_response_marketplace_audit(
        marketplace_payment_dir,
        marketplace_audit_dir,
        &mut response,
    );
    attach_partial_receipt_stream_event(&mut response);
    persist_response_stream_events(stream_event_dir, &mut response);
    persist_response_job_record(job_dir, &mut response);
    response
}

async fn execute_with_route_fallback(
    request: ExecutionRequestV1,
    package: hivemind_package::LocalPackage,
    report: RoutePlannerReportV1,
) -> ExecutionResponseV1 {
    let mut trace = RouteExecutionTraceV1::new(request.request_id.clone(), None);
    let candidates = ordered_execution_candidates(&report.plan);
    if candidates.is_empty() {
        let mut response = ExecutionResponseV1::failed(
            request.request_id,
            no_eligible_route_error(&report.plan).with_details(json!({ "plan": report.plan })),
            Default::default(),
        );
        attach_route_metadata(&mut response, &report, &trace);
        return response;
    }

    let mut last_response = None;
    for candidate in candidates {
        let mut routed_request = request.clone();
        routed_request.preferred_artifact_group = candidate
            .artifact_group
            .clone()
            .or_else(|| routed_request.preferred_artifact_group.clone());
        let route_id = candidate.route_id.clone();
        let mut response =
            execute_candidate_route(routed_request.clone(), package.clone(), &candidate).await;
        apply_route_billing(&mut response, &candidate);
        trace.push_attempt(route_attempt(&candidate, &response));
        if response.status == ExecutionStatus::Succeeded {
            trace.selected_route_id = Some(route_id);
            attach_route_metadata(&mut response, &report, &trace);
            let job_id =
                json_path_str(&response.metadata, &["jobOrder", "jobId"]).map(str::to_string);
            attach_stream_events_metadata(&mut response, &routed_request, job_id.as_deref());
            return response;
        }
        attach_route_metadata(&mut response, &report, &trace);
        if !should_attempt_fallback(&response) {
            return response;
        }
        last_response = Some(response);
        tracing::info!("route {route_id} failed; checking fallback route");
    }

    last_response.unwrap_or_else(|| {
        let mut response = ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(ErrorCode::ExecutionFailed, "Route execution failed"),
            Default::default(),
        );
        attach_route_metadata(&mut response, &report, &trace);
        response
    })
}

fn no_eligible_route_error(plan: &RoutePlanV1) -> SwarmAiErrorV1 {
    let reasons: Vec<_> = plan
        .candidate_routes
        .iter()
        .filter_map(|candidate| candidate.reason.as_deref())
        .collect();
    let code = if reasons.iter().any(|reason| {
        reason.contains("does not declare support") || reason.contains("does not support")
    }) {
        ErrorCode::UnsupportedOperation
    } else if reasons.iter().any(|reason| {
        reason.contains("access")
            || reason.contains("Access")
            || reason.contains("Permission")
            || reason.contains("license")
            || reason.contains("Trust policy")
    }) {
        ErrorCode::AccessDenied
    } else if reasons
        .iter()
        .any(|reason| reason.contains("artifact") || reason.contains("target"))
    {
        ErrorCode::UnsupportedTarget
    } else {
        ErrorCode::ExecutionFailed
    };
    let message = if reasons.is_empty() {
        "No eligible route candidate is available for execution".to_string()
    } else {
        reasons.join("; ")
    };
    SwarmAiErrorV1::new(code, message)
}

fn ordered_execution_candidates(plan: &RoutePlanV1) -> Vec<CandidateRoute> {
    let mut route_ids = Vec::new();
    if let Some(selected) = &plan.selected_route_id {
        route_ids.push(selected.clone());
    }
    route_ids.extend(plan.fallback_route_ids.iter().cloned());
    for candidate in &plan.candidate_routes {
        if candidate.decision == RouteDecision::Eligible
            && !route_ids
                .iter()
                .any(|route_id| route_id == &candidate.route_id)
        {
            route_ids.push(candidate.route_id.clone());
        }
    }
    route_ids
        .into_iter()
        .filter_map(|route_id| {
            plan.candidate_routes
                .iter()
                .find(|candidate| candidate.route_id == route_id)
                .cloned()
        })
        .collect()
}

async fn execute_candidate_route(
    request: ExecutionRequestV1,
    package: hivemind_package::LocalPackage,
    candidate: &CandidateRoute,
) -> ExecutionResponseV1 {
    match candidate.runner_type {
        RunnerType::Browser => hivemind_browser_runner::execute_manifest_with_hash_and_route(
            &package.manifest,
            package.package_ref,
            package.manifest_hash,
            request,
            &hivemind_browser_runner::default_browser_capabilities(),
            Some(candidate.route_id.clone()),
        ),
        RunnerType::Local => {
            hivemind_local_runner::execute_with_route(
                request,
                package,
                Some(candidate.route_id.clone()),
            )
            .await
        }
        RunnerType::RemoteGpu => hivemind_remote_runner::execute_manifest_with_hash_and_route(
            &package.manifest,
            package.package_ref,
            package.manifest_hash,
            request,
            &hivemind_remote_runner::default_descriptor(),
            Some(candidate.route_id.clone()),
        ),
        RunnerType::Marketplace => {
            execute_marketplace_candidate_route(request, package, candidate).await
        }
    }
}

async fn execute_marketplace_candidate_route(
    request: ExecutionRequestV1,
    package: hivemind_package::LocalPackage,
    candidate: &CandidateRoute,
) -> ExecutionResponseV1 {
    let local_runner_id = hivemind_local_runner::descriptor().runner_id;
    if candidate
        .runner_id
        .as_deref()
        .is_none_or(|runner_id| runner_id == local_runner_id)
    {
        return hivemind_local_runner::execute_with_route(
            request,
            package,
            Some(candidate.route_id.clone()),
        )
        .await;
    }

    let runner_id = candidate
        .runner_id
        .clone()
        .unwrap_or_else(|| hivemind_remote_runner::default_descriptor().runner_id);
    let descriptor = hivemind_remote_runner::default_remote_gpu_descriptor(runner_id);
    hivemind_remote_runner::execute_manifest_with_hash_and_route(
        &package.manifest,
        package.package_ref,
        package.manifest_hash,
        request,
        &descriptor,
        Some(candidate.route_id.clone()),
    )
}

fn route_attempt(candidate: &CandidateRoute, response: &ExecutionResponseV1) -> RouteAttemptV1 {
    RouteAttemptV1 {
        route_id: candidate.route_id.clone(),
        runner_id: candidate.runner_id.clone(),
        runner_type: candidate.runner_type.clone(),
        status: response.status.clone(),
        error_code: response.error.as_ref().map(|error| error.code),
        error_message: response.error.as_ref().map(|error| error.message.clone()),
    }
}

fn should_attempt_fallback(response: &ExecutionResponseV1) -> bool {
    if response.status == ExecutionStatus::Succeeded {
        return false;
    }
    let Some(error) = response.error.as_ref() else {
        return true;
    };
    matches!(
        error.code,
        ErrorCode::RunnerOverloaded
            | ErrorCode::DeadlineExceeded
            | ErrorCode::ExecutionFailed
            | ErrorCode::UnsupportedTarget
    )
}

fn apply_route_billing(response: &mut ExecutionResponseV1, candidate: &CandidateRoute) {
    let billing = hivemind_core::receipt::BillingInfo {
        estimated_cost: candidate.estimated.cost,
        currency: candidate.estimated.currency.clone(),
    };
    if !response.metadata.is_object() {
        response.metadata = json!({});
    }
    response.metadata["routeBilling"] = json!(billing);

    let Some(receipt_value) = response.metadata.get("receipt").cloned() else {
        return;
    };
    let Ok(mut receipt) =
        serde_json::from_value::<hivemind_core::ExecutionReceiptV1>(receipt_value)
    else {
        return;
    };
    receipt.billing = billing;
    sign_receipt(&mut receipt);
    if let Ok(receipt_id) = canonical_receipt_id(&receipt) {
        receipt.receipt_id = receipt_id;
        response.receipt_ref = Some(format!("local://receipt/{}", receipt.receipt_id));
        response.metadata["receipt"] = json!(receipt);
    }
}

fn attach_stream_events_metadata(
    response: &mut ExecutionResponseV1,
    request: &ExecutionRequestV1,
    job_id: Option<&str>,
) {
    if !request.options.stream || response.status != ExecutionStatus::Succeeded {
        return;
    }
    let events = stream_events_from_execution_response(request, response, job_id);
    if events.is_empty() {
        return;
    }
    if !response.metadata.is_object() {
        response.metadata = json!({});
    }
    response.metadata["streamEvents"] = json!(&events);
    response.metadata["streamEventSummary"] =
        hivemind_streams::stream_event_summary(&events, "execution-response-normalizer");
}

fn stream_events_from_execution_response(
    request: &ExecutionRequestV1,
    response: &ExecutionResponseV1,
    job_id: Option<&str>,
) -> Vec<hivemind_core::StreamingEventV1> {
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let job_id = job_id.map(str::to_string);
    let mut sequence = 0;
    let mut events = Vec::new();
    events.push(streaming_event(
        request.request_id.clone(),
        job_id.clone(),
        sequence,
        StreamingEventType::Started,
        timestamp.clone(),
        json!({
            "status": "started",
            "task": request.task.as_str(),
            "source": "execution-response-normalizer"
        }),
    ));
    sequence += 1;

    for payload in stream_delta_payloads(&response.output) {
        events.push(streaming_event(
            request.request_id.clone(),
            job_id.clone(),
            sequence,
            StreamingEventType::TextDelta,
            timestamp.clone(),
            payload,
        ));
        sequence += 1;
    }

    events.push(streaming_event(
        request.request_id.clone(),
        job_id,
        sequence,
        StreamingEventType::Completed,
        timestamp,
        json!({
            "status": "completed",
            "outputHash": hivemind_core::hash_canonical_json(&response.output),
            "source": "execution-response-normalizer"
        }),
    ));
    events
}

fn stream_delta_payloads(output: &Value) -> Vec<Value> {
    let mut payloads = stream_chunk_payloads(output);
    if payloads.is_empty()
        && let Some(text) = response_output_text(output)
        && !text.is_empty()
    {
        payloads.push(json!({
            "index": 0,
            "delta": text,
            "source": "final-output"
        }));
    }
    payloads
}

fn stream_chunk_payloads(output: &Value) -> Vec<Value> {
    output
        .get("stream")
        .and_then(|stream| stream.get("chunks"))
        .and_then(Value::as_array)
        .map(|chunks| {
            chunks
                .iter()
                .enumerate()
                .filter_map(|(fallback_index, chunk)| {
                    let delta = chunk
                        .get("delta")
                        .and_then(Value::as_str)
                        .or_else(|| chunk.get("text").and_then(Value::as_str))?;
                    Some(json!({
                        "index": chunk
                            .get("index")
                            .and_then(Value::as_u64)
                            .unwrap_or(fallback_index as u64),
                        "delta": delta,
                        "source": "runner-output-stream",
                        "rawChunk": chunk
                    }))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn response_output_text(output: &Value) -> Option<String> {
    output
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            output
                .get("text")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
}

fn persist_response_route_trace(route_trace_dir: &FsPath, response: &mut ExecutionResponseV1) {
    if let Err(error) = try_persist_response_route_trace(route_trace_dir, response) {
        warn!(
            request_id = response.request_id.as_str(),
            "failed to persist route execution trace: {error}"
        );
        if !response.metadata.is_object() {
            response.metadata = json!({});
        }
        response.metadata["routeTraceStore"] = json!({
            "schemaVersion": "swarm-ai.route-trace-store-capture.v1",
            "stored": false,
            "error": error.to_string()
        });
    }
}

fn try_persist_response_route_trace(
    route_trace_dir: &FsPath,
    response: &mut ExecutionResponseV1,
) -> Result<()> {
    let Some(trace_value) = response.metadata.get("routeExecution").cloned() else {
        return Ok(());
    };
    let trace: RouteExecutionTraceV1 = serde_json::from_value(trace_value)
        .context("response routeExecution metadata is not a RouteExecutionTraceV1")?;
    let path = hivemind_router::write_route_execution_trace(route_trace_dir, &trace)?;
    let request_id = trace.request_id.clone();
    let selected_route_id = trace.selected_route_id.clone();
    let attempted_route_count = trace.attempts.len();
    let fallback_applied = trace.fallback_applied;
    let trace_ref = hivemind_router::route_trace_ref(&trace.request_id);
    if !response.metadata.is_object() {
        response.metadata = json!({});
    }
    response.metadata["routeTraceStore"] = json!({
        "schemaVersion": "swarm-ai.route-trace-store-capture.v1",
        "stored": true,
        "storedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "requestId": request_id,
        "selectedRouteId": selected_route_id,
        "attemptedRouteCount": attempted_route_count,
        "fallbackApplied": fallback_applied,
        "traceRef": trace_ref,
        "tracePath": path.display().to_string()
    });
    Ok(())
}

fn persist_response_route_decision(route_audit_dir: &FsPath, response: &mut ExecutionResponseV1) {
    if let Err(error) = try_persist_response_route_decision(route_audit_dir, response) {
        warn!(
            request_id = response.request_id.as_str(),
            "failed to persist route decision: {error}"
        );
        if !response.metadata.is_object() {
            response.metadata = json!({});
        }
        response.metadata["routeDecisionStore"] = json!({
            "schemaVersion": "swarm-ai.route-decision-store-capture.v1",
            "stored": false,
            "error": error.to_string()
        });
    }
}

fn try_persist_response_route_decision(
    route_audit_dir: &FsPath,
    response: &mut ExecutionResponseV1,
) -> Result<()> {
    let Some(report_value) = response.metadata.get("routeReport").cloned() else {
        return Ok(());
    };
    let report: RoutePlannerReportV1 = serde_json::from_value(report_value)
        .context("response routeReport metadata is not a RoutePlannerReportV1")?;
    let path = hivemind_router::write_route_decision(route_audit_dir, &report)?;
    let proof = hivemind_router::route_decision_proof(&report);
    let verification = hivemind_router::verify_route_decision_proof(&report, &proof);
    let request_id = report.plan.request_id.clone();
    let selected_route_id = report.plan.selected_route_id.clone();
    let candidate_count = report.plan.candidate_routes.len();
    let eligible_candidate_count = report
        .plan
        .candidate_routes
        .iter()
        .filter(|candidate| candidate.decision == RouteDecision::Eligible)
        .count();
    let decision_ref = hivemind_router::route_decision_ref(&report.plan.request_id);
    if !response.metadata.is_object() {
        response.metadata = json!({});
    }
    response.metadata["routeDecisionStore"] = json!({
        "schemaVersion": "swarm-ai.route-decision-store-capture.v1",
        "stored": true,
        "storedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "requestId": request_id,
        "selectedRouteId": selected_route_id,
        "candidateCount": candidate_count,
        "eligibleCandidateCount": eligible_candidate_count,
        "rejectedCandidateCount": candidate_count.saturating_sub(eligible_candidate_count),
        "fallbackRouteCount": report.plan.fallback_route_ids.len(),
        "planningElapsedMs": report.planning_timing.as_ref().map(|timing| timing.elapsed_ms),
        "proofHash": proof.report_hash,
        "proofValid": verification.valid,
        "decisionRef": decision_ref,
        "decisionPath": path.display().to_string()
    });
    Ok(())
}

fn persist_response_receipt(receipt_dir: &FsPath, response: &mut ExecutionResponseV1) {
    if let Err(error) = try_persist_response_receipt(receipt_dir, response) {
        warn!(
            request_id = response.request_id.as_str(),
            "failed to persist receipt: {error}"
        );
        if !response.metadata.is_object() {
            response.metadata = json!({});
        }
        response.metadata["receiptStore"] = json!({
            "schemaVersion": "swarm-ai.receipt-store-capture.v1",
            "stored": false,
            "error": error.to_string()
        });
    }
}

fn try_persist_response_receipt(
    receipt_dir: &FsPath,
    response: &mut ExecutionResponseV1,
) -> Result<()> {
    let Some(capture) = hivemind_receipts::capture_response_receipt(receipt_dir, response)? else {
        return Ok(());
    };
    if !response.metadata.is_object() {
        response.metadata = json!({});
    }
    let receipt_id = capture.receipt.receipt_id.clone();
    let receipt_ref = format!("local://receipt/{receipt_id}");
    response.metadata["receiptStore"] = json!({
        "schemaVersion": "swarm-ai.receipt-store-capture.v1",
        "stored": true,
        "storedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "receiptId": receipt_id,
        "receiptRef": receipt_ref,
        "receiptPath": capture.receipt_path,
        "verificationValid": capture.verification.valid,
        "issueCount": capture.verification.issues.len(),
        "warningCount": capture.verification.warnings.len()
    });
    attach_marketplace_settlement_metadata(response);
    Ok(())
}

fn attach_marketplace_settlement_metadata(response: &mut ExecutionResponseV1) {
    let Some(receipt_value) = response.metadata.get("receipt").cloned() else {
        return;
    };
    let Ok(receipt) = serde_json::from_value::<hivemind_core::ExecutionReceiptV1>(receipt_value)
    else {
        return;
    };
    let Some(service_quote_value) = response.metadata.get("marketplaceServiceQuote").cloned()
    else {
        return;
    };
    let Ok(service_quote) =
        serde_json::from_value::<hivemind_marketplace::ServiceQuoteV1>(service_quote_value)
    else {
        return;
    };
    let Some(payment_value) = response.metadata.get("paymentAuthorization").cloned() else {
        return;
    };
    let Ok(payment_authorization) =
        serde_json::from_value::<hivemind_marketplace::PaymentAuthorizationV1>(payment_value)
    else {
        return;
    };
    let receipt_ref = json_path_str(&response.metadata, &["receiptStore", "receiptRef"])
        .map(str::to_string)
        .or_else(|| response.receipt_ref.clone());
    let result = hivemind_marketplace::settlement_from_verified_receipt_with_payment(
        &receipt,
        Some(&service_quote),
        Some(&payment_authorization),
        payment_authorization.payer.clone(),
        payment_authorization.payee.clone(),
        receipt_ref,
    );
    if !response.metadata.is_object() {
        response.metadata = json!({});
    }
    response.metadata["settlementVerification"] = json!(result.verification);
    if let Some(settlement) = result.settlement {
        let settlement_ref = format!("local://settlements/{}", settlement.settlement_id);
        response.metadata["settlementEvent"] = json!(settlement);
        response.metadata["settlement"] = json!({
            "schemaVersion": "hivemind.marketplace_settlement_link.v1",
            "settlementId": response.metadata["settlementEvent"]["settlementId"].clone(),
            "settlementRef": settlement_ref,
            "status": response.metadata["settlementEvent"]["status"].clone(),
            "quoteId": response.metadata["settlementEvent"]["quoteId"].clone(),
            "paymentAuthorizationId": response.metadata["settlementEvent"]["paymentAuthorizationId"].clone()
        });
        response.metadata["marketplaceLifecycle"]["settlementStatus"] =
            response.metadata["settlementEvent"]["status"].clone();
        response.metadata["marketplaceLifecycle"]["settlementId"] =
            response.metadata["settlementEvent"]["settlementId"].clone();
        response.metadata["marketplaceLifecycle"]["settlementRef"] =
            response.metadata["settlement"]["settlementRef"].clone();
    }
}

fn persist_response_marketplace_audit(
    marketplace_payment_dir: &FsPath,
    marketplace_audit_dir: &FsPath,
    response: &mut ExecutionResponseV1,
) {
    if let Err(error) = try_persist_response_marketplace_audit(
        marketplace_payment_dir,
        marketplace_audit_dir,
        response,
    ) {
        warn!(
            request_id = response.request_id.as_str(),
            "failed to persist marketplace audit artifacts: {error}"
        );
        if !response.metadata.is_object() {
            response.metadata = json!({});
        }
        response.metadata["marketplaceAuditStore"] = json!({
            "schemaVersion": "hivemind.marketplace-audit-store-capture.v1",
            "stored": false,
            "error": error.to_string()
        });
    }
}

fn try_persist_response_marketplace_audit(
    marketplace_payment_dir: &FsPath,
    marketplace_audit_dir: &FsPath,
    response: &mut ExecutionResponseV1,
) -> Result<()> {
    if !response.metadata.is_object() {
        response.metadata = json!({});
    }

    let mut quote_stored = false;
    let mut payment_stored = false;
    let mut settlement_stored = false;

    if let Some(quote) = response
        .metadata
        .get("marketplaceServiceQuote")
        .cloned()
        .and_then(|value| {
            serde_json::from_value::<hivemind_marketplace::ServiceQuoteV1>(value).ok()
        })
    {
        let path = hivemind_marketplace::write_service_quote(marketplace_audit_dir, &quote)?;
        let quote_ref = format!("local://marketplace-quotes/{}", quote.quote_id);
        response.metadata["serviceQuoteStore"] = json!({
            "schemaVersion": "hivemind.service-quote-store-capture.v1",
            "stored": true,
            "storedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "quoteId": quote.quote_id,
            "quoteRef": quote_ref,
            "quotePath": path.display().to_string()
        });
        let quote_ref_value = response.metadata["serviceQuoteStore"]["quoteRef"].clone();
        if let Some(lifecycle) = response
            .metadata
            .get_mut("marketplaceLifecycle")
            .and_then(Value::as_object_mut)
        {
            lifecycle.insert("serviceQuoteRef".to_string(), quote_ref_value);
        }
        quote_stored = true;
    }

    if let Some(authorization) = response
        .metadata
        .get("paymentAuthorization")
        .cloned()
        .and_then(|value| {
            serde_json::from_value::<hivemind_marketplace::PaymentAuthorizationV1>(value).ok()
        })
    {
        let path = hivemind_marketplace::write_payment_authorization(
            marketplace_payment_dir,
            &authorization,
        )?;
        let authorization_ref = format!(
            "local://payment-authorizations/{}",
            authorization.authorization_id
        );
        response.metadata["paymentAuthorizationStore"] = json!({
            "schemaVersion": "hivemind.payment-authorization-store-capture.v1",
            "stored": true,
            "storedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "authorizationId": authorization.authorization_id,
            "authorizationRef": authorization_ref,
            "authorizationPath": path.display().to_string()
        });
        let authorization_ref_value =
            response.metadata["paymentAuthorizationStore"]["authorizationRef"].clone();
        if let Some(lifecycle) = response
            .metadata
            .get_mut("marketplaceLifecycle")
            .and_then(Value::as_object_mut)
        {
            lifecycle.insert(
                "paymentAuthorizationRef".to_string(),
                authorization_ref_value,
            );
        }
        payment_stored = true;
    }

    if let Some(settlement) = response
        .metadata
        .get("settlementEvent")
        .cloned()
        .and_then(|value| {
            serde_json::from_value::<hivemind_marketplace::SettlementEventV1>(value).ok()
        })
    {
        let path =
            hivemind_marketplace::write_settlement_event(marketplace_audit_dir, &settlement)?;
        let settlement_ref = format!("local://settlements/{}", settlement.settlement_id);
        response.metadata["settlementStore"] = json!({
            "schemaVersion": "hivemind.settlement-store-capture.v1",
            "stored": true,
            "storedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "settlementId": settlement.settlement_id,
            "settlementRef": settlement_ref,
            "settlementPath": path.display().to_string()
        });
        if response.metadata.get("settlement").is_some() {
            response.metadata["settlement"]["settlementRef"] =
                response.metadata["settlementStore"]["settlementRef"].clone();
        }
        let settlement_ref_value = response.metadata["settlementStore"]["settlementRef"].clone();
        if let Some(lifecycle) = response
            .metadata
            .get_mut("marketplaceLifecycle")
            .and_then(Value::as_object_mut)
        {
            lifecycle.insert("settlementRef".to_string(), settlement_ref_value);
        }
        settlement_stored = true;
    }

    if quote_stored || payment_stored || settlement_stored {
        response.metadata["marketplaceAuditStore"] = json!({
            "schemaVersion": "hivemind.marketplace-audit-store-capture.v1",
            "stored": quote_stored || payment_stored || settlement_stored,
            "storedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "serviceQuoteStored": quote_stored,
            "paymentStored": payment_stored,
            "settlementStored": settlement_stored,
            "serviceQuoteStore": response.metadata.get("serviceQuoteStore").cloned(),
            "paymentAuthorizationStore": response.metadata.get("paymentAuthorizationStore").cloned(),
            "settlementStore": response.metadata.get("settlementStore").cloned()
        });
    }

    Ok(())
}

fn attach_partial_receipt_stream_event(response: &mut ExecutionResponseV1) {
    if let Err(error) = try_attach_partial_receipt_stream_event(response) {
        warn!(
            request_id = response.request_id.as_str(),
            "failed to attach partial receipt stream event: {error}"
        );
        if !response.metadata.is_object() {
            response.metadata = json!({});
        }
        response.metadata["partialReceiptStreamEvent"] = json!({
            "schemaVersion": "swarm-ai.partial-receipt-stream-event.v1",
            "attached": false,
            "error": error.to_string()
        });
    }
}

fn try_attach_partial_receipt_stream_event(response: &mut ExecutionResponseV1) -> Result<()> {
    if response.status != ExecutionStatus::Succeeded {
        return Ok(());
    }
    let Some(events) = hivemind_streams::response_stream_events(response)? else {
        return Ok(());
    };
    if events.is_empty()
        || events
            .iter()
            .any(|event| event.event_type == StreamingEventType::PartialReceipt)
    {
        return Ok(());
    }
    let Some(receipt_id) = json_path_str(&response.metadata, &["receiptStore", "receiptId"]) else {
        return Ok(());
    };
    let receipt_id = receipt_id.to_string();
    let receipt_ref = json_path_str(&response.metadata, &["receiptStore", "receiptRef"])
        .map(str::to_string)
        .or_else(|| response.receipt_ref.clone())
        .unwrap_or_else(|| format!("local://receipt/{receipt_id}"));
    let verification_valid = response
        .metadata
        .get("receiptStore")
        .and_then(|store| store.get("verificationValid"))
        .and_then(Value::as_bool);
    let issue_count = response
        .metadata
        .get("receiptStore")
        .and_then(|store| store.get("issueCount"))
        .and_then(Value::as_u64);
    let warning_count = response
        .metadata
        .get("receiptStore")
        .and_then(|store| store.get("warningCount"))
        .and_then(Value::as_u64);

    let request_id = events
        .first()
        .map(|event| event.request_id.clone())
        .unwrap_or_else(|| response.request_id.clone());
    let job_id = events
        .iter()
        .find_map(|event| event.job_id.clone())
        .or_else(|| {
            json_path_str(&response.metadata, &["streamEventSummary", "jobId"]).map(str::to_string)
        });
    let final_receipt = hivemind_receipts::receipt_from_response(response);
    let runner_id = final_receipt
        .as_ref()
        .map(|receipt| receipt.runner_id.clone());
    let output_hash = final_receipt
        .as_ref()
        .map(|receipt| receipt.output_hash.clone())
        .unwrap_or_else(|| hivemind_core::hash_canonical_json(&response.output));
    let metrics = response.metrics.clone();
    let partial_timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let partial_payload = |sequence: u64| {
        let partial_receipt =
            hivemind_receipts::create_partial_receipt(hivemind_receipts::PartialReceiptDraftV1 {
                request_id: request_id.clone(),
                job_id: job_id.clone(),
                receipt_id: Some(receipt_id.clone()),
                receipt_ref: Some(receipt_ref.clone()),
                runner_id: runner_id.clone(),
                sequence,
                status: ExecutionStatus::Partial,
                emitted_at: partial_timestamp.clone(),
                progress: Some(1.0),
                output_hash: Some(output_hash.clone()),
                metrics: metrics.clone(),
                verification_valid,
                issue_count,
                warning_count,
                evidence_refs: vec![receipt_ref.clone()],
            });
        json!({
            "status": "receipt-captured",
            "receiptId": receipt_id.clone(),
            "receiptRef": receipt_ref.clone(),
            "verificationValid": verification_valid,
            "issueCount": issue_count,
            "warningCount": warning_count,
            "partialReceiptId": partial_receipt.partial_receipt_id.clone(),
            "partialReceipt": partial_receipt,
            "source": "receipt-store-capture"
        })
    };

    let mut rebuilt = Vec::with_capacity(events.len() + 1);
    let mut partial_event_id = None;
    let mut inserted_partial = false;
    for event in events {
        if !inserted_partial && event.event_type == StreamingEventType::Completed {
            let partial = streaming_event(
                request_id.clone(),
                job_id.clone(),
                rebuilt.len() as u64,
                StreamingEventType::PartialReceipt,
                partial_timestamp.clone(),
                partial_payload(rebuilt.len() as u64),
            );
            partial_event_id = Some(partial.event_id.clone());
            rebuilt.push(partial);
            inserted_partial = true;
        }
        rebuilt.push(streaming_event(
            event.request_id,
            event.job_id,
            rebuilt.len() as u64,
            event.event_type,
            event.timestamp,
            event.payload,
        ));
    }
    if !inserted_partial {
        let partial = streaming_event(
            request_id.clone(),
            job_id.clone(),
            rebuilt.len() as u64,
            StreamingEventType::PartialReceipt,
            partial_timestamp.clone(),
            partial_payload(rebuilt.len() as u64),
        );
        partial_event_id = Some(partial.event_id.clone());
        rebuilt.push(partial);
    }

    response.metadata["streamEvents"] = json!(&rebuilt);
    response.metadata["streamEventSummary"] = hivemind_streams::stream_event_summary(
        &rebuilt,
        "execution-response-normalizer+receipt-capture",
    );
    response.metadata["partialReceiptStreamEvent"] = json!({
        "schemaVersion": "swarm-ai.partial-receipt-stream-event.v1",
        "attached": true,
        "eventId": partial_event_id
    });
    Ok(())
}

fn persist_response_job_record(job_dir: &FsPath, response: &mut ExecutionResponseV1) {
    if let Err(error) = try_persist_response_job_record(job_dir, response) {
        warn!(
            request_id = response.request_id.as_str(),
            "failed to persist job record: {error}"
        );
        if !response.metadata.is_object() {
            response.metadata = json!({});
        }
        response.metadata["jobStore"] = json!({
            "schemaVersion": "swarm-ai.job-store-capture.v1",
            "stored": false,
            "error": error.to_string()
        });
    }
}

fn try_persist_response_job_record(
    job_dir: &FsPath,
    response: &mut ExecutionResponseV1,
) -> Result<()> {
    let Some(record) =
        hivemind_jobs::job_record_from_execution_response(response, hivemind_jobs::now_timestamp())
    else {
        return Ok(());
    };
    let job_id = record.job_id.clone();
    let status = record.status.clone();
    let path = hivemind_jobs::upsert_job_record(job_dir, record)?;
    let job_ref = format!("local://job/{job_id}");
    if !response.metadata.is_object() {
        response.metadata = json!({});
    }
    response.metadata["jobStore"] = json!({
        "schemaVersion": "swarm-ai.job-store-capture.v1",
        "stored": true,
        "storedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "jobId": job_id,
        "jobRef": job_ref,
        "jobPath": path.display().to_string(),
        "status": status
    });
    Ok(())
}

fn persist_job_cancellation_stream_event(
    job_dir: &FsPath,
    stream_event_dir: &FsPath,
    result: &mut hivemind_jobs::JobCancellationResultV1,
) {
    if let Err(error) = try_persist_job_cancellation_stream_event(stream_event_dir, result)
        .and_then(|_| {
            hivemind_jobs::upsert_job_record(job_dir, result.record.clone())?;
            Ok(())
        })
    {
        warn!(
            job_id = result.job_id.as_str(),
            "failed to persist job cancellation stream event: {error}"
        );
        if !result.record.metadata.is_object() {
            result.record.metadata = json!({});
        }
        result.record.metadata["streamEventStore"] = json!({
            "schemaVersion": "swarm-ai.stream-event-store.v1",
            "stored": false,
            "error": error.to_string()
        });
    }
}

fn try_persist_job_cancellation_stream_event(
    stream_event_dir: &FsPath,
    result: &mut hivemind_jobs::JobCancellationResultV1,
) -> Result<()> {
    hivemind_streams::append_job_cancellation_event(stream_event_dir, result)?;
    Ok(())
}

fn persist_response_stream_events(stream_event_dir: &FsPath, response: &mut ExecutionResponseV1) {
    if let Err(error) = try_persist_response_stream_events(stream_event_dir, response) {
        warn!(
            request_id = response.request_id.as_str(),
            "failed to persist stream events: {error}"
        );
        if !response.metadata.is_object() {
            response.metadata = json!({});
        }
        response.metadata["streamEventStore"] = json!({
            "schemaVersion": "swarm-ai.stream-event-store.v1",
            "stored": false,
            "error": error.to_string()
        });
    }
}

fn try_persist_response_stream_events(
    stream_event_dir: &FsPath,
    response: &mut ExecutionResponseV1,
) -> Result<()> {
    let Some(events) = hivemind_streams::response_stream_events(response)? else {
        return Ok(());
    };
    if events.is_empty() {
        return Ok(());
    }

    let keys = hivemind_streams::stream_event_storage_keys(response, &events);
    if keys.is_empty() {
        return Ok(());
    }
    let store = hivemind_streams::write_stream_events_for_keys(stream_event_dir, &keys, &events)?;

    if !response.metadata.is_object() {
        response.metadata = json!({});
    }
    response.metadata["streamEventStore"] = json!(store);
    Ok(())
}

fn attach_route_metadata(
    response: &mut ExecutionResponseV1,
    report: &RoutePlannerReportV1,
    trace: &RouteExecutionTraceV1,
) {
    if !response.metadata.is_object() {
        response.metadata = json!({});
    }
    if let Some(job_order) = &report.job_order {
        response.metadata["jobOrder"] = json!(job_order);
    }
    response.metadata["routeReport"] = json!(report);
    response.metadata["routePlan"] = json!(report.plan);
    response.metadata["routeExecution"] = json!(trace);
    if let Some(shortlist) = &report.marketplace_shortlist {
        response.metadata["marketplaceShortlist"] = json!(shortlist);
    }
    if !report.runner_reputation.is_empty() {
        response.metadata["runnerReputation"] = json!(report.runner_reputation);
    }
    if !report.miner_capacity.is_empty() {
        response.metadata["minerCapacity"] = json!(report.miner_capacity);
    }
    if let Some(trust_policy) = &report.trust_policy {
        response.metadata["trustPolicy"] = json!(trust_policy);
    }
    attach_marketplace_lifecycle_metadata(response, report, trace);
}

fn attach_marketplace_lifecycle_metadata(
    response: &mut ExecutionResponseV1,
    report: &RoutePlannerReportV1,
    trace: &RouteExecutionTraceV1,
) {
    if response.status != ExecutionStatus::Succeeded {
        return;
    }
    let Some(selected_route_id) = trace.selected_route_id.as_deref() else {
        return;
    };
    let Some(candidate) = report
        .plan
        .candidate_routes
        .iter()
        .find(|candidate| candidate.route_id == selected_route_id)
    else {
        return;
    };
    if candidate.runner_type != RunnerType::Marketplace
        || candidate.estimated.cost <= 0.0
        || candidate.estimated.currency.trim().is_empty()
        || candidate.estimated.currency == "none"
    {
        return;
    }
    let Some(base_order) = report.job_order.as_ref() else {
        return;
    };
    let Some((job_order, job_quote)) =
        marketplace_job_quote_from_candidate(base_order, candidate, report)
    else {
        return;
    };
    let settlement_ref = format!("local://marketplace-settlement/{}", job_quote.quote_id);
    let deadline_ms = job_order
        .constraints
        .deadline_ms
        .unwrap_or(30_000)
        .clamp(1_000, i64::MAX as u64);
    let deadline = (Utc::now() + Duration::milliseconds(deadline_ms as i64))
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    let Ok(lease) = execution_lease_from_quote(
        &job_order,
        &job_quote,
        job_order.requester.clone(),
        settlement_ref.clone(),
        deadline,
    ) else {
        return;
    };
    let Some(service_quote) = marketplace_service_quote_from_job_quote(
        &job_order,
        &job_quote,
        candidate,
        report,
        response,
        &settlement_ref,
    ) else {
        return;
    };
    let payment_ref = Some(format!("local://payment/{}", service_quote.quote_id));
    let payment_authorization = hivemind_marketplace::authorize_payment(
        &service_quote,
        job_order.requester.clone(),
        candidate
            .runner_id
            .clone()
            .unwrap_or_else(|| "marketplace-runner".to_string()),
        hivemind_marketplace::PaymentAdapterKind::LocalDev,
        payment_ref,
    );
    let payment_verification = hivemind_marketplace::verify_payment_authorization(
        &payment_authorization,
        Some(&service_quote),
    );

    response.metadata["jobOrder"] = json!(job_order);
    response.metadata["jobQuotes"] = json!([job_quote.clone()]);
    response.metadata["executionLease"] = json!(lease.clone());
    response.metadata["marketplaceServiceQuote"] = json!(service_quote.clone());
    response.metadata["paymentAuthorization"] = json!(payment_authorization.clone());
    response.metadata["paymentAuthorizationVerification"] = json!(payment_verification);
    response.metadata["marketplaceLifecycle"] = json!({
        "schemaVersion": "hivemind.marketplace_execution_lifecycle.v1",
        "source": "route-planner-selected-marketplace-candidate",
        "routeId": candidate.route_id,
        "runnerId": candidate.runner_id,
        "offerId": selected_route_offer_id(&candidate.route_id),
        "jobQuoteId": job_quote.quote_id,
        "serviceQuoteId": service_quote.quote_id,
        "leaseId": lease.lease_id,
        "paymentAuthorizationId": payment_authorization.authorization_id,
        "paymentStatus": "authorized",
        "settlementRef": settlement_ref,
        "settlementStatus": "ready-for-receipt-settlement"
    });
}

fn marketplace_job_quote_from_candidate(
    base_order: &JobOrderV1,
    candidate: &CandidateRoute,
    report: &RoutePlannerReportV1,
) -> Option<(JobOrderV1, JobQuoteV1)> {
    let runner_id = candidate.runner_id.clone()?;
    let mut order = base_order.clone();
    order.settlement_method = "marketplace-direct-pay-per-call".to_string();
    order.max_price = Some(PriceV1 {
        amount: candidate.estimated.cost,
        currency: candidate.estimated.currency.clone(),
    });
    order.job_id = canonical_job_order_id(&order).ok()?;

    let privacy_mode = selected_route_privacy_tier(&candidate.route_id, &order, report);
    let verification_mode = selected_route_verification_tier(&candidate.route_id, &order, report);
    let validation_support = vec![integrity_tier_wire_name(&verification_mode)];
    let estimated_completion_ms = order
        .constraints
        .max_latency_ms
        .unwrap_or(candidate.estimated.first_token_ms.saturating_add(1_000))
        .max(candidate.estimated.first_token_ms);
    let expires_at = (Utc::now() + Duration::minutes(5)).to_rfc3339_opts(SecondsFormat::Secs, true);
    let price = PriceV1 {
        amount: candidate.estimated.cost,
        currency: candidate.estimated.currency.clone(),
    };
    let mut quote = JobQuoteV1 {
        schema_version: JOB_QUOTE_SCHEMA_VERSION.to_string(),
        quote_id: String::new(),
        job_id: order.job_id.clone(),
        runner_id,
        route_id: Some(candidate.route_id.clone()),
        price: price.clone(),
        price_model: hivemind_core::PriceModel::Fixed,
        privacy_mode,
        verification_mode,
        estimated_start_delay_ms: candidate.estimated.queue_ms,
        estimated_time_to_first_output_ms: Some(candidate.estimated.first_token_ms),
        estimated_completion_ms: Some(estimated_completion_ms),
        cache_hit_claim: selected_route_cache_hit_claim(&candidate.route_id, report),
        validation_support,
        expires_at,
        terms: json!({
            "quoteInput": "selected-route",
            "routeId": candidate.route_id,
            "runnerType": candidate.runner_type,
            "offerId": selected_route_offer_id(&candidate.route_id),
            "estimated": candidate.estimated,
            "policyMode": report.policy_mode,
            "source": "route-planner"
        }),
        signature: None,
    };
    quote.quote_id = canonical_job_quote_id(&quote).ok()?;
    Some((order, quote))
}

fn marketplace_service_quote_from_job_quote(
    order: &JobOrderV1,
    job_quote: &JobQuoteV1,
    candidate: &CandidateRoute,
    report: &RoutePlannerReportV1,
    response: &ExecutionResponseV1,
    settlement_ref: &str,
) -> Option<hivemind_marketplace::ServiceQuoteV1> {
    let runner_id = candidate.runner_id.clone()?;
    let offer_id =
        selected_route_offer_id(&candidate.route_id).unwrap_or_else(|| candidate.route_id.clone());
    let input_tokens = response.metrics.input_tokens.unwrap_or(1).max(1);
    let output_tokens = response.metrics.output_tokens.unwrap_or(1).max(1);
    let mut quote = hivemind_marketplace::ServiceQuoteV1 {
        schema_version: hivemind_marketplace::SERVICE_QUOTE_SCHEMA_VERSION.to_string(),
        quote_id: String::new(),
        job_id: Some(order.job_id.clone()),
        request_id: order.request_id.clone(),
        offer_id,
        listing_id: selected_route_offer_id(&candidate.route_id),
        runner_id,
        package_ref: order.package_ref.clone(),
        estimated_input_tokens: input_tokens,
        estimated_output_tokens: output_tokens,
        estimated_cost: job_quote.price.amount,
        currency: job_quote.price.currency.clone(),
        price: Some(job_quote.price.clone()),
        price_model: Some(job_quote.price_model.clone()),
        privacy_mode: Some(job_quote.privacy_mode.clone()),
        verification_mode: Some(job_quote.verification_mode.clone()),
        estimated_start_delay_ms: Some(job_quote.estimated_start_delay_ms),
        estimated_time_to_first_output_ms: job_quote.estimated_time_to_first_output_ms,
        estimated_completion_ms: job_quote.estimated_completion_ms,
        cache_hit_claim: Some(job_quote.cache_hit_claim),
        validation_support: job_quote.validation_support.clone(),
        settlement_model: hivemind_marketplace::SettlementModel::DirectPayPerCall,
        expires_at: job_quote.expires_at.clone(),
        terms: json!({
            "quoteInput": "selected-route-payment",
            "jobQuoteId": job_quote.quote_id,
            "routeId": candidate.route_id,
            "runnerType": candidate.runner_type,
            "policyMode": report.policy_mode,
            "settlementRef": settlement_ref
        }),
        details: json!({
            "jobId": order.job_id,
            "jobOrder": order,
            "jobQuoteId": job_quote.quote_id,
            "routeId": candidate.route_id,
            "runnerType": candidate.runner_type,
            "estimated": candidate.estimated,
            "escrowRef": format!("local://marketplace-escrow/{}", job_quote.quote_id),
            "cancellationRules": {
                "runnerTimeoutMs": order.constraints.deadline_ms.unwrap_or(30_000),
                "allowRequesterCancel": true
            }
        }),
        quote_timing: None,
        signature: None,
    };
    hivemind_marketplace::sign_service_quote(&mut quote);
    Some(quote)
}

fn selected_route_offer_id(route_id: &str) -> Option<String> {
    route_id
        .strip_prefix("marketplace-offer-")
        .or_else(|| route_id.strip_prefix("miner-offer-"))
        .map(str::to_string)
}

fn selected_route_privacy_tier(
    route_id: &str,
    order: &JobOrderV1,
    report: &RoutePlannerReportV1,
) -> PrivacyTier {
    if let Some(offer_id) = route_id.strip_prefix("marketplace-offer-")
        && let Some(tier) = report
            .marketplace_shortlist
            .as_ref()
            .and_then(|shortlist| {
                shortlist
                    .rankings
                    .iter()
                    .find(|ranking| ranking.offer_id == offer_id)
            })
            .and_then(|ranking| ranking.selected_privacy_tier.clone())
    {
        return tier;
    }
    if let Some(tier) = report
        .miner_capacity
        .iter()
        .find(|signal| signal.route_id == route_id)
        .and_then(|signal| signal.selected_privacy_tier.clone())
    {
        return tier;
    }
    order.privacy.privacy_tier.clone()
}

fn selected_route_verification_tier(
    route_id: &str,
    order: &JobOrderV1,
    report: &RoutePlannerReportV1,
) -> IntegrityTier {
    if let Some(offer_id) = route_id.strip_prefix("marketplace-offer-")
        && let Some(tier) = report
            .marketplace_shortlist
            .as_ref()
            .and_then(|shortlist| {
                shortlist
                    .rankings
                    .iter()
                    .find(|ranking| ranking.offer_id == offer_id)
            })
            .and_then(|ranking| ranking.selected_verification_tier.clone())
    {
        return tier;
    }
    if let Some(tier) = report
        .miner_capacity
        .iter()
        .find(|signal| signal.route_id == route_id)
        .and_then(|signal| signal.selected_verification_tier.clone())
    {
        return tier;
    }
    order.required_verification_tier.clone()
}

fn selected_route_cache_hit_claim(route_id: &str, report: &RoutePlannerReportV1) -> bool {
    if let Some(offer_id) = route_id.strip_prefix("marketplace-offer-")
        && let Some(cache_hit) = report
            .marketplace_shortlist
            .as_ref()
            .and_then(|shortlist| {
                shortlist
                    .rankings
                    .iter()
                    .find(|ranking| ranking.offer_id == offer_id)
            })
            .map(|ranking| ranking.cache_hit_claim)
    {
        return cache_hit;
    }
    report
        .miner_capacity
        .iter()
        .find(|signal| signal.route_id == route_id)
        .map(|signal| signal.warm_cache)
        .unwrap_or(false)
}

fn integrity_tier_wire_name(tier: &IntegrityTier) -> String {
    serde_json::to_value(tier)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "receipt_only".to_string())
}

fn package_for_request(
    indexed: &IndexedPackage,
    requested_ref: &str,
) -> hivemind_package::LocalPackage {
    let requested_ref = requested_ref.trim();
    let mut package = indexed.package.clone();
    let request_matches_known_ref = !requested_ref.is_empty()
        && (package.package_ref == requested_ref
            || indexed
                .entry
                .package_refs
                .iter()
                .any(|reference| reference.package_ref == requested_ref));
    if request_matches_known_ref {
        package.package_ref = requested_ref.to_string();
    }
    package
}

fn package_for_model<'a>(
    packages: &'a [IndexedPackage],
    model: &str,
) -> Option<(&'a IndexedPackage, String)> {
    let model = model.trim();
    if model.is_empty() {
        return None;
    }
    if let Some(indexed) = find_package(packages, model, "") {
        return Some((indexed, model.to_string()));
    }
    let indexed = find_package(packages, "", model)?;
    let reference = indexed
        .entry
        .package_refs
        .first()
        .map(|reference| reference.package_ref.clone())
        .unwrap_or_else(|| indexed.package.package_ref.clone());
    Some((indexed, reference))
}

fn package_for_ai_request<'a>(
    packages: &'a [IndexedPackage],
    request: &AiRequestV1,
) -> Option<(&'a IndexedPackage, String)> {
    let selector = &request.package_selector;
    if let Some(package_ref) = non_empty_selector_value(selector.package_ref.as_deref())
        .or_else(|| non_empty_selector_value(selector.service_ref.as_deref()))
    {
        let package_id = selector.package_id.as_deref().unwrap_or_default();
        if let Some(indexed) = find_package(packages, package_ref, package_id) {
            return Some((indexed, package_ref.to_string()));
        }
        if let Some((indexed, resolved_ref)) = package_for_model(packages, package_ref) {
            return Some((indexed, resolved_ref));
        }
    }

    if let Some(model) = non_empty_selector_value(selector.model.as_deref()) {
        if let Some((indexed, package_ref)) = package_for_model(packages, model) {
            return Some((indexed, package_ref));
        }
    }

    if let Some(package_id) = non_empty_selector_value(selector.package_id.as_deref()) {
        let indexed = find_package(packages, "", package_id)?;
        let reference = indexed
            .entry
            .package_refs
            .first()
            .map(|reference| reference.package_ref.clone())
            .unwrap_or_else(|| indexed.package.package_ref.clone());
        return Some((indexed, reference));
    }

    None
}

fn non_empty_selector_value(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn text_preview(bytes: &[u8]) -> Option<String> {
    String::from_utf8(bytes.to_vec()).ok().map(|text| {
        let preview: String = text.chars().take(240).collect();
        if text.chars().count() > 240 {
            format!("{preview}...")
        } else {
            preview
        }
    })
}

fn registry_entry_matches_model_id(entry: &RegistryEntryV1, model_id: &str) -> bool {
    entry.package_id == model_id
        || entry
            .package_refs
            .iter()
            .any(|reference| reference.package_ref == model_id)
}

fn registry_entry_matches_package_query(
    entry: &RegistryEntryV1,
    query: &HivemindPackagesQuery,
) -> bool {
    if query
        .kind
        .as_ref()
        .map(|kind| &entry.kind != kind)
        .unwrap_or(false)
    {
        return false;
    }
    if !optional_query_text_matches(&query.capability, |capability| {
        entry
            .capabilities
            .iter()
            .any(|item| item.eq_ignore_ascii_case(capability))
    }) {
        return false;
    }
    if query
        .modality
        .as_ref()
        .map(|modality| !entry.modalities.iter().any(|item| item == modality))
        .unwrap_or(false)
    {
        return false;
    }
    if query
        .api_surface
        .as_ref()
        .map(|api_surface| !entry.supported_apis.iter().any(|item| item == api_surface))
        .unwrap_or(false)
    {
        return false;
    }
    if !optional_query_text_matches(&query.publisher, |publisher| {
        entry.publisher.address.eq_ignore_ascii_case(publisher)
            || entry.publisher.display_name.eq_ignore_ascii_case(publisher)
    }) {
        return false;
    }
    if !optional_query_text_matches(&query.target, |target| {
        entry
            .targets
            .iter()
            .any(|item| item.eq_ignore_ascii_case(target))
    }) {
        return false;
    }
    if !optional_query_text_matches(&query.engine, |engine| {
        entry
            .engines
            .iter()
            .any(|item| item.eq_ignore_ascii_case(engine))
    }) {
        return false;
    }
    if !optional_query_text_matches(&query.license_type, |license_type| {
        format!("{:?}", entry.license.license_type).eq_ignore_ascii_case(license_type)
    }) {
        return false;
    }
    if query
        .privacy_tier
        .as_ref()
        .map(|tier| !entry.privacy_tiers.iter().any(|item| item == tier))
        .unwrap_or(false)
    {
        return false;
    }
    if query
        .verification_tier
        .as_ref()
        .map(|tier| !entry.verification_tiers.iter().any(|item| item == tier))
        .unwrap_or(false)
    {
        return false;
    }
    if query
        .min_artifact_bytes
        .map(|bytes| entry.approx_artifact_bytes < bytes)
        .unwrap_or(false)
    {
        return false;
    }
    if query
        .max_artifact_bytes
        .map(|bytes| entry.approx_artifact_bytes > bytes)
        .unwrap_or(false)
    {
        return false;
    }
    if query
        .browser_runnable
        .map(|required| entry.browser_runnable != required)
        .unwrap_or(false)
    {
        return false;
    }
    if query
        .gpu_required
        .map(|required| entry.gpu_required != required)
        .unwrap_or(false)
    {
        return false;
    }
    if query
        .min_validator_score
        .map(|score| entry.trust.validator_score.unwrap_or(0.0) < score)
        .unwrap_or(false)
    {
        return false;
    }
    if query
        .min_benchmark_score
        .map(|score| {
            !entry
                .benchmark_scores
                .iter()
                .any(|summary| summary.overall >= score)
        })
        .unwrap_or(false)
    {
        return false;
    }
    if let Some(max_price) = query.max_price() {
        if !registry_entry_price_hint_satisfies(entry, &max_price) {
            return false;
        }
    }

    true
}

impl HivemindPackagesQuery {
    fn max_price(&self) -> Option<PriceV1> {
        Some(PriceV1 {
            amount: self.max_price_amount?,
            currency: self
                .max_price_currency
                .as_ref()
                .filter(|currency| !currency.trim().is_empty())?
                .clone(),
        })
    }
}

fn registry_entry_price_hint_satisfies(entry: &RegistryEntryV1, max_price: &PriceV1) -> bool {
    entry.price_hint.as_ref().is_some_and(|price| {
        price
            .currency
            .eq_ignore_ascii_case(max_price.currency.as_str())
            && price.amount <= max_price.amount
    })
}

fn optional_query_text_matches(value: &Option<String>, matches: impl FnOnce(&str) -> bool) -> bool {
    match value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => matches(value),
        None => true,
    }
}

fn write_openai_record<T: Serialize>(
    storage_dir: &FsPath,
    collection: &str,
    id: &str,
    value: &T,
) -> Result<PathBuf> {
    let dir = openai_record_dir(storage_dir, collection);
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = dir.join(format!("{}.json", safe_record_component(id)));
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(&path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn read_openai_record<T: serde::de::DeserializeOwned>(
    storage_dir: &FsPath,
    collection: &str,
    id: &str,
) -> Result<Option<T>> {
    let path = openai_record_dir(storage_dir, collection)
        .join(format!("{}.json", safe_record_component(id)));
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(value))
}

fn openai_record_dir(storage_dir: &FsPath, collection: &str) -> PathBuf {
    storage_dir.join("openai").join(collection)
}

fn write_provider_record<T: Serialize>(
    storage_dir: &FsPath,
    provider: &str,
    collection: &str,
    id: &str,
    value: &T,
) -> Result<PathBuf> {
    let dir = provider_record_dir(storage_dir, provider, collection);
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let path = dir.join(format!("{}.json", safe_record_component(id)));
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(&path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

fn read_provider_record<T: serde::de::DeserializeOwned>(
    storage_dir: &FsPath,
    provider: &str,
    collection: &str,
    id: &str,
) -> Result<Option<T>> {
    let path = provider_record_dir(storage_dir, provider, collection)
        .join(format!("{}.json", safe_record_component(id)));
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(value))
}

fn provider_record_dir(storage_dir: &FsPath, provider: &str, collection: &str) -> PathBuf {
    storage_dir
        .join("provider-compat")
        .join(safe_record_component(provider))
        .join(collection)
}

fn safe_record_component(value: &str) -> String {
    let component: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if component.is_empty() {
        "record".to_string()
    } else {
        component
    }
}

fn validation_issue_summary(issues: &[hivemind_core::ValidationIssue]) -> String {
    if issues.is_empty() {
        return "no issues".to_string();
    }
    issues
        .iter()
        .take(5)
        .map(|issue| format!("{}: {}", issue.path, issue.message))
        .collect::<Vec<_>>()
        .join("; ")
}

fn json_error(code: ErrorCode, message: &str) -> Value {
    json!(SwarmAiErrorV1::new(code, message))
}

fn json_error_value(error: &SwarmAiErrorV1) -> Value {
    json!(error)
}

fn compatibility_json_response<T: Serialize>(
    status: StatusCode,
    body: T,
    execution: &ExecutionResponseV1,
) -> axum::response::Response {
    let mut response = (status, Json(json!(body))).into_response();
    attach_hivemind_headers(response.headers_mut(), execution);
    response
}

fn compatibility_event_stream_response(
    body: String,
    execution: &ExecutionResponseV1,
) -> axum::response::Response {
    let mut response = event_stream_response(body);
    let headers = response.headers_mut();
    attach_hivemind_headers(headers, execution);
    response
}

fn native_stream_event_response(
    events: &[hivemind_core::StreamingEventV1],
    job_id: &str,
) -> axum::response::Response {
    let mut response = event_stream_response(hivemind_streams::streaming_events_sse_body(events));
    insert_header(response.headers_mut(), "x-hivemind-job-id", job_id);
    response
}

fn event_stream_response(body: String) -> axum::response::Response {
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        "content-type",
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-cache"));
    headers.insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
}

fn attach_hivemind_headers(headers: &mut HeaderMap, execution: &ExecutionResponseV1) {
    insert_header(headers, "x-hivemind-request-id", &execution.request_id);
    if let Some(receipt_ref) = execution.receipt_ref.as_deref() {
        insert_header(headers, "x-hivemind-receipt-ref", receipt_ref);
    }
    if let Some(job_id) = json_path_str(&execution.metadata, &["jobOrder", "jobId"]) {
        insert_header(headers, "x-hivemind-job-id", job_id);
    }
    if let Some(route_id) = selected_route_id(&execution.metadata) {
        insert_header(headers, "x-hivemind-route-decision-ref", route_id);
    }
    if let Some(runner_id) = selected_runner_id(&execution.metadata) {
        insert_header(headers, "x-hivemind-runner-id", runner_id);
    }
    if let Some(privacy_mode) =
        json_path_str(&execution.metadata, &["jobOrder", "privacy", "privacyTier"])
    {
        insert_header(headers, "x-hivemind-privacy-mode", privacy_mode);
    }
    if let Some(verification_mode) = json_path_str(
        &execution.metadata,
        &["jobOrder", "requiredVerificationTier"],
    ) {
        insert_header(headers, "x-hivemind-verification-mode", verification_mode);
    }
    if let Some(policy_id) = json_path_str(&execution.metadata, &["trustPolicy", "policyId"]) {
        insert_header(headers, "x-hivemind-trust-policy-id", policy_id);
    }
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

fn selected_route_id(metadata: &Value) -> Option<&str> {
    json_path_str(metadata, &["routeExecution", "selectedRouteId"])
}

fn selected_runner_id(metadata: &Value) -> Option<&str> {
    let selected_route_id = selected_route_id(metadata);
    let attempts = metadata
        .get("routeExecution")
        .and_then(|trace| trace.get("attempts"))
        .and_then(Value::as_array);
    if let (Some(route_id), Some(attempts)) = (selected_route_id, attempts)
        && let Some(runner_id) = attempts
            .iter()
            .find(|attempt| attempt.get("routeId").and_then(Value::as_str) == Some(route_id))
            .and_then(|attempt| attempt.get("runnerId"))
            .and_then(Value::as_str)
    {
        return Some(runner_id);
    }
    attempts
        .and_then(|attempts| attempts.last())
        .and_then(|attempt| attempt.get("runnerId"))
        .and_then(Value::as_str)
        .or_else(|| json_path_str(metadata, &["runnerId"]))
        .or_else(|| json_path_str(metadata, &["receipt", "runnerId"]))
}

fn json_path_str<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn openai_error_response(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
) -> axum::response::Response {
    (
        status,
        Json(json!(hivemind_openai_compat::error_response(code, message))),
    )
        .into_response()
}

fn openai_error_from_execution(response: &ExecutionResponseV1) -> axum::response::Response {
    let Some(error) = response.error.as_ref() else {
        return openai_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "execution_failed",
            "Execution failed without an error payload",
        );
    };
    openai_error_response(
        openai_status_for_error(error.code),
        openai_code_for_error(error.code),
        error.message.clone(),
    )
}

fn anthropic_error_response(
    status: StatusCode,
    error_type: impl Into<String>,
    message: impl Into<String>,
) -> axum::response::Response {
    (
        status,
        Json(json!(hivemind_provider_compat::anthropic_error_response(
            error_type, message
        ))),
    )
        .into_response()
}

fn anthropic_error_from_execution(response: &ExecutionResponseV1) -> axum::response::Response {
    let Some(error) = response.error.as_ref() else {
        return anthropic_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_error",
            "Execution failed without an error payload",
        );
    };
    anthropic_error_response(
        openai_status_for_error(error.code),
        anthropic_error_type_for_error(error.code),
        error.message.clone(),
    )
}

fn anthropic_error_type_for_error(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::PackageNotFound => "not_found_error",
        ErrorCode::AccessDenied => "permission_error",
        ErrorCode::InvalidManifest | ErrorCode::InvalidRequest | ErrorCode::UnsupportedTarget => {
            "invalid_request_error"
        }
        ErrorCode::UnsupportedOperation => "unsupported_operation_error",
        ErrorCode::RunnerOverloaded | ErrorCode::DeadlineExceeded => "overloaded_error",
        ErrorCode::ExecutionFailed | ErrorCode::ValidationFailed => "api_error",
    }
}

fn gemini_error_response(
    status: StatusCode,
    provider_status: impl Into<String>,
    message: impl Into<String>,
) -> axum::response::Response {
    (
        status,
        Json(json!(hivemind_provider_compat::gemini_error_response(
            status.as_u16(),
            provider_status,
            message,
        ))),
    )
        .into_response()
}

fn gemini_error_from_execution(response: &ExecutionResponseV1) -> axum::response::Response {
    let Some(error) = response.error.as_ref() else {
        return gemini_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "Execution failed without an error payload",
        );
    };
    gemini_error_response(
        openai_status_for_error(error.code),
        gemini_status_for_error(error.code),
        error.message.clone(),
    )
}

fn gemini_status_for_error(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::PackageNotFound => "NOT_FOUND",
        ErrorCode::AccessDenied => "PERMISSION_DENIED",
        ErrorCode::RunnerOverloaded => "UNAVAILABLE",
        ErrorCode::InvalidManifest
        | ErrorCode::InvalidRequest
        | ErrorCode::UnsupportedTarget
        | ErrorCode::UnsupportedOperation => "INVALID_ARGUMENT",
        ErrorCode::DeadlineExceeded => "DEADLINE_EXCEEDED",
        ErrorCode::ExecutionFailed | ErrorCode::ValidationFailed => "INTERNAL",
    }
}

fn huggingface_error_response(
    status: StatusCode,
    error_type: impl Into<String>,
    message: impl Into<String>,
) -> axum::response::Response {
    (
        status,
        Json(json!(hivemind_provider_compat::huggingface_error_response(
            error_type, message,
        ))),
    )
        .into_response()
}

fn huggingface_error_from_execution(response: &ExecutionResponseV1) -> axum::response::Response {
    let Some(error) = response.error.as_ref() else {
        return huggingface_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_error",
            "Execution failed without an error payload",
        );
    };
    huggingface_error_response(
        openai_status_for_error(error.code),
        huggingface_error_type_for_error(error.code),
        error.message.clone(),
    )
}

fn huggingface_error_type_for_error(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::PackageNotFound => "model_not_found",
        ErrorCode::AccessDenied => "access_denied",
        ErrorCode::RunnerOverloaded => "runner_overloaded",
        ErrorCode::InvalidManifest
        | ErrorCode::InvalidRequest
        | ErrorCode::UnsupportedTarget
        | ErrorCode::UnsupportedOperation => "invalid_request",
        ErrorCode::DeadlineExceeded => "deadline_exceeded",
        ErrorCode::ExecutionFailed | ErrorCode::ValidationFailed => "api_error",
    }
}

fn openai_status_for_error(code: ErrorCode) -> StatusCode {
    match code {
        ErrorCode::PackageNotFound => StatusCode::NOT_FOUND,
        ErrorCode::AccessDenied => StatusCode::FORBIDDEN,
        ErrorCode::RunnerOverloaded => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::InvalidManifest | ErrorCode::InvalidRequest | ErrorCode::UnsupportedTarget => {
            StatusCode::BAD_REQUEST
        }
        ErrorCode::UnsupportedOperation => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorCode::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        ErrorCode::ExecutionFailed | ErrorCode::ValidationFailed => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn openai_code_for_error(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::PackageNotFound => "model_not_found",
        ErrorCode::AccessDenied => "access_denied",
        ErrorCode::RunnerOverloaded => "runner_overloaded",
        ErrorCode::InvalidManifest => "invalid_manifest",
        ErrorCode::InvalidRequest => "invalid_request_error",
        ErrorCode::UnsupportedTarget => "unsupported_target",
        ErrorCode::UnsupportedOperation => "unsupported_operation",
        ErrorCode::DeadlineExceeded => "deadline_exceeded",
        ErrorCode::ExecutionFailed => "execution_failed",
        ErrorCode::ValidationFailed => "validation_failed",
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn routing_runners() -> Vec<hivemind_core::RunnerDescriptorV1> {
    vec![
        hivemind_browser_runner::runner_descriptor(
            &hivemind_browser_runner::default_browser_capabilities(),
        ),
        hivemind_local_runner::descriptor(),
        hivemind_remote_runner::default_descriptor(),
    ]
}

fn runner_capabilities() -> Vec<RunnerCapabilityV1> {
    routing_runners()
        .iter()
        .map(hivemind_core::runner_capability_from_descriptor)
        .collect()
}

fn quotes_for_job_order(order: &JobOrderV1) -> Vec<JobQuoteV1> {
    let expires_at = (Utc::now() + Duration::minutes(5)).to_rfc3339_opts(SecondsFormat::Secs, true);
    runner_capabilities()
        .into_iter()
        .filter_map(|capability| {
            job_quote_from_runner_capability(
                order,
                &capability,
                Some(capability.runner_id.clone()),
                expires_at.clone(),
            )
            .ok()
        })
        .collect()
}

pub(crate) fn runner_reputation_summaries(
    reports: &[hivemind_validator::ValidationReportV1],
) -> Vec<RunnerReputationSummaryV1> {
    #[derive(Default)]
    struct Totals {
        quality: f64,
        latency: f64,
        overall: f64,
        count: usize,
        evidence_refs: Vec<String>,
    }

    let mut by_runner = std::collections::BTreeMap::<String, Totals>::new();
    for report in reports {
        if !hivemind_validator::verify_validation_report(report).valid {
            continue;
        }
        let totals = by_runner.entry(report.runner_id.clone()).or_default();
        totals.quality += report.scores.quality;
        totals.latency += report.scores.latency;
        totals.overall += report.scores.overall;
        totals.count += 1;
        totals.evidence_refs.push(report.report_id.clone());
    }

    by_runner
        .into_iter()
        .filter(|(_, totals)| totals.count > 0)
        .map(|(runner_id, mut totals)| {
            totals.evidence_refs.sort();
            totals.evidence_refs.dedup();
            let count = totals.count as f64;
            RunnerReputationSummaryV1 {
                schema_version: "swarm-ai.runner-reputation-summary.v1".to_string(),
                runner_id,
                quality_score: (totals.quality / count).clamp(0.0, 1.0),
                latency_score: (totals.latency / count).clamp(0.0, 1.0),
                overall_score: (totals.overall / count).clamp(0.0, 1.0),
                report_count: totals.count,
                evidence_refs: totals.evidence_refs,
            }
        })
        .collect()
}

fn public_marketplace_offers(packages: &[IndexedPackage]) -> Vec<RunnerOfferV1> {
    vec![default_local_runner_offer(
        &hivemind_local_runner::descriptor(),
        public_package_refs(packages),
    )]
}

fn marketplace_offers_from_packages_and_store(
    packages: &[IndexedPackage],
    offer_dir: &FsPath,
) -> Vec<RunnerOfferV1> {
    let mut offers = public_marketplace_offers(packages);
    if let Ok(stored) = load_runner_offers(offer_dir) {
        offers.extend(stored);
    }
    let mut by_id = BTreeMap::new();
    for offer in offers {
        by_id.insert(offer.offer_id.clone(), offer);
    }
    by_id.into_values().collect()
}

fn marketplace_offers_for_route_request(state: &AppState, package_ref: &str) -> Vec<RunnerOfferV1> {
    marketplace_offers_for_package_ref(
        state.marketplace_runner_offer_dir.as_ref().as_path(),
        package_ref,
    )
}

fn marketplace_offers_for_package_ref(offer_dir: &FsPath, package_ref: &str) -> Vec<RunnerOfferV1> {
    let default_offer = default_local_runner_offer(
        &hivemind_local_runner::descriptor(),
        vec![package_ref.to_string()],
    );
    let mut offers = load_runner_offers(offer_dir)
        .unwrap_or_default()
        .into_iter()
        .filter(|offer| runner_offer_supports_ref(offer, package_ref))
        .collect::<Vec<_>>();

    let default_shadowed = offers.iter().any(|offer| {
        offer.runner_id == default_offer.runner_id
            && hivemind_marketplace::verify_runner_offer(offer).valid
    });
    if !default_shadowed {
        offers.push(default_offer);
    }

    deduplicate_runner_offers(offers)
}

fn deduplicate_runner_offers(offers: Vec<RunnerOfferV1>) -> Vec<RunnerOfferV1> {
    let mut by_id = BTreeMap::new();
    for offer in offers {
        by_id.insert(offer.offer_id.clone(), offer);
    }
    by_id.into_values().collect()
}

fn public_hardware_resource_offers() -> Vec<HardwareResourceOfferV1> {
    vec![
        hivemind_marketplace::default_hardware_resource_offer(
            &hivemind_local_runner::descriptor(),
            "local-market",
        ),
        hivemind_marketplace::default_hardware_resource_offer(
            &hivemind_remote_runner::default_descriptor(),
            "local-market",
        ),
    ]
}

fn hardware_resource_offers_from_store(offer_dir: &FsPath) -> Vec<HardwareResourceOfferV1> {
    let mut offers = public_hardware_resource_offers();
    if let Ok(stored) = load_hardware_resource_offers(offer_dir) {
        offers.extend(stored);
    }
    let mut by_id = BTreeMap::new();
    for offer in offers {
        by_id.insert(offer.offer_id.clone(), offer);
    }
    by_id.into_values().collect()
}

fn marketplace_offer_for_quote(
    packages: &[IndexedPackage],
    offers: &[RunnerOfferV1],
    request: &ExecutionRequestV1,
) -> Option<RunnerOfferV1> {
    let indexed = find_package(packages, &request.package_ref, &request.package_id)?;
    if indexed.entry.license.license_type == LicenseType::Private {
        if !private_marketplace_request_authorized(indexed, request) {
            return None;
        }
        return offers
            .iter()
            .find(|offer| runner_offer_supports_ref(offer, &request.package_ref))
            .cloned()
            .or_else(|| {
                Some(default_local_runner_offer(
                    &hivemind_local_runner::descriptor(),
                    vec![request.package_ref.clone()],
                ))
            });
    }
    offers
        .iter()
        .find(|offer| runner_offer_supports_ref(offer, &request.package_ref))
        .cloned()
        .or_else(|| {
            Some(default_local_runner_offer(
                &hivemind_local_runner::descriptor(),
                public_package_refs(packages),
            ))
        })
}

fn runner_offer_supports_ref(offer: &RunnerOfferV1, package_ref: &str) -> bool {
    offer.supported_package_refs.is_empty()
        || offer
            .supported_package_refs
            .iter()
            .any(|supported| supported == package_ref)
}

fn private_marketplace_request_authorized(
    indexed: &IndexedPackage,
    request: &ExecutionRequestV1,
) -> bool {
    let package = package_for_request(indexed, &request.package_ref);
    let descriptor = hivemind_local_runner::descriptor();
    let access = hivemind_access::evaluate_execution_access_with_revocations(
        &package.manifest,
        &package.package_ref,
        &request.request_id,
        "local-dev",
        "runner-service",
        Some(&descriptor.runner_id),
        request.access_grant.as_ref(),
        request.access_revocation_list.as_ref(),
    );
    access.decision == AccessDecision::Granted
}

fn public_package_refs(packages: &[IndexedPackage]) -> Vec<String> {
    let mut refs: Vec<_> = packages
        .iter()
        .filter(|package| package.entry.license.license_type != LicenseType::Private)
        .flat_map(|package| {
            package
                .entry
                .package_refs
                .iter()
                .map(|reference| reference.package_ref.clone())
        })
        .collect();
    refs.sort();
    refs.dedup();
    refs
}

fn browser_swarm_provider(
    storage_dir: &PathBuf,
) -> hivemind_weeb3_adapter::BrowserSwarmProvider<hivemind_storage::LocalDirectoryStorageProvider> {
    hivemind_weeb3_adapter::BrowserSwarmProvider::with_fallback(
        hivemind_weeb3_adapter::default_browser_swarm_config(),
        hivemind_storage::LocalDirectoryStorageProvider::new(storage_dir),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ArtifactGroup, ArtifactMinimum, ExecutionMetrics, ExecutionOptions, ExecutionPrivacy,
        LicenseInfo, LicenseType, PackageKind, PackageManifestV1, PermissionRequest, Publisher,
        RouteEstimate,
    };
    use std::path::PathBuf;

    #[test]
    fn runner_reputation_summaries_average_valid_validation_reports() {
        let first = validation_report("local-dev", 0.8, 0.7, 0.75);
        let second = validation_report("local-dev", 1.0, 0.9, 0.95);
        let mut invalid = validation_report("remote-dev", 0.9, 0.9, 2.0);
        invalid.scores.overall = 2.0;

        let summaries = runner_reputation_summaries(&[first.clone(), second.clone(), invalid]);

        assert_eq!(summaries.len(), 1);
        let summary = &summaries[0];
        assert_eq!(summary.runner_id, "local-dev");
        assert_eq!(summary.report_count, 2);
        assert!((summary.quality_score - 0.9).abs() < 0.000_001);
        assert!((summary.latency_score - 0.8).abs() < 0.000_001);
        assert!((summary.overall_score - 0.85).abs() < 0.000_001);
        let mut expected_refs = vec![first.report_id.clone(), second.report_id.clone()];
        expected_refs.sort();
        assert_eq!(summary.evidence_refs, expected_refs);
    }

    #[test]
    fn native_job_quotes_use_metadata_and_runner_capabilities() {
        let package = local_package(Vec::new());
        let request = execution_request(&package);
        let order =
            job_order_from_execution_request(&request, "api-requester", ApiSurface::HivemindNative);

        let quotes = quotes_for_job_order(&order);

        assert!(!quotes.is_empty());
        assert!(quotes.iter().all(|quote| quote.job_id == order.job_id));
        assert!(
            quotes
                .iter()
                .any(|quote| quote.terms["quoteInput"] == "metadata-only")
        );
    }

    #[test]
    fn route_metadata_includes_trust_policy_and_miner_capacity() {
        let package = local_package(Vec::new());
        let request = execution_request(&package);
        let mut report = route_report(
            &request,
            &package,
            vec![candidate(
                "local-local-dev-runner",
                RunnerType::Local,
                Some("local-rust-mock"),
                0.0,
                "none",
            )],
            Some("local-local-dev-runner"),
            Vec::new(),
        );
        report.trust_policy = Some(TrustPolicyV1::local_only("test-user"));
        report.miner_capacity = vec![hivemind_router::MinerCapacitySignalV1 {
            schema_version: "swarm-ai.miner-capacity-signal.v1".to_string(),
            route_id: "miner-offer-smoke".to_string(),
            offer_id: "offer-smoke".to_string(),
            runner_id: "remote-dev-gpu-runner".to_string(),
            miner_id: Some("miner-smoke".to_string()),
            operator: "operator-smoke".to_string(),
            trust_tier: hivemind_marketplace::MinerTrustTierV1::Verified,
            privacy_tiers: vec![hivemind_core::PrivacyTier::NoLog],
            verification_tiers: vec![hivemind_core::IntegrityTier::ReceiptOnly],
            decision: RouteDecision::Rejected,
            reasons: vec!["Trust policy does not allow this miner privacy tier".to_string()],
            selected_artifact_group: Some("local-rust-mock".to_string()),
            queue_depth: 0,
            active_jobs: 0,
            max_concurrent_jobs: 1,
            estimated_queue_ms: 0,
            estimated_first_token_ms: 1_200,
            estimated_cost: 0.0,
            currency: "none".to_string(),
            warm_cache: false,
            benchmark_count: 0,
            valid_benchmark_count: 0,
            quality_score: 0.78,
            available_vram_gb: Some(48.0),
            available_ram_gb: 48.0,
            selected_privacy_tier: Some(hivemind_core::PrivacyTier::NoLog),
            selected_verification_tier: Some(hivemind_core::IntegrityTier::ReceiptOnly),
        }];

        let mut response = ExecutionResponseV1::succeeded(
            &request.request_id,
            json!({}),
            ExecutionMetrics::default(),
        );
        let trace = RouteExecutionTraceV1::new(request.request_id.clone(), None);
        attach_route_metadata(&mut response, &report, &trace);

        assert_eq!(
            response.metadata["trustPolicy"]["schemaVersion"],
            json!("swarm-ai.trust-policy.v1")
        );
        assert_eq!(
            response.metadata["minerCapacity"][0]["runnerId"],
            json!("remote-dev-gpu-runner")
        );
        assert_eq!(
            response.metadata["minerCapacity"][0]["decision"],
            json!("rejected")
        );
    }

    #[test]
    fn trust_policy_envelope_can_sign_preset_without_warnings() {
        let response = trust_policy_envelope(TrustPolicyV1::local_only("api-user"), true).unwrap();

        assert_eq!(response.schema_version, "swarm-ai.trust-policy-envelope.v1");
        assert!(response.signature.is_some());
        assert!(response.trust_policy.signature.is_some());
        assert!(response.verification.valid);
        assert!(response.verification.issues.is_empty());
        assert!(response.verification.warnings.is_empty());
    }

    #[test]
    fn route_marketplace_offers_use_stored_offer_without_duplicate_default() {
        let package_ref = "bzz://stored-route-package";
        let dir =
            std::env::temp_dir().join(format!("hivemind-api-offers-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let stored_offer = default_local_runner_offer(
            &hivemind_local_runner::descriptor(),
            vec![package_ref.to_string(), "bzz://other-package".to_string()],
        );
        std::fs::write(
            dir.join("offer.json"),
            serde_json::to_vec_pretty(&stored_offer).unwrap(),
        )
        .unwrap();

        let offers = marketplace_offers_for_package_ref(&dir, package_ref);

        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].offer_id, stored_offer.offer_id);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn route_miner_capacity_uses_stored_hardware_offer_without_daemon_records() {
        let miner_dir =
            std::env::temp_dir().join(format!("hivemind-api-miner-{}", uuid::Uuid::new_v4()));
        let hardware_dir =
            std::env::temp_dir().join(format!("hivemind-api-hardware-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&hardware_dir).unwrap();
        let offer = hivemind_marketplace::default_hardware_resource_offer(
            &hivemind_remote_runner::default_descriptor(),
            "operator-test",
        );
        std::fs::write(
            hardware_dir.join("hardware-offer.json"),
            serde_json::to_vec_pretty(&offer).unwrap(),
        )
        .unwrap();

        let inputs = route_miner_capacity_inputs(&miner_dir, &hardware_dir);

        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].hardware_offer.offer_id, offer.offer_id);
        assert!(inputs[0].heartbeat.is_none());
        assert!(inputs[0].benchmarks.is_empty());

        let _ = std::fs::remove_dir_all(miner_dir);
        let _ = std::fs::remove_dir_all(hardware_dir);
    }

    #[test]
    fn compatibility_routing_controls_parse_nested_trust_policy_metadata() {
        let policy = TrustPolicyV1::local_only("compat-user");
        let metadata = Some(json!({
            "hivemind": {
                "policyMode": "privacy-first",
                "maxMarketplaceResults": 1,
                "trustPolicy": policy,
            }
        }));

        let controls = compatibility_routing_controls(&metadata).unwrap();

        assert_eq!(controls.policy_mode, PolicyMode::PrivacyFirst);
        assert_eq!(controls.max_marketplace_results, 1);
        assert_eq!(
            controls
                .trust_policy
                .as_ref()
                .map(|policy| policy.owner.as_str()),
            Some("compat-user")
        );
    }

    #[test]
    fn compatibility_routing_controls_parse_provider_metadata_object() {
        let policy = TrustPolicyV1::open_marketplace("provider-user");
        let metadata = json!({
            "policyMode": "quality-first",
            "maxMarketplaceResults": 2,
            "trustPolicy": policy,
        });

        let controls = compatibility_routing_controls_from_value(Some(&metadata)).unwrap();

        assert_eq!(controls.policy_mode, PolicyMode::QualityFirst);
        assert_eq!(controls.max_marketplace_results, 2);
        assert_eq!(
            controls
                .trust_policy
                .as_ref()
                .map(|policy| policy.owner.as_str()),
            Some("provider-user")
        );
    }

    #[test]
    fn compatibility_routing_controls_reject_invalid_trust_policy_metadata() {
        let mut policy = TrustPolicyV1::local_only("provider-user");
        policy.policy_id = "trust-policy-tampered".to_string();
        let metadata = json!({
            "trustPolicy": policy,
        });

        let error = compatibility_routing_controls_from_value(Some(&metadata)).unwrap_err();

        assert!(error.contains("metadata trustPolicy is invalid"));
        assert!(error.contains("$.policyId"));
    }

    #[tokio::test]
    async fn fallback_updates_trace_selected_route_and_receipt_billing() {
        let package = local_package(Vec::new());
        let request = execution_request(&package);
        let report = route_report(
            &request,
            &package,
            vec![
                candidate(
                    "browser-stale",
                    RunnerType::Browser,
                    Some("browser-missing"),
                    0.0,
                    "none",
                ),
                candidate(
                    "local-local-dev-runner",
                    RunnerType::Local,
                    Some("local-rust-mock"),
                    0.25,
                    "xDAI",
                ),
            ],
            Some("browser-stale"),
            vec!["local-local-dev-runner".to_string()],
        );

        let response = execute_with_route_fallback(request, package, report).await;

        assert_eq!(response.status, ExecutionStatus::Succeeded);
        let trace: RouteExecutionTraceV1 =
            serde_json::from_value(response.metadata["routeExecution"].clone()).unwrap();
        assert_eq!(
            trace.attempted_route_ids,
            vec![
                "browser-stale".to_string(),
                "local-local-dev-runner".to_string()
            ]
        );
        assert!(trace.fallback_applied);
        assert_eq!(
            trace.selected_route_id.as_deref(),
            Some("local-local-dev-runner")
        );

        let receipt: hivemind_core::ExecutionReceiptV1 =
            serde_json::from_value(response.metadata["receipt"].clone()).unwrap();
        assert_eq!(receipt.route_id.as_deref(), Some("local-local-dev-runner"));
        assert_eq!(receipt.billing.estimated_cost, 0.25);
        assert_eq!(receipt.billing.currency, "xDAI");
        assert!(hivemind_receipts::verify_receipt(&receipt).valid);
        assert_eq!(
            response.receipt_ref,
            Some(format!("local://receipt/{}", receipt.receipt_id))
        );

        let dir = test_temp_dir("hivemind-receipt-store");
        let mut stored_response = response.clone();
        persist_response_receipt(&dir, &mut stored_response);
        assert_eq!(
            stored_response.metadata["receiptStore"]["stored"],
            json!(true)
        );
        assert_eq!(
            stored_response.metadata["receiptStore"]["receiptId"],
            json!(receipt.receipt_id.as_str())
        );
        let lookup = hivemind_receipts::get_receipt(&dir, &receipt.receipt_id)
            .unwrap()
            .unwrap();
        assert!(lookup.verification.valid);
        assert_eq!(
            lookup.receipt.route_id.as_deref(),
            Some("local-local-dev-runner")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn route_trace_store_capture_feeds_receipt_v2_context() {
        let package = local_package(Vec::new());
        let request = execution_request(&package);
        let report = route_report(
            &request,
            &package,
            vec![candidate(
                "local-local-dev-runner",
                RunnerType::Local,
                Some("local-rust-mock"),
                0.0,
                "none",
            )],
            Some("local-local-dev-runner"),
            Vec::new(),
        );

        let response = execute_with_route_fallback(request, package, report).await;
        assert_eq!(response.status, ExecutionStatus::Succeeded);

        let route_trace_dir = test_temp_dir("hivemind-route-traces-api");
        let receipt_dir = test_temp_dir("hivemind-route-trace-receipts");
        let job_dir = test_temp_dir("hivemind-route-trace-jobs");
        let mut stored_response = response.clone();
        persist_response_route_decision(&route_trace_dir, &mut stored_response);
        persist_response_route_trace(&route_trace_dir, &mut stored_response);
        persist_response_receipt(&receipt_dir, &mut stored_response);
        persist_response_job_record(&job_dir, &mut stored_response);

        assert_eq!(
            stored_response.metadata["routeDecisionStore"]["stored"],
            json!(true)
        );
        assert_eq!(
            stored_response.metadata["routeDecisionStore"]["decisionRef"],
            json!("local://route-decision/request-1")
        );
        assert_eq!(
            stored_response.metadata["routeDecisionStore"]["proofValid"],
            json!(true)
        );
        assert_eq!(
            stored_response.metadata["routeTraceStore"]["stored"],
            json!(true)
        );
        assert_eq!(
            stored_response.metadata["routeTraceStore"]["traceRef"],
            json!("local://route-trace/request-1")
        );
        let lookup = hivemind_router::get_route_execution_trace(&route_trace_dir, "request-1")
            .unwrap()
            .expect("stored route trace should be readable");
        assert_eq!(
            lookup.trace.selected_route_id.as_deref(),
            Some("local-local-dev-runner")
        );
        let decision = hivemind_router::get_route_decision(&route_trace_dir, "request-1")
            .unwrap()
            .expect("stored route decision should be readable");
        assert_eq!(
            decision.report.plan.selected_route_id.as_deref(),
            Some("local-local-dev-runner")
        );
        assert!(decision.verification.valid, "{:#?}", decision.verification);

        let receipt: hivemind_core::ExecutionReceiptV1 =
            serde_json::from_value(stored_response.metadata["receipt"].clone()).unwrap();
        let context = receipt_v2_context_from_job_store(&job_dir, &receipt);
        assert_eq!(
            context.route_decision_ref.as_deref(),
            Some("local://route-decision/request-1")
        );
        assert_eq!(
            context.trace_ref.as_deref(),
            Some("local://route-trace/request-1")
        );

        std::fs::remove_dir_all(&route_trace_dir).ok();
        std::fs::remove_dir_all(&receipt_dir).ok();
        std::fs::remove_dir_all(&job_dir).ok();
    }

    #[tokio::test]
    async fn marketplace_route_uses_non_local_runner_identity_for_receipts() {
        let package = local_package(Vec::new());
        let request = execution_request(&package);
        let mut marketplace = candidate(
            "miner-offer-hardware-remote",
            RunnerType::Marketplace,
            Some("local-rust-mock"),
            0.5,
            "xDAI",
        );
        marketplace.runner_id = Some("marketplace-miner-remote".to_string());
        marketplace.estimated.privacy = "remote:no-log".to_string();
        let report = route_report(
            &request,
            &package,
            vec![marketplace],
            Some("miner-offer-hardware-remote"),
            Vec::new(),
        );

        let response = execute_with_route_fallback(request, package, report).await;

        assert_eq!(response.status, ExecutionStatus::Succeeded);
        let trace: RouteExecutionTraceV1 =
            serde_json::from_value(response.metadata["routeExecution"].clone()).unwrap();
        assert_eq!(
            trace.selected_route_id.as_deref(),
            Some("miner-offer-hardware-remote")
        );
        let receipt: hivemind_core::ExecutionReceiptV1 =
            serde_json::from_value(response.metadata["receipt"].clone()).unwrap();
        assert_eq!(receipt.runner_id, "marketplace-miner-remote");
        assert_eq!(
            receipt.route_id.as_deref(),
            Some("miner-offer-hardware-remote")
        );
        assert_eq!(receipt.billing.estimated_cost, 0.5);
        assert_eq!(receipt.billing.currency, "xDAI");
        assert!(hivemind_receipts::verify_receipt(&receipt).valid);

        let job_order: JobOrderV1 =
            serde_json::from_value(response.metadata["jobOrder"].clone()).unwrap();
        assert_eq!(
            job_order.settlement_method,
            "marketplace-direct-pay-per-call"
        );
        assert!(job_order.max_price.is_some());
        let quotes: Vec<JobQuoteV1> =
            serde_json::from_value(response.metadata["jobQuotes"].clone()).unwrap();
        assert_eq!(quotes.len(), 1);
        assert_eq!(quotes[0].job_id, job_order.job_id);
        assert_eq!(quotes[0].runner_id, "marketplace-miner-remote");
        assert_eq!(
            quotes[0].route_id.as_deref(),
            Some("miner-offer-hardware-remote")
        );
        assert_eq!(quotes[0].price.amount, 0.5);
        assert_eq!(quotes[0].price.currency, "xDAI");
        let lease: hivemind_core::ExecutionLeaseV1 =
            serde_json::from_value(response.metadata["executionLease"].clone()).unwrap();
        assert_eq!(lease.job_id, job_order.job_id);
        assert_eq!(lease.quote_id, quotes[0].quote_id);
        assert_eq!(lease.runner_id, "marketplace-miner-remote");
        assert_eq!(lease.max_cost.amount, 0.5);
        assert_eq!(
            response.metadata["marketplaceLifecycle"]["paymentStatus"],
            json!("authorized")
        );
        assert_eq!(
            response.metadata["marketplaceLifecycle"]["settlementStatus"],
            json!("ready-for-receipt-settlement")
        );
        let service_quote: hivemind_marketplace::ServiceQuoteV1 =
            serde_json::from_value(response.metadata["marketplaceServiceQuote"].clone()).unwrap();
        assert_eq!(
            service_quote.job_id.as_deref(),
            Some(job_order.job_id.as_str())
        );
        assert_eq!(service_quote.runner_id, "marketplace-miner-remote");
        assert_eq!(service_quote.estimated_cost, 0.5);
        assert!(hivemind_marketplace::verify_service_quote(&service_quote, None).valid);
        let payment_authorization: hivemind_marketplace::PaymentAuthorizationV1 =
            serde_json::from_value(response.metadata["paymentAuthorization"].clone()).unwrap();
        assert_eq!(payment_authorization.quote_id, service_quote.quote_id);
        assert_eq!(
            payment_authorization.job_id.as_deref(),
            Some(job_order.job_id.as_str())
        );
        assert_eq!(payment_authorization.amount, 0.5);
        assert_eq!(
            payment_authorization.status,
            hivemind_marketplace::PaymentAuthorizationStatus::Authorized
        );
        assert!(
            hivemind_marketplace::verify_payment_authorization(
                &payment_authorization,
                Some(&service_quote)
            )
            .valid
        );

        let receipt_dir = test_temp_dir("hivemind-marketplace-receipts");
        let payment_dir = test_temp_dir("hivemind-marketplace-payments");
        let audit_dir = test_temp_dir("hivemind-marketplace-audit");
        let job_dir = test_temp_dir("hivemind-marketplace-job-lifecycle");
        let mut stored_response = response.clone();
        persist_response_receipt(&receipt_dir, &mut stored_response);
        persist_response_marketplace_audit(&payment_dir, &audit_dir, &mut stored_response);
        assert_eq!(
            stored_response.metadata["marketplaceLifecycle"]["settlementStatus"],
            json!("settled")
        );
        let settlement: hivemind_marketplace::SettlementEventV1 =
            serde_json::from_value(stored_response.metadata["settlementEvent"].clone()).unwrap();
        assert_eq!(settlement.receipt_id, receipt.receipt_id);
        assert_eq!(
            settlement.payment_authorization_id.as_deref(),
            Some(payment_authorization.authorization_id.as_str())
        );
        assert!(hivemind_marketplace::verify_settlement_event(&settlement).valid);
        assert_eq!(
            stored_response.metadata["paymentAuthorizationStore"]["stored"],
            json!(true)
        );
        assert_eq!(
            stored_response.metadata["serviceQuoteStore"]["stored"],
            json!(true)
        );
        assert_eq!(
            stored_response.metadata["settlementStore"]["stored"],
            json!(true)
        );
        assert_eq!(
            stored_response.metadata["marketplaceAuditStore"]["serviceQuoteStored"],
            json!(true)
        );
        assert_eq!(
            stored_response.metadata["marketplaceAuditStore"]["paymentStored"],
            json!(true)
        );
        assert_eq!(
            stored_response.metadata["marketplaceAuditStore"]["settlementStored"],
            json!(true)
        );
        let quote_lookup =
            hivemind_marketplace::get_service_quote(&audit_dir, &service_quote.quote_id)
                .unwrap()
                .unwrap();
        assert!(quote_lookup.verification.valid);
        let payment_lookup = hivemind_marketplace::get_payment_authorization(
            &payment_dir,
            &payment_authorization.authorization_id,
        )
        .unwrap()
        .unwrap();
        assert!(payment_lookup.verification.valid);
        let settlement_lookup =
            hivemind_marketplace::get_settlement_event(&audit_dir, &settlement.settlement_id)
                .unwrap()
                .unwrap();
        assert!(settlement_lookup.verification.valid);

        persist_response_job_record(&job_dir, &mut stored_response);
        let lookup = hivemind_jobs::get_job_record(&job_dir, &job_order.job_id)
            .unwrap()
            .unwrap();
        assert_eq!(lookup.record.quotes.len(), 1);
        assert_eq!(lookup.record.quotes[0].quote_id, quotes[0].quote_id);
        assert_eq!(
            lookup
                .record
                .lease
                .as_ref()
                .map(|lease| lease.lease_id.as_str()),
            Some(lease.lease_id.as_str())
        );
        assert_eq!(
            lookup.record.job_order.settlement_method,
            "marketplace-direct-pay-per-call"
        );
        let lifecycle = hivemind_jobs::job_production_lifecycle(&lookup.record);
        let payment_stage = lifecycle
            .stages
            .iter()
            .find(|stage| stage.stage == hivemind_jobs::JobProductionStageKindV1::PaymentReserved)
            .unwrap();
        assert_eq!(
            payment_stage.status,
            hivemind_jobs::JobProductionStageStatusV1::Complete
        );
        let settlement_stage = lifecycle
            .stages
            .iter()
            .find(|stage| stage.stage == hivemind_jobs::JobProductionStageKindV1::Settlement)
            .unwrap();
        assert_eq!(
            settlement_stage.status,
            hivemind_jobs::JobProductionStageStatusV1::Complete
        );
        assert!(!lifecycle.ready_for_settlement);
        std::fs::remove_dir_all(&receipt_dir).ok();
        std::fs::remove_dir_all(&payment_dir).ok();
        std::fs::remove_dir_all(&audit_dir).ok();
        std::fs::remove_dir_all(&job_dir).ok();
    }

    #[tokio::test]
    async fn non_retryable_policy_failure_does_not_try_fallback() {
        let package = local_package(vec![PermissionRequest {
            name: "network.http".to_string(),
            purpose: Some("call external API".to_string()),
            required: false,
            limits: json!({ "allowedHosts": ["api.example.com"] }),
        }]);
        let request = execution_request(&package);
        let report = route_report(
            &request,
            &package,
            vec![
                candidate(
                    "local-local-dev-runner",
                    RunnerType::Local,
                    Some("local-rust-mock"),
                    0.0,
                    "none",
                ),
                candidate(
                    "remote-remote-dev-gpu-runner",
                    RunnerType::RemoteGpu,
                    Some("local-rust-mock"),
                    0.01,
                    "xDAI",
                ),
            ],
            Some("local-local-dev-runner"),
            vec!["remote-remote-dev-gpu-runner".to_string()],
        );

        let response = execute_with_route_fallback(request, package, report).await;

        assert_eq!(response.status, ExecutionStatus::Failed);
        assert_eq!(
            response.error.as_ref().map(|error| error.code),
            Some(ErrorCode::AccessDenied)
        );
        let trace: RouteExecutionTraceV1 =
            serde_json::from_value(response.metadata["routeExecution"].clone()).unwrap();
        assert_eq!(
            trace.attempted_route_ids,
            vec!["local-local-dev-runner".to_string()]
        );
        assert!(!trace.fallback_applied);
        assert!(trace.selected_route_id.is_none());
    }

    #[test]
    fn fallback_policy_only_retries_transient_or_target_failures() {
        let mut access_denied = ExecutionResponseV1::failed(
            "request-1",
            SwarmAiErrorV1::new(ErrorCode::AccessDenied, "denied"),
            ExecutionMetrics::default(),
        );
        let overloaded = ExecutionResponseV1::failed(
            "request-1",
            SwarmAiErrorV1::new(ErrorCode::RunnerOverloaded, "busy"),
            ExecutionMetrics::default(),
        );
        let unsupported_target = ExecutionResponseV1::failed(
            "request-1",
            SwarmAiErrorV1::new(ErrorCode::UnsupportedTarget, "stale target"),
            ExecutionMetrics::default(),
        );

        assert!(!should_attempt_fallback(&access_denied));
        assert!(should_attempt_fallback(&overloaded));
        assert!(should_attempt_fallback(&unsupported_target));

        access_denied.status = ExecutionStatus::Succeeded;
        assert!(!should_attempt_fallback(&access_denied));
    }

    #[test]
    fn streaming_events_sse_body_preserves_native_event_contract() {
        let event = streaming_event(
            "request-1",
            Some("job-1".to_string()),
            7,
            StreamingEventType::TextDelta,
            "2026-06-02T00:00:00Z".to_string(),
            json!({ "text": "hello" }),
        );

        let body = hivemind_streams::streaming_events_sse_body(&[event]);

        assert!(body.contains("event: text_delta\n"));
        assert!(body.contains("id: stream-"));
        assert!(body.contains("\"sequence\":7"));
        assert!(body.contains("\"type\":\"text_delta\""));
        assert!(body.contains("\"text\":\"hello\""));
    }

    #[test]
    fn streamed_execution_metadata_normalizes_runner_chunks() {
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-stream-1".to_string(),
            package_ref: "bzz://stream-test".to_string(),
            package_id: "hivemind/stream-test".to_string(),
            package_version: "0.1.0".to_string(),
            preferred_artifact_group: None,
            task: "chat".to_string(),
            input: json!({ "text": "hello" }),
            options: ExecutionOptions {
                stream: true,
                ..ExecutionOptions::default()
            },
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };
        let mut response = ExecutionResponseV1::succeeded(
            "request-stream-1",
            json!({
                "message": { "role": "assistant", "content": "hello back" },
                "stream": {
                    "chunks": [
                        { "index": 0, "delta": "hello " },
                        { "index": 1, "delta": "back" }
                    ]
                }
            }),
            ExecutionMetrics::default(),
        );

        attach_stream_events_metadata(&mut response, &request, Some("job-stream-1"));

        let events: Vec<hivemind_core::StreamingEventV1> =
            serde_json::from_value(response.metadata["streamEvents"].clone()).unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].event_type, StreamingEventType::Started);
        assert_eq!(events[1].event_type, StreamingEventType::TextDelta);
        assert_eq!(events[2].event_type, StreamingEventType::TextDelta);
        assert_eq!(events[3].event_type, StreamingEventType::Completed);
        assert_eq!(events[1].sequence, 1);
        assert_eq!(events[1].job_id.as_deref(), Some("job-stream-1"));
        assert_eq!(events[1].payload["delta"], "hello ");
        assert_eq!(
            response.metadata["streamEventSummary"]["eventCount"],
            json!(4)
        );
    }

    #[test]
    fn partial_receipt_stream_event_is_inserted_after_receipt_capture() {
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-partial-receipt-1".to_string(),
            package_ref: "bzz://stream-test".to_string(),
            package_id: "hivemind/stream-test".to_string(),
            package_version: "0.1.0".to_string(),
            preferred_artifact_group: None,
            task: "chat".to_string(),
            input: json!({ "text": "hello" }),
            options: ExecutionOptions {
                stream: true,
                ..ExecutionOptions::default()
            },
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };
        let mut response = ExecutionResponseV1::succeeded(
            "request-partial-receipt-1",
            json!({
                "message": { "role": "assistant", "content": "hello back" },
                "stream": {
                    "chunks": [
                        { "index": 0, "delta": "hello back" }
                    ]
                }
            }),
            ExecutionMetrics::default(),
        );
        response.receipt_ref = Some("local://receipt/receipt-stream-1".to_string());
        attach_stream_events_metadata(&mut response, &request, Some("job-stream-1"));
        response.metadata["receiptStore"] = json!({
            "stored": true,
            "receiptId": "receipt-stream-1",
            "receiptRef": "local://receipt/receipt-stream-1",
            "verificationValid": true,
            "issueCount": 0,
            "warningCount": 0
        });

        attach_partial_receipt_stream_event(&mut response);

        let events: Vec<hivemind_core::StreamingEventV1> =
            serde_json::from_value(response.metadata["streamEvents"].clone()).unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].event_type, StreamingEventType::Started);
        assert_eq!(events[1].event_type, StreamingEventType::TextDelta);
        assert_eq!(events[2].event_type, StreamingEventType::PartialReceipt);
        assert_eq!(events[3].event_type, StreamingEventType::Completed);
        assert_eq!(events[2].sequence, 2);
        assert_eq!(events[3].sequence, 3);
        assert_eq!(events[2].payload["receiptId"], "receipt-stream-1");
        assert_eq!(events[2].payload["verificationValid"], true);
        let partial_receipt: hivemind_receipts::PartialReceiptV1 =
            serde_json::from_value(events[2].payload["partialReceipt"].clone()).unwrap();
        let partial_verification = hivemind_receipts::verify_partial_receipt(&partial_receipt);
        assert!(partial_verification.valid, "{partial_verification:#?}");
        assert_eq!(
            events[2].payload["partialReceiptId"],
            partial_receipt.partial_receipt_id
        );
        assert_eq!(partial_receipt.sequence, 2);
        assert_eq!(partial_receipt.status, ExecutionStatus::Partial);
        assert_eq!(
            partial_receipt.receipt_ref.as_deref(),
            Some("local://receipt/receipt-stream-1")
        );
        assert_eq!(
            response.metadata["streamEventSummary"]["eventCount"],
            json!(4)
        );
        assert_eq!(
            response.metadata["streamEventSummary"]["source"],
            "execution-response-normalizer+receipt-capture"
        );
        assert_eq!(
            response.metadata["partialReceiptStreamEvent"]["attached"],
            json!(true)
        );
    }

    #[test]
    fn stream_event_store_round_trips_by_job_and_request_keys() {
        let dir = test_temp_dir("hivemind-stream-events");
        let events = vec![streaming_event(
            "request-store-1",
            Some("job-store-1".to_string()),
            0,
            StreamingEventType::Started,
            "2026-06-02T00:00:00Z".to_string(),
            json!({ "status": "started" }),
        )];
        let mut response = ExecutionResponseV1::succeeded(
            "request-store-1",
            json!({ "message": { "content": "stored" } }),
            ExecutionMetrics::default(),
        );
        response.metadata = json!({
            "streamEvents": events,
            "streamEventSummary": {
                "requestId": "request-store-1",
                "jobId": "job-store-1"
            }
        });

        persist_response_stream_events(&dir, &mut response);

        assert_eq!(response.metadata["streamEventStore"]["stored"], json!(true));
        let by_job = hivemind_streams::read_stream_events(&dir, "job-store-1")
            .unwrap()
            .unwrap();
        let by_request = hivemind_streams::read_stream_events(&dir, "request-store-1")
            .unwrap()
            .unwrap();
        assert_eq!(by_job.len(), 1);
        assert_eq!(by_job[0].job_id.as_deref(), Some("job-store-1"));
        assert_eq!(by_request[0].event_id, by_job[0].event_id);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn job_store_captures_execution_response_audit_links() {
        let package = local_package(Vec::new());
        let request = execution_request(&package);
        let order =
            job_order_from_execution_request(&request, "api-requester", ApiSurface::HivemindNative);
        let dir = test_temp_dir("hivemind-job-store");
        let mut response = ExecutionResponseV1::succeeded(
            request.request_id.clone(),
            json!({ "message": { "content": "stored job" } }),
            ExecutionMetrics::default(),
        );
        response.receipt_ref = Some("local://receipt/receipt-job-1".to_string());
        response.metadata = json!({
            "jobOrder": order,
            "routeExecution": {
                "selectedRouteId": "local-local-dev-runner",
                "attempts": [
                    {
                        "routeId": "local-local-dev-runner",
                        "runnerId": "local-dev-runner"
                    }
                ]
            },
            "receiptStore": {
                "receiptId": "receipt-job-1",
                "receiptRef": "local://receipt/receipt-job-1"
            },
            "routeDecisionStore": {
                "stored": true,
                "decisionRef": "local://route-decision/request-1",
                "proofValid": true
            },
            "routeTraceStore": {
                "stored": true,
                "traceRef": "local://route-trace/request-1"
            },
            "streamEventSummary": {
                "eventCount": 3
            },
            "streamEventStore": {
                "storageRefs": ["local://stream-events/job-store-capture"]
            }
        });

        persist_response_job_record(&dir, &mut response);

        assert_eq!(response.metadata["jobStore"]["stored"], json!(true));
        let job_id = response.metadata["jobStore"]["jobId"].as_str().unwrap();
        let lookup = hivemind_jobs::get_job_record(&dir, job_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            lookup.record.status,
            hivemind_jobs::JobRecordStatusV1::Succeeded
        );
        assert_eq!(lookup.record.receipt_id.as_deref(), Some("receipt-job-1"));
        assert_eq!(lookup.record.stream_event_count, Some(3));
        assert_eq!(
            lookup.record.metadata["routeDecisionStore"]["decisionRef"],
            "local://route-decision/request-1"
        );
        assert_eq!(
            lookup.record.metadata["routeDecisionStore"]["proofValid"],
            true
        );
        assert_eq!(
            lookup.record.metadata["routeTraceStore"]["traceRef"],
            "local://route-trace/request-1"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn compatibility_certification_api_signs_indexed_package() {
        let dir = test_temp_dir("hivemind-compat-api");
        std::fs::create_dir_all(dir.join("model")).unwrap();
        let mut package = local_package(Vec::new());
        package.root = dir.clone();
        std::fs::write(
            dir.join("swarm-ai.json"),
            serde_json::to_vec_pretty(&package.manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join("model").join("config.json"), br#"{"ok":true}"#).unwrap();

        let identity =
            hivemind_identity::identity_from_seed("api-compat-certifier", b"api-compat-certifier")
                .unwrap();
        let state = test_state_with_package(package.clone());
        let response = compatibility_certification_response(
            &state,
            CompatibilityPackageCertificationRequest {
                schema_version: Some(
                    "swarm-ai.compatibility-package-certification-request.v1".to_string(),
                ),
                package_ref: Some(package.package_ref.clone()),
                package_id: Some(package.manifest.package_id.clone()),
                component_type: "package".to_string(),
                implementation_name: Some("api-compatible-package".to_string()),
                component_version: Some("0.1.0".to_string()),
                supported_schemas: vec!["hivemind.request.v1".to_string()],
                warnings: vec!["local API certification smoke".to_string()],
                identity: Some(identity),
                store: true,
            },
        )
        .unwrap();

        assert_eq!(response.package_id, package.manifest.package_id);
        assert_eq!(response.package_ref, package.package_ref);
        assert_eq!(
            response.report.result,
            hivemind_sdk::CompatibilityResult::Passed
        );
        let certification = response.certification.as_ref().unwrap();
        assert_eq!(certification.implementation_name, "api-compatible-package");
        assert!(
            certification
                .supported_schemas
                .iter()
                .any(|schema| schema == "hivemind.request.v1")
        );
        assert!(
            response
                .verification
                .as_ref()
                .map(|verification| verification.valid)
                .unwrap_or(false)
        );
        let store = response.store.as_ref().unwrap();
        assert!(store.stored);
        assert!(store.certification_ref.starts_with("local://compat/"));
        let lookup = hivemind_sdk::get_compatibility_certification(
            state.compatibility_dir.as_ref().as_path(),
            &store.certification_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(lookup.certification_id, store.certification_id);
        assert!(lookup.verification.valid);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn receipt_summary_enrichment_adds_job_and_settlement_context() {
        let package = local_package(Vec::new());
        let request = execution_request(&package);
        let order =
            job_order_from_execution_request(&request, "api-requester", ApiSurface::HivemindNative);
        let receipt_dir = test_temp_dir("hivemind-receipt-index");
        let job_dir = test_temp_dir("hivemind-receipt-index-jobs");
        let mut receipt = hivemind_core::ExecutionReceiptV1 {
            schema_version: "swarm-ai.receipt.v1".to_string(),
            receipt_id: String::new(),
            request_id: request.request_id.clone(),
            package_id: package.manifest.package_id.clone(),
            package_ref: package.package_ref.clone(),
            artifact_group: "local-rust-mock".to_string(),
            package_manifest_hash: package.manifest_hash.clone(),
            runner_id: "local-dev-runner".to_string(),
            route_id: Some("local-local-dev-runner".to_string()),
            input_hash: "a".repeat(64),
            output_hash: "b".repeat(64),
            privacy_mode: "hash-only".to_string(),
            started_at: "2026-06-02T00:00:00Z".to_string(),
            finished_at: "2026-06-02T00:00:01Z".to_string(),
            metrics: ExecutionMetrics::default(),
            billing: hivemind_core::receipt::BillingInfo {
                estimated_cost: 0.01,
                currency: "USD".to_string(),
            },
            access: hivemind_core::receipt::AccessInfo {
                license_grant_id: None,
            },
            policy: None,
            signature: String::new(),
        };
        sign_receipt(&mut receipt);
        receipt.receipt_id = canonical_receipt_id(&receipt).unwrap();
        hivemind_receipts::write_receipt(&receipt_dir, &receipt).unwrap();

        let mut record =
            hivemind_jobs::job_record_from_order(order.clone(), "2026-06-02T00:00:00Z");
        record.status = hivemind_jobs::JobRecordStatusV1::Succeeded;
        record.receipt_id = Some(receipt.receipt_id.clone());
        record.receipt_ref = Some(format!("local://receipt/{}", receipt.receipt_id));
        record.runner_id = Some("local-dev-runner".to_string());
        record.quotes = quotes_for_job_order(&order);
        record.metadata["settlement"] = json!({
            "settlementId": "settlement-index-1",
            "settlementRef": "local://settlements/settlement-index-1",
            "status": "disputed"
        });
        hivemind_jobs::upsert_job_record(&job_dir, record).unwrap();

        let mut summary = hivemind_receipts::list_receipts(&receipt_dir).unwrap();
        enrich_receipt_summary_from_job_store(&mut summary, &job_dir);

        assert_eq!(summary.receipt_count, 1);
        let entry = &summary.receipts[0];
        assert_eq!(entry.job_id.as_deref(), Some(order.job_id.as_str()));
        assert_eq!(entry.requester.as_deref(), Some("api-requester"));
        assert_eq!(
            entry.quote_id.as_deref(),
            Some(quotes_for_job_order(&order)[0].quote_id.as_str())
        );
        assert_eq!(
            entry.settlement_ref.as_deref(),
            Some("local://settlements/settlement-index-1")
        );
        assert_eq!(
            entry.settlement_status,
            Some(hivemind_receipts::ReceiptSettlementStatusV1::Disputed)
        );

        let mut free_local_record =
            hivemind_jobs::job_record_from_order(order.clone(), "2026-06-02T00:00:00Z");
        free_local_record.status = hivemind_jobs::JobRecordStatusV1::Succeeded;
        free_local_record.receipt_id = Some(receipt.receipt_id.clone());
        free_local_record.lease = Some(
            hivemind_core::execution_lease_from_quote(
                &order,
                &quotes_for_job_order(&order)[0],
                "api-requester",
                "local://settlement/free-local-dev",
                "2030-06-02T00:00:00Z",
            )
            .unwrap(),
        );
        assert_eq!(
            receipt_settlement_status(&free_local_record),
            hivemind_receipts::ReceiptSettlementStatusV1::NotRequired
        );

        std::fs::remove_dir_all(&receipt_dir).ok();
        std::fs::remove_dir_all(&job_dir).ok();
    }

    #[test]
    fn job_cancellation_persists_cancelled_stream_event() {
        let package = local_package(Vec::new());
        let request = execution_request(&package);
        let order =
            job_order_from_execution_request(&request, "api-requester", ApiSurface::HivemindNative);
        let job_dir = test_temp_dir("hivemind-job-cancel-api");
        let stream_dir = test_temp_dir("hivemind-job-cancel-stream");
        let record = hivemind_jobs::job_record_from_order(order.clone(), "2026-06-02T00:00:00Z");
        hivemind_jobs::upsert_job_record(&job_dir, record).unwrap();
        let cancel =
            hivemind_jobs::job_cancellation_request(&order.job_id, "api-requester", "stop job");
        let mut result =
            hivemind_jobs::cancel_job_record(&job_dir, &cancel, "2026-06-02T00:00:01Z")
                .unwrap()
                .unwrap();

        persist_job_cancellation_stream_event(&job_dir, &stream_dir, &mut result);

        assert!(result.transitioned);
        assert_eq!(
            result.current_status,
            hivemind_jobs::JobRecordStatusV1::Cancelled
        );
        assert_eq!(result.record.stream_event_count, Some(1));
        let events = hivemind_streams::read_stream_events(&stream_dir, &order.job_id)
            .unwrap()
            .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, StreamingEventType::Cancelled);
        assert_eq!(events[0].payload["cancellation"]["reason"], "stop job");
        let lookup = hivemind_jobs::get_job_record(&job_dir, &order.job_id)
            .unwrap()
            .unwrap();
        assert_eq!(lookup.record.stream_event_count, Some(1));
        assert_eq!(
            lookup.record.metadata["streamEventStore"]["stored"],
            json!(true)
        );

        std::fs::remove_dir_all(&job_dir).ok();
        std::fs::remove_dir_all(&stream_dir).ok();
    }

    fn route_report(
        request: &ExecutionRequestV1,
        package: &hivemind_package::LocalPackage,
        candidates: Vec<CandidateRoute>,
        selected_route_id: Option<&str>,
        fallback_route_ids: Vec<String>,
    ) -> RoutePlannerReportV1 {
        RoutePlannerReportV1 {
            schema_version: "swarm-ai.route-planner-report.v1".to_string(),
            job_order: Some(job_order_from_execution_request(
                request,
                "local-dev",
                ApiSurface::HivemindNative,
            )),
            plan: RoutePlanV1 {
                schema_version: "swarm-ai.route-plan.v1".to_string(),
                request_id: request.request_id.clone(),
                package_ref: package.package_ref.clone(),
                task: request.task.clone(),
                candidate_routes: candidates,
                selected_route_id: selected_route_id.map(str::to_string),
                fallback_route_ids,
                reason: "test route report".to_string(),
            },
            quotes: Vec::new(),
            marketplace_shortlist: None,
            runner_reputation: Vec::new(),
            miner_capacity: Vec::new(),
            trust_policy: None,
            policy_mode: PolicyMode::Balanced,
            planning_timing: None,
        }
    }

    fn candidate(
        route_id: &str,
        runner_type: RunnerType,
        artifact_group: Option<&str>,
        cost: f64,
        currency: &str,
    ) -> CandidateRoute {
        CandidateRoute {
            route_id: route_id.to_string(),
            runner_type,
            runner_id: Some(
                route_id
                    .split_once('-')
                    .map(|(_, runner_id)| runner_id)
                    .unwrap_or(route_id)
                    .to_string(),
            ),
            artifact_group: artifact_group.map(str::to_string),
            estimated: RouteEstimate {
                cost,
                currency: currency.to_string(),
                queue_ms: 0,
                first_token_ms: 1,
                privacy: "local".to_string(),
            },
            quality_score: None,
            policy_decision: None,
            decision: RouteDecision::Eligible,
            reason: Some("eligible in test route plan".to_string()),
        }
    }

    fn execution_request(package: &hivemind_package::LocalPackage) -> ExecutionRequestV1 {
        ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: package.package_ref.clone(),
            package_id: package.manifest.package_id.clone(),
            package_version: package.manifest.version.clone(),
            preferred_artifact_group: None,
            task: "embedding".to_string(),
            input: json!({ "text": "hello route" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        }
    }

    fn local_package(permissions: Vec<PermissionRequest>) -> hivemind_package::LocalPackage {
        hivemind_package::LocalPackage {
            root: PathBuf::new(),
            manifest: PackageManifestV1 {
                schema_version: "swarm-ai.package.v1".to_string(),
                package_id: "hivemind/api-route-test".to_string(),
                kind: PackageKind::Model,
                name: "API Route Test".to_string(),
                version: "0.1.0".to_string(),
                publisher: Publisher {
                    address: "0x0".to_string(),
                    display_name: "Hivemind".to_string(),
                    publisher_profile_ref: None,
                },
                capabilities: vec!["embedding".to_string()],
                artifact_groups: vec![ArtifactGroup {
                    id: "local-rust-mock".to_string(),
                    target: "local-mock".to_string(),
                    engine: "rust-mock".to_string(),
                    format: "json".to_string(),
                    paths: vec!["model/config.json".to_string()],
                    total_bytes: 1,
                    sha256: "0".repeat(64),
                    minimum: ArtifactMinimum {
                        memory_mb: Some(1),
                        webgpu: Some(false),
                        disk_mb: None,
                    },
                }],
                input_schema: json!({ "type": "object" }),
                output_schema: json!({ "type": "object" }),
                permissions,
                license: LicenseInfo {
                    license_type: LicenseType::Open,
                    name: Some("Apache-2.0".to_string()),
                    url: None,
                },
            },
            manifest_hash: "0".repeat(64),
            package_ref: "bzz://api-route-test".to_string(),
        }
    }

    fn test_state_with_package(package: hivemind_package::LocalPackage) -> AppState {
        let entry = RegistryEntryV1 {
            schema_version: "swarm-ai.registry.entry.v1".to_string(),
            package_id: package.manifest.package_id.clone(),
            name: package.manifest.name.clone(),
            kind: package.manifest.kind.clone(),
            latest_version: package.manifest.version.clone(),
            stable_version: package.manifest.version.clone(),
            package_refs: vec![hivemind_core::registry::RegistryPackageRef {
                version: package.manifest.version.clone(),
                package_ref: package.package_ref.clone(),
                manifest_hash: package.manifest_hash.clone(),
                published_at: "2026-06-05T00:00:00Z".to_string(),
            }],
            publisher: hivemind_core::registry::RegistryPublisher {
                address: package.manifest.publisher.address.clone(),
                display_name: package.manifest.publisher.display_name.clone(),
                publisher_profile_ref: package.manifest.publisher.publisher_profile_ref.clone(),
            },
            capabilities: package.manifest.capabilities.clone(),
            modalities: Vec::new(),
            supported_apis: Vec::new(),
            targets: vec!["local-mock".to_string()],
            engines: vec!["rust-mock".to_string()],
            license: package.manifest.license.clone(),
            trust: hivemind_core::registry::RegistryTrust {
                signature_verified: false,
                validator_score: None,
                download_count_approx: 0,
                curated: false,
            },
            privacy_tiers: vec![PrivacyTier::Standard],
            verification_tiers: vec![IntegrityTier::ReceiptOnly],
            browser_runnable: false,
            gpu_required: false,
            min_memory_mb: Some(1),
            min_vram_mb: None,
            price_hint: None,
            marketplace_listings: Vec::new(),
            runner_offer_refs: Vec::new(),
            hardware_resource_offer_refs: Vec::new(),
            permissions: Vec::new(),
            policy_summary: hivemind_core::RegistryPolicySummaryV1 {
                risk_level: hivemind_core::policy::RiskLevel::Low,
                decision: hivemind_core::PolicyDecision::Allow,
                permission_count: 0,
                code_execution: "none".to_string(),
                reasons: vec!["Package requests no elevated permissions".to_string()],
            },
            benchmark_scores: Vec::new(),
            approx_artifact_bytes: 1,
        };
        let snapshot = RegistrySnapshotV1 {
            schema_version: "swarm-ai.registry.snapshot.v1".to_string(),
            snapshot_id: String::new(),
            created_at: String::new(),
            source_records: Vec::new(),
            entries: vec![entry.clone()],
            publication_records: Vec::new(),
            publication_statuses: Vec::new(),
            feed_statuses: Vec::new(),
            validation_reports: Vec::new(),
            evaluation_results: Vec::new(),
            marketplace_listings: Vec::new(),
            runner_offers: Vec::new(),
            hardware_resource_offers: Vec::new(),
            schema_releases: Vec::new(),
            component_readiness: Vec::new(),
            signature: None,
        };
        let root = if package.root.as_os_str().is_empty() {
            test_temp_dir("hivemind-api-state")
        } else {
            package.root.join(".api-state")
        };
        AppState {
            packages: Arc::new(vec![IndexedPackage { package, entry }]),
            registry_snapshot: Arc::new(snapshot),
            package_audit_dir: Arc::new(root.join("package-audit")),
            compatibility_dir: Arc::new(root.join("compat")),
            registry_audit_dir: Arc::new(root.join("registry-audit")),
            record_dir: Arc::new(root.join("records")),
            validation_dir: Arc::new(root.join("validations")),
            evaluation_dir: Arc::new(root.join("evaluations")),
            access_grant_dir: Arc::new(root.join("access-grants")),
            access_revocation_dir: Arc::new(root.join("access-revocations")),
            receipt_dir: Arc::new(root.join("receipts")),
            dispute_dir: Arc::new(root.join("disputes")),
            job_dir: Arc::new(root.join("jobs")),
            governance_dir: Arc::new(root.join("governance")),
            research_dir: Arc::new(root.join("research")),
            eval_dir: Arc::new(root.join("evals")),
            vector_dir: Arc::new(root.join("vector")),
            workflow_dir: Arc::new(root.join("workflow")),
            batch_dir: Arc::new(root.join("batch")),
            fine_tune_dir: Arc::new(root.join("fine-tune")),
            realtime_dir: Arc::new(root.join("realtime")),
            media_dir: Arc::new(root.join("media")),
            moderation_dir: Arc::new(root.join("moderation")),
            miner_dir: Arc::new(root.join("miner")),
            marketplace_listing_dir: Arc::new(root.join("marketplace-listings")),
            marketplace_runner_offer_dir: Arc::new(root.join("marketplace-offers")),
            marketplace_hardware_offer_dir: Arc::new(root.join("hardware-offers")),
            marketplace_payment_dir: Arc::new(root.join("marketplace-payments")),
            marketplace_audit_dir: Arc::new(root.join("marketplace-audit")),
            storage_dir: Arc::new(root.join("storage")),
            storage_audit_dir: Arc::new(root.join("storage-audit")),
            runner_cache_dir: Arc::new(root.join("runner-cache")),
            trust_policy_dir: Arc::new(root.join("trust")),
            feed_dir: Arc::new(root.join("feeds")),
            stream_event_dir: Arc::new(root.join("streams")),
            route_trace_dir: Arc::new(root.join("routes")),
        }
    }

    fn validation_report(
        runner_id: &str,
        quality: f64,
        latency: f64,
        overall: f64,
    ) -> hivemind_validator::ValidationReportV1 {
        let mut report = hivemind_validator::ValidationReportV1 {
            schema_version: "swarm-ai.validation-report.v1".to_string(),
            report_id: String::new(),
            validator_id: "validator-dev".to_string(),
            runner_id: runner_id.to_string(),
            package_ref: "bzz://api-route-test".to_string(),
            challenge_id: format!("challenge-{runner_id}-{overall}"),
            receipt_id: format!("receipt-{runner_id}-{overall}"),
            scores: hivemind_validator::ValidationScoresV1 {
                quality,
                latency,
                cost_efficiency: 0.9,
                policy_compliance: 1.0,
                overall,
            },
            evidence_refs: vec![format!("evidence-{runner_id}")],
            validation_elapsed_ms: None,
            created_at: "2026-05-31T00:00:00Z".to_string(),
            signature: String::new(),
        };
        hivemind_validator::sign_validation_report(&mut report);
        report.report_id = hivemind_validator::canonical_validation_report_id(&report).unwrap();
        report
    }

    fn test_temp_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
