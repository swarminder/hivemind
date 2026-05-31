use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use hivemind_core::{
    AccessDecision, CandidateRoute, ErrorCode, ExecutionRequestV1, ExecutionResponseV1,
    ExecutionStatus, INTERFACE_VERSION, LicenseType, PolicyMode, RegistryQueryV1,
    RegistrySearchResponse, RouteDecision, RoutePlanV1, RunnerType, SwarmAiErrorV1,
    validate_package_manifest_value,
};
use hivemind_marketplace::{
    MarketplaceListingV1, RunnerOfferV1, default_local_runner_offer, listing_from_registry_entry,
    quote_execution,
};
use hivemind_registry::{
    IndexedPackage, RegistrySnapshotV1, build_registry_shards, find_package,
    load_packages_with_all_metadata_and_feeds, public_registry_snapshot,
    rebuild_registry_snapshot_with_all_sources, registry_package_lookup,
    registry_package_lookup_for_request, registry_shard_manifest_for_shards, search_registry,
};
use hivemind_router::{
    RouteAttemptV1, RouteExecutionTraceV1, RoutePlannerReportV1,
    plan_routes_with_marketplace_offers, planner_report_with_marketplace_offers,
};
use hivemind_storage::StorageProvider;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use tracing::info;

#[derive(Debug, Clone)]
pub struct ServeConfig {
    pub host: String,
    pub port: u16,
    pub package_dir: PathBuf,
    pub record_dir: PathBuf,
    pub validation_dir: PathBuf,
    pub evaluation_dir: PathBuf,
    pub access_grant_dir: PathBuf,
    pub access_revocation_dir: PathBuf,
    pub receipt_dir: PathBuf,
    pub dispute_dir: PathBuf,
    pub marketplace_payment_dir: PathBuf,
    pub marketplace_audit_dir: PathBuf,
    pub storage_dir: PathBuf,
    pub runner_cache_dir: PathBuf,
    pub feed_dir: PathBuf,
    pub static_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct AppState {
    packages: Arc<Vec<IndexedPackage>>,
    registry_snapshot: Arc<RegistrySnapshotV1>,
    record_dir: Arc<PathBuf>,
    validation_dir: Arc<PathBuf>,
    evaluation_dir: Arc<PathBuf>,
    access_grant_dir: Arc<PathBuf>,
    access_revocation_dir: Arc<PathBuf>,
    receipt_dir: Arc<PathBuf>,
    dispute_dir: Arc<PathBuf>,
    marketplace_payment_dir: Arc<PathBuf>,
    marketplace_audit_dir: Arc<PathBuf>,
    storage_dir: Arc<PathBuf>,
    runner_cache_dir: Arc<PathBuf>,
    feed_dir: Arc<PathBuf>,
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
struct MarketplaceVerifyPaymentRequest {
    authorization: hivemind_marketplace::PaymentAuthorizationV1,
    #[serde(default)]
    quote: Option<hivemind_marketplace::ServiceQuoteV1>,
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
    let packages = load_packages_with_all_metadata_and_feeds(
        &config.package_dir,
        Some(&config.record_dir),
        Some(&config.feed_dir),
        Some(&config.validation_dir),
        Some(&config.evaluation_dir),
    )
        .with_context(|| {
        format!(
            "failed to load packages from {} with publication records from {}, feeds from {}, validation reports from {}, and evaluation results from {}",
            config.package_dir.display(),
            config.record_dir.display(),
            config.feed_dir.display(),
            config.validation_dir.display(),
            config.evaluation_dir.display()
        )
    })?;
    let registry_snapshot = rebuild_registry_snapshot_with_all_sources(
        &config.package_dir,
        Some(&config.record_dir),
        Some(&config.feed_dir),
        Some(&config.validation_dir),
        Some(&config.evaluation_dir),
    )
    .with_context(|| {
        format!(
            "failed to build registry snapshot from {}, {}, {}, {}, and {}",
            config.package_dir.display(),
            config.record_dir.display(),
            config.feed_dir.display(),
            config.validation_dir.display(),
            config.evaluation_dir.display()
        )
    })?;
    let state = AppState {
        packages: Arc::new(packages),
        registry_snapshot: Arc::new(registry_snapshot),
        record_dir: Arc::new(config.record_dir),
        validation_dir: Arc::new(config.validation_dir),
        evaluation_dir: Arc::new(config.evaluation_dir),
        access_grant_dir: Arc::new(config.access_grant_dir),
        access_revocation_dir: Arc::new(config.access_revocation_dir),
        receipt_dir: Arc::new(config.receipt_dir),
        dispute_dir: Arc::new(config.dispute_dir),
        marketplace_payment_dir: Arc::new(config.marketplace_payment_dir),
        marketplace_audit_dir: Arc::new(config.marketplace_audit_dir),
        storage_dir: Arc::new(config.storage_dir),
        runner_cache_dir: Arc::new(config.runner_cache_dir),
        feed_dir: Arc::new(config.feed_dir),
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
        .route("/v1/packages/validate", post(validate_manifest))
        .route("/v1/access/verify-grant", post(verify_access_grant))
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
        .route("/v1/storage/cache", get(storage_cache))
        .route("/v1/storage/inspect", post(storage_inspect))
        .route("/v1/storage/pin", post(storage_pin))
        .route("/v1/storage/unpin", post(storage_unpin))
        .route("/v1/storage/feed/create", post(storage_feed_create))
        .route("/v1/storage/feed/update", post(storage_feed_update))
        .route("/v1/storage/feed/resolve", post(storage_feed_resolve))
        .route("/v1/policy/catalog", get(policy_catalog))
        .route("/v1/policy/inspect", post(policy_inspect))
        .route("/v1/receipts", get(receipts))
        .route("/v1/receipts/verify", post(verify_receipt))
        .route("/v1/receipts/upload", post(upload_receipt))
        .route("/v1/receipts/download", post(download_receipt))
        .route("/v1/receipts/disputes", get(disputes))
        .route("/v1/receipts/dispute", post(create_dispute))
        .route("/v1/receipts/verify-dispute", post(verify_dispute))
        .route("/v1/receipts/disputes/{dispute_id}", get(dispute_by_id))
        .route("/v1/receipts/{receipt_id}", get(receipt_by_id))
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
        .route("/v1/validator/reports", get(validator_reports))
        .route(
            "/v1/validator/reports/{report_id}",
            get(validator_report_by_id),
        )
        .route(
            "/v1/validator/reputation",
            post(validator_reputation_profile),
        )
        .route("/v1/validator/verify-report", post(validator_verify_report))
        .route("/v1/validator/upload-report", post(validator_upload_report))
        .route(
            "/v1/validator/download-report",
            post(validator_download_report),
        )
        .route("/v1/benchmarks/evaluations", get(benchmark_evaluations))
        .route(
            "/v1/benchmarks/evaluations/{evaluation_id}",
            get(benchmark_evaluation_by_id),
        )
        .route(
            "/v1/benchmarks/verify-evaluation",
            post(benchmark_verify_evaluation),
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
        .route("/v1/swarm-ai/route", post(route))
        .route("/v1/swarm-ai/route-report", post(route_report))
        .route("/v1/swarm-ai/execute", post(execute))
        .route("/v1/swarm-ai/receipt/{receipt_id}", get(receipt_by_id))
        .route("/v1/swarm-ai/cache", get(local_runner_cache))
        .route(
            "/v1/swarm-ai/cache/{*package_ref}",
            delete(clear_local_runner_cache),
        )
        .route("/v1/chat/completions", post(openai_chat_completions))
        .route("/v1/embeddings", post(openai_embeddings))
        .route("/v1/marketplace/listings", get(marketplace_listings))
        .route(
            "/v1/marketplace/verify-listing",
            post(marketplace_verify_listing),
        )
        .route("/v1/marketplace/offers", get(marketplace_offers))
        .route("/v1/marketplace/shortlist", post(marketplace_shortlist))
        .route(
            "/v1/marketplace/verify-offer",
            post(marketplace_verify_offer),
        )
        .route("/v1/marketplace/quote", post(marketplace_quote))
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

async fn validate_manifest(Json(value): Json<Value>) -> Json<hivemind_core::ValidationReport> {
    Json(validate_package_manifest_value(&value))
}

async fn verify_access_grant(
    Json(grant): Json<hivemind_core::AccessGrantV1>,
) -> Json<hivemind_access::AccessGrantVerificationV1> {
    Json(hivemind_access::verify_access_grant(&grant))
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
    Json(search_registry(&state.packages, &query))
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

async fn policy_inspect(
    Json(manifest): Json<hivemind_core::PackageManifestV1>,
) -> Json<hivemind_policy::PolicyInspectionV1> {
    Json(hivemind_policy::inspect_package_policy(
        &manifest,
        format!("local://manifest/{}", manifest.package_id),
        None,
    ))
}

async fn receipts(State(state): State<AppState>) -> impl IntoResponse {
    match hivemind_receipts::list_receipts(&state.receipt_dir) {
        Ok(summary) => (StatusCode::OK, Json(summary)).into_response(),
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

async fn verify_receipt(
    Json(receipt): Json<hivemind_core::ExecutionReceiptV1>,
) -> Json<hivemind_receipts::ReceiptVerificationV1> {
    Json(hivemind_receipts::verify_receipt(&receipt))
}

async fn upload_receipt(
    State(state): State<AppState>,
    Json(receipt): Json<hivemind_core::ExecutionReceiptV1>,
) -> impl IntoResponse {
    let mut storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    match hivemind_receipts::upload_receipt(&mut storage, &receipt) {
        Ok(upload) => (StatusCode::OK, Json(json!(upload))).into_response(),
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
        Ok(download) => (StatusCode::OK, Json(json!(download))).into_response(),
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

async fn validator_report_by_id(
    State(state): State<AppState>,
    Path(report_id): Path<String>,
) -> impl IntoResponse {
    match hivemind_validator::get_validation_report(
        state.validation_dir.as_ref().as_path(),
        &report_id,
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

async fn validator_verify_report(
    Json(report): Json<hivemind_validator::ValidationReportV1>,
) -> Json<hivemind_validator::ValidationReportVerificationV1> {
    Json(hivemind_validator::verify_validation_report(&report))
}

async fn validator_upload_report(
    State(state): State<AppState>,
    Json(report): Json<hivemind_validator::ValidationReportV1>,
) -> impl IntoResponse {
    let mut storage = hivemind_storage::LocalDirectoryStorageProvider::new(&*state.storage_dir);
    match hivemind_validator::upload_validation_report(&mut storage, &report) {
        Ok(upload) => (StatusCode::OK, Json(json!(upload))).into_response(),
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
        Ok(download) => (StatusCode::OK, Json(json!(download))).into_response(),
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

async fn remote_capabilities() -> Json<hivemind_core::RunnerDescriptorV1> {
    Json(hivemind_remote_runner::default_descriptor())
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

async fn capabilities() -> Json<hivemind_core::RunnerDescriptorV1> {
    Json(hivemind_local_runner::descriptor())
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
    Json(
        state
            .packages
            .iter()
            .filter(|package| package.entry.license.license_type != LicenseType::Private)
            .filter_map(|package| listing_from_registry_entry(&package.entry, "local-market"))
            .collect(),
    )
}

async fn marketplace_verify_listing(
    Json(listing): Json<hivemind_marketplace::MarketplaceListingV1>,
) -> Json<hivemind_marketplace::MarketplaceListingVerificationV1> {
    Json(hivemind_marketplace::verify_marketplace_listing(&listing))
}

async fn marketplace_offers(State(state): State<AppState>) -> Json<Vec<RunnerOfferV1>> {
    Json(public_marketplace_offers(&state.packages))
}

async fn marketplace_shortlist(
    State(state): State<AppState>,
    Json(request): Json<hivemind_marketplace::MarketplaceShortlistRequestV1>,
) -> Json<hivemind_marketplace::MarketplaceShortlistV1> {
    let offers = public_marketplace_offers(&state.packages);
    Json(hivemind_marketplace::shortlist_runner_offers(
        &request, &offers,
    ))
}

async fn marketplace_verify_offer(
    Json(offer): Json<hivemind_marketplace::RunnerOfferV1>,
) -> Json<hivemind_marketplace::RunnerOfferVerificationV1> {
    Json(hivemind_marketplace::verify_runner_offer(&offer))
}

async fn marketplace_quote(
    State(state): State<AppState>,
    Json(request): Json<ExecutionRequestV1>,
) -> impl IntoResponse {
    let Some(offer) = marketplace_offer_for_quote(&state.packages, &request) else {
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

async fn marketplace_verify_quote(
    Json(request): Json<MarketplaceVerifyQuoteRequest>,
) -> Json<hivemind_marketplace::ServiceQuoteVerificationV1> {
    Json(hivemind_marketplace::verify_service_quote(
        &request.quote,
        request.offer.as_ref(),
    ))
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

    let offers = default_marketplace_offers(&state.packages);
    let plan = plan_routes_with_marketplace_offers(
        &request,
        &package,
        &routing_runners(),
        &offers,
        PolicyMode::Balanced,
        3,
    );
    (StatusCode::OK, Json(json!(plan))).into_response()
}

async fn route_report(
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
    let offers = default_marketplace_offers(&state.packages);
    let report = planner_report_with_marketplace_offers(
        &request,
        &package,
        &routing_runners(),
        &offers,
        PolicyMode::Balanced,
        3,
    );
    (StatusCode::OK, Json(json!(report))).into_response()
}

async fn execute(
    State(state): State<AppState>,
    Json(request): Json<ExecutionRequestV1>,
) -> impl IntoResponse {
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
    let offers = default_marketplace_offers(&state.packages);
    let report = planner_report_with_marketplace_offers(
        &request,
        &package,
        &routing_runners(),
        &offers,
        PolicyMode::Balanced,
        3,
    );
    let response = execute_with_route_fallback(request, package, report).await;
    (StatusCode::OK, Json(response)).into_response()
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
    let response = execute_with_default_routing(execution_request, package, &state.packages).await;
    if response.status != ExecutionStatus::Succeeded {
        return openai_error_from_execution(&response);
    }

    let completion = hivemind_openai_compat::chat_completion_from_execution(
        &request,
        &response,
        request_id,
        unix_timestamp(),
    );
    (StatusCode::OK, Json(json!(completion))).into_response()
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

    let mut responses = Vec::with_capacity(execution_requests.len());
    for execution_request in execution_requests {
        let response =
            execute_with_default_routing(execution_request, package.clone(), &state.packages).await;
        if response.status != ExecutionStatus::Succeeded {
            return openai_error_from_execution(&response);
        }
        responses.push(response);
    }

    let embedding =
        hivemind_openai_compat::embedding_response_from_executions(&request, &responses);
    (StatusCode::OK, Json(json!(embedding))).into_response()
}

async fn execute_with_default_routing(
    request: ExecutionRequestV1,
    package: hivemind_package::LocalPackage,
    packages: &[IndexedPackage],
) -> ExecutionResponseV1 {
    let offers = default_marketplace_offers(packages);
    let report = planner_report_with_marketplace_offers(
        &request,
        &package,
        &routing_runners(),
        &offers,
        PolicyMode::Balanced,
        3,
    );
    execute_with_route_fallback(request, package, report).await
}

async fn execute_with_route_fallback(
    request: ExecutionRequestV1,
    package: hivemind_package::LocalPackage,
    report: RoutePlannerReportV1,
) -> ExecutionResponseV1 {
    let mut trace = RouteExecutionTraceV1::new(
        request.request_id.clone(),
        report.plan.selected_route_id.clone(),
    );
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
            execute_candidate_route(routed_request, package.clone(), &candidate).await;
        trace.push_attempt(route_attempt(&candidate, &response));
        attach_route_metadata(&mut response, &report, &trace);
        if response.status == ExecutionStatus::Succeeded {
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
        RunnerType::Local | RunnerType::Marketplace => {
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
    }
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

fn attach_route_metadata(
    response: &mut ExecutionResponseV1,
    report: &RoutePlannerReportV1,
    trace: &RouteExecutionTraceV1,
) {
    if !response.metadata.is_object() {
        response.metadata = json!({});
    }
    response.metadata["routePlan"] = json!(report.plan);
    response.metadata["routeExecution"] = json!(trace);
    if let Some(shortlist) = &report.marketplace_shortlist {
        response.metadata["marketplaceShortlist"] = json!(shortlist);
    }
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

fn package_refs(packages: &[IndexedPackage]) -> Vec<String> {
    let mut refs: Vec<_> = packages
        .iter()
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

fn json_error(code: ErrorCode, message: &str) -> Value {
    json!(SwarmAiErrorV1::new(code, message))
}

fn json_error_value(error: &SwarmAiErrorV1) -> Value {
    json!(error)
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

fn default_marketplace_offers(packages: &[IndexedPackage]) -> Vec<RunnerOfferV1> {
    vec![default_local_runner_offer(
        &hivemind_local_runner::descriptor(),
        package_refs(packages),
    )]
}

fn public_marketplace_offers(packages: &[IndexedPackage]) -> Vec<RunnerOfferV1> {
    vec![default_local_runner_offer(
        &hivemind_local_runner::descriptor(),
        public_package_refs(packages),
    )]
}

fn marketplace_offer_for_quote(
    packages: &[IndexedPackage],
    request: &ExecutionRequestV1,
) -> Option<RunnerOfferV1> {
    let indexed = find_package(packages, &request.package_ref, &request.package_id)?;
    if indexed.entry.license.license_type == LicenseType::Private {
        if !private_marketplace_request_authorized(indexed, request) {
            return None;
        }
        return Some(default_local_runner_offer(
            &hivemind_local_runner::descriptor(),
            vec![request.package_ref.clone()],
        ));
    }
    Some(default_local_runner_offer(
        &hivemind_local_runner::descriptor(),
        public_package_refs(packages),
    ))
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
