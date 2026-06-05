mod api;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hivemind_core::{
    AccessGrantRevocationV1, AccessGrantV1, AccessRevocationListV1, ExecutionOptions,
    ExecutionPrivacy, ExecutionReceiptV1, ExecutionRequestV1, LicenseType, PackageManifestV1,
    PriceV1, RegistryQueryV1,
};
use hivemind_package::{
    load_package_from_dir, validate_package_dir_with_audit, validate_package_ref_with_audit,
};
use hivemind_registry::{
    IndexedPackage, load_hardware_resource_offers, load_packages_with_all_metadata,
    load_packages_with_all_metadata_feeds_and_marketplace, load_runner_offers,
    load_validation_reports,
    rebuild_registry_snapshot_with_all_sources_marketplace_offers_and_governance,
    registry_package_lookup, registry_package_lookup_for_request, search_registry,
};
use hivemind_storage::{
    BeeHttpStorageProvider, BeeStorageConfig, LocalDirectoryStorageProvider, StorageProvider,
};
use schemars::schema_for;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;
use tracing_subscriber::{EnvFilter, fmt};
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "swarm-ai")]
#[command(about = "Rust-first SwarmAI development CLI and local server")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scaffold a new package folder containing swarm-ai.json and mock artifacts.
    Init {
        path: PathBuf,
        #[arg(long)]
        package_id: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "embedding-model")]
        template: String,
        #[arg(long, default_value = "0x0000000000000000000000000000000000000000")]
        publisher: String,
        #[arg(long, default_value = "Hivemind Labs")]
        publisher_name: String,
        #[arg(long, default_value = "0.1.0")]
        version: String,
        #[arg(long)]
        force: bool,
    },
    /// Validate a local package folder containing swarm-ai.json.
    Validate {
        path: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/package-audit")]
        package_audit: PathBuf,
    },
    /// Validate a package directly from a storage reference.
    ValidateRef {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long, default_value = ".swarm-ai-cache/package-audit")]
        package_audit: PathBuf,
    },
    /// Issue a local development access grant for a package reference.
    IssueGrant {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long, default_value = "local-dev")]
        grantee: String,
        #[arg(long, default_value = "runner-service")]
        requested_use: String,
        #[arg(long)]
        runner_id: Option<String>,
        #[arg(long)]
        expires_at: Option<String>,
        #[arg(long, default_value = "local-dev")]
        issuer: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/access/grants")]
        grants_dir: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a local development access grant signature.
    VerifyGrant { grant: PathBuf },
    /// Revoke a local development access grant.
    RevokeGrant {
        grant: PathBuf,
        #[arg(long, default_value = "local-dev")]
        revoked_by: String,
        #[arg(long, default_value = "revoked by local-dev")]
        reason: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/access/revocations")]
        revocations_dir: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// List locally stored access grants.
    AccessGrants {
        #[arg(long, default_value = ".swarm-ai-cache/access/grants")]
        grants_dir: PathBuf,
    },
    /// Look up a locally stored access grant by grant id.
    GetGrant {
        grant_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/access/grants")]
        grants_dir: PathBuf,
    },
    /// List locally stored access grant revocations.
    AccessRevocations {
        #[arg(long, default_value = ".swarm-ai-cache/access/revocations")]
        revocations_dir: PathBuf,
    },
    /// Look up a locally stored access grant revocation by revocation id.
    GetRevocation {
        revocation_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/access/revocations")]
        revocations_dir: PathBuf,
    },
    /// Verify a signed access grant revocation.
    VerifyGrantRevocation {
        revocation: PathBuf,
        #[arg(long)]
        grant: Option<PathBuf>,
    },
    /// Build an access revocation list from signed revocations.
    RevocationList { revocations: Vec<PathBuf> },
    /// Verify an access revocation list.
    VerifyRevocationList { revocations: PathBuf },
    /// Search the local example registry.
    Search {
        #[arg(long)]
        capability: Option<String>,
        #[arg(long)]
        modality: Option<String>,
        #[arg(long)]
        api_surface: Option<String>,
        #[arg(long)]
        publisher: Option<String>,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        engine: Option<String>,
        #[arg(long)]
        privacy_tier: Option<String>,
        #[arg(long)]
        verification_tier: Option<String>,
        #[arg(long)]
        max_artifact_bytes: Option<u64>,
        #[arg(long)]
        min_artifact_bytes: Option<u64>,
        #[arg(long)]
        browser_runnable: Option<bool>,
        #[arg(long)]
        gpu_required: Option<bool>,
        #[arg(long)]
        min_validator_score: Option<f64>,
        #[arg(long)]
        min_benchmark_score: Option<f64>,
        #[arg(long)]
        max_price_amount: Option<f64>,
        #[arg(long)]
        max_price_currency: Option<String>,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/listings")]
        marketplace_listings: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/registry-audit")]
        registry_audit: PathBuf,
        #[arg(long, default_value_t = 20)]
        page_size: usize,
        #[arg(long)]
        grant: Option<PathBuf>,
        #[arg(long)]
        revocations: Option<PathBuf>,
        #[arg(long)]
        requester: Option<String>,
        #[arg(long)]
        requested_use: Option<String>,
        #[arg(long)]
        runner_id: Option<String>,
    },
    /// Validate a package and estimate publish metadata without uploading.
    PublishDryRun { path: PathBuf },
    /// Create a deterministic local-dev package signature and publication record.
    Sign { path: PathBuf },
    /// Manage local Ed25519 identities and identity-backed signatures.
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },
    /// Verify a publication record signature and publication metadata.
    VerifyPublication { record: PathBuf },
    /// List locally stored publication records.
    PublicationRecords {
        #[arg(long, default_value = ".swarm-ai-cache/publications")]
        record_dir: PathBuf,
    },
    /// Look up a locally stored publication record by derived publication id.
    GetPublication {
        publication_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/publications")]
        record_dir: PathBuf,
    },
    /// Write local feed pointers from a signed publication record.
    UpdateFeed {
        record: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/feeds")]
        feed_dir: PathBuf,
    },
    /// Resolve a local feed pointer for a package channel.
    ResolveFeed {
        package_id: String,
        #[arg(long, default_value = "latest")]
        channel: String,
        #[arg(long, default_value = ".swarm-ai-cache/feeds")]
        feed_dir: PathBuf,
    },
    /// List locally stored publisher feed pointers.
    FeedPointers {
        #[arg(long, default_value = ".swarm-ai-cache/feeds")]
        feed_dir: PathBuf,
    },
    /// Look up a locally stored publisher feed pointer by package id and channel.
    GetFeed {
        package_id: String,
        #[arg(long, default_value = "latest")]
        channel: String,
        #[arg(long, default_value = ".swarm-ai-cache/feeds")]
        feed_dir: PathBuf,
    },
    /// Publish a package into the local Swarm-like development storage.
    Publish {
        path: PathBuf,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long, env = "SWARM_POSTAGE_BATCH_ID")]
        postage_batch_id: Option<String>,
        #[arg(long, default_value = ".swarm-ai-cache/publications")]
        record_dir: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/feeds")]
        feed_dir: PathBuf,
        #[arg(long, default_value = "latest")]
        channel: String,
    },
    /// Inspect a local storage reference or a file inside a directory reference.
    Inspect {
        reference: String,
        #[arg(long)]
        path: Option<String>,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
    },
    /// Inspect local development cache state.
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    /// Inspect package permissions and policy decisions.
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    /// Receipt verification and audit trail commands.
    Receipts {
        #[command(subcommand)]
        command: ReceiptCommands,
    },
    /// Job lifecycle audit store commands.
    Jobs {
        #[command(subcommand)]
        command: JobCommands,
    },
    /// Operational metric snapshot commands.
    Observability {
        #[command(subcommand)]
        command: ObservabilityCommands,
    },
    /// Install a package artifact group from storage into the local runner cache.
    Install {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long, default_value = ".swarm-ai-cache/runner")]
        cache_dir: PathBuf,
        #[arg(long)]
        artifact_group: Option<String>,
        #[arg(long)]
        grant: Option<PathBuf>,
        #[arg(long)]
        revocations: Option<PathBuf>,
        /// Allow caching a package whose default security policy is denied.
        #[arg(long)]
        developer_mode: bool,
    },
    /// Inspect local runner cache state.
    RunnerCache {
        #[command(subcommand)]
        command: RunnerCacheCommands,
    },
    /// Browser runner capability, prepare, and execution commands.
    Browser {
        #[command(subcommand)]
        command: BrowserCommands,
    },
    /// Browser Swarm/weeb-3 adapter status and retrieval commands.
    BrowserSwarm {
        #[command(subcommand)]
        command: BrowserSwarmCommands,
    },
    /// Remote GPU runner capability, prepare, execution, and cancellation commands.
    Remote {
        #[command(subcommand)]
        command: RemoteCommands,
    },
    /// Registry maintenance commands.
    Registry {
        #[command(subcommand)]
        command: RegistryCommands,
    },
    /// Marketplace listing, offer, quote, and settlement commands.
    Marketplace {
        #[command(subcommand)]
        command: MarketplaceCommands,
    },
    /// Miner daemon profile, heartbeat, benchmark, onboarding, and dashboard commands.
    Miner {
        #[command(subcommand)]
        command: MinerCommands,
    },
    /// Run the compatibility validator for a package folder.
    Compat { path: PathBuf },
    /// Run the SDK compatibility certification suite for a package folder.
    Certify {
        path: PathBuf,
        /// Emit a signed CompatibilityCertificationV1 using this Ed25519 test-runner identity.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Component type recorded in the signed certification.
        #[arg(long, default_value = "package")]
        component_type: String,
        /// Implementation name recorded in the signed certification.
        #[arg(long)]
        implementation_name: Option<String>,
        /// Implementation version recorded in the signed certification.
        #[arg(long)]
        component_version: Option<String>,
        /// Additional supported schema declared by the certified implementation.
        #[arg(long = "supported-schema")]
        supported_schemas: Vec<String>,
        /// Additional warning recorded in the signed certification.
        #[arg(long = "warning")]
        warnings: Vec<String>,
        /// Store a signed compatibility certification in the local compatibility evidence store.
        #[arg(long, default_value_t = false)]
        store: bool,
        /// Local compatibility evidence store used with --store.
        #[arg(long, default_value = ".swarm-ai-cache/compat")]
        compatibility_dir: PathBuf,
        /// Write the report or signed certification to a JSON file.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a signed SDK compatibility certification artifact.
    VerifyCertification {
        certification: PathBuf,
        /// Require the certification signature to come from this signer subject.
        #[arg(long)]
        expected_signer: Option<String>,
    },
    /// List or inspect local SDK compatibility certification evidence.
    Certifications {
        #[command(subcommand)]
        command: CertificationCommands,
    },
    /// Plan a route across browser, local, and remote runners for a local package.
    Route {
        package: PathBuf,
        #[arg(long, default_value = "embedding")]
        task: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long = "package-ref")]
        package_ref: Option<String>,
        #[arg(long)]
        artifact_group: Option<String>,
        #[arg(long, default_value = "balanced")]
        policy: String,
        #[arg(long, default_value_t = 0)]
        local_queue: u32,
        #[arg(long, default_value_t = 0)]
        remote_queue: u32,
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        validations: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/offers")]
        marketplace_offers: PathBuf,
        #[arg(long, default_value_t = 3)]
        max_marketplace_results: usize,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/hardware-offers")]
        marketplace_hardware_offers: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/miner")]
        miner: PathBuf,
        #[arg(long)]
        trust_policy: Option<PathBuf>,
    },
    /// Execute a public validation challenge and write a validation report.
    ValidateRun {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long, default_value = "local-dev-validator")]
        validator_id: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long, default_value = "embedding")]
        task: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        grant: Option<PathBuf>,
        #[arg(long)]
        revocations: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        reports_dir: PathBuf,
    },
    /// Verify a validation report signature and canonical report id.
    VerifyValidation { report: PathBuf },
    /// Replace a validation report's local-dev signature with an Ed25519 validator identity envelope.
    SignValidation {
        report: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Upload a verified validation report through a storage provider.
    UploadValidation {
        report: PathBuf,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long)]
        postage_batch_id: Option<String>,
    },
    /// Download a validation report from a storage reference.
    DownloadValidation {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        reports_dir: PathBuf,
    },
    /// List locally stored validation reports.
    ValidationReports {
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        reports_dir: PathBuf,
    },
    /// Look up a locally stored validation report by report id.
    GetValidation {
        report_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        reports_dir: PathBuf,
    },
    /// Create signed integrity evidence for TEE, zk, FHE, replay, or redundant checks.
    IntegrityEvidenceInit {
        output: PathBuf,
        #[arg(long, default_value = "tee-attestation")]
        evidence_kind: String,
        #[arg(long, default_value = "local-dev-validator")]
        validator_id: String,
        #[arg(long)]
        runner_id: Option<String>,
        #[arg(long, default_value = "runner")]
        subject_type: String,
        #[arg(long)]
        subject_id: String,
        #[arg(long)]
        package_ref: Option<String>,
        #[arg(long)]
        receipt_id: Option<String>,
        #[arg(long)]
        measurement_hash: Option<String>,
        #[arg(long = "expected-measurement-hash")]
        expected_measurement_hashes: Vec<String>,
        #[arg(long = "evidence-ref")]
        evidence_refs: Vec<String>,
        #[arg(long = "proof-ref")]
        proof_refs: Vec<String>,
        #[arg(long)]
        method: Option<String>,
        #[arg(long, default_value = "passed")]
        verdict: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify an integrity evidence object.
    VerifyIntegrityEvidence { evidence: PathBuf },
    /// Replace integrity evidence's local-dev signature with an Ed25519 validator envelope.
    SignIntegrityEvidence {
        evidence: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// List locally stored integrity evidence records.
    IntegrityEvidenceRecords {
        #[arg(long, default_value = ".swarm-ai-cache/validations/integrity")]
        evidence_dir: PathBuf,
    },
    /// Look up a locally stored integrity evidence record by id.
    GetIntegrityEvidence {
        evidence_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/validations/integrity")]
        evidence_dir: PathBuf,
    },
    /// Build a reputation profile from locally stored validation reports.
    Reputation {
        #[arg(long, default_value = "runner")]
        subject_type: String,
        subject_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        reports_dir: PathBuf,
    },
    /// Run the mini benchmark commons suite and write an evaluation result.
    BenchmarkRun {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long, default_value = "local-dev-validator")]
        validator_id: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long, default_value = "embedding-basic")]
        benchmark: String,
        #[arg(long)]
        grant: Option<PathBuf>,
        #[arg(long)]
        revocations: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/evaluations")]
        results_dir: PathBuf,
    },
    /// Verify a benchmark evaluation result signature and canonical result id.
    VerifyEvaluation { result: PathBuf },
    /// Replace an evaluation result's local-dev signature with an Ed25519 validator identity envelope.
    SignEvaluation {
        result: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// List locally stored benchmark evaluation results.
    EvaluationResults {
        #[arg(long, default_value = ".swarm-ai-cache/evaluations")]
        results_dir: PathBuf,
    },
    /// Build an evidence-backed leaderboard from locally stored benchmark evaluation results.
    EvaluationLeaderboard {
        #[arg(long, default_value = ".swarm-ai-cache/evaluations")]
        results_dir: PathBuf,
    },
    /// Look up a locally stored benchmark evaluation result by evaluation id.
    GetEvaluation {
        evaluation_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/evaluations")]
        results_dir: PathBuf,
    },
    /// Project a V1 benchmark evaluation result into the production-oriented EvaluationResultV2 shape.
    EvaluationV2FromV1 {
        result: PathBuf,
        output: PathBuf,
        #[arg(long)]
        suite_id: Option<String>,
        #[arg(long)]
        started_at: Option<String>,
        #[arg(long)]
        completed_at: Option<String>,
        #[arg(long)]
        total_ms: Option<u64>,
        #[arg(long)]
        average_ms: Option<f64>,
        #[arg(long)]
        cost_amount: Option<f64>,
        #[arg(long, default_value = "USD")]
        cost_currency: String,
        #[arg(long)]
        pricing_ref: Option<String>,
        #[arg(long)]
        runner_type: Option<String>,
        #[arg(long)]
        os: Option<String>,
        #[arg(long)]
        architecture: Option<String>,
        #[arg(long = "hardware-ref")]
        hardware_refs: Vec<String>,
        #[arg(long = "software-ref")]
        software_refs: Vec<String>,
        #[arg(long = "artifact-ref")]
        artifact_refs: Vec<String>,
        #[arg(long = "random-seed")]
        random_seeds: Vec<String>,
        /// Structured error as code|message or sampleId|code|retryable|message.
        #[arg(long = "error")]
        errors: Vec<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a production-oriented benchmark evaluation result.
    VerifyEvaluationV2 { result: PathBuf },
    /// Replace an EvaluationResultV2 local-dev signature with an Ed25519 validator envelope.
    SignEvaluationV2 {
        result: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// List locally stored production-oriented benchmark evaluation results.
    EvaluationResultsV2 {
        #[arg(long, default_value = ".swarm-ai-cache/evaluations/v2")]
        results_dir: PathBuf,
    },
    /// Look up a locally stored EvaluationResultV2 by evaluation id.
    GetEvaluationV2 {
        evaluation_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/evaluations/v2")]
        results_dir: PathBuf,
    },
    /// Create a signed benchmark suite contract with split, metric, privacy, and runtime metadata.
    BenchmarkSuiteInit {
        output: PathBuf,
        #[arg(long, default_value = "commons/embedding-basic-v1")]
        benchmark_id: String,
        #[arg(long, default_value = "Basic Embedding Shape Benchmark")]
        name: String,
        #[arg(long, default_value = "embedding")]
        task: String,
        #[arg(long, default_value = "1.0.0")]
        version: String,
        #[arg(long, default_value = "local-dev-validator")]
        maintainer_id: String,
        #[arg(long = "modality")]
        modalities: Vec<String>,
        #[arg(long = "dataset-ref")]
        dataset_refs: Vec<String>,
        #[arg(long, default_value = "local://scoring/embedding-shape")]
        scoring_method_ref: String,
        /// Split definition as name|weight|hidden|ref1,ref2.
        #[arg(long = "split")]
        splits: Vec<String>,
        #[arg(long = "allowed-model-ref")]
        allowed_model_refs: Vec<String>,
        #[arg(long = "allowed-runtime")]
        allowed_runtimes: Vec<String>,
        #[arg(long, default_value = "public")]
        privacy_tier: String,
        #[arg(long)]
        private_results: bool,
        #[arg(long)]
        disallow_remote_runners: bool,
        #[arg(long)]
        require_result_redaction: bool,
        #[arg(long = "access-policy-ref")]
        access_policy_refs: Vec<String>,
        #[arg(long, default_value_t = 0)]
        p50_ms: u64,
        #[arg(long, default_value_t = 0)]
        p95_ms: u64,
        #[arg(long, default_value_t = 30_000)]
        max_ms: u64,
        #[arg(long = "metric")]
        metric_names: Vec<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a benchmark suite contract.
    VerifyBenchmarkSuite { suite: PathBuf },
    /// Replace a benchmark suite's local-dev signature with an Ed25519 maintainer envelope.
    SignBenchmarkSuite {
        suite: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// List locally stored benchmark suites.
    BenchmarkSuites {
        #[arg(long, default_value = ".swarm-ai-cache/evaluations/suites")]
        suites_dir: PathBuf,
    },
    /// Look up a locally stored benchmark suite by suite id.
    GetBenchmarkSuite {
        suite_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/evaluations/suites")]
        suites_dir: PathBuf,
    },
    /// Create a signed hidden benchmark challenge commitment record.
    ChallengeCommitmentInit {
        output: PathBuf,
        #[arg(long, default_value = "commons/embedding-basic-v1")]
        benchmark_id: String,
        #[arg(long, default_value = "1.0.0")]
        benchmark_version: String,
        #[arg(long, default_value = "local-dev-validator")]
        validator_id: String,
        #[arg(long)]
        challenge_set_hash: String,
        #[arg(long)]
        answer_set_hash: Option<String>,
        #[arg(long)]
        salt_hash: String,
        #[arg(long, default_value_t = 1)]
        challenge_count: u64,
        #[arg(long = "public-dataset-ref")]
        public_dataset_refs: Vec<String>,
        #[arg(long = "hidden-ref-commitment")]
        hidden_ref_commitments: Vec<String>,
        #[arg(long = "scoring-rule-ref")]
        scoring_rule_refs: Vec<String>,
        #[arg(long)]
        reveal_after: Option<String>,
        #[arg(long)]
        expires_at: Option<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a hidden benchmark challenge commitment record.
    VerifyChallengeCommitment { commitment: PathBuf },
    /// Replace a challenge commitment's local-dev signature with an Ed25519 validator envelope.
    SignChallengeCommitment {
        commitment: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// List locally stored hidden benchmark challenge commitments.
    ChallengeCommitments {
        #[arg(long, default_value = ".swarm-ai-cache/evaluations/challenges")]
        commitments_dir: PathBuf,
    },
    /// Look up a locally stored challenge commitment by commitment id.
    GetChallengeCommitment {
        commitment_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/evaluations/challenges")]
        commitments_dir: PathBuf,
    },
    /// Create, verify, sign, plan, list, and look up eval suite/run contracts.
    Eval {
        #[command(subcommand)]
        command: EvalCommands,
    },
    /// Create, verify, sign, and plan reproduction for research experiment records.
    Experiment {
        #[command(subcommand)]
        command: ExperimentCommands,
    },
    /// Create, verify, sign, and plan vector store search contracts.
    Vector {
        #[command(subcommand)]
        command: VectorCommands,
    },
    /// Create, verify, sign, and plan tool/workflow contracts.
    Workflow {
        #[command(subcommand)]
        command: WorkflowCommands,
    },
    /// Create, verify, sign, and plan batch job contracts.
    Batch {
        #[command(subcommand)]
        command: BatchCommands,
    },
    /// Create, verify, sign, and plan fine-tune job contracts.
    FineTune {
        #[command(subcommand)]
        command: FineTuneCommands,
    },
    /// Create, verify, sign, and plan realtime session contracts.
    Realtime {
        #[command(subcommand)]
        command: RealtimeCommands,
    },
    /// Create, verify, sign, and plan media generation/audio contracts.
    Media {
        #[command(subcommand)]
        command: MediaCommands,
    },
    /// Create, verify, sign, and plan moderation policies and requests.
    Moderation {
        #[command(subcommand)]
        command: ModerationCommands,
    },
    /// Create, verify, sign, and plan governance policies, schema releases, and advisories.
    Governance {
        #[command(subcommand)]
        command: GovernanceCommands,
    },
    /// Execute a local package through the mock Rust runner.
    Run {
        package: PathBuf,
        #[arg(long, default_value = "embedding")]
        task: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        grant: Option<PathBuf>,
        #[arg(long)]
        revocations: Option<PathBuf>,
        #[arg(long)]
        receipts_dir: Option<PathBuf>,
    },
    /// Execute a package by storage reference through the local runner.
    RunRef {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long, default_value = "embedding")]
        task: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        artifact_group: Option<String>,
        #[arg(long)]
        grant: Option<PathBuf>,
        #[arg(long)]
        revocations: Option<PathBuf>,
        #[arg(long)]
        receipts_dir: Option<PathBuf>,
    },
    /// Print a JSON Schema for a shared contract.
    Schema {
        #[arg(default_value = "package")]
        kind: String,
    },
    /// Serve the API and Rust/WASM dashboard.
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 8787)]
        port: u16,
        #[arg(long, default_value = "examples/packages")]
        packages: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/package-audit")]
        package_audit: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/compat")]
        compatibility: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/publications")]
        records: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        validations: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/evaluations")]
        evaluations: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/access/grants")]
        access_grants: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/access/revocations")]
        access_revocations: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/receipts")]
        receipts: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/disputes")]
        disputes: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/jobs")]
        jobs: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/governance")]
        governance: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/research")]
        research: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/evals")]
        evals: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/vector")]
        vector: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/workflow")]
        workflow: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/batch")]
        batch: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/fine-tune")]
        fine_tune: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/realtime")]
        realtime: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/media")]
        media: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/moderation")]
        moderation: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/miner")]
        miner: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/listings")]
        marketplace_listings: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/offers")]
        marketplace_offers: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/hardware-offers")]
        marketplace_hardware_offers: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/payments")]
        marketplace_payments: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/audit")]
        marketplace_audit: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/storage-audit")]
        storage_audit: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/runner")]
        runner_cache: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/trust")]
        trust: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/feeds")]
        feeds: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/streams")]
        streams: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/route-traces")]
        route_traces: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/registry-audit")]
        registry_audit: PathBuf,
        #[arg(long, default_value = "crates/web/static")]
        static_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum CacheCommands {
    /// Print storage provider status and supported operations.
    Status {
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
    },
    /// List local storage cache counts and byte totals.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
    },
    /// Pin a storage reference when the provider supports pinning.
    Pin {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
    },
    /// Unpin a storage reference when the provider supports pinning.
    Unpin {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
    },
    /// Create a local storage feed pointer.
    CreateFeed {
        #[arg(long)]
        topic: String,
        #[arg(long)]
        owner: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
    },
    /// Update a local storage feed pointer to a new reference.
    UpdateFeed {
        #[arg(long)]
        topic: String,
        #[arg(long)]
        owner: String,
        reference: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
    },
    /// Resolve a local storage feed pointer.
    ResolveFeed {
        feed_ref: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum CertificationCommands {
    /// List locally stored SDK compatibility certifications.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/compat")]
        compatibility_dir: PathBuf,
    },
    /// Look up one stored SDK compatibility certification by its local certification id.
    Get {
        certification_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/compat")]
        compatibility_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum IdentityCommands {
    /// Generate a local Ed25519 identity keypair for a publisher, runner, or validator subject.
    Generate {
        #[arg(long)]
        subject: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Print the public identity document for a local identity keypair.
    Public { identity: PathBuf },
    /// Replace a publication record's local-dev signature with an Ed25519 identity envelope.
    SignPublication {
        record: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum RunnerCacheCommands {
    /// List installed package artifact groups.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/runner")]
        cache_dir: PathBuf,
    },
    /// Clear cached artifact groups for a package reference.
    Clean {
        reference: String,
        #[arg(long, default_value = ".swarm-ai-cache/runner")]
        cache_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    /// Print the built-in permission catalog.
    Catalog,
    /// Generate preset trust policies for route planning and execution.
    Trust {
        #[command(subcommand)]
        command: TrustPolicyCommands,
    },
    /// Inspect a local package folder for risk, permissions, and sandbox requirements.
    Inspect {
        path: PathBuf,
        #[arg(long)]
        package_ref: Option<String>,
        #[arg(long)]
        runner_id: Option<String>,
    },
    /// Inspect a local package folder and print the review-4 risk inspection report.
    InspectV2 {
        path: PathBuf,
        #[arg(long)]
        package_ref: Option<String>,
        #[arg(long)]
        runner_id: Option<String>,
    },
    /// Inspect a package directly from a storage reference.
    InspectRef {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long)]
        runner_id: Option<String>,
    },
    /// Inspect a package storage reference and print the review-4 risk inspection report.
    InspectRefV2 {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long)]
        runner_id: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum TrustPolicyCommands {
    /// Generate a policy that only allows local execution routes.
    LocalOnly {
        #[arg(long, default_value = "local-dev")]
        owner: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Generate a policy that allows open marketplace and miner routes.
    OpenMarketplace {
        #[arg(long, default_value = "local-dev")]
        owner: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Add a local-dev signature to a trust policy file.
    Sign {
        policy: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a trust policy's canonical id and routing constraints.
    Verify { policy: PathBuf },
    /// List locally stored trust policies.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/trust")]
        trust_dir: PathBuf,
    },
    /// Look up one locally stored trust policy by policy id.
    Get {
        policy_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/trust")]
        trust_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ReceiptCommands {
    /// List locally stored receipts.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/receipts")]
        receipts_dir: PathBuf,
    },
    /// Audit locally stored receipts for verification, privacy, settlement, and index coverage.
    Audit {
        #[arg(long, default_value = ".swarm-ai-cache/receipts")]
        receipts_dir: PathBuf,
    },
    /// Look up a locally stored receipt by receipt id.
    Get {
        receipt_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/receipts")]
        receipts_dir: PathBuf,
    },
    /// List locally stored batch receipts.
    ListBatches {
        #[arg(long, default_value = ".swarm-ai-cache/receipts")]
        receipts_dir: PathBuf,
    },
    /// Audit locally stored batch receipts for item outcomes, privacy, and settlement follow-ups.
    AuditBatches {
        #[arg(long, default_value = ".swarm-ai-cache/receipts")]
        receipts_dir: PathBuf,
    },
    /// Look up a locally stored batch receipt by batch receipt id.
    GetBatch {
        batch_receipt_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/receipts")]
        receipts_dir: PathBuf,
    },
    /// Verify a receipt JSON file.
    Verify { receipt: PathBuf },
    /// Verify an ExecutionReceiptV2 projection, optionally against its source receipt.
    VerifyV2 {
        #[arg(value_name = "RECEIPT_V2")]
        receipt_v2: PathBuf,
        #[arg(long)]
        source: Option<PathBuf>,
    },
    /// Verify a BatchReceiptV1 JSON file.
    VerifyBatch {
        #[arg(value_name = "BATCH_RECEIPT")]
        batch_receipt: PathBuf,
    },
    /// Verify a PartialReceiptV1 JSON file.
    VerifyPartial {
        #[arg(value_name = "PARTIAL_RECEIPT")]
        partial_receipt: PathBuf,
    },
    /// Verify a RedactedReceiptV1 JSON file.
    VerifyRedaction {
        #[arg(value_name = "REDACTED_RECEIPT")]
        redacted_receipt: PathBuf,
    },
    /// Print a receipt and its verification report.
    Inspect { receipt: PathBuf },
    /// Create a policy-documented redacted audit view from a receipt JSON file.
    Redact {
        receipt: PathBuf,
        #[arg(long, default_value = "public-audit")]
        profile: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Replace a receipt's local-dev signature with an Ed25519 runner identity envelope.
    Sign {
        receipt: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Extract and store the embedded receipt from a saved execution response JSON file.
    Capture {
        response: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/receipts")]
        receipts_dir: PathBuf,
    },
    /// Upload a verified receipt JSON object through a storage provider.
    Upload {
        receipt: PathBuf,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long)]
        postage_batch_id: Option<String>,
    },
    /// Download a receipt JSON object from a storage reference.
    Download {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/receipts")]
        receipts_dir: PathBuf,
    },
    /// Create signed dispute evidence from a verified receipt.
    Dispute {
        receipt: PathBuf,
        #[arg(long, default_value = "local-dev")]
        claimant: String,
        #[arg(long, default_value = "other")]
        claim_kind: String,
        #[arg(long)]
        summary: String,
        #[arg(long = "evidence-ref")]
        evidence_refs: Vec<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/disputes")]
        disputes_dir: PathBuf,
    },
    /// List locally stored receipt dispute evidence records.
    ListDisputes {
        #[arg(long, default_value = ".swarm-ai-cache/disputes")]
        disputes_dir: PathBuf,
    },
    /// Look up locally stored receipt dispute evidence by dispute id.
    GetDispute {
        dispute_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/disputes")]
        disputes_dir: PathBuf,
    },
    /// Verify a receipt dispute evidence JSON file.
    VerifyDispute { dispute: PathBuf },
    /// Print dispute evidence and its verification report.
    InspectDispute { dispute: PathBuf },
}

#[derive(Debug, Subcommand)]
enum JobCommands {
    /// List locally stored job records.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/jobs")]
        jobs_dir: PathBuf,
    },
    /// Look up a locally stored job record by job id.
    Get {
        job_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/jobs")]
        jobs_dir: PathBuf,
    },
    /// Project a locally stored job record into its lifecycle timeline.
    Timeline {
        job_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/jobs")]
        jobs_dir: PathBuf,
    },
    /// Project a locally stored job record into production lifecycle stage coverage.
    Lifecycle {
        job_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/jobs")]
        jobs_dir: PathBuf,
    },
    /// Summarize production lifecycle stage coverage across the local job store.
    LifecycleAudit {
        #[arg(long)]
        observed_at: Option<String>,
        #[arg(long, default_value = ".swarm-ai-cache/jobs")]
        jobs_dir: PathBuf,
    },
    /// Link validation, dispute, settlement, receipt, or stream evidence to a job record.
    LinkEvidence {
        job_id: String,
        #[arg(long = "kind")]
        evidence_kind: String,
        #[arg(long = "ref")]
        evidence_ref: String,
        #[arg(long = "evidence-id")]
        evidence_id: Option<String>,
        #[arg(long, default_value = "local-dev")]
        linked_by: String,
        #[arg(long)]
        linked_at: Option<String>,
        #[arg(long)]
        summary: Option<String>,
        #[arg(long)]
        metadata: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/jobs")]
        jobs_dir: PathBuf,
    },
    /// Mark quoted or leased jobs as failed when their quote or lease deadline has expired.
    Expire {
        #[arg(long)]
        observed_at: Option<String>,
        #[arg(long, default_value = ".swarm-ai-cache/jobs")]
        jobs_dir: PathBuf,
    },
    /// Summarize local job lifecycle coverage, warnings, and stale quote or lease candidates.
    Audit {
        #[arg(long)]
        observed_at: Option<String>,
        #[arg(long, default_value = ".swarm-ai-cache/jobs")]
        jobs_dir: PathBuf,
    },
    /// Read persisted native stream events for a job or request key.
    Stream {
        job_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/streams")]
        streams_dir: PathBuf,
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Summarize signed partial receipts embedded in a persisted job or request stream.
    PartialReceipts {
        job_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/streams")]
        streams_dir: PathBuf,
    },
    /// Cancel a non-terminal local job record.
    Cancel {
        job_id: String,
        #[arg(long, default_value = "local-dev")]
        cancelled_by: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        requested_at: Option<String>,
        #[arg(long, default_value = ".swarm-ai-cache/jobs")]
        jobs_dir: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/streams")]
        streams_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ObservabilityCommands {
    /// Build a signed operational metrics snapshot from local audit stores.
    Snapshot {
        #[arg(long)]
        generated_at: Option<String>,
        #[arg(long, default_value = ".swarm-ai-cache/jobs")]
        jobs_dir: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/receipts")]
        receipts_dir: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/package-audit")]
        package_audit_dir: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/registry-audit")]
        registry_audit_dir: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        validation_reports_dir: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/storage-audit")]
        storage_audit_dir: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/streams")]
        streams_dir: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/route-traces")]
        route_audit_dir: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/audit")]
        marketplace_audit_dir: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/miner")]
        miner_dir: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/governance")]
        governance_dir: PathBuf,
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
    /// List locally stored operational metrics snapshots.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/observability")]
        snapshots_dir: PathBuf,
    },
    /// Look up a locally stored operational metrics snapshot by id.
    Get {
        snapshot_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/observability")]
        snapshots_dir: PathBuf,
    },
    /// Verify an operational metrics snapshot JSON file.
    Verify { snapshot: PathBuf },
}

#[derive(Debug, Subcommand)]
enum BrowserCommands {
    /// Print default browser capabilities for local development.
    Capabilities {
        #[arg(long, default_value_t = false)]
        webgpu: bool,
        #[arg(long, default_value_t = 2048)]
        memory_mb: u64,
    },
    /// Assess whether a local package can run in the browser.
    Assess {
        path: PathBuf,
        #[arg(long)]
        artifact_group: Option<String>,
        #[arg(long, default_value_t = false)]
        webgpu: bool,
        #[arg(long, default_value_t = 2048)]
        memory_mb: u64,
    },
    /// Build a browser prepare plan for a local package.
    Prepare {
        path: PathBuf,
        #[arg(long)]
        package_ref: Option<String>,
        #[arg(long)]
        artifact_group: Option<String>,
        #[arg(long, default_value_t = false)]
        webgpu: bool,
        #[arg(long, default_value_t = 2048)]
        memory_mb: u64,
    },
    /// Execute a local package through the deterministic browser runner.
    Run {
        path: PathBuf,
        #[arg(long, default_value = "embedding")]
        task: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        artifact_group: Option<String>,
        #[arg(long, default_value_t = false)]
        webgpu: bool,
        #[arg(long, default_value_t = 2048)]
        memory_mb: u64,
        #[arg(long)]
        receipts_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum BrowserSwarmCommands {
    /// Print the weeb-3 adapter descriptor and provider contract.
    Descriptor,
    /// Print browser Swarm provider status using the local fallback storage.
    Status {
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
    },
    /// Print browser Swarm compatibility and security review metadata.
    Compatibility {
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
    },
    /// Download a directory manifest through the browser Swarm fallback.
    Manifest {
        reference: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
    },
    /// Download a package file through the browser Swarm fallback.
    File {
        reference: String,
        #[arg(long)]
        path: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum EvalCommands {
    /// Create a signed local development EvalManifestV1 JSON file.
    Init {
        path: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "local-dev-eval-owner")]
        owner: String,
        #[arg(long, default_value = "dataset")]
        kind: String,
        #[arg(long = "dataset-ref")]
        dataset_refs: Vec<String>,
        #[arg(long = "scoring-rule-ref")]
        scoring_rule_refs: Vec<String>,
        #[arg(long = "target-ref")]
        target_refs: Vec<String>,
        #[arg(long)]
        grader_model_ref: Option<String>,
        #[arg(long)]
        output_schema_ref: Option<String>,
        #[arg(long)]
        metadata: Option<PathBuf>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify an EvalManifestV1 JSON file.
    Verify { manifest: PathBuf },
    /// Replace an eval manifest's local-dev signature with an Ed25519 owner envelope.
    Sign {
        manifest: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Create a signed local development EvalRunV1 JSON file.
    RunInit {
        path: PathBuf,
        #[arg(long)]
        eval_id: String,
        #[arg(long, default_value = "local-dev-eval-requester")]
        requester: String,
        #[arg(long)]
        target_ref: String,
        #[arg(long = "input-ref")]
        input_refs: Vec<String>,
        #[arg(long)]
        sample_count: Option<u32>,
        #[arg(long, default_value = "no-log")]
        privacy_tier: String,
        #[arg(long, default_value = "validator-spot-check")]
        integrity_tier: String,
        #[arg(long, default_value = "free-local-dev")]
        settlement_method: String,
        #[arg(long)]
        report_ref: Option<String>,
        #[arg(long)]
        metadata: Option<PathBuf>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify an EvalRunV1 JSON file.
    RunVerify { run: PathBuf },
    /// Replace an eval run's local-dev signature with an Ed25519 requester envelope.
    RunSign {
        run: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build an eval run plan from a manifest and run file.
    Plan { manifest: PathBuf, run: PathBuf },
    /// List local EvalManifestV1 and EvalRunV1 records.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/evals")]
        evals_dir: PathBuf,
    },
    /// Look up one local eval manifest or run record by id.
    Get {
        record_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/evals")]
        evals_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ExperimentCommands {
    /// Create a signed local development ResearchExperimentV1 JSON file.
    Init {
        path: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "local-dev-researcher")]
        author: String,
        #[arg(long)]
        organization: Option<String>,
        #[arg(long)]
        hypothesis: String,
        #[arg(long = "package-ref")]
        package_refs: Vec<String>,
        #[arg(long = "model-ref")]
        model_refs: Vec<String>,
        #[arg(long = "dataset-ref")]
        dataset_refs: Vec<String>,
        #[arg(long = "benchmark-ref")]
        benchmark_refs: Vec<String>,
        #[arg(long)]
        scoring_method_ref: Option<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a ResearchExperimentV1 JSON file.
    Verify { experiment: PathBuf },
    /// Replace a local-dev research experiment signature with an Ed25519 author envelope.
    Sign {
        experiment: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build a reproducibility plan from a ResearchExperimentV1 JSON file.
    Reproduce {
        experiment: PathBuf,
        #[arg(long, default_value = "local")]
        runner: String,
    },
    /// Create a signed ResearchExperimentRunV1 linked to receipts, evals, validations, or outputs.
    RunInit {
        experiment: PathBuf,
        output: PathBuf,
        #[arg(long, default_value = "local-dev-research-runner")]
        requester: String,
        #[arg(long, default_value = "local")]
        runner: String,
        #[arg(long, default_value = "succeeded")]
        status: String,
        #[arg(long = "receipt-ref")]
        receipt_refs: Vec<String>,
        #[arg(long = "evaluation-result-ref")]
        evaluation_result_refs: Vec<String>,
        #[arg(long = "validation-report-ref")]
        validation_report_refs: Vec<String>,
        #[arg(long = "output-ref")]
        output_refs: Vec<String>,
        #[arg(long = "note")]
        notes: Vec<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a ResearchExperimentRunV1 JSON file.
    RunVerify {
        run: PathBuf,
        #[arg(long)]
        experiment: Option<PathBuf>,
    },
    /// Replace a local-dev research run signature with an Ed25519 requester envelope.
    RunSign {
        run: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// List local ResearchExperimentRunV1 records.
    RunList {
        #[arg(long, default_value = ".swarm-ai-cache/research")]
        runs_dir: PathBuf,
    },
    /// Look up one local ResearchExperimentRunV1 record by id.
    RunGet {
        run_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/research")]
        runs_dir: PathBuf,
    },
    /// List local ResearchExperimentV1 records.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/research")]
        experiments_dir: PathBuf,
    },
    /// Look up one local ResearchExperimentV1 record by id.
    Get {
        experiment_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/research")]
        experiments_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum VectorCommands {
    /// Create a signed local development VectorStoreManifestV1 JSON file.
    Init {
        path: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "local-dev-vector-owner")]
        owner: String,
        #[arg(long)]
        embedding_model_ref: String,
        #[arg(long = "document-ref")]
        document_collection_refs: Vec<String>,
        #[arg(long, default_value = "hnsw")]
        index_format: String,
        #[arg(long, default_value_t = 1536)]
        dimensions: u32,
        #[arg(long, default_value = "cosine")]
        metric: String,
        #[arg(long, default_value = "local://chunking/default")]
        chunking_strategy_ref: String,
        /// Storage refs as role=reference, for example index=bzz://... or chunks=bzz://...
        #[arg(long = "storage-ref")]
        storage_refs: Vec<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a VectorStoreManifestV1 JSON file.
    Verify { manifest: PathBuf },
    /// Replace a local-dev vector store signature with an Ed25519 owner envelope.
    Sign {
        manifest: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build a vector search plan from a manifest and query.
    Plan {
        manifest: PathBuf,
        #[arg(long)]
        vector_store_ref: Option<String>,
        #[arg(long, default_value = "local-dev")]
        requester: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        query: Option<PathBuf>,
        #[arg(long, default_value_t = 5)]
        top_k: u32,
        #[arg(long, default_value = "standard")]
        privacy_tier: String,
        #[arg(long, default_value_t = true)]
        trace_required: bool,
    },
    /// List local VectorStoreManifestV1 records.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/vector")]
        vector_dir: PathBuf,
    },
    /// Look up one local VectorStoreManifestV1 record by id.
    Get {
        vector_store_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/vector")]
        vector_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum WorkflowCommands {
    /// Create a signed local development ToolManifestV1 JSON file.
    ToolInit {
        path: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        description: String,
        #[arg(long, default_value = "local-dev-tool-publisher")]
        publisher: String,
        #[arg(long = "execution-mode", default_values_t = vec!["local".to_string()])]
        execution_modes: Vec<String>,
        #[arg(long = "safety-policy-ref")]
        safety_policy_refs: Vec<String>,
        #[arg(long = "permission")]
        permissions: Vec<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a ToolManifestV1 JSON file.
    ToolVerify { tool: PathBuf },
    /// Replace a tool manifest's local-dev signature with an Ed25519 publisher envelope.
    ToolSign {
        tool: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Create a signed local development WorkflowManifestV1 JSON file.
    Init {
        path: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "local-dev-workflow-publisher")]
        publisher: String,
        #[arg(long = "tool-ref")]
        tool_refs: Vec<String>,
        #[arg(long = "package-ref")]
        package_refs: Vec<String>,
        #[arg(long = "vector-store-ref")]
        vector_store_refs: Vec<String>,
        #[arg(long, default_value = "fail-fast")]
        failure_policy: String,
        #[arg(long, default_value = "receipts-only")]
        trace_policy: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a WorkflowManifestV1 JSON file.
    Verify { workflow: PathBuf },
    /// Replace a workflow manifest's local-dev signature with an Ed25519 publisher envelope.
    Sign {
        workflow: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build an ordered workflow execution plan from a WorkflowManifestV1 JSON file.
    Plan { workflow: PathBuf },
    /// List local ToolManifestV1 and WorkflowManifestV1 records.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/workflow")]
        workflow_dir: PathBuf,
    },
    /// Look up one local tool or workflow record by id.
    Get {
        record_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/workflow")]
        workflow_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum BatchCommands {
    /// Create a signed local development BatchJobV1 JSON file.
    Init {
        path: PathBuf,
        #[arg(long, default_value = "local-dev-requester")]
        requester: String,
        #[arg(long)]
        package_ref: String,
        #[arg(long)]
        package_id: String,
        #[arg(long, default_value = "0.1.0")]
        package_version: String,
        #[arg(long, default_value = "embedding")]
        task: String,
        #[arg(long, default_value = "openai_embeddings")]
        api_surface: String,
        #[arg(long = "item")]
        items: Vec<String>,
        #[arg(long, default_value_t = 4)]
        max_concurrency: u32,
        #[arg(long)]
        checkpoint_every_items: Option<u32>,
        #[arg(long, default_value = "on-checkpoint")]
        partial_result_policy: String,
        #[arg(long, default_value = "free-local-dev")]
        settlement_method: String,
        #[arg(long, default_value = "standard")]
        privacy_tier: String,
        #[arg(long, default_value = "receipt-only")]
        integrity_tier: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a BatchJobV1 JSON file.
    Verify { batch: PathBuf },
    /// Replace a batch job's local-dev signature with an Ed25519 requester envelope.
    Sign {
        batch: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build a batch execution plan from a BatchJobV1 JSON file.
    Plan { batch: PathBuf },
    /// List local BatchJobV1 records.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/batch")]
        batch_dir: PathBuf,
    },
    /// Look up one local BatchJobV1 record by id.
    Get {
        batch_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/batch")]
        batch_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum FineTuneCommands {
    /// Create a signed local development FineTuneJobV1 JSON file.
    Init {
        path: PathBuf,
        #[arg(long, default_value = "local-dev-requester")]
        requester: String,
        #[arg(long)]
        base_model_ref: String,
        #[arg(long = "training-dataset-ref")]
        training_dataset_refs: Vec<String>,
        #[arg(long = "validation-dataset-ref")]
        validation_dataset_refs: Vec<String>,
        #[arg(long, default_value = "local://fine-tune/recipe/default")]
        recipe_ref: String,
        #[arg(long)]
        hyperparameters: Option<PathBuf>,
        #[arg(long)]
        output_ref: Option<String>,
        #[arg(long, default_value = "adapter-or-lora")]
        artifact_kind: String,
        #[arg(long, default_value = "private")]
        output_visibility: String,
        #[arg(long, default_value = "local-only")]
        privacy_tier: String,
        #[arg(long, default_value = "receipt-only")]
        integrity_tier: String,
        #[arg(long)]
        max_cost_amount: Option<f64>,
        #[arg(long, default_value = "USD")]
        max_cost_currency: String,
        #[arg(long, default_value_t = false)]
        validation_required: bool,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a FineTuneJobV1 JSON file.
    Verify { job: PathBuf },
    /// Replace a fine-tune job's local-dev signature with an Ed25519 requester envelope.
    Sign {
        job: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build a fine-tune execution plan from a FineTuneJobV1 JSON file.
    Plan { job: PathBuf },
    /// List local FineTuneJobV1 records.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/fine-tune")]
        fine_tune_dir: PathBuf,
    },
    /// Look up one local FineTuneJobV1 record by id.
    Get {
        fine_tune_job_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/fine-tune")]
        fine_tune_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RealtimeCommands {
    /// Create a signed local development RealtimeSessionV1 JSON file.
    Init {
        path: PathBuf,
        #[arg(long, default_value = "local-dev-requester")]
        requester: String,
        #[arg(long)]
        package_ref: Option<String>,
        #[arg(long)]
        package_id: Option<String>,
        #[arg(long)]
        package_version: Option<String>,
        #[arg(long)]
        service_ref: Option<String>,
        #[arg(long)]
        model_alias: Option<String>,
        #[arg(long = "modality-in")]
        modalities_in: Vec<String>,
        #[arg(long = "modality-out")]
        modalities_out: Vec<String>,
        #[arg(long, default_value = "websocket")]
        transport: String,
        #[arg(long, default_value_t = 250)]
        latency_target_ms: u32,
        #[arg(long, default_value_t = true)]
        interruptions_allowed: bool,
        #[arg(long = "tool-ref")]
        tool_refs: Vec<String>,
        #[arg(long, default_value = "no-log")]
        privacy_tier: String,
        #[arg(long, default_value = "free-local-dev")]
        settlement_method: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a RealtimeSessionV1 JSON file.
    Verify { session: PathBuf },
    /// Replace a realtime session's local-dev signature with an Ed25519 requester envelope.
    Sign {
        session: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build a realtime connection plan from a RealtimeSessionV1 JSON file.
    Plan { session: PathBuf },
    /// List local RealtimeSessionV1 records.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/realtime")]
        realtime_dir: PathBuf,
    },
    /// Look up one local RealtimeSessionV1 record by id.
    Get {
        session_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/realtime")]
        realtime_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum MediaCommands {
    /// Create a signed local development MediaJobV1 JSON file.
    Init {
        path: PathBuf,
        #[arg(long, default_value = "local-dev-requester")]
        requester: String,
        #[arg(long)]
        task: String,
        #[arg(long)]
        package_ref: Option<String>,
        #[arg(long)]
        package_id: Option<String>,
        #[arg(long)]
        package_version: Option<String>,
        #[arg(long)]
        service_ref: Option<String>,
        #[arg(long)]
        model_alias: Option<String>,
        #[arg(long)]
        prompt: Option<String>,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        input_ref: Option<String>,
        #[arg(long)]
        mask_ref: Option<String>,
        #[arg(long)]
        parameters: Option<PathBuf>,
        #[arg(long, default_value = "ref")]
        response_format: String,
        #[arg(long)]
        output_ref: Option<String>,
        #[arg(long, default_value_t = 1)]
        count: u32,
        #[arg(long)]
        size: Option<String>,
        #[arg(long)]
        quality: Option<String>,
        #[arg(long)]
        style: Option<String>,
        #[arg(long)]
        voice: Option<String>,
        #[arg(long)]
        audio_format: Option<String>,
        #[arg(long, default_value = "no-log")]
        privacy_tier: String,
        #[arg(long, default_value = "receipt-only")]
        integrity_tier: String,
        #[arg(long, default_value = "free-local-dev")]
        settlement_method: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a MediaJobV1 JSON file.
    Verify { job: PathBuf },
    /// Replace a media job's local-dev signature with an Ed25519 requester envelope.
    Sign {
        job: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build a media execution plan from a MediaJobV1 JSON file.
    Plan { job: PathBuf },
    /// List local MediaJobV1 records.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/media")]
        media_dir: PathBuf,
    },
    /// Look up one local MediaJobV1 record by id.
    Get {
        media_job_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/media")]
        media_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum ModerationCommands {
    /// Create a signed local development ModerationPolicyManifestV1 JSON file.
    PolicyInit {
        path: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "local-dev-policy-publisher")]
        publisher: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long = "model-ref")]
        model_refs: Vec<String>,
        #[arg(long = "safety-policy-ref")]
        safety_policy_refs: Vec<String>,
        #[arg(long = "evidence-ref")]
        evidence_refs: Vec<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a ModerationPolicyManifestV1 JSON file.
    PolicyVerify { policy: PathBuf },
    /// Replace a moderation policy's local-dev signature with an Ed25519 publisher envelope.
    PolicySign {
        policy: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Create a signed local development ModerationRequestV1 JSON file.
    RequestInit {
        path: PathBuf,
        #[arg(long, default_value = "local-dev-requester")]
        requester: String,
        #[arg(long)]
        package_ref: Option<String>,
        #[arg(long)]
        package_id: Option<String>,
        #[arg(long)]
        package_version: Option<String>,
        #[arg(long)]
        service_ref: Option<String>,
        #[arg(long)]
        model_alias: Option<String>,
        #[arg(long, default_value = "local://moderation/policy/default")]
        policy_ref: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        input_ref: Option<String>,
        #[arg(long = "modality")]
        modalities: Vec<String>,
        #[arg(long = "category")]
        categories: Vec<String>,
        #[arg(long, default_value = "no-log")]
        privacy_tier: String,
        #[arg(long, default_value = "receipt-only")]
        integrity_tier: String,
        #[arg(long, default_value_t = true)]
        trace_required: bool,
        #[arg(long, default_value = "free-local-dev")]
        settlement_method: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a ModerationRequestV1 JSON file.
    RequestVerify { request: PathBuf },
    /// Replace a moderation request's local-dev signature with an Ed25519 requester envelope.
    RequestSign {
        request: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build a moderation plan from a request and optional policy manifest.
    Plan {
        request: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// List local moderation policy and request records.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/moderation")]
        moderation_dir: PathBuf,
    },
    /// Look up one local moderation policy or request record by id.
    Get {
        record_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/moderation")]
        moderation_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum GovernanceCommands {
    /// Create a signed local development GovernancePolicyManifestV1 JSON file.
    PolicyInit {
        path: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "core-maintainers")]
        steward: String,
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long = "approved-schema-version")]
        approved_schema_versions: Vec<String>,
        #[arg(long = "compatibility-test-ref")]
        compatibility_test_refs: Vec<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a GovernancePolicyManifestV1 JSON file.
    PolicyVerify { policy: PathBuf },
    /// Replace a governance policy's local-dev signature with an Ed25519 steward envelope.
    PolicySign {
        policy: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Create a signed local development SchemaReleaseV1 JSON file.
    SchemaReleaseInit {
        path: PathBuf,
        #[arg(long)]
        object_type: String,
        #[arg(long)]
        released_schema_version: String,
        #[arg(long, default_value = "0.2.0")]
        interface_version: String,
        #[arg(long, default_value = "development")]
        status: String,
        #[arg(long)]
        breaking_change: bool,
        #[arg(long = "compatible-with")]
        compatible_with: Vec<String>,
        #[arg(long = "compatibility-test-ref")]
        compatibility_test_refs: Vec<String>,
        #[arg(long = "approved-by")]
        approved_by: Vec<String>,
        #[arg(long)]
        migration_guide_ref: Option<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a SchemaReleaseV1 JSON file.
    SchemaReleaseVerify { release: PathBuf },
    /// Replace a schema release's local-dev signature with an Ed25519 approver envelope.
    SchemaReleaseSign {
        release: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Create a signed local development SecurityAdvisoryV1 JSON file.
    AdvisoryInit {
        path: PathBuf,
        #[arg(long)]
        title: String,
        #[arg(long, default_value = "local-security")]
        reporter: String,
        #[arg(long, default_value = "medium")]
        severity: String,
        #[arg(long = "category")]
        categories: Vec<String>,
        #[arg(long = "affected-ref")]
        affected_refs: Vec<String>,
        #[arg(long)]
        summary: String,
        #[arg(long)]
        impact: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a SecurityAdvisoryV1 JSON file.
    AdvisoryVerify { advisory: PathBuf },
    /// Replace a security advisory's local-dev signature with an Ed25519 reporter envelope.
    AdvisorySign {
        advisory: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build a security response plan from a SecurityAdvisoryV1 JSON file.
    ResponsePlan { advisory: PathBuf },
    /// Create a signed local development ComponentReadinessV1 JSON file.
    ReadinessInit {
        path: PathBuf,
        #[arg(long)]
        component_name: String,
        #[arg(long)]
        component_type: String,
        #[arg(long, default_value = "core-maintainers")]
        owner: String,
        #[arg(long, default_value = "local")]
        status: String,
        #[arg(long)]
        implementation_ref: Option<String>,
        #[arg(long)]
        version: Option<String>,
        #[arg(long = "schema-ref")]
        schema_refs: Vec<String>,
        #[arg(long = "api-surface")]
        api_surfaces: Vec<String>,
        #[arg(long = "environment")]
        supported_environments: Vec<String>,
        #[arg(long = "compatibility-certification-ref")]
        compatibility_certification_refs: Vec<String>,
        #[arg(long = "evidence-ref")]
        evidence_refs: Vec<String>,
        #[arg(long = "blocker")]
        blockers: Vec<String>,
        #[arg(long = "limitation")]
        limitations: Vec<String>,
        #[arg(long)]
        expires_at: Option<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    /// Verify a ComponentReadinessV1 JSON file.
    ReadinessVerify { readiness: PathBuf },
    /// Replace a component readiness record's local-dev signature with an Ed25519 owner envelope.
    ReadinessSign {
        readiness: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// List local governance policies, schema releases, advisories, and readiness records.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/governance")]
        governance_dir: PathBuf,
    },
    /// Look up one local governance policy, schema release, advisory, or readiness record by id.
    Get {
        record_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/governance")]
        governance_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RemoteCommands {
    /// Print the remote runner API contract.
    Api,
    /// Print default remote GPU runner capabilities.
    Capabilities {
        #[arg(long, default_value = "remote-dev-gpu-runner")]
        runner_id: String,
        #[arg(long, default_value_t = 0)]
        queue_depth: u32,
    },
    /// Print health, load, performance, and pricing status.
    Health {
        #[arg(long, default_value = "remote-dev-gpu-runner")]
        runner_id: String,
        #[arg(long, default_value_t = 0)]
        queue_depth: u32,
    },
    /// Prepare a local package for remote GPU execution.
    Prepare {
        path: PathBuf,
        #[arg(long)]
        package_ref: Option<String>,
        #[arg(long)]
        artifact_group: Option<String>,
        #[arg(long, default_value = "remote-dev-gpu-runner")]
        runner_id: String,
        #[arg(long, default_value_t = 0)]
        queue_depth: u32,
    },
    /// Execute a local package through the deterministic remote GPU runner.
    Run {
        path: PathBuf,
        #[arg(long, default_value = "chat")]
        task: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        artifact_group: Option<String>,
        #[arg(long, default_value = "remote-dev-gpu-runner")]
        runner_id: String,
        #[arg(long, default_value_t = 0)]
        queue_depth: u32,
        #[arg(long)]
        stream: bool,
        #[arg(long)]
        receipts_dir: Option<PathBuf>,
    },
    /// Cancel a queued remote GPU request.
    Cancel { request_id: String },
}

#[derive(Debug, Subcommand)]
enum RegistryCommands {
    /// Look up one indexed package with its manifest and trust evidence.
    Get {
        package_id: String,
        #[arg(long, default_value = "examples/packages")]
        packages: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/publications")]
        records: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/feeds")]
        feeds: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        validations: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/evaluations")]
        evaluations: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/listings")]
        marketplace_listings: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/offers")]
        marketplace_offers: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/hardware-offers")]
        marketplace_hardware_offers: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/governance")]
        governance_dir: PathBuf,
        #[arg(long)]
        grant: Option<PathBuf>,
        #[arg(long)]
        revocations: Option<PathBuf>,
        #[arg(long)]
        requester: Option<String>,
        #[arg(long)]
        requested_use: Option<String>,
        #[arg(long)]
        runner_id: Option<String>,
        #[arg(long, default_value_t = false)]
        include_private: bool,
    },
    /// Rebuild a registry snapshot from local packages and publication records.
    Rebuild {
        #[arg(long, default_value = "examples/packages")]
        packages: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/publications")]
        records: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/feeds")]
        feeds: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        validations: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/evaluations")]
        evaluations: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/listings")]
        marketplace_listings: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/offers")]
        marketplace_offers: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/hardware-offers")]
        marketplace_hardware_offers: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/governance")]
        governance_dir: PathBuf,
        #[arg(long, default_value = "examples/registry/index.json")]
        output: PathBuf,
        #[arg(long, default_value_t = false)]
        include_private: bool,
    },
    /// Verify a registry snapshot's canonical id, source records, and local-dev signature.
    VerifySnapshot {
        #[arg(long, default_value = "examples/registry/index.json")]
        input: PathBuf,
        #[arg(long, default_value_t = false)]
        include_private: bool,
    },
    /// Write mirrorable registry shard JSON files from a registry snapshot.
    Shards {
        #[arg(long, default_value = "examples/registry/index.json")]
        input: PathBuf,
        #[arg(long, default_value = "examples/registry/shards")]
        output: PathBuf,
        #[arg(long, default_value_t = false)]
        include_private: bool,
    },
    /// Verify registry shard JSON files against a registry snapshot.
    VerifyShards {
        #[arg(long, default_value = "examples/registry/index.json")]
        input: PathBuf,
        #[arg(long, default_value = "examples/registry/shards")]
        shards: PathBuf,
        #[arg(long, default_value_t = false)]
        include_private: bool,
    },
    /// Verify a registry shard manifest and its shard files against a registry snapshot.
    VerifyManifest {
        #[arg(long, default_value = "examples/registry/index.json")]
        input: PathBuf,
        #[arg(long, default_value = "examples/registry/shards")]
        shards: PathBuf,
        #[arg(long, default_value_t = false)]
        include_private: bool,
    },
    /// Compare a registry shard manifest against the snapshot-derived expected catalog.
    CompareManifest {
        #[arg(long, default_value = "examples/registry/index.json")]
        input: PathBuf,
        #[arg(long, default_value = "examples/registry/shards/manifest.json")]
        manifest: PathBuf,
        #[arg(long, default_value_t = false)]
        include_private: bool,
    },
}

#[derive(Debug, Subcommand)]
enum MarketplaceCommands {
    /// Build package marketplace listings from the local registry inputs.
    Listings {
        #[arg(long, default_value = "examples/packages")]
        packages: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/publications")]
        records: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        validations: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/evaluations")]
        evaluations: PathBuf,
        #[arg(long, default_value = "local-market")]
        owner: String,
        #[arg(long, default_value_t = false)]
        include_private: bool,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
    /// Verify a marketplace listing JSON file.
    VerifyListing {
        #[arg(long)]
        listing: PathBuf,
    },
    /// Replace a marketplace listing's local-dev signature with an Ed25519 owner identity envelope.
    SignListing {
        #[arg(long)]
        listing: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Build the default local runner offer.
    Offers {
        #[arg(long, default_value = "examples/packages")]
        packages: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/publications")]
        records: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        validations: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/evaluations")]
        evaluations: PathBuf,
        #[arg(long, default_value_t = false)]
        include_private: bool,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
    /// Build default hardware resource offers for local development runners.
    HardwareOffers {
        #[arg(long, default_value = "local-market")]
        operator: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
    /// Rank runner offers for a package, task, and routing policy.
    Shortlist {
        reference: String,
        #[arg(long, default_value = "hivemind/unknown")]
        package_id: String,
        #[arg(long, default_value = "0.1.0")]
        package_version: String,
        #[arg(long, default_value = "embedding")]
        task: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long, default_value = "balanced")]
        policy: String,
        #[arg(long, default_value_t = 5)]
        max_results: usize,
        #[arg(long, default_value_t = false)]
        include_rejected: bool,
        #[arg(long, default_value = "examples/packages")]
        packages: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/publications")]
        records: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/validations")]
        validations: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/evaluations")]
        evaluations: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/offers")]
        offers: PathBuf,
        #[arg(long, default_value_t = false)]
        include_private: bool,
    },
    /// Verify a runner offer JSON file.
    VerifyOffer {
        #[arg(long)]
        offer: PathBuf,
    },
    /// Replace a runner offer's local-dev signature with an Ed25519 runner identity envelope.
    SignOffer {
        #[arg(long)]
        offer: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a hardware resource offer JSON file.
    VerifyHardwareOffer {
        #[arg(long)]
        offer: PathBuf,
    },
    /// Replace a hardware resource offer's local-dev signature with an Ed25519 operator envelope.
    SignHardwareOffer {
        #[arg(long)]
        offer: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Quote an execution request against the default local runner offer.
    Quote {
        reference: String,
        #[arg(long, default_value = "hivemind/unknown")]
        package_id: String,
        #[arg(long, default_value = "0.1.0")]
        package_version: String,
        #[arg(long, default_value = "embedding")]
        task: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/offers")]
        offers: PathBuf,
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Verify a service quote JSON file, optionally against a runner offer.
    VerifyQuote {
        #[arg(long)]
        quote: PathBuf,
        #[arg(long)]
        offer: Option<PathBuf>,
    },
    /// Replace a service quote's local-dev signature with an Ed25519 runner identity envelope.
    SignQuote {
        #[arg(long)]
        quote: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Authorize payment for a service quote through a local development adapter.
    AuthorizePayment {
        #[arg(long)]
        quote: PathBuf,
        #[arg(long, default_value = "local-dev")]
        payer: String,
        #[arg(long, default_value = "local-dev-runner")]
        payee: String,
        #[arg(long, default_value = "local-dev")]
        adapter: String,
        #[arg(long)]
        payment_ref: Option<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/payments")]
        payment_dir: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// List locally stored payment authorizations.
    Payments {
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/payments")]
        payment_dir: PathBuf,
    },
    /// Look up a locally stored payment authorization by authorization id.
    GetPayment {
        authorization_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/payments")]
        payment_dir: PathBuf,
    },
    /// Verify a payment authorization JSON file, optionally against a service quote.
    VerifyPayment {
        #[arg(long)]
        authorization: PathBuf,
        #[arg(long)]
        quote: Option<PathBuf>,
    },
    /// Replace a payment authorization's local-dev signature with an Ed25519 payer identity envelope.
    SignPayment {
        #[arg(long)]
        authorization: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Create a settlement event from a receipt and optional quote/payment files.
    Settle {
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        quote: Option<PathBuf>,
        #[arg(long)]
        payment_authorization: Option<PathBuf>,
        #[arg(long, default_value = "local-dev")]
        payer: String,
        #[arg(long, default_value = "local-dev-runner")]
        payee: String,
        #[arg(long)]
        receipt_ref: Option<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/audit")]
        audit_dir: PathBuf,
    },
    /// List locally stored marketplace settlement and resolution audit records.
    Audit {
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/audit")]
        audit_dir: PathBuf,
    },
    /// Look up a locally stored marketplace settlement by settlement id.
    GetSettlement {
        settlement_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/audit")]
        audit_dir: PathBuf,
    },
    /// Verify a settlement event JSON file.
    VerifySettlement {
        #[arg(long)]
        settlement: PathBuf,
    },
    /// Replace a settlement event's local-dev signature with an Ed25519 payee identity envelope.
    SignSettlement {
        #[arg(long)]
        settlement: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Open a marketplace dispute against a settlement using signed dispute evidence.
    DisputeSettlement {
        #[arg(long)]
        settlement: PathBuf,
        #[arg(long)]
        dispute: PathBuf,
        #[arg(long, default_value = "local-market")]
        resolved_by: String,
        #[arg(long, default_value = "settlement disputed")]
        reason: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/audit")]
        audit_dir: PathBuf,
    },
    /// Mark a disputed settlement as refunded using signed dispute evidence.
    RefundSettlement {
        #[arg(long)]
        settlement: PathBuf,
        #[arg(long)]
        dispute: PathBuf,
        #[arg(long, default_value = "local-market")]
        resolved_by: String,
        #[arg(long, default_value = "refund approved")]
        reason: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/audit")]
        audit_dir: PathBuf,
    },
    /// Reject an open marketplace dispute and mark the settlement as dispute_rejected.
    RejectDispute {
        #[arg(long)]
        settlement: PathBuf,
        #[arg(long)]
        dispute: PathBuf,
        #[arg(long, default_value = "local-market")]
        resolved_by: String,
        #[arg(long, default_value = "dispute rejected")]
        reason: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/audit")]
        audit_dir: PathBuf,
    },
    /// Look up a locally stored settlement resolution by resolution id.
    GetResolution {
        resolution_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/audit")]
        audit_dir: PathBuf,
    },
    /// Verify a settlement resolution JSON file.
    VerifyResolution {
        #[arg(long)]
        resolution: PathBuf,
    },
    /// Replace a settlement resolution's local-dev signature with an Ed25519 resolver identity envelope.
    SignResolution {
        #[arg(long)]
        resolution: PathBuf,
        #[arg(long)]
        identity: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum MinerCommands {
    /// Create a signed local development MinerProfileV1 from a HardwareResourceOfferV1.
    Profile {
        #[arg(long)]
        offer: PathBuf,
        #[arg(long, default_value = "0.1.0-dev")]
        daemon_version: String,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a MinerProfileV1, optionally against its HardwareResourceOfferV1.
    VerifyProfile {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        offer: Option<PathBuf>,
    },
    /// Create a signed local development MinerHeartbeatV1 from a miner profile.
    Heartbeat {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long, default_value = "available")]
        status: String,
        #[arg(long, default_value_t = 0)]
        queue_depth: u32,
        #[arg(long, default_value_t = 0)]
        active_jobs: u32,
        #[arg(long = "current-job-id")]
        current_job_ids: Vec<String>,
        #[arg(long, default_value_t = 0.0)]
        load_average: f64,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a MinerHeartbeatV1, optionally against its MinerProfileV1.
    VerifyHeartbeat {
        #[arg(long)]
        heartbeat: PathBuf,
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    /// Create a signed local development MinerBenchmarkResultV1.
    Benchmark {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        offer: PathBuf,
        #[arg(long, default_value = "local-miner-smoke")]
        suite: String,
        #[arg(long, default_value = "package-inference")]
        workload: String,
        #[arg(long = "metric")]
        metrics: Vec<String>,
        #[arg(long = "evidence-ref")]
        evidence_refs: Vec<String>,
        #[arg(long)]
        identity: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a MinerBenchmarkResultV1.
    VerifyBenchmark {
        #[arg(long)]
        benchmark: PathBuf,
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        offer: Option<PathBuf>,
    },
    /// Build a miner onboarding plan from profile, offer, and optional benchmark evidence.
    Onboarding {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        offer: PathBuf,
        #[arg(long = "benchmark")]
        benchmarks: Vec<PathBuf>,
    },
    /// Build an operator dashboard summary from miner lifecycle records.
    Dashboard {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        heartbeat: PathBuf,
        #[arg(long)]
        offer: PathBuf,
        #[arg(long = "benchmark")]
        benchmarks: Vec<PathBuf>,
        #[arg(long, default_value_t = 0)]
        completed_jobs: u64,
        #[arg(long, default_value_t = 0)]
        settled_jobs: u64,
        #[arg(long, default_value_t = 0)]
        disputed_jobs: u64,
        #[arg(long, default_value_t = 0.0)]
        earning_amount: f64,
        #[arg(long, default_value = "USD")]
        earning_currency: String,
    },
    /// List local miner profile, heartbeat, and benchmark records.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/miner")]
        miner_dir: PathBuf,
    },
    /// Look up one local miner profile, heartbeat, or benchmark record by id.
    Get {
        record_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/miner")]
        miner_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    std::thread::Builder::new()
        .name("swarm-ai-main".to_string())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async_main())
        })?
        .join()
        .map_err(|_| anyhow::anyhow!("swarm-ai main thread panicked"))?
}

async fn async_main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            path,
            package_id,
            name,
            template,
            publisher,
            publisher_name,
            version,
            force,
        } => {
            init_command(
                path,
                package_id,
                name,
                template,
                publisher,
                publisher_name,
                version,
                force,
            )
            .await
        }
        Commands::Validate {
            path,
            package_audit,
        } => validate_command(path, package_audit).await,
        Commands::ValidateRef {
            reference,
            provider,
            storage_dir,
            bee_url,
            package_audit,
        } => validate_ref_command(reference, provider, storage_dir, bee_url, package_audit).await,
        Commands::IssueGrant {
            reference,
            provider,
            storage_dir,
            bee_url,
            grantee,
            requested_use,
            runner_id,
            expires_at,
            issuer,
            identity,
            grants_dir,
            output,
        } => {
            issue_grant_command(
                reference,
                provider,
                storage_dir,
                bee_url,
                grantee,
                requested_use,
                runner_id,
                expires_at,
                issuer,
                identity,
                grants_dir,
                output,
            )
            .await
        }
        Commands::VerifyGrant { grant } => verify_grant_command(grant).await,
        Commands::RevokeGrant {
            grant,
            revoked_by,
            reason,
            identity,
            revocations_dir,
            output,
        } => {
            revoke_grant_command(grant, revoked_by, reason, identity, revocations_dir, output).await
        }
        Commands::AccessGrants { grants_dir } => access_grants_command(grants_dir).await,
        Commands::GetGrant {
            grant_id,
            grants_dir,
        } => get_grant_command(grant_id, grants_dir).await,
        Commands::AccessRevocations { revocations_dir } => {
            access_revocations_command(revocations_dir).await
        }
        Commands::GetRevocation {
            revocation_id,
            revocations_dir,
        } => get_revocation_command(revocation_id, revocations_dir).await,
        Commands::VerifyGrantRevocation { revocation, grant } => {
            verify_grant_revocation_command(revocation, grant).await
        }
        Commands::RevocationList { revocations } => revocation_list_command(revocations).await,
        Commands::VerifyRevocationList { revocations } => {
            verify_revocation_list_command(revocations).await
        }
        Commands::Search {
            capability,
            modality,
            api_surface,
            publisher,
            target,
            engine,
            privacy_tier,
            verification_tier,
            max_artifact_bytes,
            min_artifact_bytes,
            browser_runnable,
            gpu_required,
            min_validator_score,
            min_benchmark_score,
            max_price_amount,
            max_price_currency,
            marketplace_listings,
            registry_audit,
            page_size,
            grant,
            revocations,
            requester,
            requested_use,
            runner_id,
        } => {
            search_command(
                capability,
                modality,
                api_surface,
                publisher,
                target,
                engine,
                privacy_tier,
                verification_tier,
                max_artifact_bytes,
                min_artifact_bytes,
                browser_runnable,
                gpu_required,
                min_validator_score,
                min_benchmark_score,
                max_price_amount,
                max_price_currency,
                marketplace_listings,
                registry_audit,
                page_size,
                grant,
                revocations,
                requester,
                requested_use,
                runner_id,
            )
            .await
        }
        Commands::PublishDryRun { path } => publish_dry_run_command(path).await,
        Commands::Sign { path } => sign_command(path).await,
        Commands::Identity { command } => identity_command(command).await,
        Commands::VerifyPublication { record } => verify_publication_command(record).await,
        Commands::PublicationRecords { record_dir } => {
            publication_records_command(record_dir).await
        }
        Commands::GetPublication {
            publication_id,
            record_dir,
        } => get_publication_command(publication_id, record_dir).await,
        Commands::UpdateFeed { record, feed_dir } => update_feed_command(record, feed_dir).await,
        Commands::ResolveFeed {
            package_id,
            channel,
            feed_dir,
        } => resolve_feed_command(package_id, channel, feed_dir).await,
        Commands::FeedPointers { feed_dir } => feed_pointers_command(feed_dir).await,
        Commands::GetFeed {
            package_id,
            channel,
            feed_dir,
        } => get_feed_command(package_id, channel, feed_dir).await,
        Commands::Publish {
            path,
            provider,
            storage_dir,
            bee_url,
            postage_batch_id,
            record_dir,
            feed_dir,
            channel,
        } => {
            publish_command(
                path,
                provider,
                storage_dir,
                bee_url,
                postage_batch_id,
                record_dir,
                feed_dir,
                channel,
            )
            .await
        }
        Commands::Inspect {
            reference,
            path,
            provider,
            storage_dir,
            bee_url,
        } => inspect_command(reference, path, provider, storage_dir, bee_url).await,
        Commands::Cache { command } => cache_command(command).await,
        Commands::Policy { command } => policy_command(command).await,
        Commands::Receipts { command } => receipts_command(command).await,
        Commands::Jobs { command } => jobs_command(command).await,
        Commands::Observability { command } => observability_command(command).await,
        Commands::Install {
            reference,
            provider,
            storage_dir,
            bee_url,
            cache_dir,
            artifact_group,
            grant,
            revocations,
            developer_mode,
        } => {
            install_command(
                reference,
                provider,
                storage_dir,
                bee_url,
                cache_dir,
                artifact_group,
                grant,
                revocations,
                developer_mode,
            )
            .await
        }
        Commands::RunnerCache { command } => runner_cache_command(command).await,
        Commands::Browser { command } => browser_command(command).await,
        Commands::BrowserSwarm { command } => browser_swarm_command(command).await,
        Commands::Remote { command } => remote_command(command).await,
        Commands::Registry { command } => registry_command(command).await,
        Commands::Marketplace { command } => marketplace_command(command).await,
        Commands::Compat { path } => compat_command(path).await,
        Commands::Certify {
            path,
            identity,
            component_type,
            implementation_name,
            component_version,
            supported_schemas,
            warnings,
            store,
            compatibility_dir,
            output,
        } => {
            certify_command(
                path,
                identity,
                component_type,
                implementation_name,
                component_version,
                supported_schemas,
                warnings,
                store,
                compatibility_dir,
                output,
            )
            .await
        }
        Commands::VerifyCertification {
            certification,
            expected_signer,
        } => verify_certification_command(certification, expected_signer).await,
        Commands::Certifications { command } => match command {
            CertificationCommands::List { compatibility_dir } => {
                compatibility_certification_list_command(compatibility_dir).await
            }
            CertificationCommands::Get {
                certification_id,
                compatibility_dir,
            } => compatibility_certification_get_command(certification_id, compatibility_dir).await,
        },
        Commands::Route {
            package,
            task,
            text,
            input,
            package_ref,
            artifact_group,
            policy,
            local_queue,
            remote_queue,
            validations,
            marketplace_offers,
            max_marketplace_results,
            marketplace_hardware_offers,
            miner,
            trust_policy,
        } => {
            route_command(
                package,
                task,
                text,
                input,
                package_ref,
                artifact_group,
                policy,
                local_queue,
                remote_queue,
                validations,
                marketplace_offers,
                max_marketplace_results,
                marketplace_hardware_offers,
                miner,
                trust_policy,
            )
            .await
        }
        Commands::ValidateRun {
            reference,
            provider,
            storage_dir,
            bee_url,
            validator_id,
            identity,
            task,
            text,
            input,
            grant,
            revocations,
            reports_dir,
        } => {
            validate_run_command(
                reference,
                provider,
                storage_dir,
                bee_url,
                validator_id,
                identity,
                task,
                text,
                input,
                grant,
                revocations,
                reports_dir,
            )
            .await
        }
        Commands::VerifyValidation { report } => verify_validation_command(report).await,
        Commands::SignValidation {
            report,
            identity,
            output,
        } => sign_validation_command(report, identity, output).await,
        Commands::UploadValidation {
            report,
            provider,
            storage_dir,
            bee_url,
            postage_batch_id,
        } => {
            upload_validation_command(report, provider, storage_dir, bee_url, postage_batch_id)
                .await
        }
        Commands::DownloadValidation {
            reference,
            provider,
            storage_dir,
            bee_url,
            output,
            reports_dir,
        } => {
            download_validation_command(
                reference,
                provider,
                storage_dir,
                bee_url,
                output,
                reports_dir,
            )
            .await
        }
        Commands::ValidationReports { reports_dir } => {
            validation_reports_command(reports_dir).await
        }
        Commands::GetValidation {
            report_id,
            reports_dir,
        } => get_validation_command(report_id, reports_dir).await,
        Commands::IntegrityEvidenceInit {
            output,
            evidence_kind,
            validator_id,
            runner_id,
            subject_type,
            subject_id,
            package_ref,
            receipt_id,
            measurement_hash,
            expected_measurement_hashes,
            evidence_refs,
            proof_refs,
            method,
            verdict,
            identity,
            force,
        } => {
            integrity_evidence_init_command(
                output,
                evidence_kind,
                validator_id,
                runner_id,
                subject_type,
                subject_id,
                package_ref,
                receipt_id,
                measurement_hash,
                expected_measurement_hashes,
                evidence_refs,
                proof_refs,
                method,
                verdict,
                identity,
                force,
            )
            .await
        }
        Commands::VerifyIntegrityEvidence { evidence } => {
            verify_integrity_evidence_command(evidence).await
        }
        Commands::SignIntegrityEvidence {
            evidence,
            identity,
            output,
        } => sign_integrity_evidence_command(evidence, identity, output).await,
        Commands::IntegrityEvidenceRecords { evidence_dir } => {
            integrity_evidence_records_command(evidence_dir).await
        }
        Commands::GetIntegrityEvidence {
            evidence_id,
            evidence_dir,
        } => get_integrity_evidence_command(evidence_id, evidence_dir).await,
        Commands::Reputation {
            subject_type,
            subject_id,
            reports_dir,
        } => reputation_command(subject_type, subject_id, reports_dir).await,
        Commands::BenchmarkRun {
            reference,
            provider,
            storage_dir,
            bee_url,
            validator_id,
            identity,
            benchmark,
            grant,
            revocations,
            results_dir,
        } => {
            benchmark_run_command(
                reference,
                provider,
                storage_dir,
                bee_url,
                validator_id,
                identity,
                benchmark,
                grant,
                revocations,
                results_dir,
            )
            .await
        }
        Commands::VerifyEvaluation { result } => verify_evaluation_command(result).await,
        Commands::SignEvaluation {
            result,
            identity,
            output,
        } => sign_evaluation_command(result, identity, output).await,
        Commands::EvaluationResults { results_dir } => {
            evaluation_results_command(results_dir).await
        }
        Commands::EvaluationLeaderboard { results_dir } => {
            evaluation_leaderboard_command(results_dir).await
        }
        Commands::GetEvaluation {
            evaluation_id,
            results_dir,
        } => get_evaluation_command(evaluation_id, results_dir).await,
        Commands::EvaluationV2FromV1 {
            result,
            output,
            suite_id,
            started_at,
            completed_at,
            total_ms,
            average_ms,
            cost_amount,
            cost_currency,
            pricing_ref,
            runner_type,
            os,
            architecture,
            hardware_refs,
            software_refs,
            artifact_refs,
            random_seeds,
            errors,
            identity,
            force,
        } => {
            evaluation_v2_from_v1_command(
                result,
                output,
                suite_id,
                started_at,
                completed_at,
                total_ms,
                average_ms,
                cost_amount,
                cost_currency,
                pricing_ref,
                runner_type,
                os,
                architecture,
                hardware_refs,
                software_refs,
                artifact_refs,
                random_seeds,
                errors,
                identity,
                force,
            )
            .await
        }
        Commands::VerifyEvaluationV2 { result } => verify_evaluation_v2_command(result).await,
        Commands::SignEvaluationV2 {
            result,
            identity,
            output,
        } => sign_evaluation_v2_command(result, identity, output).await,
        Commands::EvaluationResultsV2 { results_dir } => {
            evaluation_results_v2_command(results_dir).await
        }
        Commands::GetEvaluationV2 {
            evaluation_id,
            results_dir,
        } => get_evaluation_v2_command(evaluation_id, results_dir).await,
        Commands::BenchmarkSuiteInit {
            output,
            benchmark_id,
            name,
            task,
            version,
            maintainer_id,
            modalities,
            dataset_refs,
            scoring_method_ref,
            splits,
            allowed_model_refs,
            allowed_runtimes,
            privacy_tier,
            private_results,
            disallow_remote_runners,
            require_result_redaction,
            access_policy_refs,
            p50_ms,
            p95_ms,
            max_ms,
            metric_names,
            identity,
            force,
        } => {
            benchmark_suite_init_command(
                output,
                benchmark_id,
                name,
                task,
                version,
                maintainer_id,
                modalities,
                dataset_refs,
                scoring_method_ref,
                splits,
                allowed_model_refs,
                allowed_runtimes,
                privacy_tier,
                private_results,
                disallow_remote_runners,
                require_result_redaction,
                access_policy_refs,
                p50_ms,
                p95_ms,
                max_ms,
                metric_names,
                identity,
                force,
            )
            .await
        }
        Commands::VerifyBenchmarkSuite { suite } => verify_benchmark_suite_command(suite).await,
        Commands::SignBenchmarkSuite {
            suite,
            identity,
            output,
        } => sign_benchmark_suite_command(suite, identity, output).await,
        Commands::BenchmarkSuites { suites_dir } => benchmark_suites_command(suites_dir).await,
        Commands::GetBenchmarkSuite {
            suite_id,
            suites_dir,
        } => get_benchmark_suite_command(suite_id, suites_dir).await,
        Commands::ChallengeCommitmentInit {
            output,
            benchmark_id,
            benchmark_version,
            validator_id,
            challenge_set_hash,
            answer_set_hash,
            salt_hash,
            challenge_count,
            public_dataset_refs,
            hidden_ref_commitments,
            scoring_rule_refs,
            reveal_after,
            expires_at,
            identity,
            force,
        } => {
            challenge_commitment_init_command(
                output,
                benchmark_id,
                benchmark_version,
                validator_id,
                challenge_set_hash,
                answer_set_hash,
                salt_hash,
                challenge_count,
                public_dataset_refs,
                hidden_ref_commitments,
                scoring_rule_refs,
                reveal_after,
                expires_at,
                identity,
                force,
            )
            .await
        }
        Commands::VerifyChallengeCommitment { commitment } => {
            verify_challenge_commitment_command(commitment).await
        }
        Commands::SignChallengeCommitment {
            commitment,
            identity,
            output,
        } => sign_challenge_commitment_command(commitment, identity, output).await,
        Commands::ChallengeCommitments { commitments_dir } => {
            challenge_commitments_command(commitments_dir).await
        }
        Commands::GetChallengeCommitment {
            commitment_id,
            commitments_dir,
        } => get_challenge_commitment_command(commitment_id, commitments_dir).await,
        Commands::Eval { command } => eval_command(command).await,
        Commands::Experiment { command } => experiment_command(command).await,
        Commands::Vector { command } => vector_command(command).await,
        Commands::Workflow { command } => workflow_command(command).await,
        Commands::Batch { command } => batch_command(command).await,
        Commands::FineTune { command } => fine_tune_command(command).await,
        Commands::Realtime { command } => realtime_command(command).await,
        Commands::Media { command } => media_command(command).await,
        Commands::Moderation { command } => moderation_command(command).await,
        Commands::Governance { command } => governance_command(command).await,
        Commands::Miner { command } => miner_command(command).await,
        Commands::Run {
            package,
            task,
            text,
            input,
            grant,
            revocations,
            receipts_dir,
        } => run_command(package, task, text, input, grant, revocations, receipts_dir).await,
        Commands::RunRef {
            reference,
            provider,
            storage_dir,
            bee_url,
            task,
            text,
            input,
            artifact_group,
            grant,
            revocations,
            receipts_dir,
        } => {
            run_ref_command(
                reference,
                provider,
                storage_dir,
                bee_url,
                task,
                text,
                input,
                artifact_group,
                grant,
                revocations,
                receipts_dir,
            )
            .await
        }
        Commands::Schema { kind } => schema_command(&kind),
        Commands::Serve {
            host,
            port,
            packages,
            package_audit,
            compatibility,
            records,
            validations,
            evaluations,
            access_grants,
            access_revocations,
            receipts,
            disputes,
            jobs,
            governance,
            research,
            evals,
            vector,
            workflow,
            batch,
            fine_tune,
            realtime,
            media,
            moderation,
            miner,
            marketplace_listings,
            marketplace_offers,
            marketplace_hardware_offers,
            marketplace_payments,
            marketplace_audit,
            storage,
            storage_audit,
            runner_cache,
            trust,
            feeds,
            streams,
            route_traces,
            registry_audit,
            static_dir,
        } => {
            api::serve(api::ServeConfig {
                host,
                port,
                package_dir: packages,
                package_audit_dir: package_audit,
                compatibility_dir: compatibility,
                record_dir: records,
                validation_dir: validations,
                evaluation_dir: evaluations,
                access_grant_dir: access_grants,
                access_revocation_dir: access_revocations,
                receipt_dir: receipts,
                dispute_dir: disputes,
                job_dir: jobs,
                governance_dir: governance,
                research_dir: research,
                eval_dir: evals,
                vector_dir: vector,
                workflow_dir: workflow,
                batch_dir: batch,
                fine_tune_dir: fine_tune,
                realtime_dir: realtime,
                media_dir: media,
                moderation_dir: moderation,
                miner_dir: miner,
                marketplace_listing_dir: marketplace_listings,
                marketplace_runner_offer_dir: marketplace_offers,
                marketplace_hardware_offer_dir: marketplace_hardware_offers,
                marketplace_payment_dir: marketplace_payments,
                marketplace_audit_dir: marketplace_audit,
                storage_dir: storage,
                storage_audit_dir: storage_audit,
                runner_cache_dir: runner_cache,
                trust_policy_dir: trust,
                feed_dir: feeds,
                stream_event_dir: streams,
                route_trace_dir: route_traces,
                registry_audit_dir: registry_audit,
                static_dir,
            })
            .await
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();
}

async fn init_command(
    path: PathBuf,
    package_id: String,
    name: Option<String>,
    template: String,
    publisher: String,
    publisher_name: String,
    version: String,
    force: bool,
) -> Result<()> {
    let template = parse_package_template(&template)?;
    let mut options = hivemind_package::default_init_options(package_id, name, template);
    options.publisher = publisher;
    options.publisher_display_name = publisher_name;
    options.version = version;
    options.force = force;
    let result = hivemind_package::init_package_dir(&path, &options)
        .with_context(|| format!("failed to initialize package at {}", path.display()))?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

async fn validate_command(path: PathBuf, package_audit: PathBuf) -> Result<()> {
    let (report, audit_record) = validate_package_dir_with_audit(&path)
        .with_context(|| format!("failed to validate package at {}", path.display()))?;
    hivemind_package::write_package_validation_audit_record(&package_audit, &audit_record)
        .with_context(|| {
            format!(
                "failed to write package validation audit record into {}",
                package_audit.display()
            )
        })?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn validate_ref_command(
    reference: String,
    provider: String,
    storage_dir: PathBuf,
    bee_url: String,
    package_audit: PathBuf,
) -> Result<()> {
    let report = match provider.as_str() {
        "local" => {
            let storage = LocalDirectoryStorageProvider::new(storage_dir);
            validate_package_ref_with_audit(&reference, &storage)
        }
        "bee" => {
            let storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                api_url: bee_url,
                postage_batch_id: None,
                pin: false,
                deferred_upload: true,
                redundancy_level: 0,
            });
            validate_package_ref_with_audit(&reference, &storage)
        }
        other => anyhow::bail!("unknown validate-ref provider {other}; expected local or bee"),
    }
    .with_context(|| format!("failed to validate package ref {reference}"))?;
    let (report, audit_record) = report;
    hivemind_package::write_package_validation_audit_record(&package_audit, &audit_record)
        .with_context(|| {
            format!(
                "failed to write package validation audit record into {}",
                package_audit.display()
            )
        })?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn issue_grant_command(
    reference: String,
    provider: String,
    storage_dir: PathBuf,
    bee_url: String,
    grantee: String,
    requested_use: String,
    runner_id: Option<String>,
    expires_at: Option<String>,
    issuer: String,
    identity: Option<PathBuf>,
    grants_dir: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let package = match provider.as_str() {
        "local" => {
            let storage = LocalDirectoryStorageProvider::new(storage_dir);
            hivemind_package::load_package_from_storage(&reference, &storage)
        }
        "bee" => {
            let storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                api_url: bee_url,
                postage_batch_id: None,
                pin: false,
                deferred_upload: true,
                redundancy_level: 0,
            });
            hivemind_package::load_package_from_storage(&reference, &storage)
        }
        other => anyhow::bail!("unknown issue-grant provider {other}; expected local or bee"),
    }
    .with_context(|| format!("failed to load package {reference}"))?;
    let policy = hivemind_core::license_policy_from_manifest(&package.manifest, &reference);
    let mut grant = hivemind_access::dev_access_grant_issued_by(
        &policy,
        grantee,
        requested_use,
        runner_id,
        expires_at,
        issuer,
    );
    if let Some(identity_path) = identity {
        let identity: hivemind_identity::IdentityKeypairV1 = read_json_file(&identity_path).await?;
        hivemind_access::sign_access_grant_with_identity(&mut grant, &identity)
            .with_context(|| format!("failed to sign grant with {}", identity_path.display()))?;
    }
    let verification = hivemind_access::verify_access_grant(&grant);
    let grant_path = hivemind_access::write_access_grant(&grants_dir, &grant)
        .with_context(|| format!("failed to write access grant into {}", grants_dir.display()))?;
    if let Some(output) = output {
        write_json_file(&output, &grant).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "outputPath": output.display().to_string(),
                "grantPath": grant_path,
                "grant": grant,
                "verification": verification
            }))?
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&grant)?);
    }
    Ok(())
}

async fn verify_grant_command(grant: PathBuf) -> Result<()> {
    let grant: AccessGrantV1 = read_json_file(&grant).await?;
    let verification = hivemind_access::verify_access_grant(&grant);
    println!("{}", serde_json::to_string_pretty(&verification)?);
    Ok(())
}

async fn revoke_grant_command(
    grant: PathBuf,
    revoked_by: String,
    reason: String,
    identity: Option<PathBuf>,
    revocations_dir: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let grant: AccessGrantV1 = read_json_file(&grant).await?;
    let mut revocation = hivemind_access::revoke_access_grant(&grant, revoked_by, reason);
    if let Some(identity_path) = identity {
        let identity: hivemind_identity::IdentityKeypairV1 = read_json_file(&identity_path).await?;
        hivemind_access::sign_access_grant_revocation_with_identity(&mut revocation, &identity)
            .with_context(|| {
                format!(
                    "failed to sign grant revocation with {}",
                    identity_path.display()
                )
            })?;
    }
    let verification = hivemind_access::verify_access_grant_revocation(&revocation, Some(&grant));
    let revocation_path =
        hivemind_access::write_access_grant_revocation(&revocations_dir, &revocation)
            .with_context(|| {
                format!(
                    "failed to write access revocation into {}",
                    revocations_dir.display()
                )
            })?;
    if let Some(output) = output {
        write_json_file(&output, &revocation).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "outputPath": output.display().to_string(),
                "revocationPath": revocation_path,
                "revocation": revocation,
                "verification": verification
            }))?
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&revocation)?);
    }
    Ok(())
}

async fn access_grants_command(grants_dir: PathBuf) -> Result<()> {
    let summary = hivemind_access::list_access_grants(&grants_dir)
        .with_context(|| format!("failed to list {}", grants_dir.display()))?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn get_grant_command(grant_id: String, grants_dir: PathBuf) -> Result<()> {
    let lookup = hivemind_access::get_access_grant(&grants_dir, &grant_id)
        .with_context(|| format!("failed to read {}", grants_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("access grant {grant_id} was not found"))?;
    println!("{}", serde_json::to_string_pretty(&lookup)?);
    Ok(())
}

async fn access_revocations_command(revocations_dir: PathBuf) -> Result<()> {
    let summary = hivemind_access::list_access_grant_revocations(&revocations_dir)
        .with_context(|| format!("failed to list {}", revocations_dir.display()))?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn get_revocation_command(revocation_id: String, revocations_dir: PathBuf) -> Result<()> {
    let lookup = hivemind_access::get_access_grant_revocation(&revocations_dir, &revocation_id)
        .with_context(|| format!("failed to read {}", revocations_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("access revocation {revocation_id} was not found"))?;
    println!("{}", serde_json::to_string_pretty(&lookup)?);
    Ok(())
}

async fn verify_grant_revocation_command(
    revocation: PathBuf,
    grant: Option<PathBuf>,
) -> Result<()> {
    let revocation: AccessGrantRevocationV1 = read_json_file(&revocation).await?;
    let grant = match grant {
        Some(path) => Some(read_json_file::<AccessGrantV1>(&path).await?),
        None => None,
    };
    let verification = hivemind_access::verify_access_grant_revocation(&revocation, grant.as_ref());
    println!("{}", serde_json::to_string_pretty(&verification)?);
    Ok(())
}

async fn revocation_list_command(revocations: Vec<PathBuf>) -> Result<()> {
    let mut records = Vec::new();
    for path in revocations {
        records.push(read_json_file::<AccessGrantRevocationV1>(&path).await?);
    }
    let revocation_list = hivemind_access::access_revocation_list(records);
    println!("{}", serde_json::to_string_pretty(&revocation_list)?);
    Ok(())
}

async fn verify_revocation_list_command(revocations: PathBuf) -> Result<()> {
    let revocation_list: AccessRevocationListV1 = read_json_file(&revocations).await?;
    let verification = hivemind_access::verify_access_revocation_list(&revocation_list);
    println!("{}", serde_json::to_string_pretty(&verification)?);
    Ok(())
}

async fn search_command(
    capability: Option<String>,
    modality: Option<String>,
    api_surface: Option<String>,
    publisher: Option<String>,
    target: Option<String>,
    engine: Option<String>,
    privacy_tier: Option<String>,
    verification_tier: Option<String>,
    max_artifact_bytes: Option<u64>,
    min_artifact_bytes: Option<u64>,
    browser_runnable: Option<bool>,
    gpu_required: Option<bool>,
    min_validator_score: Option<f64>,
    min_benchmark_score: Option<f64>,
    max_price_amount: Option<f64>,
    max_price_currency: Option<String>,
    marketplace_listings: PathBuf,
    registry_audit: PathBuf,
    page_size: usize,
    grant: Option<PathBuf>,
    revocations: Option<PathBuf>,
    requester: Option<String>,
    requested_use: Option<String>,
    runner_id: Option<String>,
) -> Result<()> {
    let access_grant = read_access_grant(grant).await?;
    let access_revocation_list = read_access_revocation_list(revocations).await?;
    let modality = modality
        .as_deref()
        .map(parse_modality)
        .transpose()
        .context("invalid registry modality filter")?;
    let api_surface = api_surface
        .as_deref()
        .map(parse_api_surface)
        .transpose()
        .context("invalid registry API surface filter")?;
    let privacy_tier = privacy_tier
        .as_deref()
        .map(parse_privacy_tier)
        .transpose()
        .context("invalid registry privacy tier filter")?;
    let verification_tier = verification_tier
        .as_deref()
        .map(parse_integrity_tier)
        .transpose()
        .context("invalid registry verification tier filter")?;
    let max_price = registry_cli_max_price(max_price_amount, max_price_currency)?;
    let packages = load_packages_with_all_metadata_feeds_and_marketplace(
        &PathBuf::from("examples/packages"),
        Some(&PathBuf::from(".swarm-ai-cache/publications")),
        Some(&PathBuf::from(".swarm-ai-cache/feeds")),
        Some(&PathBuf::from(".swarm-ai-cache/validations")),
        Some(&PathBuf::from(".swarm-ai-cache/evaluations")),
        Some(&marketplace_listings),
    )?;
    let query = RegistryQueryV1 {
        schema_version: "swarm-ai.registry.query.v1".to_string(),
        kind: None,
        capability,
        modality,
        api_surface,
        publisher,
        target,
        engine,
        license_type: None,
        privacy_tier,
        verification_tier,
        max_artifact_bytes,
        min_artifact_bytes,
        browser_runnable,
        gpu_required,
        min_validator_score,
        min_benchmark_score,
        max_price,
        page_size,
        cursor: None,
        requester,
        requested_use,
        runner_id,
        access_grant,
        access_revocation_list,
    };
    let requested_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let started = Instant::now();
    let response = search_registry(&packages, &query);
    let elapsed_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    let completed_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let audit_record = hivemind_registry::registry_search_audit_record(
        &query,
        &response,
        hivemind_registry::RegistrySearchRetrievalModeV1::LocalCache,
        packages.len(),
        elapsed_ms,
        requested_at,
        completed_at,
    );
    hivemind_registry::write_registry_search_audit_record(&registry_audit, &audit_record)
        .with_context(|| {
            format!(
                "failed to write registry search audit record into {}",
                registry_audit.display()
            )
        })?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn registry_cli_max_price(
    amount: Option<f64>,
    currency: Option<String>,
) -> Result<Option<PriceV1>> {
    match (amount, currency) {
        (Some(amount), Some(currency)) => {
            if !amount.is_finite() || amount < 0.0 {
                anyhow::bail!("--max-price-amount must be a finite non-negative number");
            }
            let currency = currency.trim();
            if currency.is_empty() {
                anyhow::bail!("--max-price-currency must not be empty");
            }
            Ok(Some(PriceV1 {
                amount,
                currency: currency.to_string(),
            }))
        }
        (Some(_), None) => {
            anyhow::bail!("--max-price-currency is required when --max-price-amount is supplied")
        }
        (None, Some(_)) => {
            anyhow::bail!("--max-price-amount is required when --max-price-currency is supplied")
        }
        (None, None) => Ok(None),
    }
}

async fn publish_dry_run_command(path: PathBuf) -> Result<()> {
    let dry_run = hivemind_publisher::dry_run_package(&path)
        .with_context(|| format!("failed to dry-run publish {}", path.display()))?;
    let package = load_package_from_dir(&path)
        .with_context(|| format!("failed to load package at {}", path.display()))?;
    let package_signature = hivemind_publisher::package_signature(&package);
    let publication = hivemind_publisher::create_signed_publication_record(&package);
    let verification = hivemind_publisher::verify_publication_record(&publication);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "dryRun": dry_run,
            "packageSignature": package_signature,
            "publicationRecord": publication,
            "verification": verification
        }))?
    );
    Ok(())
}

async fn sign_command(path: PathBuf) -> Result<()> {
    let package = load_package_from_dir(&path)
        .with_context(|| format!("failed to load package at {}", path.display()))?;
    let package_signature = hivemind_publisher::package_signature(&package);
    let publication = hivemind_publisher::create_signed_publication_record(&package);
    let verification = hivemind_publisher::verify_publication_record(&publication);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "packageSignature": package_signature,
            "publicationRecord": publication,
            "verification": verification
        }))?
    );
    Ok(())
}

async fn identity_command(command: IdentityCommands) -> Result<()> {
    match command {
        IdentityCommands::Generate { subject, output } => {
            let identity = hivemind_identity::generate_identity(subject)?;
            let public_identity = hivemind_identity::public_identity(&identity);
            if let Some(path) = output {
                write_json_file(&path, &identity).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "identityPath": path.display().to_string(),
                        "publicIdentity": public_identity
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "identity": identity,
                        "publicIdentity": public_identity
                    }))?
                );
            }
        }
        IdentityCommands::Public { identity } => {
            let identity: hivemind_identity::IdentityKeypairV1 = read_json_file(&identity).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&hivemind_identity::public_identity(&identity))?
            );
        }
        IdentityCommands::SignPublication {
            record,
            identity,
            output,
        } => {
            let mut publication: hivemind_publisher::PublicationRecordV1 =
                read_json_file(&record).await?;
            let identity: hivemind_identity::IdentityKeypairV1 = read_json_file(&identity).await?;
            let signature = hivemind_publisher::sign_publication_record_with_identity(
                &mut publication,
                &identity,
            )?;
            let verification = hivemind_publisher::verify_publication_record(&publication);
            if let Some(path) = output {
                write_json_file(&path, &publication).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "recordPath": path.display().to_string(),
                        "signature": signature,
                        "publicationRecord": publication,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "publicationRecord": publication,
                        "verification": verification
                    }))?
                );
            }
        }
    }
    Ok(())
}

async fn verify_publication_command(record: PathBuf) -> Result<()> {
    let publication: hivemind_publisher::PublicationRecordV1 = read_json_file(&record).await?;
    let verification = hivemind_publisher::verify_publication_record(&publication);
    println!("{}", serde_json::to_string_pretty(&verification)?);
    Ok(())
}

async fn publication_records_command(record_dir: PathBuf) -> Result<()> {
    let summary = hivemind_publisher::list_publication_records(&record_dir)
        .with_context(|| format!("failed to list {}", record_dir.display()))?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn get_publication_command(publication_id: String, record_dir: PathBuf) -> Result<()> {
    let lookup = hivemind_publisher::get_publication_record(&record_dir, &publication_id)
        .with_context(|| format!("failed to read {}", record_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("publication record {publication_id} was not found"))?;
    println!("{}", serde_json::to_string_pretty(&lookup)?);
    Ok(())
}

async fn update_feed_command(record: PathBuf, feed_dir: PathBuf) -> Result<()> {
    let publication: hivemind_publisher::PublicationRecordV1 = read_json_file(&record).await?;
    let verification = hivemind_publisher::verify_publication_record(&publication);
    if !verification.valid {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "verification": verification,
                "feedUpdates": []
            }))?
        );
        anyhow::bail!("publication record failed verification");
    }
    let feed_updates = hivemind_publisher::write_feed_updates(&feed_dir, &publication)
        .with_context(|| format!("failed to update feeds in {}", feed_dir.display()))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "verification": verification,
            "feedUpdates": feed_updates
        }))?
    );
    Ok(())
}

async fn resolve_feed_command(
    package_id: String,
    channel: String,
    feed_dir: PathBuf,
) -> Result<()> {
    let resolution = hivemind_publisher::resolve_feed(&feed_dir, &package_id, &channel)
        .with_context(|| {
            format!(
                "failed to resolve feed {package_id}/{channel} in {}",
                feed_dir.display()
            )
        })?;
    println!("{}", serde_json::to_string_pretty(&resolution)?);
    Ok(())
}

async fn feed_pointers_command(feed_dir: PathBuf) -> Result<()> {
    let summary = hivemind_publisher::list_feed_pointers(&feed_dir)
        .with_context(|| format!("failed to list {}", feed_dir.display()))?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn get_feed_command(package_id: String, channel: String, feed_dir: PathBuf) -> Result<()> {
    let lookup = hivemind_publisher::get_feed_pointer(&feed_dir, &package_id, &channel)
        .with_context(|| format!("failed to read {}", feed_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("feed pointer {package_id}/{channel} was not found"))?;
    println!("{}", serde_json::to_string_pretty(&lookup)?);
    Ok(())
}

async fn publish_command(
    path: PathBuf,
    provider: String,
    storage_dir: PathBuf,
    bee_url: String,
    postage_batch_id: Option<String>,
    record_dir: PathBuf,
    feed_dir: PathBuf,
    channel: String,
) -> Result<()> {
    let mut result = match provider.as_str() {
        "local" => {
            let mut storage = LocalDirectoryStorageProvider::new(storage_dir);
            hivemind_publisher::publish_package(&path, &mut storage, Some(&record_dir), &channel)
        }
        "bee" => {
            let mut storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                api_url: bee_url,
                postage_batch_id,
                pin: false,
                deferred_upload: true,
                redundancy_level: 0,
            });
            hivemind_publisher::publish_package(&path, &mut storage, Some(&record_dir), &channel)
        }
        other => anyhow::bail!("unknown publish provider {other}; expected local or bee"),
    }
    .with_context(|| format!("failed to publish {}", path.display()))?;
    if result.validation.valid {
        result.feed_updates =
            hivemind_publisher::write_feed_updates(&feed_dir, &result.publication_record)
                .with_context(|| format!("failed to update feeds in {}", feed_dir.display()))?;
    }
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

async fn inspect_command(
    reference: String,
    path: Option<String>,
    provider: String,
    storage_dir: PathBuf,
    bee_url: String,
) -> Result<()> {
    match provider.as_str() {
        "local" => {
            let storage = LocalDirectoryStorageProvider::new(storage_dir);
            if let Some(path) = path {
                print_download_response(
                    storage
                        .download_file(&reference, &path)
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?,
                )?;
            } else {
                let inspection = storage
                    .inspect(&reference)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                println!("{}", serde_json::to_string_pretty(&inspection)?);
            }
        }
        "bee" => {
            let storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                api_url: bee_url,
                postage_batch_id: None,
                pin: false,
                deferred_upload: true,
                redundancy_level: 0,
            });
            if let Some(path) = path {
                print_download_response(
                    storage
                        .download_file(&reference, &path)
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?,
                )?;
            } else {
                print_download_response(
                    storage
                        .download_bytes(&reference)
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?,
                )?;
            }
        }
        other => anyhow::bail!("unknown inspect provider {other}; expected local or bee"),
    }
    Ok(())
}

fn print_download_response(response: hivemind_storage::DownloadResponseV1) -> Result<()> {
    let preview = String::from_utf8(response.bytes.clone()).ok().map(|text| {
        let preview: String = text.chars().take(240).collect();
        if text.chars().count() > 240 {
            format!("{preview}...")
        } else {
            preview
        }
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schemaVersion": response.schema_version,
            "ref": response.reference,
            "path": response.path,
            "contentType": response.content_type,
            "sizeBytes": response.size_bytes,
            "sha256": response.sha256,
            "metrics": response.metrics,
            "textPreview": preview
        }))?
    );
    Ok(())
}

async fn cache_command(command: CacheCommands) -> Result<()> {
    match command {
        CacheCommands::Status {
            provider,
            storage_dir,
            bee_url,
        } => {
            let status = match provider.as_str() {
                "local" => LocalDirectoryStorageProvider::new(storage_dir).get_status(),
                "bee" => BeeHttpStorageProvider::new(BeeStorageConfig {
                    api_url: bee_url,
                    postage_batch_id: None,
                    pin: false,
                    deferred_upload: true,
                    redundancy_level: 0,
                })
                .get_status(),
                other => {
                    anyhow::bail!("unknown cache status provider {other}; expected local or bee")
                }
            };
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        CacheCommands::List { storage_dir } => {
            let storage = LocalDirectoryStorageProvider::new(storage_dir);
            let summary = storage
                .cache_summary()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        CacheCommands::Pin {
            reference,
            provider,
            storage_dir,
            bee_url,
        } => {
            let result = match provider.as_str() {
                "local" => {
                    let mut storage = LocalDirectoryStorageProvider::new(storage_dir);
                    storage.pin(&reference)
                }
                "bee" => {
                    let mut storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                        api_url: bee_url,
                        postage_batch_id: None,
                        pin: false,
                        deferred_upload: true,
                        redundancy_level: 0,
                    });
                    storage.pin(&reference)
                }
                other => anyhow::bail!("unknown cache pin provider {other}; expected local or bee"),
            }
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        CacheCommands::Unpin {
            reference,
            provider,
            storage_dir,
            bee_url,
        } => {
            let result = match provider.as_str() {
                "local" => {
                    let mut storage = LocalDirectoryStorageProvider::new(storage_dir);
                    storage.unpin(&reference)
                }
                "bee" => {
                    let mut storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                        api_url: bee_url,
                        postage_batch_id: None,
                        pin: false,
                        deferred_upload: true,
                        redundancy_level: 0,
                    });
                    storage.unpin(&reference)
                }
                other => {
                    anyhow::bail!("unknown cache unpin provider {other}; expected local or bee")
                }
            }
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        CacheCommands::CreateFeed {
            topic,
            owner,
            storage_dir,
        } => {
            let mut storage = LocalDirectoryStorageProvider::new(storage_dir);
            let pointer = storage
                .create_feed(&topic, &owner)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&pointer)?);
            Ok(())
        }
        CacheCommands::UpdateFeed {
            topic,
            owner,
            reference,
            storage_dir,
        } => {
            let mut storage = LocalDirectoryStorageProvider::new(storage_dir);
            let update = storage
                .update_feed(&topic, &owner, &reference)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&update)?);
            Ok(())
        }
        CacheCommands::ResolveFeed {
            feed_ref,
            storage_dir,
        } => {
            let storage = LocalDirectoryStorageProvider::new(storage_dir);
            let resolution = storage
                .resolve_feed(&feed_ref)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&resolution)?);
            Ok(())
        }
    }
}

async fn policy_command(command: PolicyCommands) -> Result<()> {
    match command {
        PolicyCommands::Catalog => {
            println!(
                "{}",
                serde_json::to_string_pretty(&hivemind_policy::permission_catalog())?
            );
            Ok(())
        }
        PolicyCommands::Trust { command } => trust_policy_command(command).await,
        PolicyCommands::Inspect {
            path,
            package_ref,
            runner_id,
        } => {
            let package = load_package_from_dir(&path)
                .with_context(|| format!("failed to load package at {}", path.display()))?;
            let package_ref = package_ref.unwrap_or_else(|| package.package_ref.clone());
            let inspection =
                hivemind_policy::inspect_package_policy(&package.manifest, package_ref, runner_id);
            println!("{}", serde_json::to_string_pretty(&inspection)?);
            Ok(())
        }
        PolicyCommands::InspectV2 {
            path,
            package_ref,
            runner_id,
        } => {
            let package = load_package_from_dir(&path)
                .with_context(|| format!("failed to load package at {}", path.display()))?;
            let package_ref = package_ref.unwrap_or_else(|| package.package_ref.clone());
            let report = hivemind_policy::inspect_package_policy_v2(
                &package.manifest,
                package_ref,
                runner_id,
            );
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        PolicyCommands::InspectRef {
            reference,
            provider,
            storage_dir,
            bee_url,
            runner_id,
        } => {
            let package = match provider.as_str() {
                "local" => {
                    let storage = LocalDirectoryStorageProvider::new(storage_dir);
                    hivemind_package::load_package_from_storage(&reference, &storage)
                }
                "bee" => {
                    let storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                        api_url: bee_url,
                        postage_batch_id: None,
                        pin: false,
                        deferred_upload: true,
                        redundancy_level: 0,
                    });
                    hivemind_package::load_package_from_storage(&reference, &storage)
                }
                other => {
                    anyhow::bail!(
                        "unknown policy inspect-ref provider {other}; expected local or bee"
                    )
                }
            }
            .with_context(|| format!("failed to load package {reference}"))?;
            let inspection =
                hivemind_policy::inspect_package_policy(&package.manifest, reference, runner_id);
            println!("{}", serde_json::to_string_pretty(&inspection)?);
            Ok(())
        }
        PolicyCommands::InspectRefV2 {
            reference,
            provider,
            storage_dir,
            bee_url,
            runner_id,
        } => {
            let package = match provider.as_str() {
                "local" => {
                    let storage = LocalDirectoryStorageProvider::new(storage_dir);
                    hivemind_package::load_package_from_storage(&reference, &storage)
                }
                "bee" => {
                    let storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                        api_url: bee_url,
                        postage_batch_id: None,
                        pin: false,
                        deferred_upload: true,
                        redundancy_level: 0,
                    });
                    hivemind_package::load_package_from_storage(&reference, &storage)
                }
                other => {
                    anyhow::bail!(
                        "unknown policy inspect-ref-v2 provider {other}; expected local or bee"
                    )
                }
            }
            .with_context(|| format!("failed to load package {reference}"))?;
            let report =
                hivemind_policy::inspect_package_policy_v2(&package.manifest, reference, runner_id);
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
    }
}

async fn trust_policy_command(command: TrustPolicyCommands) -> Result<()> {
    let (policy, output) = match command {
        TrustPolicyCommands::LocalOnly { owner, output } => {
            (hivemind_core::TrustPolicyV1::local_only(owner), output)
        }
        TrustPolicyCommands::OpenMarketplace { owner, output } => (
            hivemind_core::TrustPolicyV1::open_marketplace(owner),
            output,
        ),
        TrustPolicyCommands::Sign { policy, output } => {
            let mut policy_value: hivemind_core::TrustPolicyV1 = read_json_file(&policy).await?;
            let signature = hivemind_core::sign_trust_policy(&mut policy_value)
                .with_context(|| format!("failed to sign trust policy {}", policy.display()))?;
            let verification = hivemind_core::verify_trust_policy(&policy_value);
            if let Some(output) = output {
                write_json_file(&output, &policy_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "trustPolicyPath": output.display().to_string(),
                        "signature": signature,
                        "trustPolicy": policy_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "trustPolicy": policy_value,
                        "verification": verification
                    }))?
                );
            }
            return Ok(());
        }
        TrustPolicyCommands::Verify { policy } => {
            let policy_value: hivemind_core::TrustPolicyV1 = read_json_file(&policy).await?;
            let verification = hivemind_core::verify_trust_policy(&policy_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            return Ok(());
        }
        TrustPolicyCommands::List { trust_dir } => {
            let summary = hivemind_policy::list_trust_policy_records(&trust_dir)
                .with_context(|| format!("failed to list {}", trust_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            return Ok(());
        }
        TrustPolicyCommands::Get {
            policy_id,
            trust_dir,
        } => {
            let Some(lookup) = hivemind_policy::get_trust_policy_record(&trust_dir, &policy_id)
                .with_context(|| {
                    format!(
                        "failed to look up trust policy {policy_id} in {}",
                        trust_dir.display()
                    )
                })?
            else {
                anyhow::bail!(
                    "trust policy {policy_id} not found in {}",
                    trust_dir.display()
                );
            };
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            return Ok(());
        }
    };
    if let Some(path) = output {
        write_json_file(&path, &policy).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "trustPolicyPath": path.display().to_string(),
                "trustPolicy": policy
            }))?
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&policy)?);
    }
    Ok(())
}

async fn receipts_command(command: ReceiptCommands) -> Result<()> {
    match command {
        ReceiptCommands::List { receipts_dir } => {
            let summary = hivemind_receipts::list_receipts(&receipts_dir)
                .with_context(|| format!("failed to list {}", receipts_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        ReceiptCommands::Audit { receipts_dir } => {
            let audit = hivemind_receipts::audit_receipts_dir(&receipts_dir)
                .with_context(|| format!("failed to audit {}", receipts_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&audit)?);
            Ok(())
        }
        ReceiptCommands::Get {
            receipt_id,
            receipts_dir,
        } => {
            let lookup = hivemind_receipts::get_receipt(&receipts_dir, &receipt_id)
                .with_context(|| format!("failed to read {}", receipts_dir.display()))?
                .ok_or_else(|| anyhow::anyhow!("receipt {receipt_id} was not found"))?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
        ReceiptCommands::ListBatches { receipts_dir } => {
            let summary =
                hivemind_receipts::list_batch_receipts(&receipts_dir).with_context(|| {
                    format!(
                        "failed to list batch receipts in {}",
                        receipts_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        ReceiptCommands::AuditBatches { receipts_dir } => {
            let audit =
                hivemind_receipts::audit_batch_receipts_dir(&receipts_dir).with_context(|| {
                    format!(
                        "failed to audit batch receipts in {}",
                        receipts_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&audit)?);
            Ok(())
        }
        ReceiptCommands::GetBatch {
            batch_receipt_id,
            receipts_dir,
        } => {
            let lookup = hivemind_receipts::get_batch_receipt(&receipts_dir, &batch_receipt_id)
                .with_context(|| {
                    format!(
                        "failed to read batch receipts in {}",
                        receipts_dir.display()
                    )
                })?
                .ok_or_else(|| anyhow::anyhow!("batch receipt {batch_receipt_id} was not found"))?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
        ReceiptCommands::Verify { receipt } => {
            let receipt_value = hivemind_receipts::read_receipt(&receipt)
                .with_context(|| format!("failed to read {}", receipt.display()))?;
            let verification = hivemind_receipts::verify_receipt(&receipt_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        ReceiptCommands::VerifyV2 { receipt_v2, source } => {
            let receipt_value: hivemind_core::ExecutionReceiptV2 = read_json_file(&receipt_v2)
                .await
                .with_context(|| format!("failed to read {}", receipt_v2.display()))?;
            let source_receipt = if let Some(source) = source {
                Some(
                    hivemind_receipts::read_receipt(&source)
                        .with_context(|| format!("failed to read {}", source.display()))?,
                )
            } else {
                None
            };
            let verification = hivemind_receipts::verify_execution_receipt_v2(
                &receipt_value,
                source_receipt.as_ref(),
            );
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        ReceiptCommands::VerifyBatch { batch_receipt } => {
            let receipt_value: hivemind_receipts::BatchReceiptV1 =
                read_json_file(&batch_receipt).await.with_context(|| {
                    format!("failed to read batch receipt {}", batch_receipt.display())
                })?;
            let verification = hivemind_receipts::verify_batch_receipt(&receipt_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        ReceiptCommands::VerifyPartial { partial_receipt } => {
            let receipt_value: hivemind_receipts::PartialReceiptV1 =
                read_json_file(&partial_receipt).await.with_context(|| {
                    format!(
                        "failed to read partial receipt {}",
                        partial_receipt.display()
                    )
                })?;
            let verification = hivemind_receipts::verify_partial_receipt(&receipt_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        ReceiptCommands::VerifyRedaction { redacted_receipt } => {
            let redacted: hivemind_receipts::RedactedReceiptV1 =
                read_json_file(&redacted_receipt).await.with_context(|| {
                    format!(
                        "failed to read redacted receipt {}",
                        redacted_receipt.display()
                    )
                })?;
            let verification = hivemind_receipts::verify_redacted_receipt(&redacted);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        ReceiptCommands::Inspect { receipt } => {
            let receipt_value = hivemind_receipts::read_receipt(&receipt)
                .with_context(|| format!("failed to read {}", receipt.display()))?;
            let verification = hivemind_receipts::verify_receipt(&receipt_value);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "receipt": receipt_value,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        ReceiptCommands::Redact {
            receipt,
            profile,
            output,
        } => {
            let receipt_value = hivemind_receipts::read_receipt(&receipt)
                .with_context(|| format!("failed to read receipt {}", receipt.display()))?;
            let policy = hivemind_receipts::receipt_redaction_policy(
                parse_receipt_redaction_profile(&profile)?,
            );
            let redacted = hivemind_receipts::redact_receipt(&receipt_value, policy);
            let verification = hivemind_receipts::verify_redacted_receipt(&redacted);
            if let Some(output) = output {
                write_json_file(&output, &redacted).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "redactedReceiptPath": output.display().to_string(),
                        "redactedReceipt": redacted,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "redactedReceipt": redacted,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        ReceiptCommands::Sign {
            receipt,
            identity,
            output,
        } => {
            let mut receipt_value = hivemind_receipts::read_receipt(&receipt)
                .with_context(|| format!("failed to read {}", receipt.display()))?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature =
                hivemind_receipts::sign_receipt_with_identity(&mut receipt_value, &identity_value)
                    .with_context(|| {
                        format!("failed to sign receipt with {}", identity.display())
                    })?;
            let verification = hivemind_receipts::verify_receipt(&receipt_value);
            if let Some(output) = output {
                write_json_file(&output, &receipt_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "receiptPath": output.display().to_string(),
                        "signature": signature,
                        "receipt": receipt_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "receipt": receipt_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        ReceiptCommands::Capture {
            response,
            receipts_dir,
        } => {
            let response_value = read_json_file::<hivemind_core::ExecutionResponseV1>(&response)
                .await
                .with_context(|| format!("failed to read response {}", response.display()))?;
            let capture =
                hivemind_receipts::capture_response_receipt(&receipts_dir, &response_value)
                    .with_context(|| {
                        format!(
                            "failed to capture receipt from response into {}",
                            receipts_dir.display()
                        )
                    })?;
            println!("{}", serde_json::to_string_pretty(&capture)?);
            Ok(())
        }
        ReceiptCommands::Upload {
            receipt,
            provider,
            storage_dir,
            bee_url,
            postage_batch_id,
        } => {
            let receipt_value = hivemind_receipts::read_receipt(&receipt)
                .with_context(|| format!("failed to read receipt {}", receipt.display()))?;
            let upload = match provider.as_str() {
                "local" => {
                    let mut storage = LocalDirectoryStorageProvider::new(storage_dir);
                    hivemind_receipts::upload_receipt(&mut storage, &receipt_value)
                }
                "bee" => {
                    let mut storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                        api_url: bee_url,
                        postage_batch_id,
                        pin: false,
                        deferred_upload: true,
                        redundancy_level: 0,
                    });
                    hivemind_receipts::upload_receipt(&mut storage, &receipt_value)
                }
                other => {
                    anyhow::bail!("unknown receipt upload provider {other}; expected local or bee")
                }
            }
            .with_context(|| format!("failed to upload receipt {}", receipt.display()))?;
            println!("{}", serde_json::to_string_pretty(&upload)?);
            Ok(())
        }
        ReceiptCommands::Download {
            reference,
            provider,
            storage_dir,
            bee_url,
            output,
            receipts_dir,
        } => {
            let download = match provider.as_str() {
                "local" => {
                    let storage = LocalDirectoryStorageProvider::new(storage_dir);
                    hivemind_receipts::download_receipt(&storage, &reference)
                }
                "bee" => {
                    let storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                        api_url: bee_url,
                        postage_batch_id: None,
                        pin: false,
                        deferred_upload: true,
                        redundancy_level: 0,
                    });
                    hivemind_receipts::download_receipt(&storage, &reference)
                }
                other => anyhow::bail!(
                    "unknown receipt download provider {other}; expected local or bee"
                ),
            }
            .with_context(|| format!("failed to download receipt {reference}"))?;
            let receipt_path = if let Some(output) = output {
                if let Some(parent) = output.parent()
                    && !parent.as_os_str().is_empty()
                {
                    tokio::fs::create_dir_all(parent).await.with_context(|| {
                        format!("failed to create output directory {}", parent.display())
                    })?;
                }
                tokio::fs::write(&output, serde_json::to_vec_pretty(&download.receipt)?)
                    .await
                    .with_context(|| format!("failed to write receipt {}", output.display()))?;
                output
            } else {
                hivemind_receipts::write_receipt(&receipts_dir, &download.receipt).with_context(
                    || format!("failed to write receipt into {}", receipts_dir.display()),
                )?
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "receiptPath": receipt_path,
                    "download": download
                }))?
            );
            Ok(())
        }
        ReceiptCommands::Dispute {
            receipt,
            claimant,
            claim_kind,
            summary,
            evidence_refs,
            identity,
            disputes_dir,
        } => {
            let receipt_value = hivemind_receipts::read_receipt(&receipt)
                .with_context(|| format!("failed to read receipt {}", receipt.display()))?;
            let mut evidence = hivemind_receipts::create_dispute_evidence(
                receipt_value,
                claimant,
                parse_dispute_claim_kind(&claim_kind)?,
                summary,
                evidence_refs,
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_receipts::sign_dispute_evidence_with_identity(
                        &mut evidence,
                        &identity_value,
                    )
                    .with_context(|| {
                        format!("failed to sign dispute with {}", identity_path.display())
                    })?,
                )
            } else {
                None
            };
            let verification = hivemind_receipts::verify_dispute_evidence(&evidence);
            let dispute_path = hivemind_receipts::write_dispute_evidence(&disputes_dir, &evidence)
                .with_context(|| {
                    format!(
                        "failed to write dispute evidence into {}",
                        disputes_dir.display()
                    )
                })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "disputePath": dispute_path,
                    "signature": signature,
                    "evidence": evidence,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        ReceiptCommands::ListDisputes { disputes_dir } => {
            let summary = hivemind_receipts::list_dispute_evidence(&disputes_dir)
                .with_context(|| format!("failed to list {}", disputes_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        ReceiptCommands::GetDispute {
            dispute_id,
            disputes_dir,
        } => {
            let lookup = hivemind_receipts::get_dispute_evidence(&disputes_dir, &dispute_id)
                .with_context(|| format!("failed to read {}", disputes_dir.display()))?
                .ok_or_else(|| anyhow::anyhow!("dispute {dispute_id} was not found"))?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
        ReceiptCommands::VerifyDispute { dispute } => {
            let evidence = hivemind_receipts::read_dispute_evidence(&dispute)
                .with_context(|| format!("failed to read dispute {}", dispute.display()))?;
            let verification = hivemind_receipts::verify_dispute_evidence(&evidence);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        ReceiptCommands::InspectDispute { dispute } => {
            let evidence = hivemind_receipts::read_dispute_evidence(&dispute)
                .with_context(|| format!("failed to read dispute {}", dispute.display()))?;
            let verification = hivemind_receipts::verify_dispute_evidence(&evidence);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "evidence": evidence,
                    "verification": verification
                }))?
            );
            Ok(())
        }
    }
}

fn parse_dispute_claim_kind(value: &str) -> Result<hivemind_receipts::DisputeClaimKind> {
    match value {
        "output-mismatch" => Ok(hivemind_receipts::DisputeClaimKind::OutputMismatch),
        "incorrect-billing" => Ok(hivemind_receipts::DisputeClaimKind::IncorrectBilling),
        "access-violation" => Ok(hivemind_receipts::DisputeClaimKind::AccessViolation),
        "policy-violation" => Ok(hivemind_receipts::DisputeClaimKind::PolicyViolation),
        "runner-failure" => Ok(hivemind_receipts::DisputeClaimKind::RunnerFailure),
        "other" => Ok(hivemind_receipts::DisputeClaimKind::Other),
        other => {
            anyhow::bail!(
                "unknown dispute claim kind {other}; expected output-mismatch, incorrect-billing, access-violation, policy-violation, runner-failure, or other"
            )
        }
    }
}

fn parse_receipt_redaction_profile(
    value: &str,
) -> Result<hivemind_receipts::ReceiptRedactionProfileV1> {
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
        other => {
            anyhow::bail!(
                "unknown receipt redaction profile {other}; expected public-audit, settlement-audit, or internal-audit"
            )
        }
    }
}

async fn jobs_command(command: JobCommands) -> Result<()> {
    match command {
        JobCommands::List { jobs_dir } => {
            let summary = hivemind_jobs::list_job_records(&jobs_dir)
                .with_context(|| format!("failed to list {}", jobs_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        JobCommands::Get { job_id, jobs_dir } => {
            let lookup = hivemind_jobs::get_job_record(&jobs_dir, &job_id)
                .with_context(|| format!("failed to read {}", jobs_dir.display()))?
                .ok_or_else(|| anyhow::anyhow!("job {job_id} was not found"))?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
        JobCommands::Timeline { job_id, jobs_dir } => {
            let lookup = hivemind_jobs::get_job_record(&jobs_dir, &job_id)
                .with_context(|| format!("failed to read {}", jobs_dir.display()))?
                .ok_or_else(|| anyhow::anyhow!("job {job_id} was not found"))?;
            let timeline = hivemind_jobs::job_lifecycle_timeline(&lookup.record);
            println!("{}", serde_json::to_string_pretty(&timeline)?);
            Ok(())
        }
        JobCommands::Lifecycle { job_id, jobs_dir } => {
            let lookup = hivemind_jobs::get_job_record(&jobs_dir, &job_id)
                .with_context(|| format!("failed to read {}", jobs_dir.display()))?
                .ok_or_else(|| anyhow::anyhow!("job {job_id} was not found"))?;
            let lifecycle = hivemind_jobs::job_production_lifecycle(&lookup.record);
            println!("{}", serde_json::to_string_pretty(&lifecycle)?);
            Ok(())
        }
        JobCommands::LifecycleAudit {
            observed_at,
            jobs_dir,
        } => {
            let mut request = hivemind_jobs::job_store_audit_request();
            request.observed_at = observed_at;
            let result = hivemind_jobs::audit_job_production_lifecycles(&jobs_dir, &request)
                .with_context(|| {
                    format!(
                        "failed to audit production lifecycles in {}",
                        jobs_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        JobCommands::LinkEvidence {
            job_id,
            evidence_kind,
            evidence_ref,
            evidence_id,
            linked_by,
            linked_at,
            summary,
            metadata,
            jobs_dir,
        } => {
            let metadata = if let Some(path) = metadata {
                read_json_file::<Value>(&path)
                    .await
                    .with_context(|| format!("failed to read metadata {}", path.display()))?
            } else {
                json!({})
            };
            let mut request = hivemind_jobs::job_evidence_link_request(
                &job_id,
                parse_job_evidence_kind(&evidence_kind)?,
                evidence_ref,
                linked_by,
            );
            request.evidence_id = evidence_id;
            request.linked_at = linked_at;
            request.summary = summary;
            request.metadata = metadata;
            let result = hivemind_jobs::link_job_evidence(
                &jobs_dir,
                &request,
                hivemind_jobs::now_timestamp(),
            )
            .with_context(|| format!("failed to update {}", jobs_dir.display()))?
            .ok_or_else(|| anyhow::anyhow!("job {job_id} was not found"))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        JobCommands::Expire {
            observed_at,
            jobs_dir,
        } => {
            let mut request = hivemind_jobs::job_expiration_sweep_request();
            request.observed_at = observed_at;
            let result = hivemind_jobs::expire_stale_job_records(&jobs_dir, &request)
                .with_context(|| format!("failed to update {}", jobs_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        JobCommands::Audit {
            observed_at,
            jobs_dir,
        } => {
            let mut request = hivemind_jobs::job_store_audit_request();
            request.observed_at = observed_at;
            let result = hivemind_jobs::audit_job_store(&jobs_dir, &request)
                .with_context(|| format!("failed to audit {}", jobs_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        JobCommands::Stream {
            job_id,
            streams_dir,
            format,
        } => {
            let events = hivemind_streams::read_stream_events(&streams_dir, &job_id)
                .with_context(|| format!("failed to read {}", streams_dir.display()))?
                .ok_or_else(|| anyhow::anyhow!("stream events for {job_id} were not found"))?;
            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&events)?),
                "sse" => print!("{}", hivemind_streams::streaming_events_sse_body(&events)),
                other => anyhow::bail!("unknown jobs stream format {other}; expected json or sse"),
            }
            Ok(())
        }
        JobCommands::PartialReceipts {
            job_id,
            streams_dir,
        } => {
            let events = hivemind_streams::read_stream_events(&streams_dir, &job_id)
                .with_context(|| format!("failed to read {}", streams_dir.display()))?
                .ok_or_else(|| anyhow::anyhow!("stream events for {job_id} were not found"))?;
            let summary = hivemind_receipts::partial_receipt_stream_summary(&job_id, &events);
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        JobCommands::Cancel {
            job_id,
            cancelled_by,
            reason,
            requested_at,
            jobs_dir,
            streams_dir,
        } => {
            let mut request =
                hivemind_jobs::job_cancellation_request(&job_id, cancelled_by, reason);
            request.requested_at = requested_at;
            let mut result = hivemind_jobs::cancel_job_record(
                &jobs_dir,
                &request,
                hivemind_jobs::now_timestamp(),
            )
            .with_context(|| format!("failed to update {}", jobs_dir.display()))?
            .ok_or_else(|| anyhow::anyhow!("job {job_id} was not found"))?;
            if result.transitioned {
                hivemind_streams::append_job_cancellation_event(&streams_dir, &mut result)
                    .with_context(|| format!("failed to write {}", streams_dir.display()))?;
                hivemind_jobs::upsert_job_record(&jobs_dir, result.record.clone())
                    .with_context(|| format!("failed to update {}", jobs_dir.display()))?;
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
    }
}

async fn observability_command(command: ObservabilityCommands) -> Result<()> {
    match command {
        ObservabilityCommands::Snapshot {
            generated_at,
            jobs_dir,
            receipts_dir,
            package_audit_dir,
            registry_audit_dir,
            validation_reports_dir,
            storage_audit_dir,
            streams_dir,
            route_audit_dir,
            marketplace_audit_dir,
            miner_dir,
            governance_dir,
            output_dir,
        } => {
            let mut request =
                hivemind_observability::OperationalMetricSnapshotRequestV1::local_stores(
                    jobs_dir,
                    receipts_dir,
                    route_audit_dir,
                    marketplace_audit_dir,
                );
            request.storage_audit_dir = Some(storage_audit_dir);
            request.stream_dir = Some(streams_dir);
            request.package_validation_audit_dir = Some(package_audit_dir);
            request.registry_search_audit_dir = Some(registry_audit_dir);
            request.validation_report_dir = Some(validation_reports_dir);
            request.miner_dir = Some(miner_dir);
            request.governance_dir = Some(governance_dir);
            request.generated_at = generated_at;
            let snapshot = hivemind_observability::operational_snapshot_from_local_stores(&request)
                .context("failed to build operational metrics snapshot")?;
            if let Some(output_dir) = output_dir {
                let path =
                    hivemind_observability::write_operational_snapshot(&output_dir, &snapshot)
                        .with_context(|| format!("failed to write {}", output_dir.display()))?;
                let verification = hivemind_observability::verify_operational_snapshot(&snapshot);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "schemaVersion": "hivemind.operational_metric_snapshot_write.v1",
                        "snapshotPath": path,
                        "snapshot": snapshot,
                        "verification": verification
                    }))?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&snapshot)?);
            }
            Ok(())
        }
        ObservabilityCommands::List { snapshots_dir } => {
            let summary = hivemind_observability::list_operational_snapshots(&snapshots_dir)
                .with_context(|| format!("failed to list {}", snapshots_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        ObservabilityCommands::Get {
            snapshot_id,
            snapshots_dir,
        } => {
            let lookup =
                hivemind_observability::get_operational_snapshot(&snapshots_dir, &snapshot_id)
                    .with_context(|| format!("failed to read {}", snapshots_dir.display()))?
                    .ok_or_else(|| {
                        anyhow::anyhow!("operational snapshot {snapshot_id} was not found")
                    })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
        ObservabilityCommands::Verify { snapshot } => {
            let snapshot_value = hivemind_observability::read_operational_snapshot(&snapshot)
                .with_context(|| format!("failed to read {}", snapshot.display()))?;
            let verification = hivemind_observability::verify_operational_snapshot(&snapshot_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
    }
}

fn parse_job_evidence_kind(value: &str) -> Result<hivemind_jobs::JobEvidenceKindV1> {
    match value {
        "validation-report" => Ok(hivemind_jobs::JobEvidenceKindV1::ValidationReport),
        "dispute-evidence" => Ok(hivemind_jobs::JobEvidenceKindV1::DisputeEvidence),
        "settlement-event" => Ok(hivemind_jobs::JobEvidenceKindV1::SettlementEvent),
        "settlement-resolution" => Ok(hivemind_jobs::JobEvidenceKindV1::SettlementResolution),
        "receipt" => Ok(hivemind_jobs::JobEvidenceKindV1::Receipt),
        "stream-events" => Ok(hivemind_jobs::JobEvidenceKindV1::StreamEvents),
        "other" => Ok(hivemind_jobs::JobEvidenceKindV1::Other),
        other => {
            anyhow::bail!(
                "unknown job evidence kind {other}; expected validation-report, dispute-evidence, settlement-event, settlement-resolution, receipt, stream-events, or other"
            )
        }
    }
}

async fn install_command(
    reference: String,
    provider: String,
    storage_dir: PathBuf,
    bee_url: String,
    cache_dir: PathBuf,
    artifact_group: Option<String>,
    grant: Option<PathBuf>,
    revocations: Option<PathBuf>,
    developer_mode: bool,
) -> Result<()> {
    let access_grant = read_access_grant(grant).await?;
    let access_revocation_list = read_access_revocation_list(revocations).await?;
    let install = match provider.as_str() {
        "local" => {
            let storage = LocalDirectoryStorageProvider::new(storage_dir);
            hivemind_local_runner::install_from_storage_with_revocations_and_policy(
                &reference,
                &storage,
                &cache_dir,
                artifact_group.as_deref(),
                access_grant.as_ref(),
                access_revocation_list.as_ref(),
                developer_mode,
            )
        }
        "bee" => {
            let storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                api_url: bee_url,
                postage_batch_id: None,
                pin: false,
                deferred_upload: true,
                redundancy_level: 0,
            });
            hivemind_local_runner::install_from_storage_with_revocations_and_policy(
                &reference,
                &storage,
                &cache_dir,
                artifact_group.as_deref(),
                access_grant.as_ref(),
                access_revocation_list.as_ref(),
                developer_mode,
            )
        }
        other => anyhow::bail!("unknown install provider {other}; expected local or bee"),
    }
    .with_context(|| format!("failed to install {reference}"))?;
    println!("{}", serde_json::to_string_pretty(&install)?);
    Ok(())
}

async fn runner_cache_command(command: RunnerCacheCommands) -> Result<()> {
    match command {
        RunnerCacheCommands::List { cache_dir } => {
            let summary = hivemind_local_runner::list_cache(&cache_dir)
                .with_context(|| format!("failed to list {}", cache_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        RunnerCacheCommands::Clean {
            reference,
            cache_dir,
        } => {
            let result = hivemind_local_runner::clear_cache(&cache_dir, &reference)
                .with_context(|| format!("failed to clear {}", cache_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
    }
}

async fn browser_command(command: BrowserCommands) -> Result<()> {
    match command {
        BrowserCommands::Capabilities { webgpu, memory_mb } => {
            let capabilities = browser_capabilities(webgpu, memory_mb);
            println!("{}", serde_json::to_string_pretty(&capabilities)?);
            Ok(())
        }
        BrowserCommands::Assess {
            path,
            artifact_group,
            webgpu,
            memory_mb,
        } => {
            let package = load_package_from_dir(&path)
                .with_context(|| format!("failed to load package at {}", path.display()))?;
            let assessment = hivemind_browser_runner::assess_package(
                &package.manifest,
                &browser_capabilities(webgpu, memory_mb),
                artifact_group.as_deref(),
            );
            println!("{}", serde_json::to_string_pretty(&assessment)?);
            Ok(())
        }
        BrowserCommands::Prepare {
            path,
            package_ref,
            artifact_group,
            webgpu,
            memory_mb,
        } => {
            let package = load_package_from_dir(&path)
                .with_context(|| format!("failed to load package at {}", path.display()))?;
            let package_ref = package_ref.unwrap_or_else(|| package.package_ref.clone());
            let plan = hivemind_browser_runner::prepare_plan(
                &package.manifest,
                package_ref,
                package.manifest_hash.clone(),
                &browser_capabilities(webgpu, memory_mb),
                artifact_group.as_deref(),
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let prepared = hivemind_browser_runner::record_prepared_package(
                &package.manifest,
                package.manifest_hash,
                &plan,
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "plan": plan,
                    "prepared": prepared
                }))?
            );
            Ok(())
        }
        BrowserCommands::Run {
            path,
            task,
            text,
            input,
            artifact_group,
            webgpu,
            memory_mb,
            receipts_dir,
        } => {
            let package = load_package_from_dir(&path)
                .with_context(|| format!("failed to load package at {}", path.display()))?;
            let input_value = read_execution_input(text, input).await?;
            let request = ExecutionRequestV1 {
                schema_version: "swarm-ai.execution.request.v1".to_string(),
                request_id: Uuid::new_v4().to_string(),
                package_ref: package.package_ref.clone(),
                package_id: package.manifest.package_id.clone(),
                package_version: package.manifest.version.clone(),
                preferred_artifact_group: artifact_group,
                task,
                input: input_value,
                options: ExecutionOptions::default(),
                privacy: ExecutionPrivacy::default(),
                access_grant: None,
                access_revocation_list: None,
            };
            let response = hivemind_browser_runner::execute_manifest_with_hash(
                &package.manifest,
                package.package_ref.clone(),
                package.manifest_hash.clone(),
                request,
                &browser_capabilities(webgpu, memory_mb),
            );
            print_response_with_optional_receipt_capture(response, receipts_dir)?;
            Ok(())
        }
    }
}

async fn browser_swarm_command(command: BrowserSwarmCommands) -> Result<()> {
    match command {
        BrowserSwarmCommands::Descriptor => {
            println!(
                "{}",
                serde_json::to_string_pretty(&hivemind_weeb3_adapter::descriptor())?
            );
            Ok(())
        }
        BrowserSwarmCommands::Status { storage_dir } => {
            let mut provider = browser_swarm_provider(storage_dir);
            let status = provider.start();
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        BrowserSwarmCommands::Compatibility { storage_dir } => {
            let mut provider = browser_swarm_provider(storage_dir);
            provider.start();
            println!(
                "{}",
                serde_json::to_string_pretty(&provider.compatibility_report())?
            );
            Ok(())
        }
        BrowserSwarmCommands::Manifest {
            reference,
            storage_dir,
        } => {
            let mut provider = browser_swarm_provider(storage_dir);
            provider.start();
            let (manifest, retrieval) = provider
                .download_manifest_with_report(&reference)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!(
                    hivemind_weeb3_adapter::BrowserSwarmManifestResultV1 {
                        schema_version: "swarm-ai.browser-swarm-manifest-result.v1".to_string(),
                        manifest,
                        retrieval,
                    }
                ))?
            );
            Ok(())
        }
        BrowserSwarmCommands::File {
            reference,
            path,
            storage_dir,
        } => {
            let mut provider = browser_swarm_provider(storage_dir);
            provider.start();
            let (response, retrieval) = provider
                .download_file_with_report(&reference, &path)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&hivemind_weeb3_adapter::encode_file_result(
                    response, retrieval
                ))?
            );
            Ok(())
        }
    }
}

async fn remote_command(command: RemoteCommands) -> Result<()> {
    match command {
        RemoteCommands::Api => {
            println!(
                "{}",
                serde_json::to_string_pretty(&hivemind_remote_runner::remote_runner_api_contract())?
            );
            Ok(())
        }
        RemoteCommands::Capabilities {
            runner_id,
            queue_depth,
        } => {
            let descriptor = remote_descriptor(runner_id, queue_depth);
            let capability = hivemind_core::runner_capability_from_descriptor(&descriptor);
            println!("{}", serde_json::to_string_pretty(&capability)?);
            Ok(())
        }
        RemoteCommands::Health {
            runner_id,
            queue_depth,
        } => {
            let descriptor = remote_descriptor(runner_id, queue_depth);
            let health = hivemind_remote_runner::health(&descriptor, &[]);
            println!("{}", serde_json::to_string_pretty(&health)?);
            Ok(())
        }
        RemoteCommands::Prepare {
            path,
            package_ref,
            artifact_group,
            runner_id,
            queue_depth,
        } => {
            let package = load_package_from_dir(&path)
                .with_context(|| format!("failed to load package at {}", path.display()))?;
            let descriptor = remote_descriptor(runner_id, queue_depth);
            let package_ref = package_ref.unwrap_or_else(|| package.package_ref.clone());
            let prepared = hivemind_remote_runner::prepare_manifest(
                &package.manifest,
                package_ref,
                package.manifest_hash,
                &descriptor,
                artifact_group.as_deref(),
            )
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&prepared)?);
            Ok(())
        }
        RemoteCommands::Run {
            path,
            task,
            text,
            input,
            artifact_group,
            runner_id,
            queue_depth,
            stream,
            receipts_dir,
        } => {
            let package = load_package_from_dir(&path)
                .with_context(|| format!("failed to load package at {}", path.display()))?;
            let input_value = read_execution_input(text, input).await?;
            let descriptor = remote_descriptor(runner_id, queue_depth);
            let request = ExecutionRequestV1 {
                schema_version: "swarm-ai.execution.request.v1".to_string(),
                request_id: Uuid::new_v4().to_string(),
                package_ref: package.package_ref.clone(),
                package_id: package.manifest.package_id.clone(),
                package_version: package.manifest.version.clone(),
                preferred_artifact_group: artifact_group,
                task,
                input: input_value,
                options: ExecutionOptions {
                    stream,
                    ..ExecutionOptions::default()
                },
                privacy: ExecutionPrivacy::default(),
                access_grant: None,
                access_revocation_list: None,
            };
            let response = hivemind_remote_runner::execute_manifest_with_hash(
                &package.manifest,
                package.package_ref,
                package.manifest_hash,
                request,
                &descriptor,
            );
            print_response_with_optional_receipt_capture(response, receipts_dir)?;
            Ok(())
        }
        RemoteCommands::Cancel { request_id } => {
            let result =
                hivemind_remote_runner::cancel(hivemind_remote_runner::RemoteCancelRequestV1 {
                    schema_version: "swarm-ai.remote-cancel-request.v1".to_string(),
                    request_id,
                });
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
    }
}

async fn route_command(
    package: PathBuf,
    task: String,
    text: Option<String>,
    input: Option<PathBuf>,
    package_ref: Option<String>,
    artifact_group: Option<String>,
    policy: String,
    local_queue: u32,
    remote_queue: u32,
    validations: PathBuf,
    marketplace_offers: PathBuf,
    max_marketplace_results: usize,
    marketplace_hardware_offers: PathBuf,
    miner: PathBuf,
    trust_policy: Option<PathBuf>,
) -> Result<()> {
    let package = load_package_from_dir(&package)
        .with_context(|| format!("failed to load package at {}", package.display()))?;
    let input_value = read_execution_input(text, input).await?;
    let policy_mode = parse_policy_mode(&policy)?;
    let request_package_ref = package_ref.unwrap_or_else(|| package.package_ref.clone());
    let request = ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: Uuid::new_v4().to_string(),
        package_ref: request_package_ref.clone(),
        package_id: package.manifest.package_id.clone(),
        package_version: package.manifest.version.clone(),
        preferred_artifact_group: artifact_group,
        task,
        input: input_value,
        options: ExecutionOptions::default(),
        privacy: ExecutionPrivacy::default(),
        access_grant: None,
        access_revocation_list: None,
    };
    let runners = routing_runners(local_queue, remote_queue);
    let offers = marketplace_runner_offers_for_refs(
        vec![request_package_ref.clone()],
        &marketplace_offers,
        &request_package_ref,
    )?;
    let validation_reports = load_validation_reports(&validations).with_context(|| {
        format!(
            "failed to load validation reports from {}",
            validations.display()
        )
    })?;
    let runner_reputation = api::runner_reputation_summaries(&validation_reports);
    let miner_capacity = load_route_miner_capacity_inputs(&miner, &marketplace_hardware_offers)
        .with_context(|| {
            format!(
                "failed to load miner capacity records from {} and hardware offers from {}",
                miner.display(),
                marketplace_hardware_offers.display()
            )
        })?;
    let trust_policy = match trust_policy {
        Some(path) => Some(read_verified_trust_policy_file(&path).await?),
        None => None,
    };
    let report = hivemind_router::planner_report_with_trust_policy(
        &request,
        &package,
        &runners,
        &offers,
        &miner_capacity,
        policy_mode,
        max_marketplace_results,
        &runner_reputation,
        trust_policy.as_ref(),
    );
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn read_verified_trust_policy_file(path: &PathBuf) -> Result<hivemind_core::TrustPolicyV1> {
    let policy = read_json_file::<hivemind_core::TrustPolicyV1>(path)
        .await
        .with_context(|| format!("failed to read trust policy {}", path.display()))?;
    let verification = hivemind_core::verify_trust_policy(&policy);
    if !verification.valid {
        anyhow::bail!(
            "trust policy {} is invalid: {}",
            path.display(),
            summarize_validation_issues(&verification.issues)
        );
    }
    Ok(policy)
}

fn summarize_validation_issues(issues: &[hivemind_core::ValidationIssue]) -> String {
    if issues.is_empty() {
        return "no issue details were reported".to_string();
    }
    issues
        .iter()
        .map(|issue| format!("{}: {}", issue.path, issue.message))
        .collect::<Vec<_>>()
        .join("; ")
}

fn load_route_miner_capacity_inputs(
    miner_dir: &PathBuf,
    hardware_offer_dir: &PathBuf,
) -> Result<Vec<hivemind_router::MinerCapacityInputV1>> {
    let mut benchmarks_by_miner: BTreeMap<String, Vec<hivemind_miner::MinerBenchmarkResultV1>> =
        BTreeMap::new();
    let mut profile_offers: BTreeMap<String, hivemind_marketplace::HardwareResourceOfferV1> =
        BTreeMap::new();
    let mut latest_by_runner: BTreeMap<String, (String, hivemind_router::MinerCapacityInputV1)> =
        BTreeMap::new();

    if miner_dir.exists() {
        let summary = hivemind_miner::list_miner_records(miner_dir)?;

        for record in &summary.records {
            let Some(lookup) = hivemind_miner::get_miner_record(miner_dir, &record.record_id)?
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
            let Some(lookup) = hivemind_miner::get_miner_record(miner_dir, &record.record_id)?
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
            let input = hivemind_router::MinerCapacityInputV1 {
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
                hivemind_router::MinerCapacityInputV1 {
                    schema_version: "swarm-ai.miner-capacity-input.v1".to_string(),
                    hardware_offer,
                    heartbeat: None,
                    benchmarks: Vec::new(),
                },
            ),
        );
    }

    if hardware_offer_dir.exists() {
        for hardware_offer in load_hardware_resource_offers(hardware_offer_dir)? {
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

    Ok(latest_by_runner
        .into_values()
        .map(|(_, input)| input)
        .collect())
}

fn miner_capacity_input_from_hardware_offer(
    hardware_offer: hivemind_marketplace::HardwareResourceOfferV1,
) -> hivemind_router::MinerCapacityInputV1 {
    hivemind_router::MinerCapacityInputV1 {
        schema_version: "swarm-ai.miner-capacity-input.v1".to_string(),
        hardware_offer,
        heartbeat: None,
        benchmarks: Vec::new(),
    }
}

async fn registry_command(command: RegistryCommands) -> Result<()> {
    match command {
        RegistryCommands::Get {
            package_id,
            packages,
            records,
            feeds,
            validations,
            evaluations,
            marketplace_listings,
            marketplace_offers,
            marketplace_hardware_offers,
            governance_dir,
            grant,
            revocations,
            requester,
            requested_use,
            runner_id,
            include_private,
        } => {
            let access_grant = read_access_grant(grant).await?;
            let access_revocation_list = read_access_revocation_list(revocations).await?;
            let indexed = load_packages_with_all_metadata_feeds_and_marketplace(
                &packages,
                Some(&records),
                Some(&feeds),
                Some(&validations),
                Some(&evaluations),
                Some(&marketplace_listings),
            )
            .with_context(|| {
                format!(
                    "failed to load registry packages from {}, {}, {}, {}, {}, and {}",
                    packages.display(),
                    records.display(),
                    feeds.display(),
                    validations.display(),
                    evaluations.display(),
                    marketplace_listings.display()
                )
            })?;
            let raw_snapshot =
                rebuild_registry_snapshot_with_all_sources_marketplace_offers_and_governance(
                    &packages,
                    Some(&records),
                    Some(&feeds),
                    Some(&validations),
                    Some(&evaluations),
                    Some(&marketplace_listings),
                    Some(&marketplace_offers),
                    Some(&marketplace_hardware_offers),
                    Some(&governance_dir),
                )
                .with_context(|| {
                    format!(
                        "failed to rebuild registry from {}, {}, {}, {}, {}, {}, {}, {}, and {}",
                        packages.display(),
                        records.display(),
                        feeds.display(),
                        validations.display(),
                        evaluations.display(),
                        marketplace_listings.display(),
                        marketplace_offers.display(),
                        marketplace_hardware_offers.display(),
                        governance_dir.display()
                    )
                })?;
            let lookup = if include_private {
                registry_package_lookup(&indexed, &raw_snapshot, "", &package_id)
            } else {
                let request = hivemind_registry::RegistryPackageLookupRequestV1 {
                    schema_version: "swarm-ai.registry.package-lookup.request.v1".to_string(),
                    package_id: Some(package_id.clone()),
                    package_ref: None,
                    requester,
                    requested_use,
                    runner_id,
                    access_grant,
                    access_revocation_list,
                };
                registry_package_lookup_for_request(&indexed, &raw_snapshot, &request)
            };
            let lookup = lookup.with_context(|| {
                format!("package {package_id} is not in the local registry or is not authorized")
            })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
        RegistryCommands::Rebuild {
            packages,
            records,
            feeds,
            validations,
            evaluations,
            marketplace_listings,
            marketplace_offers,
            marketplace_hardware_offers,
            governance_dir,
            output,
            include_private,
        } => {
            let raw_snapshot =
                rebuild_registry_snapshot_with_all_sources_marketplace_offers_and_governance(
                    &packages,
                    Some(&records),
                    Some(&feeds),
                    Some(&validations),
                    Some(&evaluations),
                    Some(&marketplace_listings),
                    Some(&marketplace_offers),
                    Some(&marketplace_hardware_offers),
                    Some(&governance_dir),
                )
                .with_context(|| {
                    format!(
                        "failed to rebuild registry from {}, {}, {}, {}, {}, {}, {}, {}, and {}",
                        packages.display(),
                        records.display(),
                        feeds.display(),
                        validations.display(),
                        evaluations.display(),
                        marketplace_listings.display(),
                        marketplace_offers.display(),
                        marketplace_hardware_offers.display(),
                        governance_dir.display()
                    )
                })?;
            let snapshot = if include_private {
                raw_snapshot.clone()
            } else {
                hivemind_registry::public_registry_snapshot(&raw_snapshot)
            };
            let private_entries_hidden = raw_snapshot
                .entries
                .len()
                .saturating_sub(snapshot.entries.len());
            hivemind_registry::write_registry_snapshot(&snapshot, &output)
                .with_context(|| format!("failed to write {}", output.display()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": "swarm-ai.registry.rebuild-result.v1",
                    "output": output,
                    "public": !include_private,
                    "privateEntriesHidden": private_entries_hidden,
                    "entries": snapshot.entries.len(),
                    "publicationRecords": snapshot.publication_records.len(),
                    "publicationStatuses": snapshot.publication_statuses.len(),
                    "feedStatuses": snapshot.feed_statuses.len(),
                    "validationReports": snapshot.validation_reports.len(),
                    "evaluationResults": snapshot.evaluation_results.len(),
                    "marketplaceListings": snapshot.marketplace_listings.len(),
                    "runnerOffers": snapshot.runner_offers.len(),
                    "hardwareResourceOffers": snapshot.hardware_resource_offers.len(),
                    "schemaReleases": snapshot.schema_releases.len(),
                    "componentReadiness": snapshot.component_readiness.len(),
                    "sourceRecords": snapshot.source_records.len(),
                    "snapshotId": snapshot.snapshot_id,
                    "snapshotHash": hivemind_registry::registry_snapshot_hash(&snapshot),
                    "signature": snapshot.signature
                }))?
            );
            Ok(())
        }
        RegistryCommands::VerifySnapshot {
            input,
            include_private,
        } => {
            let raw_snapshot: hivemind_registry::RegistrySnapshotV1 =
                read_json_file(&input).await?;
            let snapshot = if include_private {
                raw_snapshot.clone()
            } else {
                hivemind_registry::public_registry_snapshot(&raw_snapshot)
            };
            let private_entries_hidden = raw_snapshot
                .entries
                .len()
                .saturating_sub(snapshot.entries.len());
            let verification = hivemind_registry::verify_registry_snapshot(&snapshot);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": "swarm-ai.registry.snapshot-verification-command-result.v1",
                    "public": !include_private,
                    "privateEntriesHidden": private_entries_hidden,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        RegistryCommands::Shards {
            input,
            output,
            include_private,
        } => {
            let raw_snapshot: hivemind_registry::RegistrySnapshotV1 =
                read_json_file(&input).await?;
            let snapshot = if include_private {
                raw_snapshot.clone()
            } else {
                hivemind_registry::public_registry_snapshot(&raw_snapshot)
            };
            let private_entries_hidden = raw_snapshot
                .entries
                .len()
                .saturating_sub(snapshot.entries.len());
            let result = hivemind_registry::write_registry_shards(&snapshot, &output)
                .with_context(|| {
                    format!("failed to write registry shards to {}", output.display())
                })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": "swarm-ai.registry.shard-command-result.v1",
                    "public": !include_private,
                    "privateEntriesHidden": private_entries_hidden,
                    "write": result
                }))?
            );
            Ok(())
        }
        RegistryCommands::VerifyShards {
            input,
            shards,
            include_private,
        } => {
            let raw_snapshot: hivemind_registry::RegistrySnapshotV1 =
                read_json_file(&input).await?;
            let snapshot = if include_private {
                raw_snapshot.clone()
            } else {
                hivemind_registry::public_registry_snapshot(&raw_snapshot)
            };
            let private_entries_hidden = raw_snapshot
                .entries
                .len()
                .saturating_sub(snapshot.entries.len());
            let verification = hivemind_registry::verify_registry_shards(&snapshot, &shards)
                .with_context(|| {
                    format!(
                        "failed to verify registry shards in {} against {}",
                        shards.display(),
                        input.display()
                    )
                })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": "swarm-ai.registry.shard-verification-command-result.v1",
                    "public": !include_private,
                    "privateEntriesHidden": private_entries_hidden,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        RegistryCommands::VerifyManifest {
            input,
            shards,
            include_private,
        } => {
            let raw_snapshot: hivemind_registry::RegistrySnapshotV1 =
                read_json_file(&input).await?;
            let snapshot = if include_private {
                raw_snapshot.clone()
            } else {
                hivemind_registry::public_registry_snapshot(&raw_snapshot)
            };
            let private_entries_hidden = raw_snapshot
                .entries
                .len()
                .saturating_sub(snapshot.entries.len());
            let verification =
                hivemind_registry::verify_registry_shard_manifest_dir(&snapshot, &shards)
                    .with_context(|| {
                        format!(
                            "failed to verify registry shard manifest in {} against {}",
                            shards.display(),
                            input.display()
                        )
                    })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": "swarm-ai.registry.shard-manifest-verification-command-result.v1",
                    "public": !include_private,
                    "privateEntriesHidden": private_entries_hidden,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        RegistryCommands::CompareManifest {
            input,
            manifest,
            include_private,
        } => {
            let raw_snapshot: hivemind_registry::RegistrySnapshotV1 =
                read_json_file(&input).await?;
            let snapshot = if include_private {
                raw_snapshot.clone()
            } else {
                hivemind_registry::public_registry_snapshot(&raw_snapshot)
            };
            let private_entries_hidden = raw_snapshot
                .entries
                .len()
                .saturating_sub(snapshot.entries.len());
            let comparison =
                hivemind_registry::compare_registry_shard_manifest_file(&snapshot, &manifest)
                    .with_context(|| {
                        format!(
                            "failed to compare registry shard manifest {} against {}",
                            manifest.display(),
                            input.display()
                        )
                    })?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schemaVersion": "swarm-ai.registry.shard-manifest-comparison-command-result.v1",
                    "public": !include_private,
                    "privateEntriesHidden": private_entries_hidden,
                    "comparison": comparison
                }))?
            );
            Ok(())
        }
    }
}

async fn marketplace_command(command: MarketplaceCommands) -> Result<()> {
    match command {
        MarketplaceCommands::Listings {
            packages,
            records,
            validations,
            evaluations,
            owner,
            include_private,
            identity,
            output_dir,
        } => {
            let packages = load_packages_with_all_metadata(
                &packages,
                Some(&records),
                Some(&validations),
                Some(&evaluations),
            )?;
            let packages = filter_private_packages(packages, include_private);
            let listings: Vec<_> = packages
                .iter()
                .filter_map(|package| {
                    hivemind_marketplace::listing_from_registry_entry(&package.entry, owner.clone())
                })
                .collect();
            let listings = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                listings
                    .into_iter()
                    .map(|mut listing| {
                        hivemind_marketplace::sign_marketplace_listing_with_identity(
                            &mut listing,
                            &identity_value,
                        )
                        .with_context(|| {
                            format!(
                                "failed to sign marketplace listing with {}",
                                identity_path.display()
                            )
                        })?;
                        Ok(listing)
                    })
                    .collect::<Result<Vec<_>>>()?
            } else {
                listings
            };
            if let Some(output_dir) = output_dir {
                std::fs::create_dir_all(&output_dir)
                    .with_context(|| format!("failed to create {}", output_dir.display()))?;
                let mut paths = Vec::new();
                for listing in &listings {
                    let path = output_dir
                        .join(format!("{}.json", safe_file_component(&listing.listing_id)));
                    write_json_file(&path, listing).await?;
                    paths.push(path.display().to_string());
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "schemaVersion": "hivemind.marketplace_listing_store_write.v1",
                        "listingCount": listings.len(),
                        "listingPaths": paths,
                        "listings": listings
                    }))?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&listings)?);
            }
            Ok(())
        }
        MarketplaceCommands::VerifyListing { listing } => {
            let listing =
                read_json_file::<hivemind_marketplace::MarketplaceListingV1>(&listing).await?;
            let verification = hivemind_marketplace::verify_marketplace_listing(&listing);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        MarketplaceCommands::SignListing {
            listing,
            identity,
            output,
        } => {
            let mut listing_value =
                read_json_file::<hivemind_marketplace::MarketplaceListingV1>(&listing).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_marketplace::sign_marketplace_listing_with_identity(
                &mut listing_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign marketplace listing with {}",
                    identity.display()
                )
            })?;
            let verification = hivemind_marketplace::verify_marketplace_listing(&listing_value);
            if let Some(output) = output {
                write_json_file(&output, &listing_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "listingPath": output.display().to_string(),
                        "signature": signature,
                        "listing": listing_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "listing": listing_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        MarketplaceCommands::Offers {
            packages,
            records,
            validations,
            evaluations,
            include_private,
            identity,
            output_dir,
        } => {
            let packages = load_packages_with_all_metadata(
                &packages,
                Some(&records),
                Some(&validations),
                Some(&evaluations),
            )?;
            let packages = filter_private_packages(packages, include_private);
            let mut offer = hivemind_marketplace::default_local_runner_offer(
                &hivemind_local_runner::descriptor(),
                package_refs(&packages),
            );
            if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                hivemind_marketplace::sign_runner_offer_with_identity(&mut offer, &identity_value)
                    .with_context(|| {
                        format!(
                            "failed to sign runner offer with {}",
                            identity_path.display()
                        )
                    })?;
            }
            let offers = vec![offer];
            if let Some(output_dir) = output_dir {
                std::fs::create_dir_all(&output_dir)
                    .with_context(|| format!("failed to create {}", output_dir.display()))?;
                let mut paths = Vec::new();
                for offer in &offers {
                    let path =
                        output_dir.join(format!("{}.json", safe_file_component(&offer.offer_id)));
                    write_json_file(&path, offer).await?;
                    paths.push(path.display().to_string());
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "schemaVersion": "hivemind.runner_offer_store_write.v1",
                        "offerCount": offers.len(),
                        "offerPaths": paths,
                        "offers": offers
                    }))?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&offers)?);
            }
            Ok(())
        }
        MarketplaceCommands::HardwareOffers {
            operator,
            identity,
            output_dir,
        } => {
            let mut offers = vec![
                hivemind_marketplace::default_hardware_resource_offer(
                    &hivemind_local_runner::descriptor(),
                    operator.clone(),
                ),
                hivemind_marketplace::default_hardware_resource_offer(
                    &hivemind_remote_runner::default_descriptor(),
                    operator,
                ),
            ];
            if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                for offer in &mut offers {
                    hivemind_marketplace::sign_hardware_resource_offer_with_identity(
                        offer,
                        &identity_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign hardware resource offer with {}",
                            identity_path.display()
                        )
                    })?;
                }
            }
            if let Some(output_dir) = output_dir {
                std::fs::create_dir_all(&output_dir)
                    .with_context(|| format!("failed to create {}", output_dir.display()))?;
                let mut paths = Vec::new();
                for offer in &offers {
                    let path =
                        output_dir.join(format!("{}.json", safe_file_component(&offer.offer_id)));
                    write_json_file(&path, offer).await?;
                    paths.push(path.display().to_string());
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "schemaVersion": "hivemind.hardware_resource_offer_store_write.v1",
                        "offerCount": offers.len(),
                        "offerPaths": paths,
                        "offers": offers
                    }))?
                );
            } else {
                println!("{}", serde_json::to_string_pretty(&offers)?);
            }
            Ok(())
        }
        MarketplaceCommands::Shortlist {
            reference,
            package_id,
            package_version,
            task,
            text,
            input,
            policy,
            max_results,
            include_rejected,
            packages,
            records,
            validations,
            evaluations,
            offers,
            include_private,
        } => {
            let input = read_execution_input(text, input).await?;
            let request = ExecutionRequestV1 {
                schema_version: "swarm-ai.execution.request.v1".to_string(),
                request_id: Uuid::new_v4().to_string(),
                package_ref: reference.clone(),
                package_id,
                package_version,
                preferred_artifact_group: None,
                task,
                input,
                options: ExecutionOptions::default(),
                privacy: ExecutionPrivacy::default(),
                access_grant: None,
                access_revocation_list: None,
            };
            let policy_mode = parse_policy_mode(&policy)?;
            let packages = load_packages_with_all_metadata(
                &packages,
                Some(&records),
                Some(&validations),
                Some(&evaluations),
            )?;
            let packages = filter_private_packages(packages, include_private);
            let offers = marketplace_runner_offers_for_request(&packages, &offers, &reference)?;
            let mut shortlist_request = hivemind_marketplace::shortlist_request_from_execution(
                &request,
                policy_mode,
                max_results,
            );
            shortlist_request.include_rejected = include_rejected;
            let shortlist =
                hivemind_marketplace::shortlist_runner_offers(&shortlist_request, &offers);
            println!("{}", serde_json::to_string_pretty(&shortlist)?);
            Ok(())
        }
        MarketplaceCommands::VerifyOffer { offer } => {
            let offer = read_json_file::<hivemind_marketplace::RunnerOfferV1>(&offer).await?;
            let verification = hivemind_marketplace::verify_runner_offer(&offer);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        MarketplaceCommands::SignOffer {
            offer,
            identity,
            output,
        } => {
            let mut offer_value =
                read_json_file::<hivemind_marketplace::RunnerOfferV1>(&offer).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_marketplace::sign_runner_offer_with_identity(
                &mut offer_value,
                &identity_value,
            )
            .with_context(|| format!("failed to sign runner offer with {}", identity.display()))?;
            let verification = hivemind_marketplace::verify_runner_offer(&offer_value);
            if let Some(output) = output {
                write_json_file(&output, &offer_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "offerPath": output.display().to_string(),
                        "signature": signature,
                        "offer": offer_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "offer": offer_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        MarketplaceCommands::VerifyHardwareOffer { offer } => {
            let offer =
                read_json_file::<hivemind_marketplace::HardwareResourceOfferV1>(&offer).await?;
            let verification = hivemind_marketplace::verify_hardware_resource_offer(&offer);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        MarketplaceCommands::SignHardwareOffer {
            offer,
            identity,
            output,
        } => {
            let mut offer_value =
                read_json_file::<hivemind_marketplace::HardwareResourceOfferV1>(&offer).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_marketplace::sign_hardware_resource_offer_with_identity(
                &mut offer_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign hardware resource offer with {}",
                    identity.display()
                )
            })?;
            let verification = hivemind_marketplace::verify_hardware_resource_offer(&offer_value);
            if let Some(output) = output {
                write_json_file(&output, &offer_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "offerPath": output.display().to_string(),
                        "signature": signature,
                        "offer": offer_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "offer": offer_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        MarketplaceCommands::Quote {
            reference,
            package_id,
            package_version,
            task,
            text,
            input,
            offers,
            identity,
        } => {
            let input = read_execution_input(text, input).await?;
            let request = ExecutionRequestV1 {
                schema_version: "swarm-ai.execution.request.v1".to_string(),
                request_id: Uuid::new_v4().to_string(),
                package_ref: reference.clone(),
                package_id,
                package_version,
                preferred_artifact_group: None,
                task,
                input,
                options: ExecutionOptions::default(),
                privacy: ExecutionPrivacy::default(),
                access_grant: None,
                access_revocation_list: None,
            };
            let offer = marketplace_quote_offer_for_reference(&reference, &offers)?;
            let mut quote = hivemind_marketplace::quote_execution(&request, &offer, None)
                .context("selected runner offer does not support this request")?;
            if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                hivemind_marketplace::sign_service_quote_with_identity(&mut quote, &identity_value)
                    .with_context(|| {
                        format!(
                            "failed to sign service quote with {}",
                            identity_path.display()
                        )
                    })?;
            }
            println!("{}", serde_json::to_string_pretty(&quote)?);
            Ok(())
        }
        MarketplaceCommands::VerifyQuote { quote, offer } => {
            let quote = read_json_file::<hivemind_marketplace::ServiceQuoteV1>(&quote).await?;
            let offer = if let Some(offer) = offer {
                Some(read_json_file::<hivemind_marketplace::RunnerOfferV1>(&offer).await?)
            } else {
                None
            };
            let verification = hivemind_marketplace::verify_service_quote(&quote, offer.as_ref());
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        MarketplaceCommands::SignQuote {
            quote,
            identity,
            output,
        } => {
            let mut quote_value =
                read_json_file::<hivemind_marketplace::ServiceQuoteV1>(&quote).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_marketplace::sign_service_quote_with_identity(
                &mut quote_value,
                &identity_value,
            )
            .with_context(|| format!("failed to sign service quote with {}", identity.display()))?;
            let verification = hivemind_marketplace::verify_service_quote(&quote_value, None);
            if let Some(output) = output {
                write_json_file(&output, &quote_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "quotePath": output.display().to_string(),
                        "signature": signature,
                        "quote": quote_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "quote": quote_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        MarketplaceCommands::AuthorizePayment {
            quote,
            payer,
            payee,
            adapter,
            payment_ref,
            identity,
            payment_dir,
            output,
        } => {
            let quote = read_json_file::<hivemind_marketplace::ServiceQuoteV1>(&quote).await?;
            let adapter = parse_payment_adapter(&adapter)?;
            let mut authorization =
                hivemind_marketplace::authorize_payment(&quote, payer, payee, adapter, payment_ref);
            if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                hivemind_marketplace::sign_payment_authorization_with_identity(
                    &mut authorization,
                    &identity_value,
                )
                .with_context(|| {
                    format!(
                        "failed to sign payment authorization with {}",
                        identity_path.display()
                    )
                })?;
            }
            let verification =
                hivemind_marketplace::verify_payment_authorization(&authorization, Some(&quote));
            let authorization_path =
                hivemind_marketplace::write_payment_authorization(&payment_dir, &authorization)
                    .with_context(|| {
                        format!(
                            "failed to write payment authorization into {}",
                            payment_dir.display()
                        )
                    })?;
            if let Some(output) = output {
                write_json_file(&output, &authorization).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "outputPath": output.display().to_string(),
                        "authorizationPath": authorization_path,
                        "authorization": authorization,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "authorizationPath": authorization_path,
                        "authorization": authorization,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        MarketplaceCommands::Payments { payment_dir } => {
            let summary = hivemind_marketplace::list_payment_authorizations(&payment_dir)
                .with_context(|| format!("failed to list {}", payment_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        MarketplaceCommands::GetPayment {
            authorization_id,
            payment_dir,
        } => {
            let lookup =
                hivemind_marketplace::get_payment_authorization(&payment_dir, &authorization_id)
                    .with_context(|| format!("failed to read {}", payment_dir.display()))?
                    .ok_or_else(|| {
                        anyhow::anyhow!("payment authorization {authorization_id} was not found")
                    })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
        MarketplaceCommands::VerifyPayment {
            authorization,
            quote,
        } => {
            let authorization =
                read_json_file::<hivemind_marketplace::PaymentAuthorizationV1>(&authorization)
                    .await?;
            let quote = if let Some(quote) = quote {
                Some(read_json_file::<hivemind_marketplace::ServiceQuoteV1>(&quote).await?)
            } else {
                None
            };
            let verification =
                hivemind_marketplace::verify_payment_authorization(&authorization, quote.as_ref());
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        MarketplaceCommands::SignPayment {
            authorization,
            identity,
            output,
        } => {
            let mut authorization_value =
                read_json_file::<hivemind_marketplace::PaymentAuthorizationV1>(&authorization)
                    .await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_marketplace::sign_payment_authorization_with_identity(
                &mut authorization_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign payment authorization with {}",
                    identity.display()
                )
            })?;
            let verification =
                hivemind_marketplace::verify_payment_authorization(&authorization_value, None);
            if let Some(output) = output {
                write_json_file(&output, &authorization_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "authorizationPath": output.display().to_string(),
                        "signature": signature,
                        "authorization": authorization_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "authorization": authorization_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        MarketplaceCommands::Settle {
            receipt,
            quote,
            payment_authorization,
            payer,
            payee,
            receipt_ref,
            identity,
            audit_dir,
        } => {
            let receipt = read_json_file::<ExecutionReceiptV1>(&receipt).await?;
            let quote = if let Some(quote) = quote {
                Some(read_json_file::<hivemind_marketplace::ServiceQuoteV1>(&quote).await?)
            } else {
                None
            };
            let payment_authorization = if let Some(payment_authorization) = payment_authorization {
                Some(
                    read_json_file::<hivemind_marketplace::PaymentAuthorizationV1>(
                        &payment_authorization,
                    )
                    .await?,
                )
            } else {
                None
            };
            let mut result = hivemind_marketplace::settlement_from_verified_receipt_with_payment(
                &receipt,
                quote.as_ref(),
                payment_authorization.as_ref(),
                payer,
                payee,
                receipt_ref,
            );
            if let Some(identity_path) = identity
                && let Some(settlement) = result.settlement.as_mut()
            {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                hivemind_marketplace::sign_settlement_event_with_identity(
                    settlement,
                    &identity_value,
                )
                .with_context(|| {
                    format!("failed to sign settlement with {}", identity_path.display())
                })?;
                let verification = hivemind_marketplace::verify_settlement_event(settlement);
                result.verification.expected_signature = verification.expected_signature;
                result.verification.settlement_id = Some(settlement.settlement_id.clone());
                if !verification.valid {
                    result.verification.valid = false;
                    result.verification.issues.extend(verification.issues);
                    result.verification.warnings.extend(verification.warnings);
                }
            }
            if result.verification.valid
                && let Some(settlement) = &result.settlement
            {
                hivemind_marketplace::write_settlement_event(&audit_dir, settlement).with_context(
                    || {
                        format!(
                            "failed to write settlement audit record into {}",
                            audit_dir.display()
                        )
                    },
                )?;
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        MarketplaceCommands::Audit { audit_dir } => {
            let summary = hivemind_marketplace::list_marketplace_audit(&audit_dir)
                .with_context(|| format!("failed to list {}", audit_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        MarketplaceCommands::GetSettlement {
            settlement_id,
            audit_dir,
        } => {
            let lookup = hivemind_marketplace::get_settlement_event(&audit_dir, &settlement_id)
                .with_context(|| format!("failed to read {}", audit_dir.display()))?
                .ok_or_else(|| anyhow::anyhow!("settlement {settlement_id} was not found"))?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
        MarketplaceCommands::VerifySettlement { settlement } => {
            let settlement =
                read_json_file::<hivemind_marketplace::SettlementEventV1>(&settlement).await?;
            let verification = hivemind_marketplace::verify_settlement_event(&settlement);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        MarketplaceCommands::SignSettlement {
            settlement,
            identity,
            output,
        } => {
            let mut settlement_value =
                read_json_file::<hivemind_marketplace::SettlementEventV1>(&settlement).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_marketplace::sign_settlement_event_with_identity(
                &mut settlement_value,
                &identity_value,
            )
            .with_context(|| format!("failed to sign settlement with {}", identity.display()))?;
            let verification = hivemind_marketplace::verify_settlement_event(&settlement_value);
            if let Some(output) = output {
                write_json_file(&output, &settlement_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "settlementPath": output.display().to_string(),
                        "signature": signature,
                        "settlement": settlement_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "settlement": settlement_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        MarketplaceCommands::DisputeSettlement {
            settlement,
            dispute,
            resolved_by,
            reason,
            identity,
            audit_dir,
        } => {
            let settlement =
                read_json_file::<hivemind_marketplace::SettlementEventV1>(&settlement).await?;
            let dispute = read_json_file::<hivemind_receipts::DisputeEvidenceV1>(&dispute).await?;
            let mut result = hivemind_marketplace::open_settlement_dispute(
                &settlement,
                &dispute,
                resolved_by,
                reason,
            );
            sign_marketplace_resolution_with_optional_identity(&mut result, identity).await?;
            if result.verification.valid {
                write_marketplace_resolution_audit(&audit_dir, &result)?;
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        MarketplaceCommands::RefundSettlement {
            settlement,
            dispute,
            resolved_by,
            reason,
            identity,
            audit_dir,
        } => {
            let settlement =
                read_json_file::<hivemind_marketplace::SettlementEventV1>(&settlement).await?;
            let dispute = read_json_file::<hivemind_receipts::DisputeEvidenceV1>(&dispute).await?;
            let mut result =
                hivemind_marketplace::refund_settlement(&settlement, &dispute, resolved_by, reason);
            sign_marketplace_resolution_with_optional_identity(&mut result, identity).await?;
            if result.verification.valid {
                write_marketplace_resolution_audit(&audit_dir, &result)?;
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        MarketplaceCommands::RejectDispute {
            settlement,
            dispute,
            resolved_by,
            reason,
            identity,
            audit_dir,
        } => {
            let settlement =
                read_json_file::<hivemind_marketplace::SettlementEventV1>(&settlement).await?;
            let dispute = read_json_file::<hivemind_receipts::DisputeEvidenceV1>(&dispute).await?;
            let mut result = hivemind_marketplace::reject_settlement_dispute(
                &settlement,
                &dispute,
                resolved_by,
                reason,
            );
            sign_marketplace_resolution_with_optional_identity(&mut result, identity).await?;
            if result.verification.valid {
                write_marketplace_resolution_audit(&audit_dir, &result)?;
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
        MarketplaceCommands::GetResolution {
            resolution_id,
            audit_dir,
        } => {
            let lookup =
                hivemind_marketplace::get_settlement_resolution(&audit_dir, &resolution_id)
                    .with_context(|| format!("failed to read {}", audit_dir.display()))?
                    .ok_or_else(|| {
                        anyhow::anyhow!("settlement resolution {resolution_id} was not found")
                    })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
        MarketplaceCommands::VerifyResolution { resolution } => {
            let resolution =
                read_json_file::<hivemind_marketplace::SettlementResolutionV1>(&resolution).await?;
            let verification = hivemind_marketplace::verify_settlement_resolution(&resolution);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        MarketplaceCommands::SignResolution {
            resolution,
            identity,
            output,
        } => {
            let mut resolution_value =
                read_json_file::<hivemind_marketplace::SettlementResolutionV1>(&resolution).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_marketplace::sign_settlement_resolution_with_identity(
                &mut resolution_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign settlement resolution with {}",
                    identity.display()
                )
            })?;
            let verification =
                hivemind_marketplace::verify_settlement_resolution(&resolution_value);
            if let Some(output) = output {
                write_json_file(&output, &resolution_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "resolutionPath": output.display().to_string(),
                        "signature": signature,
                        "resolution": resolution_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "resolution": resolution_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
    }
}

async fn sign_marketplace_resolution_with_optional_identity(
    result: &mut hivemind_marketplace::SettlementResolutionResultV1,
    identity: Option<PathBuf>,
) -> Result<()> {
    let Some(identity_path) = identity else {
        return Ok(());
    };
    let Some(resolution) = result.resolution.as_mut() else {
        return Ok(());
    };

    let identity_value: hivemind_identity::IdentityKeypairV1 =
        read_json_file(&identity_path).await?;
    hivemind_marketplace::sign_settlement_resolution_with_identity(resolution, &identity_value)
        .with_context(|| {
            format!(
                "failed to sign settlement resolution with {}",
                identity_path.display()
            )
        })?;
    let verification = hivemind_marketplace::verify_settlement_resolution(resolution);
    result.verification.expected_signature = verification.expected_signature;
    result.verification.resolution_id = Some(resolution.resolution_id.clone());
    if !verification.valid {
        result.verification.valid = false;
        result.verification.issues.extend(verification.issues);
        result.verification.warnings.extend(verification.warnings);
    }
    Ok(())
}

fn write_marketplace_resolution_audit(
    audit_dir: &PathBuf,
    result: &hivemind_marketplace::SettlementResolutionResultV1,
) -> Result<()> {
    if let Some(settlement) = &result.updated_settlement {
        hivemind_marketplace::write_settlement_event(audit_dir, settlement).with_context(|| {
            format!(
                "failed to write settlement audit record into {}",
                audit_dir.display()
            )
        })?;
    }
    if let Some(resolution) = &result.resolution {
        hivemind_marketplace::write_settlement_resolution(audit_dir, resolution).with_context(
            || {
                format!(
                    "failed to write settlement resolution audit record into {}",
                    audit_dir.display()
                )
            },
        )?;
    }
    Ok(())
}

async fn compat_command(path: PathBuf) -> Result<()> {
    let (validation, compatibility) = hivemind_validator::validate_package_compatibility(&path)
        .with_context(|| format!("failed to run compatibility checks for {}", path.display()))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "validation": validation,
            "compatibility": compatibility
        }))?
    );
    Ok(())
}

async fn certify_command(
    path: PathBuf,
    identity: Option<PathBuf>,
    component_type: String,
    implementation_name: Option<String>,
    component_version: Option<String>,
    supported_schemas: Vec<String>,
    warnings: Vec<String>,
    store: bool,
    compatibility_dir: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let report = hivemind_sdk::certify_package_dir(&path)
        .with_context(|| format!("failed to certify {}", path.display()))?;
    if let Some(identity_path) = identity {
        let identity_value: hivemind_identity::IdentityKeypairV1 =
            read_json_file(&identity_path).await?;
        let implementation_name =
            implementation_name.unwrap_or_else(|| report.component_name.clone());
        let component_version =
            component_version.unwrap_or_else(|| report.component_version.clone());
        let mut declared_schemas = hivemind_sdk::package_certification_supported_schemas();
        declared_schemas.extend(supported_schemas);
        let mut certification = hivemind_sdk::compatibility_certification_from_report(
            &report,
            component_type,
            implementation_name,
            component_version,
            declared_schemas,
            warnings,
        );
        hivemind_sdk::sign_compatibility_certification(&mut certification, &identity_value)
            .with_context(|| {
                format!(
                    "failed to sign compatibility certification with {}",
                    identity_path.display()
                )
            })?;
        let verification = hivemind_sdk::verify_compatibility_certification(
            &certification,
            Some(identity_value.subject.as_str()),
        );
        if !verification.valid {
            anyhow::bail!(
                "signed compatibility certification failed verification: {}",
                serde_json::to_string_pretty(&verification)?
            );
        }
        let store_result = if store {
            Some(
                hivemind_sdk::write_compatibility_certification(&compatibility_dir, &certification)
                    .with_context(|| {
                        format!(
                            "failed to write compatibility certification into {}",
                            compatibility_dir.display()
                        )
                    })?,
            )
        } else {
            None
        };
        if let Some(output) = output {
            write_json_file(&output, &certification).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "outputPath": output.display().to_string(),
                    "certification": certification,
                    "store": store_result
                }))?
            );
        } else if store_result.is_some() {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "certification": certification,
                    "store": store_result
                }))?
            );
        } else {
            println!("{}", serde_json::to_string_pretty(&certification)?);
        }
    } else {
        if store {
            anyhow::bail!("--store requires --identity so the certification evidence is signed");
        }
        if let Some(output) = output {
            write_json_file(&output, &report).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "outputPath": output.display().to_string(),
                    "report": report
                }))?
            );
        } else {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

async fn verify_certification_command(
    certification: PathBuf,
    expected_signer: Option<String>,
) -> Result<()> {
    let certification_value: hivemind_sdk::CompatibilityCertificationV1 =
        read_json_file(&certification).await?;
    let verification = hivemind_sdk::verify_compatibility_certification(
        &certification_value,
        expected_signer.as_deref(),
    );
    println!("{}", serde_json::to_string_pretty(&verification)?);
    Ok(())
}

async fn compatibility_certification_list_command(compatibility_dir: PathBuf) -> Result<()> {
    let summary = hivemind_sdk::list_compatibility_certifications(&compatibility_dir)
        .with_context(|| {
            format!(
                "failed to list compatibility certifications from {}",
                compatibility_dir.display()
            )
        })?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn compatibility_certification_get_command(
    certification_id: String,
    compatibility_dir: PathBuf,
) -> Result<()> {
    let Some(lookup) =
        hivemind_sdk::get_compatibility_certification(&compatibility_dir, &certification_id)
            .with_context(|| {
                format!(
                    "failed to read compatibility certification {} from {}",
                    certification_id,
                    compatibility_dir.display()
                )
            })?
    else {
        anyhow::bail!("compatibility certification {certification_id} was not found");
    };
    println!("{}", serde_json::to_string_pretty(&lookup)?);
    Ok(())
}

async fn validate_run_command(
    reference: String,
    provider: String,
    storage_dir: PathBuf,
    bee_url: String,
    validator_id: String,
    identity: Option<PathBuf>,
    task: String,
    text: Option<String>,
    input: Option<PathBuf>,
    grant: Option<PathBuf>,
    revocations: Option<PathBuf>,
    reports_dir: PathBuf,
) -> Result<()> {
    let input_value = read_execution_input(text, input).await?;
    let access_grant = read_access_grant(grant).await?;
    let access_revocation_list = read_access_revocation_list(revocations).await?;
    let package = match provider.as_str() {
        "local" => {
            let storage = LocalDirectoryStorageProvider::new(storage_dir);
            hivemind_package::load_package_from_storage(&reference, &storage)
        }
        "bee" => {
            let storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                api_url: bee_url,
                postage_batch_id: None,
                pin: false,
                deferred_upload: true,
                redundancy_level: 0,
            });
            hivemind_package::load_package_from_storage(&reference, &storage)
        }
        other => anyhow::bail!("unknown validate-run provider {other}; expected local or bee"),
    }
    .with_context(|| format!("failed to load package {reference}"))?;

    let challenge =
        hivemind_validator::public_challenge(&reference, task, input_value, validator_id);
    let mut request = hivemind_validator::challenge_execution_request(
        &challenge,
        package.manifest.package_id.clone(),
        package.manifest.version.clone(),
        access_grant,
    );
    request.access_revocation_list = access_revocation_list;
    let runner_id = hivemind_local_runner::descriptor().runner_id;
    let response = hivemind_local_runner::execute(request, package).await;
    let mut report =
        hivemind_validator::score_execution(&challenge, &response, runner_id, Vec::new());
    if let Some(identity_path) = identity {
        let identity_value: hivemind_identity::IdentityKeypairV1 =
            read_json_file(&identity_path).await?;
        hivemind_validator::sign_validation_report_with_identity(&mut report, &identity_value)
            .with_context(|| {
                format!(
                    "failed to sign validation report with {}",
                    identity_path.display()
                )
            })?;
    }
    let report_path = write_validation_report(&reports_dir, &report).await?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "challenge": challenge,
            "response": response,
            "report": report,
            "reportPath": report_path
        }))?
    );
    Ok(())
}

async fn verify_validation_command(report: PathBuf) -> Result<()> {
    let report: hivemind_validator::ValidationReportV1 = read_json_file(&report).await?;
    let verification = hivemind_validator::verify_validation_report(&report);
    println!("{}", serde_json::to_string_pretty(&verification)?);
    Ok(())
}

async fn sign_validation_command(
    report: PathBuf,
    identity: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let mut report_value: hivemind_validator::ValidationReportV1 = read_json_file(&report).await?;
    let identity_value: hivemind_identity::IdentityKeypairV1 = read_json_file(&identity).await?;
    let signature = hivemind_validator::sign_validation_report_with_identity(
        &mut report_value,
        &identity_value,
    )
    .with_context(|| {
        format!(
            "failed to sign validation report with {}",
            identity.display()
        )
    })?;
    let verification = hivemind_validator::verify_validation_report(&report_value);
    if let Some(output) = output {
        write_json_file(&output, &report_value).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "reportPath": output.display().to_string(),
                "signature": signature,
                "report": report_value,
                "verification": verification
            }))?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "signature": signature,
                "report": report_value,
                "verification": verification
            }))?
        );
    }
    Ok(())
}

async fn upload_validation_command(
    report: PathBuf,
    provider: String,
    storage_dir: PathBuf,
    bee_url: String,
    postage_batch_id: Option<String>,
) -> Result<()> {
    let report_value = read_json_file::<hivemind_validator::ValidationReportV1>(&report)
        .await
        .with_context(|| format!("failed to read validation report {}", report.display()))?;
    let upload = match provider.as_str() {
        "local" => {
            let mut storage = LocalDirectoryStorageProvider::new(storage_dir);
            hivemind_validator::upload_validation_report(&mut storage, &report_value)
        }
        "bee" => {
            let mut storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                api_url: bee_url,
                postage_batch_id,
                pin: false,
                deferred_upload: true,
                redundancy_level: 0,
            });
            hivemind_validator::upload_validation_report(&mut storage, &report_value)
        }
        other => anyhow::bail!(
            "unknown validation report upload provider {other}; expected local or bee"
        ),
    }
    .with_context(|| format!("failed to upload validation report {}", report.display()))?;
    println!("{}", serde_json::to_string_pretty(&upload)?);
    Ok(())
}

async fn download_validation_command(
    reference: String,
    provider: String,
    storage_dir: PathBuf,
    bee_url: String,
    output: Option<PathBuf>,
    reports_dir: PathBuf,
) -> Result<()> {
    let download = match provider.as_str() {
        "local" => {
            let storage = LocalDirectoryStorageProvider::new(storage_dir);
            hivemind_validator::download_validation_report(&storage, &reference)
        }
        "bee" => {
            let storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                api_url: bee_url,
                postage_batch_id: None,
                pin: false,
                deferred_upload: true,
                redundancy_level: 0,
            });
            hivemind_validator::download_validation_report(&storage, &reference)
        }
        other => anyhow::bail!(
            "unknown validation report download provider {other}; expected local or bee"
        ),
    }
    .with_context(|| format!("failed to download validation report {reference}"))?;
    let report_path = if let Some(output) = output {
        if let Some(parent) = output.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!("failed to create output directory {}", parent.display())
            })?;
        }
        tokio::fs::write(&output, serde_json::to_vec_pretty(&download.report)?)
            .await
            .with_context(|| format!("failed to write validation report {}", output.display()))?;
        output
    } else {
        write_validation_report(&reports_dir, &download.report)
            .await
            .with_context(|| {
                format!(
                    "failed to write validation report into {}",
                    reports_dir.display()
                )
            })?
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "reportPath": report_path,
            "download": download
        }))?
    );
    Ok(())
}

async fn validation_reports_command(reports_dir: PathBuf) -> Result<()> {
    let summary = hivemind_validator::list_validation_reports(&reports_dir)
        .with_context(|| format!("failed to list {}", reports_dir.display()))?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn get_validation_command(report_id: String, reports_dir: PathBuf) -> Result<()> {
    let lookup = hivemind_validator::get_validation_report(&reports_dir, &report_id)
        .with_context(|| format!("failed to read {}", reports_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("validation report {report_id} was not found"))?;
    println!("{}", serde_json::to_string_pretty(&lookup)?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn integrity_evidence_init_command(
    output: PathBuf,
    evidence_kind: String,
    validator_id: String,
    runner_id: Option<String>,
    subject_type: String,
    subject_id: String,
    package_ref: Option<String>,
    receipt_id: Option<String>,
    measurement_hash: Option<String>,
    expected_measurement_hashes: Vec<String>,
    evidence_refs: Vec<String>,
    proof_refs: Vec<String>,
    method: Option<String>,
    verdict: String,
    identity: Option<PathBuf>,
    force: bool,
) -> Result<()> {
    if output.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite it",
            output.display()
        );
    }
    let method = method
        .as_deref()
        .map(parse_validation_method_v2)
        .transpose()?;
    let mut evidence = hivemind_validator::create_integrity_evidence(
        hivemind_validator::IntegrityEvidenceInitOptionsV1 {
            evidence_kind: parse_integrity_evidence_kind(&evidence_kind)?,
            validator_id,
            runner_id,
            subject_type: parse_validation_subject_type_v2(&subject_type)?,
            subject_id,
            package_ref,
            receipt_id,
            measurement_hash,
            expected_measurement_hashes,
            evidence_refs,
            proof_refs,
            method,
            verdict: parse_integrity_evidence_verdict(&verdict)?,
            metadata: json!({ "source": "cli" }),
        },
    );
    let signature = if let Some(identity_path) = identity {
        let identity_value: hivemind_identity::IdentityKeypairV1 =
            read_json_file(&identity_path).await?;
        let signature = hivemind_validator::sign_integrity_evidence_with_identity(
            &mut evidence,
            &identity_value,
        )
        .with_context(|| {
            format!(
                "failed to sign integrity evidence with {}",
                identity_path.display()
            )
        })?;
        serde_json::to_value(signature)?
    } else {
        json!(evidence.signature.clone())
    };
    let verification = hivemind_validator::verify_integrity_evidence(&evidence);
    let report_v2 = hivemind_validator::validation_report_v2_from_integrity_evidence(&evidence);
    write_json_file(&output, &evidence).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "evidencePath": output.display().to_string(),
            "signature": signature,
            "evidence": evidence,
            "verification": verification,
            "validationReportV2": report_v2
        }))?
    );
    Ok(())
}

async fn verify_integrity_evidence_command(evidence: PathBuf) -> Result<()> {
    let evidence: hivemind_validator::IntegrityEvidenceV1 = read_json_file(&evidence).await?;
    let verification = hivemind_validator::verify_integrity_evidence(&evidence);
    let report_v2 = hivemind_validator::validation_report_v2_from_integrity_evidence(&evidence);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "verification": verification,
            "validationReportV2": report_v2
        }))?
    );
    Ok(())
}

async fn sign_integrity_evidence_command(
    evidence: PathBuf,
    identity: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let mut evidence_value: hivemind_validator::IntegrityEvidenceV1 =
        read_json_file(&evidence).await?;
    let identity_value: hivemind_identity::IdentityKeypairV1 = read_json_file(&identity).await?;
    let signature = hivemind_validator::sign_integrity_evidence_with_identity(
        &mut evidence_value,
        &identity_value,
    )
    .with_context(|| {
        format!(
            "failed to sign integrity evidence with {}",
            identity.display()
        )
    })?;
    let verification = hivemind_validator::verify_integrity_evidence(&evidence_value);
    if let Some(output) = output {
        write_json_file(&output, &evidence_value).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "evidencePath": output.display().to_string(),
                "signature": signature,
                "evidence": evidence_value,
                "verification": verification
            }))?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "signature": signature,
                "evidence": evidence_value,
                "verification": verification
            }))?
        );
    }
    Ok(())
}

async fn integrity_evidence_records_command(evidence_dir: PathBuf) -> Result<()> {
    let summary = hivemind_validator::list_integrity_evidence(&evidence_dir)
        .with_context(|| format!("failed to list {}", evidence_dir.display()))?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn get_integrity_evidence_command(evidence_id: String, evidence_dir: PathBuf) -> Result<()> {
    let lookup = hivemind_validator::get_integrity_evidence(&evidence_dir, &evidence_id)
        .with_context(|| format!("failed to read {}", evidence_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("integrity evidence {evidence_id} was not found"))?;
    println!("{}", serde_json::to_string_pretty(&lookup)?);
    Ok(())
}

async fn reputation_command(
    subject_type: String,
    subject_id: String,
    reports_dir: PathBuf,
) -> Result<()> {
    let subject_type = parse_reputation_subject_type(&subject_type)?;
    let profile =
        hivemind_validator::reputation_profile_from_store(&reports_dir, subject_type, subject_id)
            .with_context(|| format!("failed to build reputation from {}", reports_dir.display()))?;
    println!("{}", serde_json::to_string_pretty(&profile)?);
    Ok(())
}

async fn benchmark_run_command(
    reference: String,
    provider: String,
    storage_dir: PathBuf,
    bee_url: String,
    validator_id: String,
    identity: Option<PathBuf>,
    benchmark_name: String,
    grant: Option<PathBuf>,
    revocations: Option<PathBuf>,
    results_dir: PathBuf,
) -> Result<()> {
    let access_grant = read_access_grant(grant).await?;
    let access_revocation_list = read_access_revocation_list(revocations).await?;
    let package = match provider.as_str() {
        "local" => {
            let storage = LocalDirectoryStorageProvider::new(storage_dir);
            hivemind_package::load_package_from_storage(&reference, &storage)
        }
        "bee" => {
            let storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                api_url: bee_url,
                postage_batch_id: None,
                pin: false,
                deferred_upload: true,
                redundancy_level: 0,
            });
            hivemind_package::load_package_from_storage(&reference, &storage)
        }
        other => anyhow::bail!("unknown benchmark-run provider {other}; expected local or bee"),
    }
    .with_context(|| format!("failed to load package {reference}"))?;

    let (benchmark, dataset) = match benchmark_name.as_str() {
        "embedding-basic" | "commons/embedding-basic-v1" => (
            hivemind_benchmarks::mini_embedding_benchmark(),
            hivemind_benchmarks::mini_embedding_dataset(),
        ),
        other => anyhow::bail!(
            "unknown benchmark {other}; expected embedding-basic or commons/embedding-basic-v1"
        ),
    };
    let deadline_ms = hivemind_benchmarks::scoring_deadline_ms(&benchmark);
    let runner_id = hivemind_local_runner::descriptor().runner_id;
    let mut responses = Vec::new();
    let mut sample_results = Vec::new();

    for entry in &dataset {
        let mut request = hivemind_benchmarks::benchmark_execution_request(
            &benchmark,
            entry,
            &reference,
            package.manifest.package_id.clone(),
            package.manifest.version.clone(),
            access_grant.clone(),
        );
        request.access_revocation_list = access_revocation_list.clone();
        let response = hivemind_local_runner::execute(request, package.clone()).await;
        sample_results.push(hivemind_benchmarks::sample_result_from_response(
            entry,
            &response,
            deadline_ms,
        ));
        responses.push(response);
    }

    let mut result = hivemind_benchmarks::evaluation_result(
        &benchmark,
        &reference,
        Some(runner_id),
        validator_id,
        sample_results,
        Vec::new(),
    );
    if let Some(identity_path) = identity {
        let identity_value: hivemind_identity::IdentityKeypairV1 =
            read_json_file(&identity_path).await?;
        hivemind_benchmarks::sign_evaluation_result_with_identity(&mut result, &identity_value)
            .with_context(|| {
                format!(
                    "failed to sign evaluation result with {}",
                    identity_path.display()
                )
            })?;
    }
    let result_path = hivemind_benchmarks::write_evaluation_result(&results_dir, &result)
        .with_context(|| {
            format!(
                "failed to write evaluation result into {}",
                results_dir.display()
            )
        })?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "benchmark": benchmark,
            "dataset": dataset,
            "responses": responses,
            "evaluation": result,
            "resultPath": result_path
        }))?
    );
    Ok(())
}

async fn verify_evaluation_command(result: PathBuf) -> Result<()> {
    let result: hivemind_benchmarks::EvaluationResultV1 = read_json_file(&result).await?;
    let verification = hivemind_benchmarks::verify_evaluation_result(&result);
    println!("{}", serde_json::to_string_pretty(&verification)?);
    Ok(())
}

async fn sign_evaluation_command(
    result: PathBuf,
    identity: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let mut result_value: hivemind_benchmarks::EvaluationResultV1 = read_json_file(&result).await?;
    let identity_value: hivemind_identity::IdentityKeypairV1 = read_json_file(&identity).await?;
    let signature = hivemind_benchmarks::sign_evaluation_result_with_identity(
        &mut result_value,
        &identity_value,
    )
    .with_context(|| {
        format!(
            "failed to sign evaluation result with {}",
            identity.display()
        )
    })?;
    let verification = hivemind_benchmarks::verify_evaluation_result(&result_value);
    if let Some(output) = output {
        write_json_file(&output, &result_value).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "resultPath": output.display().to_string(),
                "signature": signature,
                "evaluation": result_value,
                "verification": verification
            }))?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "signature": signature,
                "evaluation": result_value,
                "verification": verification
            }))?
        );
    }
    Ok(())
}

async fn evaluation_results_command(results_dir: PathBuf) -> Result<()> {
    let summary = hivemind_benchmarks::list_evaluation_results(&results_dir)
        .with_context(|| format!("failed to list {}", results_dir.display()))?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn evaluation_leaderboard_command(results_dir: PathBuf) -> Result<()> {
    let leaderboard = hivemind_benchmarks::evaluation_leaderboard(&results_dir)
        .with_context(|| format!("failed to build leaderboard from {}", results_dir.display()))?;
    println!("{}", serde_json::to_string_pretty(&leaderboard)?);
    Ok(())
}

async fn get_evaluation_command(evaluation_id: String, results_dir: PathBuf) -> Result<()> {
    let lookup = hivemind_benchmarks::get_evaluation_result(&results_dir, &evaluation_id)
        .with_context(|| format!("failed to read {}", results_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("evaluation result {evaluation_id} was not found"))?;
    println!("{}", serde_json::to_string_pretty(&lookup)?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn evaluation_v2_from_v1_command(
    result: PathBuf,
    output: PathBuf,
    suite_id: Option<String>,
    started_at: Option<String>,
    completed_at: Option<String>,
    total_ms: Option<u64>,
    average_ms: Option<f64>,
    cost_amount: Option<f64>,
    cost_currency: String,
    pricing_ref: Option<String>,
    runner_type: Option<String>,
    os: Option<String>,
    architecture: Option<String>,
    hardware_refs: Vec<String>,
    software_refs: Vec<String>,
    artifact_refs: Vec<String>,
    random_seeds: Vec<String>,
    errors: Vec<String>,
    identity: Option<PathBuf>,
    force: bool,
) -> Result<()> {
    if output.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite it",
            output.display()
        );
    }
    let source: hivemind_benchmarks::EvaluationResultV1 = read_json_file(&result).await?;
    let has_timing = started_at.is_some()
        || completed_at.is_some()
        || total_ms.is_some()
        || average_ms.is_some();
    let timing = has_timing.then(|| hivemind_benchmarks::EvaluationTimingV2 {
        started_at,
        completed_at,
        total_ms: total_ms.unwrap_or(source.metrics.total_ms),
        average_ms: average_ms.unwrap_or(source.metrics.average_ms),
    });
    let cost = cost_amount.map(|amount| hivemind_benchmarks::EvaluationCostV2 {
        amount,
        currency: cost_currency,
        pricing_ref,
    });
    let has_environment = runner_type.is_some()
        || os.is_some()
        || architecture.is_some()
        || !hardware_refs.is_empty()
        || !software_refs.is_empty();
    let environment = has_environment.then(|| hivemind_benchmarks::EvaluationEnvironmentV2 {
        runner_type,
        os,
        architecture,
        hardware_refs,
        software_refs,
        metadata: json!({ "source": "cli" }),
    });
    let mut result_v2 = hivemind_benchmarks::evaluation_result_v2_from_v1(
        &source,
        hivemind_benchmarks::EvaluationResultV2ContextV1 {
            suite_id,
            timing,
            cost,
            environment,
            artifact_refs,
            random_seeds,
            errors: parse_evaluation_v2_errors(errors)?,
            metadata: json!({ "source": "cli", "sourceResultPath": result.display().to_string() }),
        },
    );
    let signature = if let Some(identity_path) = identity {
        let identity_value: hivemind_identity::IdentityKeypairV1 =
            read_json_file(&identity_path).await?;
        serde_json::to_value(
            hivemind_benchmarks::sign_evaluation_result_v2_with_identity(
                &mut result_v2,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign evaluation result v2 with {}",
                    identity_path.display()
                )
            })?,
        )?
    } else {
        json!(result_v2.signature.clone())
    };
    let verification = hivemind_benchmarks::verify_evaluation_result_v2(&result_v2);
    if !verification.valid {
        let issues = verification
            .issues
            .iter()
            .map(|issue| format!("{}: {}", issue.path, issue.message))
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!("evaluation result v2 is not valid: {issues}");
    }
    write_json_file(&output, &result_v2).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "resultPath": output.display().to_string(),
            "signature": signature,
            "evaluation": result_v2,
            "verification": verification
        }))?
    );
    Ok(())
}

async fn verify_evaluation_v2_command(result: PathBuf) -> Result<()> {
    let result: hivemind_benchmarks::EvaluationResultV2 = read_json_file(&result).await?;
    let verification = hivemind_benchmarks::verify_evaluation_result_v2(&result);
    println!("{}", serde_json::to_string_pretty(&verification)?);
    Ok(())
}

async fn sign_evaluation_v2_command(
    result: PathBuf,
    identity: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let mut result_value: hivemind_benchmarks::EvaluationResultV2 = read_json_file(&result).await?;
    let identity_value: hivemind_identity::IdentityKeypairV1 = read_json_file(&identity).await?;
    let signature = hivemind_benchmarks::sign_evaluation_result_v2_with_identity(
        &mut result_value,
        &identity_value,
    )
    .with_context(|| {
        format!(
            "failed to sign evaluation result v2 with {}",
            identity.display()
        )
    })?;
    let verification = hivemind_benchmarks::verify_evaluation_result_v2(&result_value);
    if let Some(output) = output {
        write_json_file(&output, &result_value).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "resultPath": output.display().to_string(),
                "signature": signature,
                "evaluation": result_value,
                "verification": verification
            }))?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "signature": signature,
                "evaluation": result_value,
                "verification": verification
            }))?
        );
    }
    Ok(())
}

async fn evaluation_results_v2_command(results_dir: PathBuf) -> Result<()> {
    let summary = hivemind_benchmarks::list_evaluation_results_v2(&results_dir)
        .with_context(|| format!("failed to list {}", results_dir.display()))?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn get_evaluation_v2_command(evaluation_id: String, results_dir: PathBuf) -> Result<()> {
    let lookup = hivemind_benchmarks::get_evaluation_result_v2(&results_dir, &evaluation_id)
        .with_context(|| format!("failed to read {}", results_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("evaluation result v2 {evaluation_id} was not found"))?;
    println!("{}", serde_json::to_string_pretty(&lookup)?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn benchmark_suite_init_command(
    output: PathBuf,
    benchmark_id: String,
    name: String,
    task: String,
    version: String,
    maintainer_id: String,
    modalities: Vec<String>,
    dataset_refs: Vec<String>,
    scoring_method_ref: String,
    splits: Vec<String>,
    allowed_model_refs: Vec<String>,
    allowed_runtimes: Vec<String>,
    privacy_tier: String,
    private_results: bool,
    disallow_remote_runners: bool,
    require_result_redaction: bool,
    access_policy_refs: Vec<String>,
    p50_ms: u64,
    p95_ms: u64,
    max_ms: u64,
    metric_names: Vec<String>,
    identity: Option<PathBuf>,
    force: bool,
) -> Result<()> {
    if output.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite it",
            output.display()
        );
    }
    let allowed_model_refs = if allowed_model_refs.is_empty() {
        vec!["package-kind://model".to_string()]
    } else {
        allowed_model_refs
    };
    let allowed_runtimes = if allowed_runtimes.is_empty() {
        vec!["local".to_string()]
    } else {
        allowed_runtimes
    };
    let metric_names = if metric_names.is_empty() {
        vec![
            "quality".to_string(),
            "latency".to_string(),
            "overall".to_string(),
        ]
    } else {
        metric_names
    };
    let mut suite = hivemind_benchmarks::create_benchmark_suite(
        hivemind_benchmarks::BenchmarkSuiteInitOptionsV1 {
            benchmark_id,
            name,
            task,
            version,
            maintainer_id,
            modalities,
            dataset_refs,
            scoring_method_ref,
            splits: parse_benchmark_splits(splits)?,
            allowed_model_refs,
            allowed_runtimes,
            privacy_rules: hivemind_benchmarks::BenchmarkPrivacyRulesV1 {
                required_tier: privacy_tier,
                allow_public_results: !private_results,
                allow_remote_runners: !disallow_remote_runners,
                require_result_redaction,
                access_policy_refs,
            },
            expected_runtime: hivemind_benchmarks::BenchmarkExpectedRuntimeV1 {
                p50_ms,
                p95_ms,
                max_ms,
            },
            metric_names,
            license: None,
            metadata: json!({ "source": "cli" }),
        },
    );
    let signature = if let Some(identity_path) = identity {
        let identity_value: hivemind_identity::IdentityKeypairV1 =
            read_json_file(&identity_path).await?;
        serde_json::to_value(
            hivemind_benchmarks::sign_benchmark_suite_with_identity(&mut suite, &identity_value)
                .with_context(|| {
                    format!(
                        "failed to sign benchmark suite with {}",
                        identity_path.display()
                    )
                })?,
        )?
    } else {
        json!(suite.signature.clone())
    };
    let verification = hivemind_benchmarks::verify_benchmark_suite(&suite);
    if !verification.valid {
        let issues = verification
            .issues
            .iter()
            .map(|issue| format!("{}: {}", issue.path, issue.message))
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!("benchmark suite is not valid: {issues}");
    }
    write_json_file(&output, &suite).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "suitePath": output.display().to_string(),
            "signature": signature,
            "suite": suite,
            "verification": verification
        }))?
    );
    Ok(())
}

async fn verify_benchmark_suite_command(suite: PathBuf) -> Result<()> {
    let suite_value: hivemind_benchmarks::BenchmarkSuiteV1 = read_json_file(&suite).await?;
    let verification = hivemind_benchmarks::verify_benchmark_suite(&suite_value);
    println!("{}", serde_json::to_string_pretty(&verification)?);
    Ok(())
}

async fn sign_benchmark_suite_command(
    suite: PathBuf,
    identity: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let mut suite_value: hivemind_benchmarks::BenchmarkSuiteV1 = read_json_file(&suite).await?;
    let identity_value: hivemind_identity::IdentityKeypairV1 = read_json_file(&identity).await?;
    let signature =
        hivemind_benchmarks::sign_benchmark_suite_with_identity(&mut suite_value, &identity_value)
            .with_context(|| {
                format!("failed to sign benchmark suite with {}", identity.display())
            })?;
    let verification = hivemind_benchmarks::verify_benchmark_suite(&suite_value);
    if let Some(output) = output {
        write_json_file(&output, &suite_value).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "suitePath": output.display().to_string(),
                "signature": signature,
                "suite": suite_value,
                "verification": verification
            }))?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "signature": signature,
                "suite": suite_value,
                "verification": verification
            }))?
        );
    }
    Ok(())
}

async fn benchmark_suites_command(suites_dir: PathBuf) -> Result<()> {
    let summary = hivemind_benchmarks::list_benchmark_suites(&suites_dir)
        .with_context(|| format!("failed to list {}", suites_dir.display()))?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn get_benchmark_suite_command(suite_id: String, suites_dir: PathBuf) -> Result<()> {
    let lookup = hivemind_benchmarks::get_benchmark_suite(&suites_dir, &suite_id)
        .with_context(|| format!("failed to read {}", suites_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("benchmark suite {suite_id} was not found"))?;
    println!("{}", serde_json::to_string_pretty(&lookup)?);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn challenge_commitment_init_command(
    output: PathBuf,
    benchmark_id: String,
    benchmark_version: String,
    validator_id: String,
    challenge_set_hash: String,
    answer_set_hash: Option<String>,
    salt_hash: String,
    challenge_count: u64,
    public_dataset_refs: Vec<String>,
    hidden_ref_commitments: Vec<String>,
    scoring_rule_refs: Vec<String>,
    reveal_after: Option<String>,
    expires_at: Option<String>,
    identity: Option<PathBuf>,
    force: bool,
) -> Result<()> {
    if output.exists() && !force {
        anyhow::bail!(
            "{} already exists; pass --force to overwrite it",
            output.display()
        );
    }
    let mut commitment = hivemind_benchmarks::create_challenge_commitment(
        hivemind_benchmarks::ChallengeCommitmentInitOptionsV1 {
            benchmark_id,
            benchmark_version,
            validator_id,
            challenge_set_hash,
            answer_set_hash,
            salt_hash,
            challenge_count,
            public_dataset_refs,
            hidden_ref_commitments,
            scoring_rule_refs,
            reveal_after,
            expires_at,
            metadata: json!({ "source": "cli" }),
        },
    );
    let signature = if let Some(identity_path) = identity {
        let identity_value: hivemind_identity::IdentityKeypairV1 =
            read_json_file(&identity_path).await?;
        serde_json::to_value(
            hivemind_benchmarks::sign_challenge_commitment_with_identity(
                &mut commitment,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign challenge commitment with {}",
                    identity_path.display()
                )
            })?,
        )?
    } else {
        json!(commitment.signature.clone())
    };
    let verification = hivemind_benchmarks::verify_challenge_commitment(&commitment);
    if !verification.valid {
        let issues = verification
            .issues
            .iter()
            .map(|issue| format!("{}: {}", issue.path, issue.message))
            .collect::<Vec<_>>()
            .join("; ");
        anyhow::bail!("challenge commitment is not valid: {issues}");
    }
    write_json_file(&output, &commitment).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "commitmentPath": output.display().to_string(),
            "signature": signature,
            "commitment": commitment,
            "verification": verification
        }))?
    );
    Ok(())
}

async fn verify_challenge_commitment_command(commitment: PathBuf) -> Result<()> {
    let commitment_value: hivemind_benchmarks::ChallengeCommitmentV1 =
        read_json_file(&commitment).await?;
    let verification = hivemind_benchmarks::verify_challenge_commitment(&commitment_value);
    println!("{}", serde_json::to_string_pretty(&verification)?);
    Ok(())
}

async fn sign_challenge_commitment_command(
    commitment: PathBuf,
    identity: PathBuf,
    output: Option<PathBuf>,
) -> Result<()> {
    let mut commitment_value: hivemind_benchmarks::ChallengeCommitmentV1 =
        read_json_file(&commitment).await?;
    let identity_value: hivemind_identity::IdentityKeypairV1 = read_json_file(&identity).await?;
    let signature = hivemind_benchmarks::sign_challenge_commitment_with_identity(
        &mut commitment_value,
        &identity_value,
    )
    .with_context(|| {
        format!(
            "failed to sign challenge commitment with {}",
            identity.display()
        )
    })?;
    let verification = hivemind_benchmarks::verify_challenge_commitment(&commitment_value);
    if let Some(output) = output {
        write_json_file(&output, &commitment_value).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "commitmentPath": output.display().to_string(),
                "signature": signature,
                "commitment": commitment_value,
                "verification": verification
            }))?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "signature": signature,
                "commitment": commitment_value,
                "verification": verification
            }))?
        );
    }
    Ok(())
}

async fn challenge_commitments_command(commitments_dir: PathBuf) -> Result<()> {
    let summary = hivemind_benchmarks::list_challenge_commitments(&commitments_dir)
        .with_context(|| format!("failed to list {}", commitments_dir.display()))?;
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

async fn get_challenge_commitment_command(
    commitment_id: String,
    commitments_dir: PathBuf,
) -> Result<()> {
    let lookup = hivemind_benchmarks::get_challenge_commitment(&commitments_dir, &commitment_id)
        .with_context(|| format!("failed to read {}", commitments_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("challenge commitment {commitment_id} was not found"))?;
    println!("{}", serde_json::to_string_pretty(&lookup)?);
    Ok(())
}

async fn eval_command(command: EvalCommands) -> Result<()> {
    match command {
        EvalCommands::Init {
            path,
            name,
            owner,
            kind,
            dataset_refs,
            scoring_rule_refs,
            target_refs,
            grader_model_ref,
            output_schema_ref,
            metadata,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let metadata = match metadata {
                Some(path) => Some(read_json_file::<Value>(&path).await?),
                None => None,
            };
            let mut manifest =
                hivemind_evals::create_eval_manifest(hivemind_evals::EvalManifestInitOptionsV1 {
                    name,
                    owner,
                    kind: Some(parse_eval_kind(&kind)?),
                    dataset_refs,
                    scoring_rule_refs,
                    target_refs,
                    grader_model_ref,
                    output_schema_ref,
                    metadata,
                });
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_evals::sign_eval_manifest_with_identity(
                        &mut manifest,
                        &identity_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign eval manifest with {}",
                            identity_path.display()
                        )
                    })?,
                )
            } else {
                None
            };
            let verification = hivemind_evals::verify_eval_manifest(&manifest);
            write_json_file(&path, &manifest).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "manifestPath": path.display().to_string(),
                    "manifest": manifest,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        EvalCommands::Verify { manifest } => {
            let manifest_value: hivemind_evals::EvalManifestV1 = read_json_file(&manifest).await?;
            let verification = hivemind_evals::verify_eval_manifest(&manifest_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        EvalCommands::Sign {
            manifest,
            identity,
            output,
        } => {
            let mut manifest_value: hivemind_evals::EvalManifestV1 =
                read_json_file(&manifest).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_evals::sign_eval_manifest_with_identity(
                &mut manifest_value,
                &identity_value,
            )
            .with_context(|| format!("failed to sign eval manifest with {}", identity.display()))?;
            let verification = hivemind_evals::verify_eval_manifest(&manifest_value);
            if let Some(output) = output {
                write_json_file(&output, &manifest_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "manifestPath": output.display().to_string(),
                        "signature": signature,
                        "manifest": manifest_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "manifest": manifest_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        EvalCommands::RunInit {
            path,
            eval_id,
            requester,
            target_ref,
            input_refs,
            sample_count,
            privacy_tier,
            integrity_tier,
            settlement_method,
            report_ref,
            metadata,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let metadata = match metadata {
                Some(path) => Some(read_json_file::<Value>(&path).await?),
                None => None,
            };
            let mut run = hivemind_evals::create_eval_run(hivemind_evals::EvalRunInitOptionsV1 {
                eval_id,
                requester,
                target_ref,
                input_refs,
                sample_count,
                privacy_tier: Some(parse_privacy_tier(&privacy_tier)?),
                integrity_tier: Some(parse_integrity_tier(&integrity_tier)?),
                settlement_method: Some(settlement_method),
                report_ref,
                metadata,
            });
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_evals::sign_eval_run_with_identity(&mut run, &identity_value)
                        .with_context(|| {
                            format!("failed to sign eval run with {}", identity_path.display())
                        })?,
                )
            } else {
                None
            };
            let verification = hivemind_evals::verify_eval_run(&run);
            write_json_file(&path, &run).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "runPath": path.display().to_string(),
                    "run": run,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        EvalCommands::RunVerify { run } => {
            let run_value: hivemind_evals::EvalRunV1 = read_json_file(&run).await?;
            let verification = hivemind_evals::verify_eval_run(&run_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        EvalCommands::RunSign {
            run,
            identity,
            output,
        } => {
            let mut run_value: hivemind_evals::EvalRunV1 = read_json_file(&run).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature =
                hivemind_evals::sign_eval_run_with_identity(&mut run_value, &identity_value)
                    .with_context(|| {
                        format!("failed to sign eval run with {}", identity.display())
                    })?;
            let verification = hivemind_evals::verify_eval_run(&run_value);
            if let Some(output) = output {
                write_json_file(&output, &run_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "runPath": output.display().to_string(),
                        "signature": signature,
                        "run": run_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "run": run_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        EvalCommands::Plan { manifest, run } => {
            let manifest_value: hivemind_evals::EvalManifestV1 = read_json_file(&manifest).await?;
            let run_value: hivemind_evals::EvalRunV1 = read_json_file(&run).await?;
            let plan = hivemind_evals::eval_run_plan(&manifest_value, &run_value);
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(())
        }
        EvalCommands::List { evals_dir } => {
            let summary = hivemind_evals::list_eval_records(&evals_dir)
                .with_context(|| format!("failed to read {}", evals_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        EvalCommands::Get {
            record_id,
            evals_dir,
        } => {
            let lookup = hivemind_evals::get_eval_record(&evals_dir, &record_id)
                .with_context(|| format!("failed to read {}", evals_dir.display()))?
                .with_context(|| {
                    format!(
                        "eval record {record_id} was not found under {}",
                        evals_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
    }
}

async fn miner_command(command: MinerCommands) -> Result<()> {
    match command {
        MinerCommands::Profile {
            offer,
            daemon_version,
            identity,
            output,
        } => {
            let offer_value =
                read_json_file::<hivemind_marketplace::HardwareResourceOfferV1>(&offer).await?;
            let mut profile =
                hivemind_miner::miner_profile_from_hardware_offer(&offer_value, daemon_version);
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_miner::sign_miner_profile_with_identity(&mut profile, &identity_value)
                        .with_context(|| {
                            format!(
                                "failed to sign miner profile with {}",
                                identity_path.display()
                            )
                        })?,
                )
            } else {
                None
            };
            let verification = hivemind_miner::verify_miner_profile(&profile, Some(&offer_value));
            if let Some(output) = output {
                write_json_file(&output, &profile).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "profilePath": output.display().to_string(),
                        "signature": signature,
                        "profile": profile,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "profile": profile,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        MinerCommands::VerifyProfile { profile, offer } => {
            let profile_value = read_json_file::<hivemind_miner::MinerProfileV1>(&profile).await?;
            let offer_value = if let Some(offer) = offer {
                Some(read_json_file::<hivemind_marketplace::HardwareResourceOfferV1>(&offer).await?)
            } else {
                None
            };
            let verification =
                hivemind_miner::verify_miner_profile(&profile_value, offer_value.as_ref());
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        MinerCommands::Heartbeat {
            profile,
            status,
            queue_depth,
            active_jobs,
            current_job_ids,
            load_average,
            output,
        } => {
            let profile_value = read_json_file::<hivemind_miner::MinerProfileV1>(&profile).await?;
            let status = parse_miner_daemon_status(&status)?;
            let heartbeat = hivemind_miner::miner_heartbeat_from_profile(
                &profile_value,
                status,
                queue_depth,
                active_jobs,
                current_job_ids,
                load_average,
            );
            let verification =
                hivemind_miner::verify_miner_heartbeat(&heartbeat, Some(&profile_value));
            if let Some(output) = output {
                write_json_file(&output, &heartbeat).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "heartbeatPath": output.display().to_string(),
                        "heartbeat": heartbeat,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "heartbeat": heartbeat,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        MinerCommands::VerifyHeartbeat { heartbeat, profile } => {
            let heartbeat_value =
                read_json_file::<hivemind_miner::MinerHeartbeatV1>(&heartbeat).await?;
            let profile_value = if let Some(profile) = profile {
                Some(read_json_file::<hivemind_miner::MinerProfileV1>(&profile).await?)
            } else {
                None
            };
            let verification =
                hivemind_miner::verify_miner_heartbeat(&heartbeat_value, profile_value.as_ref());
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        MinerCommands::Benchmark {
            profile,
            offer,
            suite,
            workload,
            metrics,
            evidence_refs,
            identity,
            output,
        } => {
            let profile_value = read_json_file::<hivemind_miner::MinerProfileV1>(&profile).await?;
            let offer_value =
                read_json_file::<hivemind_marketplace::HardwareResourceOfferV1>(&offer).await?;
            let metrics = parse_miner_benchmark_metrics(metrics)?;
            let mut benchmark = hivemind_miner::miner_benchmark_result(
                &profile_value,
                &offer_value,
                suite,
                workload,
                metrics,
                evidence_refs,
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_miner::sign_miner_benchmark_result_with_identity(
                        &mut benchmark,
                        &identity_value,
                        &profile_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign miner benchmark with {}",
                            identity_path.display()
                        )
                    })?,
                )
            } else {
                None
            };
            let verification = hivemind_miner::verify_miner_benchmark_result(
                &benchmark,
                Some(&profile_value),
                Some(&offer_value),
            );
            if let Some(output) = output {
                write_json_file(&output, &benchmark).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "benchmarkPath": output.display().to_string(),
                        "signature": signature,
                        "benchmark": benchmark,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "benchmark": benchmark,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        MinerCommands::VerifyBenchmark {
            benchmark,
            profile,
            offer,
        } => {
            let benchmark_value =
                read_json_file::<hivemind_miner::MinerBenchmarkResultV1>(&benchmark).await?;
            let profile_value = if let Some(profile) = profile {
                Some(read_json_file::<hivemind_miner::MinerProfileV1>(&profile).await?)
            } else {
                None
            };
            let offer_value = if let Some(offer) = offer {
                Some(read_json_file::<hivemind_marketplace::HardwareResourceOfferV1>(&offer).await?)
            } else {
                None
            };
            let verification = hivemind_miner::verify_miner_benchmark_result(
                &benchmark_value,
                profile_value.as_ref(),
                offer_value.as_ref(),
            );
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        MinerCommands::Onboarding {
            profile,
            offer,
            benchmarks,
        } => {
            let profile_value = read_json_file::<hivemind_miner::MinerProfileV1>(&profile).await?;
            let offer_value =
                read_json_file::<hivemind_marketplace::HardwareResourceOfferV1>(&offer).await?;
            let benchmarks = read_miner_benchmark_files(benchmarks).await?;
            let plan =
                hivemind_miner::miner_onboarding_plan(&profile_value, &offer_value, &benchmarks);
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(())
        }
        MinerCommands::Dashboard {
            profile,
            heartbeat,
            offer,
            benchmarks,
            completed_jobs,
            settled_jobs,
            disputed_jobs,
            earning_amount,
            earning_currency,
        } => {
            let profile_value = read_json_file::<hivemind_miner::MinerProfileV1>(&profile).await?;
            let heartbeat_value =
                read_json_file::<hivemind_miner::MinerHeartbeatV1>(&heartbeat).await?;
            let offer_value =
                read_json_file::<hivemind_marketplace::HardwareResourceOfferV1>(&offer).await?;
            let benchmarks = read_miner_benchmark_files(benchmarks).await?;
            let summary =
                hivemind_miner::miner_dashboard_summary(hivemind_miner::MinerDashboardInputV1 {
                    profile: profile_value,
                    heartbeat: heartbeat_value,
                    hardware_offer: offer_value,
                    benchmarks,
                    completed_jobs,
                    settled_jobs,
                    disputed_jobs,
                    estimated_earnings: Some(hivemind_core::PriceV1 {
                        amount: earning_amount,
                        currency: earning_currency,
                    }),
                });
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        MinerCommands::List { miner_dir } => {
            let summary = hivemind_miner::list_miner_records(&miner_dir)
                .with_context(|| format!("failed to read {}", miner_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        MinerCommands::Get {
            record_id,
            miner_dir,
        } => {
            let lookup = hivemind_miner::get_miner_record(&miner_dir, &record_id)
                .with_context(|| format!("failed to read {}", miner_dir.display()))?
                .with_context(|| {
                    format!(
                        "miner record {record_id} was not found under {}",
                        miner_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
    }
}

async fn experiment_command(command: ExperimentCommands) -> Result<()> {
    match command {
        ExperimentCommands::Init {
            path,
            title,
            author,
            organization,
            hypothesis,
            package_refs,
            model_refs,
            dataset_refs,
            benchmark_refs,
            scoring_method_ref,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let mut experiment = hivemind_research::create_research_experiment(
                hivemind_research::ResearchExperimentInitOptionsV1 {
                    title,
                    author,
                    organization,
                    hypothesis,
                    package_refs,
                    model_refs,
                    dataset_refs,
                    benchmark_refs,
                    scoring_method_ref,
                },
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_research::sign_research_experiment_with_identity(
                        &mut experiment,
                        &identity_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign research experiment with {}",
                            identity_path.display()
                        )
                    })?,
                )
            } else {
                None
            };
            let verification = hivemind_research::verify_research_experiment(&experiment);
            write_json_file(&path, &experiment).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "experimentPath": path.display().to_string(),
                    "experiment": experiment,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        ExperimentCommands::Verify { experiment } => {
            let experiment_value: hivemind_research::ResearchExperimentV1 =
                read_json_file(&experiment).await?;
            let verification = hivemind_research::verify_research_experiment(&experiment_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        ExperimentCommands::Sign {
            experiment,
            identity,
            output,
        } => {
            let mut experiment_value: hivemind_research::ResearchExperimentV1 =
                read_json_file(&experiment).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_research::sign_research_experiment_with_identity(
                &mut experiment_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign research experiment with {}",
                    identity.display()
                )
            })?;
            let verification = hivemind_research::verify_research_experiment(&experiment_value);
            if let Some(output) = output {
                write_json_file(&output, &experiment_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "experimentPath": output.display().to_string(),
                        "signature": signature,
                        "experiment": experiment_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "experiment": experiment_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        ExperimentCommands::Reproduce { experiment, runner } => {
            let experiment_value: hivemind_research::ResearchExperimentV1 =
                read_json_file(&experiment).await?;
            let verification = hivemind_research::verify_research_experiment(&experiment_value);
            let plan = hivemind_research::reproduction_plan(&experiment_value, runner);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "verification": verification,
                    "plan": plan
                }))?
            );
            Ok(())
        }
        ExperimentCommands::RunInit {
            experiment,
            output,
            requester,
            runner,
            status,
            receipt_refs,
            evaluation_result_refs,
            validation_report_refs,
            output_refs,
            notes,
            identity,
            force,
        } => {
            if output.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    output.display()
                );
            }
            let experiment_value: hivemind_research::ResearchExperimentV1 =
                read_json_file(&experiment).await?;
            let status = parse_research_run_status(&status)?;
            let mut run = hivemind_research::create_research_experiment_run(
                &experiment_value,
                hivemind_research::ResearchExperimentRunInitOptionsV1 {
                    requester,
                    runner,
                    status: Some(status),
                    receipt_refs,
                    evaluation_result_refs,
                    validation_report_refs,
                    output_refs,
                    cost: None,
                    notes,
                    metadata: None,
                },
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_research::sign_research_experiment_run_with_identity(
                        &mut run,
                        &identity_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign research run with {}",
                            identity_path.display()
                        )
                    })?,
                )
            } else {
                None
            };
            let verification =
                hivemind_research::verify_research_experiment_run(&run, Some(&experiment_value));
            write_json_file(&output, &run).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "runPath": output.display().to_string(),
                    "signature": signature,
                    "run": run,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        ExperimentCommands::RunVerify { run, experiment } => {
            let run_value: hivemind_research::ResearchExperimentRunV1 =
                read_json_file(&run).await?;
            let experiment_value = if let Some(experiment) = experiment {
                Some(read_json_file::<hivemind_research::ResearchExperimentV1>(&experiment).await?)
            } else {
                None
            };
            let verification = hivemind_research::verify_research_experiment_run(
                &run_value,
                experiment_value.as_ref(),
            );
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        ExperimentCommands::RunSign {
            run,
            identity,
            output,
        } => {
            let mut run_value: hivemind_research::ResearchExperimentRunV1 =
                read_json_file(&run).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_research::sign_research_experiment_run_with_identity(
                &mut run_value,
                &identity_value,
            )
            .with_context(|| format!("failed to sign research run with {}", identity.display()))?;
            let verification = hivemind_research::verify_research_experiment_run(&run_value, None);
            if let Some(output) = output {
                write_json_file(&output, &run_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "runPath": output.display().to_string(),
                        "signature": signature,
                        "run": run_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "run": run_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        ExperimentCommands::RunList { runs_dir } => {
            let summary = hivemind_research::list_research_experiment_runs(&runs_dir)
                .with_context(|| format!("failed to list {}", runs_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        ExperimentCommands::RunGet { run_id, runs_dir } => {
            let lookup = hivemind_research::get_research_experiment_run(&runs_dir, &run_id)
                .with_context(|| format!("failed to read {}", runs_dir.display()))?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "research run {run_id} was not found in {}",
                        runs_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
        ExperimentCommands::List { experiments_dir } => {
            let summary = hivemind_research::list_research_experiments(&experiments_dir)
                .with_context(|| format!("failed to list {}", experiments_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        ExperimentCommands::Get {
            experiment_id,
            experiments_dir,
        } => {
            let lookup =
                hivemind_research::get_research_experiment(&experiments_dir, &experiment_id)
                    .with_context(|| format!("failed to read {}", experiments_dir.display()))?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "research experiment {experiment_id} was not found in {}",
                            experiments_dir.display()
                        )
                    })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
    }
}

async fn vector_command(command: VectorCommands) -> Result<()> {
    match command {
        VectorCommands::Init {
            path,
            name,
            owner,
            embedding_model_ref,
            document_collection_refs,
            index_format,
            dimensions,
            metric,
            chunking_strategy_ref,
            storage_refs,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let storage_refs = parse_vector_storage_refs(storage_refs)?;
            let mut manifest = hivemind_vector::create_vector_store_manifest(
                hivemind_vector::VectorStoreInitOptionsV1 {
                    name,
                    owner,
                    embedding_model_ref,
                    document_collection_refs,
                    index_format: Some(index_format),
                    dimensions,
                    metric: Some(parse_vector_metric(&metric)?),
                    chunking_strategy_ref: Some(chunking_strategy_ref),
                    storage_refs,
                    access_policy: None,
                },
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_vector::sign_vector_store_with_identity(
                        &mut manifest,
                        &identity_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign vector store manifest with {}",
                            identity_path.display()
                        )
                    })?,
                )
            } else {
                None
            };
            let verification = hivemind_vector::verify_vector_store_manifest(&manifest);
            write_json_file(&path, &manifest).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "manifestPath": path.display().to_string(),
                    "manifest": manifest,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        VectorCommands::Verify { manifest } => {
            let manifest_value: hivemind_vector::VectorStoreManifestV1 =
                read_json_file(&manifest).await?;
            let verification = hivemind_vector::verify_vector_store_manifest(&manifest_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        VectorCommands::Sign {
            manifest,
            identity,
            output,
        } => {
            let mut manifest_value: hivemind_vector::VectorStoreManifestV1 =
                read_json_file(&manifest).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_vector::sign_vector_store_with_identity(
                &mut manifest_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign vector store manifest with {}",
                    identity.display()
                )
            })?;
            let verification = hivemind_vector::verify_vector_store_manifest(&manifest_value);
            if let Some(output) = output {
                write_json_file(&output, &manifest_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "manifestPath": output.display().to_string(),
                        "signature": signature,
                        "manifest": manifest_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "manifest": manifest_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        VectorCommands::Plan {
            manifest,
            vector_store_ref,
            requester,
            text,
            query,
            top_k,
            privacy_tier,
            trace_required,
        } => {
            let manifest_value: hivemind_vector::VectorStoreManifestV1 =
                read_json_file(&manifest).await?;
            let query_value = if let Some(query_path) = query {
                read_json_file::<Value>(&query_path).await?
            } else {
                json!({ "text": text.unwrap_or_else(|| "search".to_string()) })
            };
            let mut request = hivemind_vector::vector_search_request(
                vector_store_ref
                    .unwrap_or_else(|| format!("local://{}", manifest_value.vector_store_id)),
                manifest_value.vector_store_id.clone(),
                requester,
                query_value,
            );
            request.top_k = top_k;
            request.privacy_tier = parse_privacy_tier(&privacy_tier)?;
            request.trace_required = trace_required;
            let plan = hivemind_vector::vector_search_plan(&manifest_value, &request);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "request": request,
                    "plan": plan
                }))?
            );
            Ok(())
        }
        VectorCommands::List { vector_dir } => {
            let summary = hivemind_vector::list_vector_store_manifests(&vector_dir)
                .with_context(|| format!("failed to list {}", vector_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        VectorCommands::Get {
            vector_store_id,
            vector_dir,
        } => {
            let lookup = hivemind_vector::get_vector_store_manifest(&vector_dir, &vector_store_id)
                .with_context(|| format!("failed to read {}", vector_dir.display()))?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "vector store {vector_store_id} was not found in {}",
                        vector_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
    }
}

async fn workflow_command(command: WorkflowCommands) -> Result<()> {
    match command {
        WorkflowCommands::ToolInit {
            path,
            name,
            description,
            publisher,
            execution_modes,
            safety_policy_refs,
            permissions,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let mut tool = hivemind_workflow::create_tool_manifest(
                hivemind_workflow::ToolManifestInitOptionsV1 {
                    name,
                    description,
                    publisher,
                    execution_modes: parse_tool_execution_modes(execution_modes)?,
                    safety_policy_refs,
                    permissions: parse_permission_requests(permissions)?,
                },
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_workflow::sign_tool_with_identity(&mut tool, &identity_value)
                        .with_context(|| {
                            format!(
                                "failed to sign tool manifest with {}",
                                identity_path.display()
                            )
                        })?,
                )
            } else {
                None
            };
            let verification = hivemind_workflow::verify_tool_manifest(&tool);
            write_json_file(&path, &tool).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "toolPath": path.display().to_string(),
                    "tool": tool,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        WorkflowCommands::ToolVerify { tool } => {
            let tool_value: hivemind_workflow::ToolManifestV1 = read_json_file(&tool).await?;
            let verification = hivemind_workflow::verify_tool_manifest(&tool_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        WorkflowCommands::ToolSign {
            tool,
            identity,
            output,
        } => {
            let mut tool_value: hivemind_workflow::ToolManifestV1 = read_json_file(&tool).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature =
                hivemind_workflow::sign_tool_with_identity(&mut tool_value, &identity_value)
                    .with_context(|| {
                        format!("failed to sign tool manifest with {}", identity.display())
                    })?;
            let verification = hivemind_workflow::verify_tool_manifest(&tool_value);
            if let Some(output) = output {
                write_json_file(&output, &tool_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "toolPath": output.display().to_string(),
                        "signature": signature,
                        "tool": tool_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "tool": tool_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        WorkflowCommands::Init {
            path,
            name,
            publisher,
            tool_refs,
            package_refs,
            vector_store_refs,
            failure_policy,
            trace_policy,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let mut workflow = hivemind_workflow::create_workflow_manifest(
                hivemind_workflow::WorkflowManifestInitOptionsV1 {
                    name,
                    publisher,
                    tool_refs,
                    package_refs,
                    vector_store_refs,
                    failure_policy: Some(parse_workflow_failure_policy(&failure_policy)?),
                    trace_policy: Some(parse_workflow_trace_policy(&trace_policy)?),
                },
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_workflow::sign_workflow_with_identity(&mut workflow, &identity_value)
                        .with_context(|| {
                            format!(
                                "failed to sign workflow manifest with {}",
                                identity_path.display()
                            )
                        })?,
                )
            } else {
                None
            };
            let verification = hivemind_workflow::verify_workflow_manifest(&workflow);
            write_json_file(&path, &workflow).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "workflowPath": path.display().to_string(),
                    "workflow": workflow,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        WorkflowCommands::Verify { workflow } => {
            let workflow_value: hivemind_workflow::WorkflowManifestV1 =
                read_json_file(&workflow).await?;
            let verification = hivemind_workflow::verify_workflow_manifest(&workflow_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        WorkflowCommands::Sign {
            workflow,
            identity,
            output,
        } => {
            let mut workflow_value: hivemind_workflow::WorkflowManifestV1 =
                read_json_file(&workflow).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_workflow::sign_workflow_with_identity(
                &mut workflow_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign workflow manifest with {}",
                    identity.display()
                )
            })?;
            let verification = hivemind_workflow::verify_workflow_manifest(&workflow_value);
            if let Some(output) = output {
                write_json_file(&output, &workflow_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "workflowPath": output.display().to_string(),
                        "signature": signature,
                        "workflow": workflow_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "workflow": workflow_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        WorkflowCommands::Plan { workflow } => {
            let workflow_value: hivemind_workflow::WorkflowManifestV1 =
                read_json_file(&workflow).await?;
            let plan = hivemind_workflow::workflow_plan(&workflow_value);
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(())
        }
        WorkflowCommands::List { workflow_dir } => {
            let summary = hivemind_workflow::list_workflow_records(&workflow_dir)
                .with_context(|| format!("failed to list {}", workflow_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        WorkflowCommands::Get {
            record_id,
            workflow_dir,
        } => {
            let lookup = hivemind_workflow::get_workflow_record(&workflow_dir, &record_id)
                .with_context(|| format!("failed to read {}", workflow_dir.display()))?
                .with_context(|| {
                    format!(
                        "workflow record {record_id} was not found under {}",
                        workflow_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
    }
}

async fn batch_command(command: BatchCommands) -> Result<()> {
    match command {
        BatchCommands::Init {
            path,
            requester,
            package_ref,
            package_id,
            package_version,
            task,
            api_surface,
            items,
            max_concurrency,
            checkpoint_every_items,
            partial_result_policy,
            settlement_method,
            privacy_tier,
            integrity_tier,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let mut batch =
                hivemind_batch::create_batch_job(hivemind_batch::BatchJobInitOptionsV1 {
                    requester,
                    package_ref,
                    package_id,
                    package_version,
                    task,
                    api_surface: Some(parse_api_surface(&api_surface)?),
                    items: parse_batch_items(items)?,
                    max_concurrency,
                    checkpoint_every_items,
                    partial_result_policy: Some(parse_batch_partial_result_policy(
                        &partial_result_policy,
                    )?),
                    settlement_method: Some(settlement_method),
                    privacy_tier: Some(parse_privacy_tier(&privacy_tier)?),
                    integrity_tier: Some(parse_integrity_tier(&integrity_tier)?),
                });
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_batch::sign_batch_job_with_identity(&mut batch, &identity_value)
                        .with_context(|| {
                            format!("failed to sign batch job with {}", identity_path.display())
                        })?,
                )
            } else {
                None
            };
            let verification = hivemind_batch::verify_batch_job(&batch);
            write_json_file(&path, &batch).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "batchPath": path.display().to_string(),
                    "batch": batch,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        BatchCommands::Verify { batch } => {
            let batch_value: hivemind_batch::BatchJobV1 = read_json_file(&batch).await?;
            let verification = hivemind_batch::verify_batch_job(&batch_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        BatchCommands::Sign {
            batch,
            identity,
            output,
        } => {
            let mut batch_value: hivemind_batch::BatchJobV1 = read_json_file(&batch).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature =
                hivemind_batch::sign_batch_job_with_identity(&mut batch_value, &identity_value)
                    .with_context(|| {
                        format!("failed to sign batch job with {}", identity.display())
                    })?;
            let verification = hivemind_batch::verify_batch_job(&batch_value);
            if let Some(output) = output {
                write_json_file(&output, &batch_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "batchPath": output.display().to_string(),
                        "signature": signature,
                        "batch": batch_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "batch": batch_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        BatchCommands::Plan { batch } => {
            let batch_value: hivemind_batch::BatchJobV1 = read_json_file(&batch).await?;
            let plan = hivemind_batch::batch_execution_plan(&batch_value);
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(())
        }
        BatchCommands::List { batch_dir } => {
            let summary = hivemind_batch::list_batch_jobs(&batch_dir)
                .with_context(|| format!("failed to list {}", batch_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        BatchCommands::Get {
            batch_id,
            batch_dir,
        } => {
            let lookup = hivemind_batch::get_batch_job(&batch_dir, &batch_id)
                .with_context(|| format!("failed to read {}", batch_dir.display()))?
                .with_context(|| {
                    format!(
                        "batch job {batch_id} was not found under {}",
                        batch_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
    }
}

async fn fine_tune_command(command: FineTuneCommands) -> Result<()> {
    match command {
        FineTuneCommands::Init {
            path,
            requester,
            base_model_ref,
            training_dataset_refs,
            validation_dataset_refs,
            recipe_ref,
            hyperparameters,
            output_ref,
            artifact_kind,
            output_visibility,
            privacy_tier,
            integrity_tier,
            max_cost_amount,
            max_cost_currency,
            validation_required,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let hyperparameters = if let Some(path) = hyperparameters {
                Some(read_json_file::<Value>(&path).await?)
            } else {
                None
            };
            let max_cost = max_cost_amount.map(|amount| hivemind_core::PriceV1 {
                amount,
                currency: max_cost_currency,
            });
            let mut job = hivemind_fine_tune::create_fine_tune_job(
                hivemind_fine_tune::FineTuneJobInitOptionsV1 {
                    requester,
                    base_model_ref,
                    training_dataset_refs,
                    validation_dataset_refs,
                    recipe_ref: Some(recipe_ref),
                    hyperparameters,
                    output_ref,
                    artifact_kind: Some(parse_fine_tune_output_artifact_kind(&artifact_kind)?),
                    output_visibility: Some(parse_fine_tune_output_visibility(&output_visibility)?),
                    privacy_tier: Some(parse_privacy_tier(&privacy_tier)?),
                    integrity_tier: Some(parse_integrity_tier(&integrity_tier)?),
                    max_cost,
                    validation_required: Some(validation_required),
                },
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_fine_tune::sign_fine_tune_job_with_identity(&mut job, &identity_value)
                        .with_context(|| {
                            format!(
                                "failed to sign fine-tune job with {}",
                                identity_path.display()
                            )
                        })?,
                )
            } else {
                None
            };
            let verification = hivemind_fine_tune::verify_fine_tune_job(&job);
            write_json_file(&path, &job).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "jobPath": path.display().to_string(),
                    "job": job,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        FineTuneCommands::Verify { job } => {
            let job_value: hivemind_fine_tune::FineTuneJobV1 = read_json_file(&job).await?;
            let verification = hivemind_fine_tune::verify_fine_tune_job(&job_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        FineTuneCommands::Sign {
            job,
            identity,
            output,
        } => {
            let mut job_value: hivemind_fine_tune::FineTuneJobV1 = read_json_file(&job).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_fine_tune::sign_fine_tune_job_with_identity(
                &mut job_value,
                &identity_value,
            )
            .with_context(|| format!("failed to sign fine-tune job with {}", identity.display()))?;
            let verification = hivemind_fine_tune::verify_fine_tune_job(&job_value);
            if let Some(output) = output {
                write_json_file(&output, &job_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "jobPath": output.display().to_string(),
                        "signature": signature,
                        "job": job_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "job": job_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        FineTuneCommands::Plan { job } => {
            let job_value: hivemind_fine_tune::FineTuneJobV1 = read_json_file(&job).await?;
            let plan = hivemind_fine_tune::fine_tune_execution_plan(&job_value);
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(())
        }
        FineTuneCommands::List { fine_tune_dir } => {
            let summary = hivemind_fine_tune::list_fine_tune_jobs(&fine_tune_dir)
                .with_context(|| format!("failed to list {}", fine_tune_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        FineTuneCommands::Get {
            fine_tune_job_id,
            fine_tune_dir,
        } => {
            let lookup = hivemind_fine_tune::get_fine_tune_job(&fine_tune_dir, &fine_tune_job_id)
                .with_context(|| format!("failed to read {}", fine_tune_dir.display()))?
                .with_context(|| {
                    format!(
                        "fine-tune job {fine_tune_job_id} was not found under {}",
                        fine_tune_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
    }
}

async fn realtime_command(command: RealtimeCommands) -> Result<()> {
    match command {
        RealtimeCommands::Init {
            path,
            requester,
            package_ref,
            package_id,
            package_version,
            service_ref,
            model_alias,
            modalities_in,
            modalities_out,
            transport,
            latency_target_ms,
            interruptions_allowed,
            tool_refs,
            privacy_tier,
            settlement_method,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let mut session = hivemind_realtime::create_realtime_session(
                hivemind_realtime::RealtimeSessionInitOptionsV1 {
                    requester,
                    package_ref,
                    package_id,
                    package_version,
                    service_ref,
                    model_alias,
                    modalities_in: parse_modalities(modalities_in)?,
                    modalities_out: parse_modalities(modalities_out)?,
                    transport: Some(parse_realtime_transport(&transport)?),
                    latency_target_ms: Some(latency_target_ms),
                    interruptions_allowed: Some(interruptions_allowed),
                    tool_refs,
                    privacy_tier: Some(parse_privacy_tier(&privacy_tier)?),
                    settlement_method: Some(settlement_method),
                },
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_realtime::sign_realtime_session_with_identity(
                        &mut session,
                        &identity_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign realtime session with {}",
                            identity_path.display()
                        )
                    })?,
                )
            } else {
                None
            };
            let verification = hivemind_realtime::verify_realtime_session(&session);
            write_json_file(&path, &session).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "sessionPath": path.display().to_string(),
                    "session": session,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        RealtimeCommands::Verify { session } => {
            let session_value: hivemind_realtime::RealtimeSessionV1 =
                read_json_file(&session).await?;
            let verification = hivemind_realtime::verify_realtime_session(&session_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        RealtimeCommands::Sign {
            session,
            identity,
            output,
        } => {
            let mut session_value: hivemind_realtime::RealtimeSessionV1 =
                read_json_file(&session).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_realtime::sign_realtime_session_with_identity(
                &mut session_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign realtime session with {}",
                    identity.display()
                )
            })?;
            let verification = hivemind_realtime::verify_realtime_session(&session_value);
            if let Some(output) = output {
                write_json_file(&output, &session_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "sessionPath": output.display().to_string(),
                        "signature": signature,
                        "session": session_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "session": session_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        RealtimeCommands::Plan { session } => {
            let session_value: hivemind_realtime::RealtimeSessionV1 =
                read_json_file(&session).await?;
            let plan = hivemind_realtime::realtime_connection_plan(&session_value);
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(())
        }
        RealtimeCommands::List { realtime_dir } => {
            let summary = hivemind_realtime::list_realtime_sessions(&realtime_dir)
                .with_context(|| format!("failed to list {}", realtime_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        RealtimeCommands::Get {
            session_id,
            realtime_dir,
        } => {
            let lookup = hivemind_realtime::get_realtime_session(&realtime_dir, &session_id)
                .with_context(|| format!("failed to read {}", realtime_dir.display()))?
                .with_context(|| {
                    format!(
                        "realtime session {session_id} was not found under {}",
                        realtime_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
    }
}

async fn media_command(command: MediaCommands) -> Result<()> {
    match command {
        MediaCommands::Init {
            path,
            requester,
            task,
            package_ref,
            package_id,
            package_version,
            service_ref,
            model_alias,
            prompt,
            text,
            input_ref,
            mask_ref,
            parameters,
            response_format,
            output_ref,
            count,
            size,
            quality,
            style,
            voice,
            audio_format,
            privacy_tier,
            integrity_tier,
            settlement_method,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let parameters_value = if let Some(parameters_path) = parameters {
                Some(read_json_file(&parameters_path).await.with_context(|| {
                    format!("failed to read parameters {}", parameters_path.display())
                })?)
            } else {
                None
            };
            let mut job = hivemind_media::create_media_job(hivemind_media::MediaJobInitOptionsV1 {
                requester,
                task: parse_media_task(&task)?,
                package_ref,
                package_id,
                package_version,
                service_ref,
                model_alias,
                prompt,
                text,
                input_ref,
                mask_ref,
                parameters: parameters_value,
                response_format: Some(response_format),
                output_ref,
                count: Some(count),
                size,
                quality,
                style,
                voice,
                audio_format,
                privacy_tier: Some(parse_privacy_tier(&privacy_tier)?),
                integrity_tier: Some(parse_integrity_tier(&integrity_tier)?),
                settlement_method: Some(settlement_method),
            });
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_media::sign_media_job_with_identity(&mut job, &identity_value)
                        .with_context(|| {
                            format!("failed to sign media job with {}", identity_path.display())
                        })?,
                )
            } else {
                None
            };
            let verification = hivemind_media::verify_media_job(&job);
            write_json_file(&path, &job).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "jobPath": path.display().to_string(),
                    "job": job,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        MediaCommands::Verify { job } => {
            let job_value: hivemind_media::MediaJobV1 = read_json_file(&job).await?;
            let verification = hivemind_media::verify_media_job(&job_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        MediaCommands::Sign {
            job,
            identity,
            output,
        } => {
            let mut job_value: hivemind_media::MediaJobV1 = read_json_file(&job).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature =
                hivemind_media::sign_media_job_with_identity(&mut job_value, &identity_value)
                    .with_context(|| {
                        format!("failed to sign media job with {}", identity.display())
                    })?;
            let verification = hivemind_media::verify_media_job(&job_value);
            if let Some(output) = output {
                write_json_file(&output, &job_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "jobPath": output.display().to_string(),
                        "signature": signature,
                        "job": job_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "job": job_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        MediaCommands::Plan { job } => {
            let job_value: hivemind_media::MediaJobV1 = read_json_file(&job).await?;
            let plan = hivemind_media::media_execution_plan(&job_value);
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(())
        }
        MediaCommands::List { media_dir } => {
            let summary = hivemind_media::list_media_jobs(&media_dir)
                .with_context(|| format!("failed to list {}", media_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        MediaCommands::Get {
            media_job_id,
            media_dir,
        } => {
            let lookup = hivemind_media::get_media_job(&media_dir, &media_job_id)
                .with_context(|| format!("failed to read {}", media_dir.display()))?
                .with_context(|| {
                    format!(
                        "media job {media_job_id} was not found under {}",
                        media_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
    }
}

async fn moderation_command(command: ModerationCommands) -> Result<()> {
    match command {
        ModerationCommands::PolicyInit {
            path,
            name,
            publisher,
            description,
            model_refs,
            safety_policy_refs,
            evidence_refs,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let mut policy = hivemind_moderation::create_moderation_policy(
                hivemind_moderation::ModerationPolicyInitOptionsV1 {
                    name,
                    publisher,
                    description,
                    model_refs,
                    safety_policy_refs,
                    evidence_refs,
                },
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_moderation::sign_moderation_policy_with_identity(
                        &mut policy,
                        &identity_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign moderation policy with {}",
                            identity_path.display()
                        )
                    })?,
                )
            } else {
                None
            };
            let verification = hivemind_moderation::verify_moderation_policy(&policy);
            write_json_file(&path, &policy).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "policyPath": path.display().to_string(),
                    "policy": policy,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        ModerationCommands::PolicyVerify { policy } => {
            let policy_value: hivemind_moderation::ModerationPolicyManifestV1 =
                read_json_file(&policy).await?;
            let verification = hivemind_moderation::verify_moderation_policy(&policy_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        ModerationCommands::PolicySign {
            policy,
            identity,
            output,
        } => {
            let mut policy_value: hivemind_moderation::ModerationPolicyManifestV1 =
                read_json_file(&policy).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_moderation::sign_moderation_policy_with_identity(
                &mut policy_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign moderation policy with {}",
                    identity.display()
                )
            })?;
            let verification = hivemind_moderation::verify_moderation_policy(&policy_value);
            if let Some(output) = output {
                write_json_file(&output, &policy_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "policyPath": output.display().to_string(),
                        "signature": signature,
                        "policy": policy_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "policy": policy_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        ModerationCommands::RequestInit {
            path,
            requester,
            package_ref,
            package_id,
            package_version,
            service_ref,
            model_alias,
            policy_ref,
            text,
            input,
            input_ref,
            modalities,
            categories,
            privacy_tier,
            integrity_tier,
            trace_required,
            settlement_method,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let inline_input = read_moderation_input(text, input, input_ref.as_ref()).await?;
            let mut request = hivemind_moderation::create_moderation_request(
                hivemind_moderation::ModerationRequestInitOptionsV1 {
                    requester,
                    package_ref,
                    package_id,
                    package_version,
                    service_ref,
                    model_alias,
                    policy_ref: Some(policy_ref),
                    input: inline_input,
                    input_ref,
                    modalities: parse_modalities(modalities)?,
                    categories,
                    privacy_tier: Some(parse_privacy_tier(&privacy_tier)?),
                    integrity_tier: Some(parse_integrity_tier(&integrity_tier)?),
                    trace_required: Some(trace_required),
                    settlement_method: Some(settlement_method),
                },
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_moderation::sign_moderation_request_with_identity(
                        &mut request,
                        &identity_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign moderation request with {}",
                            identity_path.display()
                        )
                    })?,
                )
            } else {
                None
            };
            let verification = hivemind_moderation::verify_moderation_request(&request);
            write_json_file(&path, &request).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "requestPath": path.display().to_string(),
                    "request": request,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        ModerationCommands::RequestVerify { request } => {
            let request_value: hivemind_moderation::ModerationRequestV1 =
                read_json_file(&request).await?;
            let verification = hivemind_moderation::verify_moderation_request(&request_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        ModerationCommands::RequestSign {
            request,
            identity,
            output,
        } => {
            let mut request_value: hivemind_moderation::ModerationRequestV1 =
                read_json_file(&request).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_moderation::sign_moderation_request_with_identity(
                &mut request_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign moderation request with {}",
                    identity.display()
                )
            })?;
            let verification = hivemind_moderation::verify_moderation_request(&request_value);
            if let Some(output) = output {
                write_json_file(&output, &request_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "requestPath": output.display().to_string(),
                        "signature": signature,
                        "request": request_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "request": request_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        ModerationCommands::Plan { request, policy } => {
            let request_value: hivemind_moderation::ModerationRequestV1 =
                read_json_file(&request).await?;
            let policy_value = if let Some(policy) = policy {
                Some(
                    read_json_file::<hivemind_moderation::ModerationPolicyManifestV1>(&policy)
                        .await?,
                )
            } else {
                None
            };
            let plan = hivemind_moderation::moderation_plan_with_policy(
                &request_value,
                policy_value.as_ref(),
            );
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(())
        }
        ModerationCommands::List { moderation_dir } => {
            let summary = hivemind_moderation::list_moderation_records(&moderation_dir)
                .with_context(|| format!("failed to read {}", moderation_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        ModerationCommands::Get {
            record_id,
            moderation_dir,
        } => {
            let lookup = hivemind_moderation::get_moderation_record(&moderation_dir, &record_id)
                .with_context(|| format!("failed to read {}", moderation_dir.display()))?
                .with_context(|| {
                    format!(
                        "moderation record {record_id} was not found under {}",
                        moderation_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
    }
}

async fn governance_command(command: GovernanceCommands) -> Result<()> {
    match command {
        GovernanceCommands::PolicyInit {
            path,
            title,
            steward,
            scopes,
            approved_schema_versions,
            compatibility_test_refs,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let mut policy = hivemind_governance::create_governance_policy(
                hivemind_governance::GovernancePolicyInitOptionsV1 {
                    title,
                    steward,
                    scopes: parse_governance_scopes(scopes)?,
                    approved_schema_versions,
                    compatibility_test_refs,
                },
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_governance::sign_governance_policy_with_identity(
                        &mut policy,
                        &identity_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign governance policy with {}",
                            identity_path.display()
                        )
                    })?,
                )
            } else {
                None
            };
            let verification = hivemind_governance::verify_governance_policy(&policy);
            write_json_file(&path, &policy).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "policyPath": path.display().to_string(),
                    "policy": policy,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        GovernanceCommands::PolicyVerify { policy } => {
            let policy_value: hivemind_governance::GovernancePolicyManifestV1 =
                read_json_file(&policy).await?;
            let verification = hivemind_governance::verify_governance_policy(&policy_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        GovernanceCommands::PolicySign {
            policy,
            identity,
            output,
        } => {
            let mut policy_value: hivemind_governance::GovernancePolicyManifestV1 =
                read_json_file(&policy).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_governance::sign_governance_policy_with_identity(
                &mut policy_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign governance policy with {}",
                    identity.display()
                )
            })?;
            let verification = hivemind_governance::verify_governance_policy(&policy_value);
            if let Some(output) = output {
                write_json_file(&output, &policy_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "policyPath": output.display().to_string(),
                        "signature": signature,
                        "policy": policy_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "policy": policy_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        GovernanceCommands::SchemaReleaseInit {
            path,
            object_type,
            released_schema_version,
            interface_version,
            status,
            breaking_change,
            compatible_with,
            compatibility_test_refs,
            mut approved_by,
            migration_guide_ref,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let identity_value = if let Some(identity_path) = identity.as_ref() {
                Some(read_json_file::<hivemind_identity::IdentityKeypairV1>(identity_path).await?)
            } else {
                None
            };
            if let Some(identity_value) = identity_value.as_ref() {
                if approved_by.is_empty() {
                    approved_by.push(identity_value.subject.clone());
                }
            }
            let mut release = hivemind_governance::create_schema_release(
                hivemind_governance::SchemaReleaseInitOptionsV1 {
                    object_type,
                    released_schema_version,
                    interface_version,
                    status: parse_schema_compatibility_status(&status)?,
                    breaking_change,
                    compatible_with,
                    compatibility_test_refs,
                    approved_by,
                    migration_guide_ref,
                },
            );
            let signature = if let Some(identity_value) = identity_value.as_ref() {
                Some(
                    hivemind_governance::sign_schema_release_with_identity(
                        &mut release,
                        identity_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign schema release with {}",
                            identity.as_ref().unwrap().display()
                        )
                    })?,
                )
            } else {
                None
            };
            let verification = hivemind_governance::verify_schema_release(&release);
            write_json_file(&path, &release).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "releasePath": path.display().to_string(),
                    "release": release,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        GovernanceCommands::SchemaReleaseVerify { release } => {
            let release_value: hivemind_governance::SchemaReleaseV1 =
                read_json_file(&release).await?;
            let verification = hivemind_governance::verify_schema_release(&release_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        GovernanceCommands::SchemaReleaseSign {
            release,
            identity,
            output,
        } => {
            let mut release_value: hivemind_governance::SchemaReleaseV1 =
                read_json_file(&release).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_governance::sign_schema_release_with_identity(
                &mut release_value,
                &identity_value,
            )
            .with_context(|| {
                format!("failed to sign schema release with {}", identity.display())
            })?;
            let verification = hivemind_governance::verify_schema_release(&release_value);
            if let Some(output) = output {
                write_json_file(&output, &release_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "releasePath": output.display().to_string(),
                        "signature": signature,
                        "release": release_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "release": release_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        GovernanceCommands::AdvisoryInit {
            path,
            title,
            reporter,
            severity,
            categories,
            affected_refs,
            summary,
            impact,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let mut advisory = hivemind_governance::create_security_advisory(
                hivemind_governance::SecurityAdvisoryInitOptionsV1 {
                    title,
                    reporter,
                    severity: parse_security_severity(&severity)?,
                    categories: parse_security_advisory_categories(categories)?,
                    affected_refs,
                    summary,
                    impact,
                },
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_governance::sign_security_advisory_with_identity(
                        &mut advisory,
                        &identity_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign security advisory with {}",
                            identity_path.display()
                        )
                    })?,
                )
            } else {
                None
            };
            let verification = hivemind_governance::verify_security_advisory(&advisory);
            let response_plan = hivemind_governance::security_response_plan(&advisory);
            write_json_file(&path, &advisory).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "advisoryPath": path.display().to_string(),
                    "advisory": advisory,
                    "identitySignature": signature,
                    "verification": verification,
                    "responsePlan": response_plan
                }))?
            );
            Ok(())
        }
        GovernanceCommands::AdvisoryVerify { advisory } => {
            let advisory_value: hivemind_governance::SecurityAdvisoryV1 =
                read_json_file(&advisory).await?;
            let verification = hivemind_governance::verify_security_advisory(&advisory_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        GovernanceCommands::AdvisorySign {
            advisory,
            identity,
            output,
        } => {
            let mut advisory_value: hivemind_governance::SecurityAdvisoryV1 =
                read_json_file(&advisory).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_governance::sign_security_advisory_with_identity(
                &mut advisory_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign security advisory with {}",
                    identity.display()
                )
            })?;
            let verification = hivemind_governance::verify_security_advisory(&advisory_value);
            if let Some(output) = output {
                write_json_file(&output, &advisory_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "advisoryPath": output.display().to_string(),
                        "signature": signature,
                        "advisory": advisory_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "advisory": advisory_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        GovernanceCommands::ResponsePlan { advisory } => {
            let advisory_value: hivemind_governance::SecurityAdvisoryV1 =
                read_json_file(&advisory).await?;
            let plan = hivemind_governance::security_response_plan(&advisory_value);
            println!("{}", serde_json::to_string_pretty(&plan)?);
            Ok(())
        }
        GovernanceCommands::ReadinessInit {
            path,
            component_name,
            component_type,
            owner,
            status,
            implementation_ref,
            version,
            schema_refs,
            api_surfaces,
            supported_environments,
            compatibility_certification_refs,
            evidence_refs,
            blockers,
            limitations,
            expires_at,
            identity,
            force,
        } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists; pass --force to overwrite it",
                    path.display()
                );
            }
            let mut readiness = hivemind_governance::create_component_readiness(
                hivemind_governance::ComponentReadinessInitOptionsV1 {
                    schema_version:
                        hivemind_governance::COMPONENT_READINESS_INIT_OPTIONS_SCHEMA_VERSION
                            .to_string(),
                    component_name,
                    component_type,
                    owner,
                    status: parse_component_readiness_level(&status)?,
                    implementation_ref,
                    version,
                    schema_refs,
                    api_surfaces,
                    supported_environments,
                    compatibility_certification_refs,
                    evidence_refs,
                    blockers,
                    limitations,
                    expires_at,
                    metadata: json!({}),
                },
            );
            let signature = if let Some(identity_path) = identity {
                let identity_value: hivemind_identity::IdentityKeypairV1 =
                    read_json_file(&identity_path).await?;
                Some(
                    hivemind_governance::sign_component_readiness_with_identity(
                        &mut readiness,
                        &identity_value,
                    )
                    .with_context(|| {
                        format!(
                            "failed to sign component readiness with {}",
                            identity_path.display()
                        )
                    })?,
                )
            } else {
                None
            };
            let verification = hivemind_governance::verify_component_readiness(&readiness);
            write_json_file(&path, &readiness).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "readinessPath": path.display().to_string(),
                    "readiness": readiness,
                    "identitySignature": signature,
                    "verification": verification
                }))?
            );
            Ok(())
        }
        GovernanceCommands::ReadinessVerify { readiness } => {
            let readiness_value: hivemind_governance::ComponentReadinessV1 =
                read_json_file(&readiness).await?;
            let verification = hivemind_governance::verify_component_readiness(&readiness_value);
            println!("{}", serde_json::to_string_pretty(&verification)?);
            Ok(())
        }
        GovernanceCommands::ReadinessSign {
            readiness,
            identity,
            output,
        } => {
            let mut readiness_value: hivemind_governance::ComponentReadinessV1 =
                read_json_file(&readiness).await?;
            let identity_value: hivemind_identity::IdentityKeypairV1 =
                read_json_file(&identity).await?;
            let signature = hivemind_governance::sign_component_readiness_with_identity(
                &mut readiness_value,
                &identity_value,
            )
            .with_context(|| {
                format!(
                    "failed to sign component readiness with {}",
                    identity.display()
                )
            })?;
            let verification = hivemind_governance::verify_component_readiness(&readiness_value);
            if let Some(output) = output {
                write_json_file(&output, &readiness_value).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "readinessPath": output.display().to_string(),
                        "signature": signature,
                        "readiness": readiness_value,
                        "verification": verification
                    }))?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "signature": signature,
                        "readiness": readiness_value,
                        "verification": verification
                    }))?
                );
            }
            Ok(())
        }
        GovernanceCommands::List { governance_dir } => {
            let summary = hivemind_governance::list_governance_records(&governance_dir)
                .with_context(|| format!("failed to list {}", governance_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
            Ok(())
        }
        GovernanceCommands::Get {
            record_id,
            governance_dir,
        } => {
            let lookup = hivemind_governance::get_governance_record(&governance_dir, &record_id)
                .with_context(|| format!("failed to read {}", governance_dir.display()))?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "governance record {record_id} was not found in {}",
                        governance_dir.display()
                    )
                })?;
            println!("{}", serde_json::to_string_pretty(&lookup)?);
            Ok(())
        }
    }
}

async fn read_moderation_input(
    text: Option<String>,
    input: Option<PathBuf>,
    input_ref: Option<&String>,
) -> Result<Option<Value>> {
    if let Some(text) = text {
        return Ok(Some(Value::String(text)));
    }
    if let Some(path) = input {
        return read_json_file::<Value>(&path).await.map(Some);
    }
    if input_ref.is_some() {
        return Ok(None);
    }
    Ok(Some(Value::String(
        "local moderation smoke input".to_string(),
    )))
}

fn parse_governance_scopes(
    values: Vec<String>,
) -> Result<Vec<hivemind_governance::GovernanceScope>> {
    values
        .iter()
        .map(|value| parse_governance_scope(value))
        .collect()
}

fn parse_governance_scope(value: &str) -> Result<hivemind_governance::GovernanceScope> {
    match normalized_cli_value(value).as_str() {
        "protocol-schemas" => Ok(hivemind_governance::GovernanceScope::ProtocolSchemas),
        "compatibility-certification" => {
            Ok(hivemind_governance::GovernanceScope::CompatibilityCertification)
        }
        "registry-curation" => Ok(hivemind_governance::GovernanceScope::RegistryCuration),
        "validator-eligibility" => Ok(hivemind_governance::GovernanceScope::ValidatorEligibility),
        "marketplace-rules" => Ok(hivemind_governance::GovernanceScope::MarketplaceRules),
        "miner-onboarding" => Ok(hivemind_governance::GovernanceScope::MinerOnboarding),
        "security-response" => Ok(hivemind_governance::GovernanceScope::SecurityResponse),
        "economic-policy" => Ok(hivemind_governance::GovernanceScope::EconomicPolicy),
        other => anyhow::bail!(
            "unknown governance scope {other}; expected protocol-schemas, compatibility-certification, registry-curation, validator-eligibility, marketplace-rules, miner-onboarding, security-response, or economic-policy"
        ),
    }
}

fn parse_schema_compatibility_status(
    value: &str,
) -> Result<hivemind_governance::SchemaCompatibilityStatus> {
    match normalized_cli_value(value).as_str() {
        "experimental" => Ok(hivemind_governance::SchemaCompatibilityStatus::Experimental),
        "development" => Ok(hivemind_governance::SchemaCompatibilityStatus::Development),
        "production-approved" => {
            Ok(hivemind_governance::SchemaCompatibilityStatus::ProductionApproved)
        }
        "deprecated" => Ok(hivemind_governance::SchemaCompatibilityStatus::Deprecated),
        "retired" => Ok(hivemind_governance::SchemaCompatibilityStatus::Retired),
        other => anyhow::bail!(
            "unknown schema release status {other}; expected experimental, development, production-approved, deprecated, or retired"
        ),
    }
}

fn parse_component_readiness_level(
    value: &str,
) -> Result<hivemind_governance::ComponentReadinessLevelV1> {
    match normalized_cli_value(value).as_str() {
        "mock" => Ok(hivemind_governance::ComponentReadinessLevelV1::Mock),
        "local" => Ok(hivemind_governance::ComponentReadinessLevelV1::Local),
        "gateway" => Ok(hivemind_governance::ComponentReadinessLevelV1::Gateway),
        "testnet" => Ok(hivemind_governance::ComponentReadinessLevelV1::Testnet),
        "production" => Ok(hivemind_governance::ComponentReadinessLevelV1::Production),
        other => anyhow::bail!(
            "unknown component readiness status {other}; expected mock, local, gateway, testnet, or production"
        ),
    }
}

fn parse_security_severity(value: &str) -> Result<hivemind_governance::SecuritySeverity> {
    match normalized_cli_value(value).as_str() {
        "informational" | "info" => Ok(hivemind_governance::SecuritySeverity::Informational),
        "low" => Ok(hivemind_governance::SecuritySeverity::Low),
        "medium" => Ok(hivemind_governance::SecuritySeverity::Medium),
        "high" => Ok(hivemind_governance::SecuritySeverity::High),
        "critical" => Ok(hivemind_governance::SecuritySeverity::Critical),
        other => anyhow::bail!(
            "unknown security severity {other}; expected informational, low, medium, high, or critical"
        ),
    }
}

fn parse_security_advisory_categories(
    values: Vec<String>,
) -> Result<Vec<hivemind_governance::SecurityAdvisoryCategory>> {
    values
        .iter()
        .map(|value| parse_security_advisory_category(value))
        .collect()
}

fn parse_security_advisory_category(
    value: &str,
) -> Result<hivemind_governance::SecurityAdvisoryCategory> {
    match normalized_cli_value(value).as_str() {
        "package-vulnerability" => {
            Ok(hivemind_governance::SecurityAdvisoryCategory::PackageVulnerability)
        }
        "malicious-package" => Ok(hivemind_governance::SecurityAdvisoryCategory::MaliciousPackage),
        "runner-abuse" => Ok(hivemind_governance::SecurityAdvisoryCategory::RunnerAbuse),
        "miner-fraud" => Ok(hivemind_governance::SecurityAdvisoryCategory::MinerFraud),
        "compromised-key" => Ok(hivemind_governance::SecurityAdvisoryCategory::CompromisedKey),
        "hidden-benchmark-leakage" => {
            Ok(hivemind_governance::SecurityAdvisoryCategory::HiddenBenchmarkLeakage)
        }
        "emergency-access-revocation" => {
            Ok(hivemind_governance::SecurityAdvisoryCategory::EmergencyAccessRevocation)
        }
        "sandbox-escape" => Ok(hivemind_governance::SecurityAdvisoryCategory::SandboxEscape),
        "confidential-attestation-failure" => {
            Ok(hivemind_governance::SecurityAdvisoryCategory::ConfidentialAttestationFailure)
        }
        "dispute-escalation" => {
            Ok(hivemind_governance::SecurityAdvisoryCategory::DisputeEscalation)
        }
        "security-response" => Ok(hivemind_governance::SecurityAdvisoryCategory::SecurityResponse),
        "registry-curation" => Ok(hivemind_governance::SecurityAdvisoryCategory::RegistryCuration),
        other => anyhow::bail!(
            "unknown security advisory category {other}; expected package-vulnerability, malicious-package, runner-abuse, miner-fraud, compromised-key, hidden-benchmark-leakage, emergency-access-revocation, sandbox-escape, confidential-attestation-failure, dispute-escalation, security-response, or registry-curation"
        ),
    }
}

fn normalized_cli_value(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('_', "-")
}

async fn read_miner_benchmark_files(
    benchmarks: Vec<PathBuf>,
) -> Result<Vec<hivemind_miner::MinerBenchmarkResultV1>> {
    let mut records = Vec::with_capacity(benchmarks.len());
    for benchmark in benchmarks {
        records.push(
            read_json_file::<hivemind_miner::MinerBenchmarkResultV1>(&benchmark)
                .await
                .with_context(|| format!("failed to read benchmark {}", benchmark.display()))?,
        );
    }
    Ok(records)
}

fn parse_miner_daemon_status(value: &str) -> Result<hivemind_miner::MinerDaemonStatus> {
    match value {
        "starting" => Ok(hivemind_miner::MinerDaemonStatus::Starting),
        "available" => Ok(hivemind_miner::MinerDaemonStatus::Available),
        "busy" => Ok(hivemind_miner::MinerDaemonStatus::Busy),
        "draining" => Ok(hivemind_miner::MinerDaemonStatus::Draining),
        "offline" => Ok(hivemind_miner::MinerDaemonStatus::Offline),
        "error" => Ok(hivemind_miner::MinerDaemonStatus::Error),
        other => anyhow::bail!(
            "unknown miner status {other}; expected starting, available, busy, draining, offline, or error"
        ),
    }
}

fn parse_miner_benchmark_metrics(
    values: Vec<String>,
) -> Result<Vec<hivemind_miner::MinerBenchmarkMetricV1>> {
    if values.is_empty() {
        return Ok(vec![hivemind_miner::MinerBenchmarkMetricV1 {
            name: "throughput_score".to_string(),
            value: 1.0,
            unit: "score".to_string(),
        }]);
    }

    values
        .iter()
        .map(|value| parse_miner_benchmark_metric(value))
        .collect()
}

fn parse_miner_benchmark_metric(value: &str) -> Result<hivemind_miner::MinerBenchmarkMetricV1> {
    let (name, rest) = value
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("metric {value} must use name=value or name=value:unit"))?;
    let (raw_value, unit) = rest.split_once(':').unwrap_or((rest, "score"));
    let metric_value = raw_value
        .parse::<f64>()
        .with_context(|| format!("metric {value} has invalid numeric value"))?;
    if name.trim().is_empty() || unit.trim().is_empty() {
        anyhow::bail!("metric {value} must include a non-empty name and unit");
    }
    Ok(hivemind_miner::MinerBenchmarkMetricV1 {
        name: name.trim().to_string(),
        value: metric_value,
        unit: unit.trim().to_string(),
    })
}

fn parse_benchmark_splits(
    values: Vec<String>,
) -> Result<Vec<hivemind_benchmarks::BenchmarkSplitV1>> {
    values
        .into_iter()
        .map(|value| {
            let mut parts = value.splitn(4, '|');
            let name = parts.next().unwrap_or_default().trim().to_string();
            let weight = parts
                .next()
                .unwrap_or("1.0")
                .trim()
                .parse::<f64>()
                .with_context(|| format!("invalid benchmark split weight in {value}"))?;
            let hidden = parse_bool_flag(parts.next().unwrap_or("false").trim())
                .with_context(|| format!("invalid benchmark split hidden flag in {value}"))?;
            let dataset_refs = parts
                .next()
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|reference| !reference.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>();
            if name.is_empty() {
                anyhow::bail!("benchmark split name is required in {value}");
            }
            if dataset_refs.is_empty() {
                anyhow::bail!("benchmark split dataset refs are required in {value}");
            }
            Ok(hivemind_benchmarks::BenchmarkSplitV1 {
                name,
                dataset_refs,
                weight,
                hidden,
            })
        })
        .collect()
}

fn parse_evaluation_v2_errors(
    values: Vec<String>,
) -> Result<Vec<hivemind_benchmarks::EvaluationErrorV2>> {
    values
        .into_iter()
        .map(|value| {
            let parts = value
                .split('|')
                .map(str::trim)
                .collect::<Vec<_>>();
            match parts.as_slice() {
                [code, message] => {
                    if code.is_empty() || message.is_empty() {
                        anyhow::bail!(
                            "evaluation error {value} must include non-empty code and message"
                        );
                    }
                    Ok(hivemind_benchmarks::EvaluationErrorV2 {
                        sample_id: None,
                        code: (*code).to_string(),
                        message: (*message).to_string(),
                        retryable: false,
                    })
                }
                [sample_id, code, retryable, message] => {
                    if code.is_empty() || message.is_empty() {
                        anyhow::bail!(
                            "evaluation error {value} must include non-empty code and message"
                        );
                    }
                    Ok(hivemind_benchmarks::EvaluationErrorV2 {
                        sample_id: if sample_id.is_empty() || *sample_id == "-" {
                            None
                        } else {
                            Some((*sample_id).to_string())
                        },
                        code: (*code).to_string(),
                        message: (*message).to_string(),
                        retryable: parse_bool_flag(retryable).with_context(|| {
                            format!("invalid retryable flag in evaluation error {value}")
                        })?,
                    })
                }
                _ => anyhow::bail!(
                    "evaluation error {value} must use code|message or sampleId|code|retryable|message"
                ),
            }
        })
        .collect()
}

fn parse_bool_flag(value: &str) -> Result<bool> {
    match value {
        "true" | "yes" | "1" | "hidden" => Ok(true),
        "false" | "no" | "0" | "public" => Ok(false),
        other => anyhow::bail!("expected true/false, yes/no, 1/0, hidden, or public; got {other}"),
    }
}

fn parse_batch_items(values: Vec<String>) -> Result<Vec<Value>> {
    values
        .into_iter()
        .map(|value| parse_batch_item_value(&value))
        .collect()
}

fn parse_batch_item_value(value: &str) -> Result<Value> {
    let trimmed = value.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        serde_json::from_str(trimmed)
            .with_context(|| format!("failed to parse batch item JSON: {value}"))
    } else {
        Ok(json!({ "text": value }))
    }
}

fn parse_batch_partial_result_policy(
    value: &str,
) -> Result<hivemind_batch::BatchPartialResultPolicy> {
    serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
        format!(
            "unknown batch partial result policy {value}; expected none, on-checkpoint, on-item-completion, or on-failure-and-checkpoint"
        )
    })
}

fn parse_fine_tune_output_artifact_kind(
    value: &str,
) -> Result<hivemind_fine_tune::FineTuneOutputArtifactKind> {
    serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
        format!(
            "unknown fine-tune output artifact kind {value}; expected adapter-or-lora, full-model, merged-model, or checkpoint-set"
        )
    })
}

fn parse_fine_tune_output_visibility(
    value: &str,
) -> Result<hivemind_fine_tune::FineTuneOutputVisibility> {
    serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
        format!(
            "unknown fine-tune output visibility {value}; expected private, organization, public, or token-gated"
        )
    })
}

fn parse_realtime_transport(value: &str) -> Result<hivemind_realtime::RealtimeTransport> {
    serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
        format!(
            "unknown realtime transport {value}; expected websocket, webrtc, http-stream, or local"
        )
    })
}

fn parse_media_task(value: &str) -> Result<hivemind_media::MediaTask> {
    serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
        format!(
            "unknown media task {value}; expected image-generation, image-edit, audio-transcription, or text-to-speech"
        )
    })
}

fn parse_modalities(values: Vec<String>) -> Result<Vec<hivemind_core::Modality>> {
    values
        .into_iter()
        .map(|value| parse_modality(&value))
        .collect()
}

fn parse_modality(value: &str) -> Result<hivemind_core::Modality> {
    serde_json::from_value(Value::String(value.replace('-', "_"))).with_context(|| {
        format!(
            "unknown modality {value}; expected text, chat, structured_output, embedding, image, audio, video, document, file, tool_call, browser_action, vector_search, training_data, or evaluation_data"
        )
    })
}

fn parse_vector_storage_refs(
    values: Vec<String>,
) -> Result<Vec<hivemind_vector::VectorStorageRefV1>> {
    if values.is_empty() {
        return Ok(vec![hivemind_vector::VectorStorageRefV1 {
            role: hivemind_vector::VectorStorageRole::Index,
            reference: "local://vector/index-placeholder".to_string(),
            content_type: Some("application/octet-stream".to_string()),
            sha256: None,
            size_bytes: None,
        }]);
    }
    values
        .into_iter()
        .map(|value| {
            let (role, reference) = value
                .split_once('=')
                .map(|(role, reference)| (role, reference))
                .unwrap_or(("index", value.as_str()));
            Ok(hivemind_vector::VectorStorageRefV1 {
                role: parse_vector_storage_role(role)?,
                reference: reference.to_string(),
                content_type: None,
                sha256: None,
                size_bytes: None,
            })
        })
        .collect()
}

fn parse_vector_storage_role(value: &str) -> Result<hivemind_vector::VectorStorageRole> {
    serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
        format!(
            "unknown vector storage role {value}; expected index, metadata, chunks, documents, embedding-cache, or manifest"
        )
    })
}

fn parse_vector_metric(value: &str) -> Result<hivemind_vector::VectorMetric> {
    serde_json::from_value(Value::String(value.replace('-', "_"))).with_context(|| {
        format!("unknown vector metric {value}; expected cosine, dot_product, or euclidean")
    })
}

fn parse_privacy_tier(value: &str) -> Result<hivemind_core::PrivacyTier> {
    serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
        format!(
            "unknown privacy tier {value}; expected public, standard, standard-remote, no-log, no-log-remote, redacted-input, local-only, browser-only, encrypted-storage, tee-confidential, fhe-encrypted, fhe-encrypted-inference, split-trust-redundant, zk-verified-inference, or mpc-experimental"
        )
    })
}

fn parse_eval_kind(value: &str) -> Result<hivemind_evals::EvalKind> {
    serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
        format!(
            "unknown eval kind {value}; expected dataset, model-graded, human-review, regression, safety, retrieval, agent-tooling, or rag"
        )
    })
}

fn parse_research_run_status(value: &str) -> Result<hivemind_research::ResearchRunStatusV1> {
    serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
        format!(
            "unknown research run status {value}; expected planned, running, succeeded, failed, or cancelled"
        )
    })
}

fn parse_integrity_tier(value: &str) -> Result<hivemind_core::IntegrityTier> {
    serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
        format!(
            "unknown integrity tier {value}; expected receipt-only, validator-spot-check, redundant-execution, deterministic-replay, tee-attested, or zk-proof-when-supported"
        )
    })
}

fn parse_api_surface(value: &str) -> Result<hivemind_core::ApiSurface> {
    serde_json::from_value(Value::String(value.replace('-', "_"))).with_context(|| {
        format!(
            "unknown API surface {value}; expected hivemind_native, openai_chat_completions, openai_responses, openai_embeddings, openai_batches, vector_search, batch, fine_tune, or another supported core API surface"
        )
    })
}

fn parse_tool_execution_modes(
    values: Vec<String>,
) -> Result<Vec<hivemind_workflow::ToolExecutionMode>> {
    values
        .into_iter()
        .map(|value| {
            serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
                format!(
                    "unknown tool execution mode {value}; expected browser, local, remote-runner, marketplace-runner, external-http, wasm, or container"
                )
            })
        })
        .collect()
}

fn parse_workflow_failure_policy(value: &str) -> Result<hivemind_workflow::WorkflowFailurePolicy> {
    serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
        format!(
            "unknown workflow failure policy {value}; expected fail-fast, continue-on-failure, retry-step, or manual-review"
        )
    })
}

fn parse_workflow_trace_policy(value: &str) -> Result<hivemind_workflow::WorkflowTracePolicy> {
    serde_json::from_value(Value::String(value.replace('_', "-"))).with_context(|| {
        format!(
            "unknown workflow trace policy {value}; expected minimal, receipts-only, full, or redacted"
        )
    })
}

fn parse_permission_requests(values: Vec<String>) -> Result<Vec<hivemind_core::PermissionRequest>> {
    values
        .into_iter()
        .map(|value| {
            let (name, purpose) = value
                .split_once(':')
                .map(|(name, purpose)| (name, Some(purpose.to_string())))
                .unwrap_or((value.as_str(), None));
            if name.trim().is_empty() {
                anyhow::bail!("permission names must not be empty");
            }
            Ok(hivemind_core::PermissionRequest {
                name: name.to_string(),
                purpose,
                required: true,
                limits: json!({}),
            })
        })
        .collect()
}

async fn run_command(
    package: PathBuf,
    task: String,
    text: Option<String>,
    input: Option<PathBuf>,
    grant: Option<PathBuf>,
    revocations: Option<PathBuf>,
    receipts_dir: Option<PathBuf>,
) -> Result<()> {
    let package = load_package_from_dir(&package)
        .with_context(|| format!("failed to load package at {}", package.display()))?;
    let input_value = read_execution_input(text, input).await?;
    let access_grant = read_access_grant(grant).await?;
    let access_revocation_list = read_access_revocation_list(revocations).await?;

    let request = ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: Uuid::new_v4().to_string(),
        package_ref: package.package_ref.clone(),
        package_id: package.manifest.package_id.clone(),
        package_version: package.manifest.version.clone(),
        preferred_artifact_group: None,
        task,
        input: input_value,
        options: ExecutionOptions::default(),
        privacy: ExecutionPrivacy::default(),
        access_grant,
        access_revocation_list,
    };

    let response = hivemind_local_runner::execute(request, package).await;
    print_response_with_optional_receipt_capture(response, receipts_dir)?;
    Ok(())
}

async fn run_ref_command(
    reference: String,
    provider: String,
    storage_dir: PathBuf,
    bee_url: String,
    task: String,
    text: Option<String>,
    input: Option<PathBuf>,
    artifact_group: Option<String>,
    grant: Option<PathBuf>,
    revocations: Option<PathBuf>,
    receipts_dir: Option<PathBuf>,
) -> Result<()> {
    let input_value = read_execution_input(text, input).await?;
    let access_grant = read_access_grant(grant).await?;
    let access_revocation_list = read_access_revocation_list(revocations).await?;
    let package = match provider.as_str() {
        "local" => {
            let storage = LocalDirectoryStorageProvider::new(storage_dir);
            hivemind_package::load_package_from_storage(&reference, &storage)
        }
        "bee" => {
            let storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                api_url: bee_url,
                postage_batch_id: None,
                pin: false,
                deferred_upload: true,
                redundancy_level: 0,
            });
            hivemind_package::load_package_from_storage(&reference, &storage)
        }
        other => anyhow::bail!("unknown run-ref provider {other}; expected local or bee"),
    }
    .with_context(|| format!("failed to load package {reference}"))?;

    let request = ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: Uuid::new_v4().to_string(),
        package_ref: reference,
        package_id: package.manifest.package_id.clone(),
        package_version: package.manifest.version.clone(),
        preferred_artifact_group: artifact_group,
        task,
        input: input_value,
        options: ExecutionOptions::default(),
        privacy: ExecutionPrivacy::default(),
        access_grant,
        access_revocation_list,
    };

    let response = hivemind_local_runner::execute(request, package).await;
    print_response_with_optional_receipt_capture(response, receipts_dir)?;
    Ok(())
}

fn print_response_with_optional_receipt_capture(
    response: hivemind_core::ExecutionResponseV1,
    receipts_dir: Option<PathBuf>,
) -> Result<()> {
    if let Some(receipts_dir) = receipts_dir {
        let capture = hivemind_receipts::capture_response_receipt(&receipts_dir, &response)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "response": response,
                "receiptCapture": capture
            }))?
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&response)?);
    }
    Ok(())
}

fn browser_capabilities(
    webgpu: bool,
    memory_mb: u64,
) -> hivemind_browser_runner::BrowserCapabilitiesV1 {
    let mut engines = vec!["wasm-mock".to_string(), "rust-mock".to_string()];
    if webgpu {
        engines.push("webgpu-mock".to_string());
    }
    hivemind_browser_runner::browser_capabilities_from_hints(
        webgpu, true, true, true, memory_mb, engines,
    )
}

fn browser_swarm_provider(
    storage_dir: PathBuf,
) -> hivemind_weeb3_adapter::BrowserSwarmProvider<hivemind_storage::LocalDirectoryStorageProvider> {
    hivemind_weeb3_adapter::BrowserSwarmProvider::with_fallback(
        hivemind_weeb3_adapter::default_browser_swarm_config(),
        LocalDirectoryStorageProvider::new(storage_dir),
    )
}

fn remote_descriptor(runner_id: String, queue_depth: u32) -> hivemind_core::RunnerDescriptorV1 {
    let mut descriptor = hivemind_remote_runner::default_remote_gpu_descriptor(runner_id);
    descriptor.queue_depth = queue_depth;
    descriptor
}

fn routing_runners(local_queue: u32, remote_queue: u32) -> Vec<hivemind_core::RunnerDescriptorV1> {
    let mut local = hivemind_local_runner::descriptor();
    local.queue_depth = local_queue;
    let mut remote = hivemind_remote_runner::default_descriptor();
    remote.queue_depth = remote_queue;
    vec![
        hivemind_browser_runner::runner_descriptor(
            &hivemind_browser_runner::default_browser_capabilities(),
        ),
        local,
        remote,
    ]
}

fn parse_policy_mode(value: &str) -> Result<hivemind_core::PolicyMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "privacy-first" | "privacy" => Ok(hivemind_core::PolicyMode::PrivacyFirst),
        "speed-first" | "speed" => Ok(hivemind_core::PolicyMode::SpeedFirst),
        "cost-first" | "cost" => Ok(hivemind_core::PolicyMode::CostFirst),
        "quality-first" | "quality" => Ok(hivemind_core::PolicyMode::QualityFirst),
        "balanced" | "balance" => Ok(hivemind_core::PolicyMode::Balanced),
        "developer" | "dev" => Ok(hivemind_core::PolicyMode::Developer),
        other => anyhow::bail!(
            "unknown policy {other}; expected privacy-first, speed-first, cost-first, quality-first, balanced, or developer"
        ),
    }
}

fn parse_package_template(value: &str) -> Result<hivemind_package::PackageTemplateKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "embedding" | "embedding-model" => {
            Ok(hivemind_package::PackageTemplateKind::EmbeddingModel)
        }
        "chat" | "chat-model" => Ok(hivemind_package::PackageTemplateKind::ChatModel),
        other => anyhow::bail!(
            "unknown package template {other}; expected embedding-model or chat-model"
        ),
    }
}

fn parse_payment_adapter(value: &str) -> Result<hivemind_marketplace::PaymentAdapterKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "local-dev" | "local" | "dev" => Ok(hivemind_marketplace::PaymentAdapterKind::LocalDev),
        "external-transaction" | "external" | "transaction" => {
            Ok(hivemind_marketplace::PaymentAdapterKind::ExternalTransaction)
        }
        "free" => Ok(hivemind_marketplace::PaymentAdapterKind::Free),
        other => anyhow::bail!(
            "unknown payment adapter {other}; expected local-dev, external-transaction, or free"
        ),
    }
}

fn parse_reputation_subject_type(value: &str) -> Result<hivemind_validator::ReputationSubjectType> {
    match value.trim().to_ascii_lowercase().as_str() {
        "runner" => Ok(hivemind_validator::ReputationSubjectType::Runner),
        "package" => Ok(hivemind_validator::ReputationSubjectType::Package),
        "publisher" => Ok(hivemind_validator::ReputationSubjectType::Publisher),
        "validator" => Ok(hivemind_validator::ReputationSubjectType::Validator),
        other => anyhow::bail!(
            "unknown reputation subject type {other}; expected runner, package, publisher, or validator"
        ),
    }
}

fn parse_validation_subject_type_v2(
    value: &str,
) -> Result<hivemind_validator::ValidationSubjectTypeV2> {
    match value.trim().to_ascii_lowercase().as_str() {
        "receipt" => Ok(hivemind_validator::ValidationSubjectTypeV2::Receipt),
        "runner" => Ok(hivemind_validator::ValidationSubjectTypeV2::Runner),
        "miner" => Ok(hivemind_validator::ValidationSubjectTypeV2::Miner),
        "package" => Ok(hivemind_validator::ValidationSubjectTypeV2::Package),
        "publisher" => Ok(hivemind_validator::ValidationSubjectTypeV2::Publisher),
        "validator" => Ok(hivemind_validator::ValidationSubjectTypeV2::Validator),
        "benchmark" => Ok(hivemind_validator::ValidationSubjectTypeV2::Benchmark),
        "hardware-offer" | "hardware_offer" => {
            Ok(hivemind_validator::ValidationSubjectTypeV2::HardwareOffer)
        }
        other => anyhow::bail!(
            "unknown validation subject type {other}; expected receipt, runner, miner, package, publisher, validator, benchmark, or hardware-offer"
        ),
    }
}

fn parse_validation_method_v2(value: &str) -> Result<hivemind_validator::ValidationMethodV2> {
    match value.trim().to_ascii_lowercase().as_str() {
        "schema-check" | "schema_check" => Ok(hivemind_validator::ValidationMethodV2::SchemaCheck),
        "manifest-compatibility" | "manifest_compatibility" => {
            Ok(hivemind_validator::ValidationMethodV2::ManifestCompatibility)
        }
        "artifact-hash-check" | "artifact_hash_check" => {
            Ok(hivemind_validator::ValidationMethodV2::ArtifactHashCheck)
        }
        "benchmark-run" | "benchmark_run" | "benchmark-score" | "benchmark_score" => {
            Ok(hivemind_validator::ValidationMethodV2::BenchmarkRun)
        }
        "hidden-challenge" | "hidden_challenge" => {
            Ok(hivemind_validator::ValidationMethodV2::HiddenChallenge)
        }
        "receipt-check" | "receipt_check" => {
            Ok(hivemind_validator::ValidationMethodV2::ReceiptCheck)
        }
        "redundant-execution-compare"
        | "redundant_execution_compare"
        | "redundant-execution"
        | "redundant_execution" => {
            Ok(hivemind_validator::ValidationMethodV2::RedundantExecutionCompare)
        }
        "deterministic-replay" | "deterministic_replay" => {
            Ok(hivemind_validator::ValidationMethodV2::DeterministicReplay)
        }
        "statistical-similarity" | "statistical_similarity" => {
            Ok(hivemind_validator::ValidationMethodV2::StatisticalSimilarity)
        }
        "reference-answer-score" | "reference_answer_score" => {
            Ok(hivemind_validator::ValidationMethodV2::ReferenceAnswerScore)
        }
        "llm-judge-with-controls" | "llm_judge_with_controls" => {
            Ok(hivemind_validator::ValidationMethodV2::LlmJudgeWithControls)
        }
        "llm-judge-with-disclosure" | "llm_judge_with_disclosure" => {
            Ok(hivemind_validator::ValidationMethodV2::LlmJudgeWithDisclosure)
        }
        "human-review" | "human_review" => Ok(hivemind_validator::ValidationMethodV2::HumanReview),
        "sandbox-trace-review" | "sandbox_trace_review" => {
            Ok(hivemind_validator::ValidationMethodV2::SandboxTraceReview)
        }
        "tee-attestation-check" | "tee_attestation_check" => {
            Ok(hivemind_validator::ValidationMethodV2::TeeAttestationCheck)
        }
        "zk-proof-check" | "zk_proof_check" => {
            Ok(hivemind_validator::ValidationMethodV2::ZkProofCheck)
        }
        "fhe-result-check" | "fhe_result_check" => {
            Ok(hivemind_validator::ValidationMethodV2::FheResultCheck)
        }
        "policy-compliance-check" | "policy_compliance_check" => {
            Ok(hivemind_validator::ValidationMethodV2::PolicyComplianceCheck)
        }
        other => anyhow::bail!(
            "unknown validation method {other}; expected schema-check, manifest-compatibility, artifact-hash-check, benchmark-run, hidden-challenge, receipt-check, redundant-execution-compare, deterministic-replay, statistical-similarity, reference-answer-score, llm-judge-with-controls, llm-judge-with-disclosure, human-review, sandbox-trace-review, tee-attestation-check, zk-proof-check, fhe-result-check, or policy-compliance-check"
        ),
    }
}

fn parse_integrity_evidence_kind(
    value: &str,
) -> Result<hivemind_validator::IntegrityEvidenceKindV1> {
    match value.trim().to_ascii_lowercase().as_str() {
        "tee-attestation" | "tee_attestation" | "tee" => {
            Ok(hivemind_validator::IntegrityEvidenceKindV1::TeeAttestation)
        }
        "zk-proof" | "zk_proof" | "zk" => Ok(hivemind_validator::IntegrityEvidenceKindV1::ZkProof),
        "fhe-result" | "fhe_result" | "fhe" => {
            Ok(hivemind_validator::IntegrityEvidenceKindV1::FheResult)
        }
        "deterministic-replay" | "deterministic_replay" | "replay" => {
            Ok(hivemind_validator::IntegrityEvidenceKindV1::DeterministicReplay)
        }
        "redundant-execution" | "redundant_execution" | "redundant" => {
            Ok(hivemind_validator::IntegrityEvidenceKindV1::RedundantExecution)
        }
        other => anyhow::bail!(
            "unknown integrity evidence kind {other}; expected tee-attestation, zk-proof, fhe-result, deterministic-replay, or redundant-execution"
        ),
    }
}

fn parse_integrity_evidence_verdict(
    value: &str,
) -> Result<hivemind_validator::IntegrityEvidenceVerdictV1> {
    match value.trim().to_ascii_lowercase().as_str() {
        "passed" | "pass" => Ok(hivemind_validator::IntegrityEvidenceVerdictV1::Passed),
        "failed" | "fail" => Ok(hivemind_validator::IntegrityEvidenceVerdictV1::Failed),
        "inconclusive" | "unknown" => {
            Ok(hivemind_validator::IntegrityEvidenceVerdictV1::Inconclusive)
        }
        other => anyhow::bail!(
            "unknown integrity evidence verdict {other}; expected passed, failed, or inconclusive"
        ),
    }
}

async fn read_execution_input(text: Option<String>, input: Option<PathBuf>) -> Result<Value> {
    if let Some(input_path) = input {
        let bytes = tokio::fs::read(&input_path)
            .await
            .with_context(|| format!("failed to read {}", input_path.display()))?;
        parse_json_bytes::<Value>(&bytes, &input_path.display().to_string())
    } else {
        Ok(json!({"text": text.unwrap_or_else(|| "hello world".to_string())}))
    }
}

async fn read_access_grant(path: Option<PathBuf>) -> Result<Option<AccessGrantV1>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read access grant {}", path.display()))?;
    parse_json_bytes::<AccessGrantV1>(&bytes, &path.display().to_string()).map(Some)
}

async fn read_access_revocation_list(
    path: Option<PathBuf>,
) -> Result<Option<AccessRevocationListV1>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed to read access revocation list {}", path.display()))?;
    parse_json_bytes::<AccessRevocationListV1>(&bytes, &path.display().to_string()).map(Some)
}

async fn read_json_file<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("failed to read {}", path.display()))?;
    parse_json_bytes::<T>(&bytes, &path.display().to_string())
}

async fn write_json_file<T: Serialize>(path: &PathBuf, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    tokio::fs::write(path, serde_json::to_vec_pretty(value)?)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn parse_json_bytes<T: serde::de::DeserializeOwned>(bytes: &[u8], source: &str) -> Result<T> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return serde_json::from_slice::<T>(&bytes[3..])
            .with_context(|| format!("failed to parse JSON from {source}"));
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let text = decode_utf16_json(&bytes[2..], true, source)?;
        return serde_json::from_str::<T>(&text)
            .with_context(|| format!("failed to parse JSON from {source}"));
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        let text = decode_utf16_json(&bytes[2..], false, source)?;
        return serde_json::from_str::<T>(&text)
            .with_context(|| format!("failed to parse JSON from {source}"));
    }
    serde_json::from_slice::<T>(bytes)
        .with_context(|| format!("failed to parse JSON from {source}"))
}

fn decode_utf16_json(bytes: &[u8], little_endian: bool, source: &str) -> Result<String> {
    if bytes.len() % 2 != 0 {
        anyhow::bail!("failed to decode UTF-16 JSON from {source}: odd byte length");
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    String::from_utf16(&units)
        .with_context(|| format!("failed to decode UTF-16 JSON from {source}"))
}

async fn write_validation_report(
    reports_dir: &PathBuf,
    report: &hivemind_validator::ValidationReportV1,
) -> Result<PathBuf> {
    tokio::fs::create_dir_all(reports_dir)
        .await
        .with_context(|| format!("failed to create {}", reports_dir.display()))?;
    let path = reports_dir.join(format!("{}.json", safe_file_component(&report.report_id)));
    tokio::fs::write(&path, serde_json::to_vec_pretty(report)?)
        .await
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
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

fn marketplace_runner_offers_for_request(
    packages: &[IndexedPackage],
    offer_dir: &PathBuf,
    package_ref: &str,
) -> Result<Vec<hivemind_marketplace::RunnerOfferV1>> {
    marketplace_runner_offers_for_refs(package_refs(packages), offer_dir, package_ref)
}

fn marketplace_runner_offers_for_refs(
    visible_refs: Vec<String>,
    offer_dir: &PathBuf,
    package_ref: &str,
) -> Result<Vec<hivemind_marketplace::RunnerOfferV1>> {
    let request_visible = visible_refs.is_empty()
        || visible_refs
            .iter()
            .any(|visible_ref| visible_ref == package_ref);
    let default_offer = hivemind_marketplace::default_local_runner_offer(
        &hivemind_local_runner::descriptor(),
        visible_refs,
    );
    let mut offers = Vec::new();

    if request_visible {
        let stored = load_runner_offers(offer_dir).with_context(|| {
            format!("failed to load runner offers from {}", offer_dir.display())
        })?;
        offers.extend(
            stored
                .into_iter()
                .filter(|offer| runner_offer_supports_reference(offer, package_ref)),
        );
    }

    let default_shadowed = offers.iter().any(|offer| {
        offer.runner_id == default_offer.runner_id
            && hivemind_marketplace::verify_runner_offer(offer).valid
    });
    if !default_shadowed {
        offers.push(default_offer);
    }

    Ok(deduplicate_runner_offers(offers))
}

fn marketplace_quote_offer_for_reference(
    package_ref: &str,
    offer_dir: &PathBuf,
) -> Result<hivemind_marketplace::RunnerOfferV1> {
    let stored = load_runner_offers(offer_dir)
        .with_context(|| format!("failed to load runner offers from {}", offer_dir.display()))?;
    let mut broad_offer = None;

    for offer in stored {
        if !hivemind_marketplace::verify_runner_offer(&offer).valid {
            continue;
        }
        if offer.supported_package_refs.is_empty() {
            broad_offer.get_or_insert(offer);
        } else if runner_offer_supports_reference(&offer, package_ref) {
            return Ok(offer);
        }
    }

    if let Some(offer) = broad_offer {
        return Ok(offer);
    }

    Ok(hivemind_marketplace::default_local_runner_offer(
        &hivemind_local_runner::descriptor(),
        vec![package_ref.to_string()],
    ))
}

fn runner_offer_supports_reference(
    offer: &hivemind_marketplace::RunnerOfferV1,
    package_ref: &str,
) -> bool {
    offer.supported_package_refs.is_empty()
        || offer
            .supported_package_refs
            .iter()
            .any(|supported| supported == package_ref)
}

fn deduplicate_runner_offers(
    offers: Vec<hivemind_marketplace::RunnerOfferV1>,
) -> Vec<hivemind_marketplace::RunnerOfferV1> {
    let mut by_id = BTreeMap::new();
    for offer in offers {
        by_id.insert(offer.offer_id.clone(), offer);
    }
    by_id.into_values().collect()
}

fn filter_private_packages(
    packages: Vec<IndexedPackage>,
    include_private: bool,
) -> Vec<IndexedPackage> {
    if include_private {
        return packages;
    }
    packages
        .into_iter()
        .filter(|package| package.entry.license.license_type != LicenseType::Private)
        .collect()
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

fn schema_command(kind: &str) -> Result<()> {
    let schema = match kind {
        "package" => serde_json::to_value(schema_for!(PackageManifestV1))?,
        "package-v2" => serde_json::to_value(schema_for!(hivemind_core::PackageManifestV2))?,
        "package-v3" => serde_json::to_value(schema_for!(hivemind_core::PackageManifestV3))?,
        "package-v4" => serde_json::to_value(schema_for!(hivemind_core::PackageManifestV4))?,
        "artifact-group-v2" => serde_json::to_value(schema_for!(hivemind_core::ArtifactGroupV2))?,
        "universal-capability" => {
            serde_json::to_value(schema_for!(hivemind_core::UniversalCapabilityV1))?
        }
        "capability-set" => serde_json::to_value(schema_for!(hivemind_core::CapabilitySetV1))?,
        "asset-descriptor" => serde_json::to_value(schema_for!(hivemind_core::AssetDescriptorV1))?,
        "asset-role" => serde_json::to_value(schema_for!(hivemind_core::AssetRoleV1))?,
        "runtime-descriptor-v2" => {
            serde_json::to_value(schema_for!(hivemind_core::RuntimeDescriptorV2))?
        }
        "policy-ref" => serde_json::to_value(schema_for!(hivemind_core::PolicyRefV1))?,
        "provenance-record" => {
            serde_json::to_value(schema_for!(hivemind_core::ProvenanceRecordV1))?
        }
        "package-index-summary" => {
            serde_json::to_value(schema_for!(hivemind_core::PackageIndexSummaryV1))?
        }
        "browser-publish-profile" => {
            serde_json::to_value(schema_for!(hivemind_core::BrowserPublishProfileV1))?
        }
        "package-init-options" => {
            serde_json::to_value(schema_for!(hivemind_package::PackageInitOptionsV1))?
        }
        "package-init-result" => {
            serde_json::to_value(schema_for!(hivemind_package::PackageInitResultV1))?
        }
        "package-validation-audit-record" => serde_json::to_value(schema_for!(
            hivemind_package::PackageValidationAuditRecordV1
        ))?,
        "package-validation-audit-store-summary" => serde_json::to_value(schema_for!(
            hivemind_package::PackageValidationAuditStoreSummaryV1
        ))?,
        "execution-request" => serde_json::to_value(schema_for!(ExecutionRequestV1))?,
        "ai-request" => serde_json::to_value(schema_for!(hivemind_core::AiRequestV1))?,
        "ai-workload" => serde_json::to_value(schema_for!(hivemind_core::AIWorkloadV1))?,
        "ai-workload-verification" => {
            serde_json::to_value(schema_for!(hivemind_core::AIWorkloadVerificationV1))?
        }
        "task-envelope" => serde_json::to_value(schema_for!(hivemind_core::TaskEnvelopeV1))?,
        "task-envelope-verification" => {
            serde_json::to_value(schema_for!(hivemind_core::TaskEnvelopeVerificationV1))?
        }
        "task-envelope-input" => {
            serde_json::to_value(schema_for!(hivemind_core::AssetOrInlineInputV1))?
        }
        "expected-output-descriptor" => {
            serde_json::to_value(schema_for!(hivemind_core::ExpectedOutputDescriptorV1))?
        }
        "job-policy" => serde_json::to_value(schema_for!(hivemind_core::JobPolicyV1))?,
        "privacy-requirement" => {
            serde_json::to_value(schema_for!(hivemind_core::PrivacyRequirementV1))?
        }
        "verification-requirement" => {
            serde_json::to_value(schema_for!(hivemind_core::VerificationRequirementV1))?
        }
        "budget" => serde_json::to_value(schema_for!(hivemind_core::BudgetV1))?,
        "runtime-preferences" => {
            serde_json::to_value(schema_for!(hivemind_core::RuntimePreferencesV1))?
        }
        "task-streaming" => serde_json::to_value(schema_for!(hivemind_core::TaskStreamingV1))?,
        "ai-request-verification" => {
            serde_json::to_value(schema_for!(hivemind_core::AiRequestVerificationV1))?
        }
        "ai-response" => serde_json::to_value(schema_for!(hivemind_core::AiResponseV1))?,
        "ai-response-verification" => {
            serde_json::to_value(schema_for!(hivemind_core::AiResponseVerificationV1))?
        }
        "ai-execution-plan" => {
            serde_json::to_value(schema_for!(hivemind_router::AiExecutionPlanV1))?
        }
        "universal-route-plan" => {
            serde_json::to_value(schema_for!(hivemind_router::UniversalRoutePlanV1))?
        }
        "ai-input-part" => serde_json::to_value(schema_for!(hivemind_core::AiInputPartV1))?,
        "ai-output-part" => serde_json::to_value(schema_for!(hivemind_core::AiOutputPartV1))?,
        "swarm-ai-error" => serde_json::to_value(schema_for!(hivemind_core::SwarmAiErrorV1))?,
        "standard-error-code" => {
            serde_json::to_value(schema_for!(hivemind_core::StandardErrorCodeV1))?
        }
        "standard-error-definition" => {
            serde_json::to_value(schema_for!(hivemind_core::StandardErrorDefinitionV1))?
        }
        "standard-error-catalog" => {
            serde_json::to_value(schema_for!(hivemind_core::StandardErrorCatalogV1))?
        }
        "registry-entry" => serde_json::to_value(schema_for!(hivemind_core::RegistryEntryV1))?,
        "registry-query" => serde_json::to_value(schema_for!(RegistryQueryV1))?,
        "registry-search-audit-record" => {
            serde_json::to_value(schema_for!(hivemind_registry::RegistrySearchAuditRecordV1))?
        }
        "registry-search-audit-store-summary" => serde_json::to_value(schema_for!(
            hivemind_registry::RegistrySearchAuditStoreSummaryV1
        ))?,
        "registry-snapshot" => {
            serde_json::to_value(schema_for!(hivemind_registry::RegistrySnapshotV1))?
        }
        "registry-snapshot-source-record" => serde_json::to_value(schema_for!(
            hivemind_registry::RegistrySnapshotSourceRecordV1
        ))?,
        "registry-snapshot-verification" => serde_json::to_value(schema_for!(
            hivemind_registry::RegistrySnapshotVerificationV1
        ))?,
        "registry-package-lookup" => {
            serde_json::to_value(schema_for!(hivemind_registry::RegistryPackageLookupV1))?
        }
        "registry-package-lookup-request" => serde_json::to_value(schema_for!(
            hivemind_registry::RegistryPackageLookupRequestV1
        ))?,
        "registry-publication-status" => {
            serde_json::to_value(schema_for!(hivemind_registry::RegistryPublicationStatusV1))?
        }
        "registry-feed-status" => {
            serde_json::to_value(schema_for!(hivemind_registry::RegistryFeedStatusV1))?
        }
        "registry-shard" => serde_json::to_value(schema_for!(hivemind_registry::RegistryShardV1))?,
        "registry-shard-manifest" => {
            serde_json::to_value(schema_for!(hivemind_registry::RegistryShardManifestV1))?
        }
        "registry-shard-manifest-comparison" => serde_json::to_value(schema_for!(
            hivemind_registry::RegistryShardManifestComparisonV1
        ))?,
        "registry-shard-manifest-comparison-request" => serde_json::to_value(schema_for!(
            hivemind_registry::RegistryShardManifestComparisonRequestV1
        ))?,
        "registry-shard-manifest-verification" => serde_json::to_value(schema_for!(
            hivemind_registry::RegistryShardManifestVerificationV1
        ))?,
        "registry-shard-manifest-verification-request" => serde_json::to_value(schema_for!(
            hivemind_registry::RegistryShardManifestVerificationRequestV1
        ))?,
        "registry-shard-write-result" => {
            serde_json::to_value(schema_for!(hivemind_registry::RegistryShardWriteResultV1))?
        }
        "registry-shard-verification" => {
            serde_json::to_value(schema_for!(hivemind_registry::RegistryShardVerificationV1))?
        }
        "registry-shard-verification-request" => serde_json::to_value(schema_for!(
            hivemind_registry::RegistryShardVerificationRequestV1
        ))?,
        "storage-status" => serde_json::to_value(schema_for!(hivemind_storage::StorageStatusV1))?,
        "storage-retry-policy" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageRetryPolicyV1))?
        }
        "storage-transfer-metrics" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageTransferMetricsV1))?
        }
        "storage-download" => {
            serde_json::to_value(schema_for!(hivemind_storage::DownloadResponseV1))?
        }
        "storage-upload" => serde_json::to_value(schema_for!(hivemind_storage::UploadResponseV1))?,
        "storage-transfer-audit-record" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageTransferAuditRecordV1))?
        }
        "storage-transfer-audit-summary" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageTransferAuditSummaryV1))?
        }
        "storage-local-inspection" => {
            serde_json::to_value(schema_for!(hivemind_storage::LocalStorageInspectionV1))?
        }
        "storage-local-cache-summary" => {
            serde_json::to_value(schema_for!(hivemind_storage::LocalStorageCacheSummaryV1))?
        }
        "storage-feed-pointer" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageFeedPointerV1))?
        }
        "storage-feed-update" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageFeedUpdateResultV1))?
        }
        "storage-feed-resolution" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageFeedResolutionV1))?
        }
        "storage-pin-result" => {
            serde_json::to_value(schema_for!(hivemind_storage::StoragePinResultV1))?
        }
        "storage-provider-descriptor-v3" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageProviderDescriptorV3))?
        }
        "storage-provider-kind-v3" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageProviderKindV3))?
        }
        "storage-provider-capability-v3" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageProviderCapabilityV3))?
        }
        "storage-provider-kind-v4" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageProviderKindV4))?
        }
        "browser-swarm-storage-provider-v4" => {
            serde_json::to_value(schema_for!(hivemind_storage::BrowserSwarmStorageProviderV4))?
        }
        "browser-swarm-capability-report" => serde_json::to_value(schema_for!(
            hivemind_storage::BrowserSwarmCapabilityReportV1
        ))?,
        "browser-swarm-storage-method-v4" => {
            serde_json::to_value(schema_for!(hivemind_storage::BrowserSwarmStorageMethodV4))?
        }
        "browser-swarm-provider-conformance" => serde_json::to_value(schema_for!(
            hivemind_storage::BrowserSwarmProviderConformanceReportV1
        ))?,
        "browser-swarm-provider-catalog-v4" => {
            serde_json::to_value(schema_for!(hivemind_storage::BrowserSwarmProviderCatalogV4))?
        }
        "wallet-connection-result" => {
            serde_json::to_value(schema_for!(hivemind_storage::WalletConnectionResultV1))?
        }
        "retrieved-asset" => serde_json::to_value(schema_for!(hivemind_storage::RetrievedAssetV1))?,
        "storage-reference-verification-result" => serde_json::to_value(schema_for!(
            hivemind_storage::StorageReferenceVerificationResultV1
        ))?,
        "clear-state-receipt" => {
            serde_json::to_value(schema_for!(hivemind_storage::ClearStateReceiptV1))?
        }
        "browser-storage-capability-probe" => serde_json::to_value(schema_for!(
            hivemind_storage::BrowserStorageCapabilityProbeV1
        ))?,
        "browser-storage-purchase-quote" => {
            serde_json::to_value(schema_for!(hivemind_storage::BrowserStoragePurchaseQuoteV1))?
        }
        "browser-storage-purchase-authorization" => serde_json::to_value(schema_for!(
            hivemind_storage::BrowserStoragePurchaseAuthorizationV1
        ))?,
        "browser-storage-session-v2" => {
            serde_json::to_value(schema_for!(hivemind_storage::BrowserStorageSessionV2))?
        }
        "storage-event-receipt-v2" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageEventReceiptV2))?
        }
        "browser-storage-state-report" => {
            serde_json::to_value(schema_for!(hivemind_storage::BrowserStorageStateReportV1))?
        }
        "storage-cost" => serde_json::to_value(schema_for!(hivemind_storage::StorageCostV1))?,
        "browser-storage-consent" => {
            serde_json::to_value(schema_for!(hivemind_storage::BrowserStorageConsentV1))?
        }
        "browser-storage-session" => {
            serde_json::to_value(schema_for!(hivemind_storage::BrowserStorageSessionV1))?
        }
        "storage-event-receipt" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageEventReceiptV1))?
        }
        "storage-sponsorship" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageSponsorshipV1))?
        }
        "browser-service-worker-policy" => {
            serde_json::to_value(schema_for!(hivemind_storage::BrowserServiceWorkerPolicyV1))?
        }
        "browser-storage-security-assessment-request" => serde_json::to_value(schema_for!(
            hivemind_storage::BrowserStorageSecurityAssessmentRequestV1
        ))?,
        "browser-storage-security-assessment" => serde_json::to_value(schema_for!(
            hivemind_storage::BrowserStorageSecurityAssessmentV1
        ))?,
        "storage-contract-verification" => {
            serde_json::to_value(schema_for!(hivemind_storage::StorageContractVerificationV1))?
        }
        "identity-keypair" => {
            serde_json::to_value(schema_for!(hivemind_identity::IdentityKeypairV1))?
        }
        "identity-public" => {
            serde_json::to_value(schema_for!(hivemind_identity::PublicIdentityV1))?
        }
        "identity-signature" => {
            serde_json::to_value(schema_for!(hivemind_identity::SignatureEnvelopeV1))?
        }
        "identity-signature-verification" => {
            serde_json::to_value(schema_for!(hivemind_identity::SignatureVerificationV1))?
        }
        "access-grant" => serde_json::to_value(schema_for!(hivemind_core::AccessGrantV1))?,
        "access-grant-v2" => serde_json::to_value(schema_for!(hivemind_core::AccessGrantV2))?,
        "access-grant-v3" => serde_json::to_value(schema_for!(hivemind_core::AccessGrantV3))?,
        "access-scope" => serde_json::to_value(schema_for!(hivemind_core::AccessScopeV1))?,
        "access-subject" => serde_json::to_value(schema_for!(hivemind_core::AccessSubjectV1))?,
        "access-subject-type" => {
            serde_json::to_value(schema_for!(hivemind_core::AccessSubjectTypeV1))?
        }
        "access-grant-verification" => {
            serde_json::to_value(schema_for!(hivemind_access::AccessGrantVerificationV1))?
        }
        "access-grant-v2-verification" => {
            serde_json::to_value(schema_for!(hivemind_access::AccessGrantV2VerificationV1))?
        }
        "access-grant-v3-verification" => {
            serde_json::to_value(schema_for!(hivemind_access::AccessGrantV3VerificationV1))?
        }
        "access-grant-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_access::AccessGrantStoreSummaryV1))?
        }
        "access-grant-lookup" => {
            serde_json::to_value(schema_for!(hivemind_access::AccessGrantLookupV1))?
        }
        "access-grant-revocation" => {
            serde_json::to_value(schema_for!(hivemind_core::AccessGrantRevocationV1))?
        }
        "access-grant-revocation-verification" => serde_json::to_value(schema_for!(
            hivemind_access::AccessGrantRevocationVerificationV1
        ))?,
        "access-grant-revocation-store-summary" => serde_json::to_value(schema_for!(
            hivemind_access::AccessGrantRevocationStoreSummaryV1
        ))?,
        "access-grant-revocation-lookup" => {
            serde_json::to_value(schema_for!(hivemind_access::AccessGrantRevocationLookupV1))?
        }
        "access-revocation-list" => {
            serde_json::to_value(schema_for!(hivemind_core::AccessRevocationListV1))?
        }
        "access-revocation-list-verification" => serde_json::to_value(schema_for!(
            hivemind_access::AccessRevocationListVerificationV1
        ))?,
        "access-policy" => serde_json::to_value(schema_for!(hivemind_core::AccessPolicyV1))?,
        "access-policy-verification" => {
            serde_json::to_value(schema_for!(hivemind_core::AccessPolicyVerificationV1))?
        }
        "access-policy-v2" => serde_json::to_value(schema_for!(hivemind_core::AccessPolicyV2))?,
        "access-policy-v2-verification" => {
            serde_json::to_value(schema_for!(hivemind_core::AccessPolicyV2VerificationV1))?
        }
        "asset-access-rule" => serde_json::to_value(schema_for!(hivemind_core::AssetAccessRuleV1))?,
        "asset-access-rule-v2" => {
            serde_json::to_value(schema_for!(hivemind_core::AssetAccessRuleV2))?
        }
        "paid-access-quote" => serde_json::to_value(schema_for!(hivemind_core::PaidAccessQuoteV1))?,
        "access-evaluation-result" => {
            serde_json::to_value(schema_for!(hivemind_core::AccessEvaluationResultV1))?
        }
        "access-request" => serde_json::to_value(schema_for!(hivemind_core::AccessRequestV1))?,
        "license-policy" => serde_json::to_value(schema_for!(hivemind_core::LicensePolicyV1))?,
        "license-policy-v2" => serde_json::to_value(schema_for!(hivemind_core::LicensePolicyV2))?,
        "policy-decision" => serde_json::to_value(schema_for!(hivemind_core::PolicyDecisionV1))?,
        "privacy-tier-profile" => {
            serde_json::to_value(schema_for!(hivemind_core::PrivacyTierProfileV1))?
        }
        "privacy-tier-catalog" => {
            serde_json::to_value(schema_for!(hivemind_core::PrivacyTierCatalogV1))?
        }
        "privacy-requirement-assessment-request" => serde_json::to_value(schema_for!(
            hivemind_core::PrivacyRequirementAssessmentRequestV1
        ))?,
        "privacy-requirement-assessment" => {
            serde_json::to_value(schema_for!(hivemind_core::PrivacyRequirementAssessmentV1))?
        }
        "trust-policy" => serde_json::to_value(schema_for!(hivemind_core::TrustPolicyV1))?,
        "trust-policy-verification" => {
            serde_json::to_value(schema_for!(hivemind_core::TrustPolicyVerificationV1))?
        }
        "trust-policy-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_policy::TrustPolicyStoreSummaryV1))?
        }
        "trust-policy-lookup" => {
            serde_json::to_value(schema_for!(hivemind_policy::TrustPolicyLookupV1))?
        }
        "trust-policy-write-result" => {
            serde_json::to_value(schema_for!(hivemind_policy::TrustPolicyWriteResultV1))?
        }
        "permission-manifest" => {
            serde_json::to_value(schema_for!(hivemind_policy::PermissionManifestV1))?
        }
        "permission-manifest-v2" => {
            serde_json::to_value(schema_for!(hivemind_policy::PermissionManifestV2))?
        }
        "policy-inspection" => {
            serde_json::to_value(schema_for!(hivemind_policy::PolicyInspectionV1))?
        }
        "risk-inspection-report" => {
            serde_json::to_value(schema_for!(hivemind_policy::RiskInspectionReportV1))?
        }
        "consent-record" => serde_json::to_value(schema_for!(hivemind_policy::ConsentRecordV1))?,
        "tool-permission-grant" => {
            serde_json::to_value(schema_for!(hivemind_policy::ToolPermissionGrantV1))?
        }
        "marketplace-listing" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::MarketplaceListingV1))?
        }
        "marketplace-listing-verification" => serde_json::to_value(schema_for!(
            hivemind_marketplace::MarketplaceListingVerificationV1
        ))?,
        "marketplace-listing-v2" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::MarketplaceListingV2))?
        }
        "marketplace-listing-v2-verification" => serde_json::to_value(schema_for!(
            hivemind_marketplace::MarketplaceListingV2VerificationV1
        ))?,
        "runner-offer" => serde_json::to_value(schema_for!(hivemind_marketplace::RunnerOfferV1))?,
        "runner-offer-verification" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::RunnerOfferVerificationV1))?
        }
        "hardware-resource-offer" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::HardwareResourceOfferV1))?
        }
        "hardware-resource-offer-verification" => serde_json::to_value(schema_for!(
            hivemind_marketplace::HardwareResourceOfferVerificationV1
        ))?,
        "miner-profile" => serde_json::to_value(schema_for!(hivemind_miner::MinerProfileV1))?,
        "miner-profile-verification" => {
            serde_json::to_value(schema_for!(hivemind_miner::MinerProfileVerificationV1))?
        }
        "miner-heartbeat" => serde_json::to_value(schema_for!(hivemind_miner::MinerHeartbeatV1))?,
        "miner-heartbeat-verification" => {
            serde_json::to_value(schema_for!(hivemind_miner::MinerHeartbeatVerificationV1))?
        }
        "miner-benchmark-result" => {
            serde_json::to_value(schema_for!(hivemind_miner::MinerBenchmarkResultV1))?
        }
        "miner-benchmark-verification" => {
            serde_json::to_value(schema_for!(hivemind_miner::MinerBenchmarkVerificationV1))?
        }
        "miner-onboarding-plan" => {
            serde_json::to_value(schema_for!(hivemind_miner::MinerOnboardingPlanV1))?
        }
        "miner-dashboard-input" => {
            serde_json::to_value(schema_for!(hivemind_miner::MinerDashboardInputV1))?
        }
        "miner-dashboard-summary" => {
            serde_json::to_value(schema_for!(hivemind_miner::MinerDashboardSummaryV1))?
        }
        "miner-record-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_miner::MinerRecordStoreSummaryV1))?
        }
        "miner-record-lookup" => {
            serde_json::to_value(schema_for!(hivemind_miner::MinerRecordLookupV1))?
        }
        "miner-capacity-input" => {
            serde_json::to_value(schema_for!(hivemind_router::MinerCapacityInputV1))?
        }
        "miner-capacity-signal" => {
            serde_json::to_value(schema_for!(hivemind_router::MinerCapacitySignalV1))?
        }
        "marketplace-shortlist-request" => serde_json::to_value(schema_for!(
            hivemind_marketplace::MarketplaceShortlistRequestV1
        ))?,
        "runner-offer-score" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::RunnerOfferScoreV1))?
        }
        "marketplace-shortlist" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::MarketplaceShortlistV1))?
        }
        "service-quote" => serde_json::to_value(schema_for!(hivemind_marketplace::ServiceQuoteV1))?,
        "service-quote-timing" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::ServiceQuoteTimingV1))?
        }
        "service-quote-verification" => serde_json::to_value(schema_for!(
            hivemind_marketplace::ServiceQuoteVerificationV1
        ))?,
        "service-quote-store-summary" => serde_json::to_value(schema_for!(
            hivemind_marketplace::ServiceQuoteStoreSummaryV1
        ))?,
        "service-quote-lookup" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::ServiceQuoteLookupV1))?
        }
        "payment-authorization" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::PaymentAuthorizationV1))?
        }
        "payment-authorization-verification" => serde_json::to_value(schema_for!(
            hivemind_marketplace::PaymentAuthorizationVerificationV1
        ))?,
        "payment-authorization-store-summary" => serde_json::to_value(schema_for!(
            hivemind_marketplace::PaymentAuthorizationStoreSummaryV1
        ))?,
        "payment-authorization-lookup" => serde_json::to_value(schema_for!(
            hivemind_marketplace::PaymentAuthorizationLookupV1
        ))?,
        "escrow-record" => serde_json::to_value(schema_for!(hivemind_marketplace::EscrowRecordV1))?,
        "escrow-record-verification" => serde_json::to_value(schema_for!(
            hivemind_marketplace::EscrowRecordVerificationV1
        ))?,
        "escrow-release-request" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::EscrowReleaseRequestV1))?
        }
        "escrow-release-result" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::EscrowReleaseResultV1))?
        }
        "escrow-record-store-summary" => serde_json::to_value(schema_for!(
            hivemind_marketplace::EscrowRecordStoreSummaryV1
        ))?,
        "escrow-record-lookup" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::EscrowRecordLookupV1))?
        }
        "settlement-event" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::SettlementEventV1))?
        }
        "settlement-event-verification" => serde_json::to_value(schema_for!(
            hivemind_marketplace::SettlementEventVerificationV1
        ))?,
        "settlement-verification" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::SettlementVerificationV1))?
        }
        "settlement-build-result" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::SettlementBuildResultV1))?
        }
        "settlement-resolution" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::SettlementResolutionV1))?
        }
        "settlement-resolution-verification" => serde_json::to_value(schema_for!(
            hivemind_marketplace::SettlementResolutionVerificationV1
        ))?,
        "settlement-resolution-result" => serde_json::to_value(schema_for!(
            hivemind_marketplace::SettlementResolutionResultV1
        ))?,
        "refund-build-request" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::RefundBuildRequestV1))?
        }
        "refund-record" => serde_json::to_value(schema_for!(hivemind_marketplace::RefundRecordV1))?,
        "refund-record-verification" => serde_json::to_value(schema_for!(
            hivemind_marketplace::RefundRecordVerificationV1
        ))?,
        "refund-build-result" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::RefundBuildResultV1))?
        }
        "refund-record-store-summary" => serde_json::to_value(schema_for!(
            hivemind_marketplace::RefundRecordStoreSummaryV1
        ))?,
        "refund-record-lookup" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::RefundRecordLookupV1))?
        }
        "marketplace-audit-summary" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::MarketplaceAuditSummaryV1))?
        }
        "settlement-event-lookup" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::SettlementEventLookupV1))?
        }
        "settlement-resolution-lookup" => serde_json::to_value(schema_for!(
            hivemind_marketplace::SettlementResolutionLookupV1
        ))?,
        "slashing-build-request" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::SlashingBuildRequestV1))?
        }
        "slashing-record" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::SlashingRecordV1))?
        }
        "slashing-record-verification" => serde_json::to_value(schema_for!(
            hivemind_marketplace::SlashingRecordVerificationV1
        ))?,
        "slashing-build-result" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::SlashingBuildResultV1))?
        }
        "challenge" => serde_json::to_value(schema_for!(hivemind_validator::ChallengeV1))?,
        "validation-method" => {
            serde_json::to_value(schema_for!(hivemind_validator::ValidationMethodV2))?
        }
        "validation-method-descriptor" => serde_json::to_value(schema_for!(
            hivemind_validator::ValidationMethodDescriptorV1
        ))?,
        "validation-method-registry" => {
            serde_json::to_value(schema_for!(hivemind_validator::ValidationMethodRegistryV1))?
        }
        "validation-report" => {
            serde_json::to_value(schema_for!(hivemind_validator::ValidationReportV1))?
        }
        "validation-report-v2" => {
            serde_json::to_value(schema_for!(hivemind_validator::ValidationReportV2))?
        }
        "validation-report-verification" => serde_json::to_value(schema_for!(
            hivemind_validator::ValidationReportVerificationV1
        ))?,
        "validation-report-store-summary" => serde_json::to_value(schema_for!(
            hivemind_validator::ValidationReportStoreSummaryV1
        ))?,
        "validation-report-lookup" => {
            serde_json::to_value(schema_for!(hivemind_validator::ValidationReportLookupV1))?
        }
        "validation-report-upload" => serde_json::to_value(schema_for!(
            hivemind_validator::ValidationReportUploadResultV1
        ))?,
        "validation-report-download" => serde_json::to_value(schema_for!(
            hivemind_validator::ValidationReportDownloadResultV1
        ))?,
        "integrity-evidence" => {
            serde_json::to_value(schema_for!(hivemind_validator::IntegrityEvidenceV1))?
        }
        "integrity-evidence-init-options" => serde_json::to_value(schema_for!(
            hivemind_validator::IntegrityEvidenceInitOptionsV1
        ))?,
        "integrity-evidence-verification" => serde_json::to_value(schema_for!(
            hivemind_validator::IntegrityEvidenceVerificationV1
        ))?,
        "integrity-evidence-store-summary" => serde_json::to_value(schema_for!(
            hivemind_validator::IntegrityEvidenceStoreSummaryV1
        ))?,
        "integrity-evidence-lookup" => {
            serde_json::to_value(schema_for!(hivemind_validator::IntegrityEvidenceLookupV1))?
        }
        "reputation-profile" => {
            serde_json::to_value(schema_for!(hivemind_validator::ReputationProfileV1))?
        }
        "reputation-profile-v2" => {
            serde_json::to_value(schema_for!(hivemind_validator::ReputationProfileV2))?
        }
        "benchmark-package" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::BenchmarkPackageV1))?
        }
        "benchmark-split" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::BenchmarkSplitV1))?
        }
        "benchmark-privacy-rules" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::BenchmarkPrivacyRulesV1))?
        }
        "benchmark-expected-runtime" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::BenchmarkExpectedRuntimeV1))?
        }
        "benchmark-suite-init-options" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::BenchmarkSuiteInitOptionsV1
        ))?,
        "benchmark-suite" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::BenchmarkSuiteV1))?
        }
        "benchmark-suite-verification" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::BenchmarkSuiteVerificationV1
        ))?,
        "benchmark-pack-context" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::BenchmarkPackContextV1))?
        }
        "benchmark-pack-projection-request" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::BenchmarkPackProjectionRequestV1
        ))?,
        "benchmark-pack" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::BenchmarkPackV1))?
        }
        "benchmark-pack-verification" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::BenchmarkPackVerificationV1
        ))?,
        "benchmark-pack-projection" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::BenchmarkPackProjectionV1))?
        }
        "benchmark-suite-store-summary" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::BenchmarkSuiteStoreSummaryV1
        ))?,
        "benchmark-suite-lookup" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::BenchmarkSuiteLookupV1))?
        }
        "dataset-entry" => serde_json::to_value(schema_for!(hivemind_benchmarks::DatasetEntryV1))?,
        "scoring-rule" => serde_json::to_value(schema_for!(hivemind_benchmarks::ScoringRuleV1))?,
        "challenge-commitment-init-options" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::ChallengeCommitmentInitOptionsV1
        ))?,
        "challenge-commitment" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::ChallengeCommitmentV1))?
        }
        "challenge-commitment-verification" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::ChallengeCommitmentVerificationV1
        ))?,
        "challenge-commitment-store-summary" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::ChallengeCommitmentStoreSummaryV1
        ))?,
        "challenge-commitment-lookup" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::ChallengeCommitmentLookupV1
        ))?,
        "evaluation-result" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::EvaluationResultV1))?
        }
        "evaluation-result-verification" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::EvaluationResultVerificationV1
        ))?,
        "evaluation-result-store-summary" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::EvaluationResultStoreSummaryV1
        ))?,
        "evaluation-result-lookup" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::EvaluationResultLookupV1))?
        }
        "evaluation-cost-v2" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::EvaluationCostV2))?
        }
        "evaluation-timing-v2" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::EvaluationTimingV2))?
        }
        "evaluation-environment-v2" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::EvaluationEnvironmentV2))?
        }
        "evaluation-error-v2" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::EvaluationErrorV2))?
        }
        "evaluation-result-v2-context" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::EvaluationResultV2ContextV1
        ))?,
        "evaluation-result-v2-projection-request" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::EvaluationResultV2ProjectionRequestV1
        ))?,
        "evaluation-result-v2" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::EvaluationResultV2))?
        }
        "evaluation-result-v2-verification" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::EvaluationResultV2VerificationV1
        ))?,
        "evaluation-result-v2-store-summary" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::EvaluationResultV2StoreSummaryV1
        ))?,
        "evaluation-result-v2-lookup" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::EvaluationResultV2LookupV1))?
        }
        "evaluation-leaderboard-entry" => serde_json::to_value(schema_for!(
            hivemind_benchmarks::EvaluationLeaderboardEntryV1
        ))?,
        "evaluation-leaderboard" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::EvaluationLeaderboardV1))?
        }
        "eval-manifest" => serde_json::to_value(schema_for!(hivemind_evals::EvalManifestV1))?,
        "eval-manifest-init-options" => {
            serde_json::to_value(schema_for!(hivemind_evals::EvalManifestInitOptionsV1))?
        }
        "eval-manifest-verification" => {
            serde_json::to_value(schema_for!(hivemind_evals::EvalManifestVerificationV1))?
        }
        "eval-run" => serde_json::to_value(schema_for!(hivemind_evals::EvalRunV1))?,
        "eval-run-init-options" => {
            serde_json::to_value(schema_for!(hivemind_evals::EvalRunInitOptionsV1))?
        }
        "eval-run-verification" => {
            serde_json::to_value(schema_for!(hivemind_evals::EvalRunVerificationV1))?
        }
        "eval-run-planning-request" => {
            serde_json::to_value(schema_for!(hivemind_evals::EvalRunPlanningRequestV1))?
        }
        "eval-run-plan" => serde_json::to_value(schema_for!(hivemind_evals::EvalRunPlanV1))?,
        "eval-record-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_evals::EvalRecordStoreSummaryV1))?
        }
        "eval-record-lookup" => {
            serde_json::to_value(schema_for!(hivemind_evals::EvalRecordLookupV1))?
        }
        "research-experiment" => {
            serde_json::to_value(schema_for!(hivemind_research::ResearchExperimentV1))?
        }
        "research-experiment-init-options" => serde_json::to_value(schema_for!(
            hivemind_research::ResearchExperimentInitOptionsV1
        ))?,
        "research-experiment-verification" => serde_json::to_value(schema_for!(
            hivemind_research::ResearchExperimentVerificationV1
        ))?,
        "research-experiment-store-summary" => serde_json::to_value(schema_for!(
            hivemind_research::ResearchExperimentStoreSummaryV1
        ))?,
        "research-experiment-lookup" => {
            serde_json::to_value(schema_for!(hivemind_research::ResearchExperimentLookupV1))?
        }
        "research-reproduction-plan" => {
            serde_json::to_value(schema_for!(hivemind_research::ResearchReproductionPlanV1))?
        }
        "research-experiment-run" => {
            serde_json::to_value(schema_for!(hivemind_research::ResearchExperimentRunV1))?
        }
        "research-experiment-run-init-options" => serde_json::to_value(schema_for!(
            hivemind_research::ResearchExperimentRunInitOptionsV1
        ))?,
        "research-experiment-run-verification" => serde_json::to_value(schema_for!(
            hivemind_research::ResearchExperimentRunVerificationV1
        ))?,
        "research-experiment-run-store-summary" => serde_json::to_value(schema_for!(
            hivemind_research::ResearchExperimentRunStoreSummaryV1
        ))?,
        "research-experiment-run-lookup" => serde_json::to_value(schema_for!(
            hivemind_research::ResearchExperimentRunLookupV1
        ))?,
        "research-artifact-ref" => {
            serde_json::to_value(schema_for!(hivemind_research::ResearchArtifactRefV1))?
        }
        "evaluation-run-v2" => {
            serde_json::to_value(schema_for!(hivemind_research::EvaluationRunV2))?
        }
        "evaluation-run-v2-init-options" => {
            serde_json::to_value(schema_for!(hivemind_research::EvaluationRunV2InitOptionsV1))?
        }
        "evaluation-run-v2-verification" => serde_json::to_value(schema_for!(
            hivemind_research::EvaluationRunV2VerificationV1
        ))?,
        "research-result-record" => {
            serde_json::to_value(schema_for!(hivemind_research::ResearchResultRecordV1))?
        }
        "research-result-record-init-options" => serde_json::to_value(schema_for!(
            hivemind_research::ResearchResultRecordInitOptionsV1
        ))?,
        "research-result-record-verification" => serde_json::to_value(schema_for!(
            hivemind_research::ResearchResultRecordVerificationV1
        ))?,
        "reproducibility-bundle" => {
            serde_json::to_value(schema_for!(hivemind_research::ReproducibilityBundleV1))?
        }
        "reproducibility-bundle-init-options" => serde_json::to_value(schema_for!(
            hivemind_research::ReproducibilityBundleInitOptionsV1
        ))?,
        "reproducibility-bundle-verification" => serde_json::to_value(schema_for!(
            hivemind_research::ReproducibilityBundleVerificationV1
        ))?,
        "vector-store" => {
            serde_json::to_value(schema_for!(hivemind_vector::VectorStoreManifestV1))?
        }
        "vector-store-init-options" => {
            serde_json::to_value(schema_for!(hivemind_vector::VectorStoreInitOptionsV1))?
        }
        "vector-store-verification" => {
            serde_json::to_value(schema_for!(hivemind_vector::VectorStoreVerificationV1))?
        }
        "vector-store-manifest-store-summary" => serde_json::to_value(schema_for!(
            hivemind_vector::VectorStoreManifestStoreSummaryV1
        ))?,
        "vector-store-manifest-lookup" => {
            serde_json::to_value(schema_for!(hivemind_vector::VectorStoreManifestLookupV1))?
        }
        "document-collection" => {
            serde_json::to_value(schema_for!(hivemind_vector::DocumentCollectionManifestV1))?
        }
        "chunk-set" => serde_json::to_value(schema_for!(hivemind_vector::ChunkSetManifestV1))?,
        "embedding-set" => {
            serde_json::to_value(schema_for!(hivemind_vector::EmbeddingSetManifestV1))?
        }
        "vector-index-v2" => {
            serde_json::to_value(schema_for!(hivemind_vector::VectorIndexManifestV2))?
        }
        "retrieval-query" => serde_json::to_value(schema_for!(hivemind_vector::RetrievalQueryV1))?,
        "retrieval-planning-request" => {
            serde_json::to_value(schema_for!(hivemind_vector::RetrievalPlanningRequestV1))?
        }
        "retrieval-plan" => serde_json::to_value(schema_for!(hivemind_vector::RetrievalPlanV1))?,
        "rag-pipeline-v2" => {
            serde_json::to_value(schema_for!(hivemind_vector::RagPipelineManifestV2))?
        }
        "citation-trace" => serde_json::to_value(schema_for!(hivemind_vector::CitationTraceV1))?,
        "knowledge-asset-verification" => {
            serde_json::to_value(schema_for!(hivemind_vector::KnowledgeAssetVerificationV1))?
        }
        "vector-search-request" => {
            serde_json::to_value(schema_for!(hivemind_vector::VectorSearchRequestV1))?
        }
        "vector-search-planning-request" => {
            serde_json::to_value(schema_for!(hivemind_vector::VectorSearchPlanningRequestV1))?
        }
        "vector-search-plan" => {
            serde_json::to_value(schema_for!(hivemind_vector::VectorSearchPlanV1))?
        }
        "tool-manifest" => serde_json::to_value(schema_for!(hivemind_workflow::ToolManifestV1))?,
        "tool-manifest-init-options" => {
            serde_json::to_value(schema_for!(hivemind_workflow::ToolManifestInitOptionsV1))?
        }
        "tool-manifest-verification" => {
            serde_json::to_value(schema_for!(hivemind_workflow::ToolManifestVerificationV1))?
        }
        "workflow-manifest" => {
            serde_json::to_value(schema_for!(hivemind_workflow::WorkflowManifestV1))?
        }
        "workflow-manifest-init-options" => serde_json::to_value(schema_for!(
            hivemind_workflow::WorkflowManifestInitOptionsV1
        ))?,
        "workflow-manifest-verification" => serde_json::to_value(schema_for!(
            hivemind_workflow::WorkflowManifestVerificationV1
        ))?,
        "workflow-plan-request" => {
            serde_json::to_value(schema_for!(hivemind_workflow::WorkflowPlanRequestV1))?
        }
        "workflow-plan" => serde_json::to_value(schema_for!(hivemind_workflow::WorkflowPlanV1))?,
        "workflow-record-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_workflow::WorkflowRecordStoreSummaryV1))?
        }
        "workflow-record-lookup" => {
            serde_json::to_value(schema_for!(hivemind_workflow::WorkflowRecordLookupV1))?
        }
        "batch-job" => serde_json::to_value(schema_for!(hivemind_batch::BatchJobV1))?,
        "batch-job-init-options" => {
            serde_json::to_value(schema_for!(hivemind_batch::BatchJobInitOptionsV1))?
        }
        "batch-job-verification" => {
            serde_json::to_value(schema_for!(hivemind_batch::BatchJobVerificationV1))?
        }
        "batch-execution-plan" => {
            serde_json::to_value(schema_for!(hivemind_batch::BatchExecutionPlanV1))?
        }
        "batch-job-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_batch::BatchJobStoreSummaryV1))?
        }
        "batch-job-lookup" => serde_json::to_value(schema_for!(hivemind_batch::BatchJobLookupV1))?,
        "fine-tune-job" => serde_json::to_value(schema_for!(hivemind_fine_tune::FineTuneJobV1))?,
        "fine-tune-job-init-options" => {
            serde_json::to_value(schema_for!(hivemind_fine_tune::FineTuneJobInitOptionsV1))?
        }
        "fine-tune-job-verification" => {
            serde_json::to_value(schema_for!(hivemind_fine_tune::FineTuneJobVerificationV1))?
        }
        "fine-tune-execution-plan" => {
            serde_json::to_value(schema_for!(hivemind_fine_tune::FineTuneExecutionPlanV1))?
        }
        "fine-tune-job-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_fine_tune::FineTuneJobStoreSummaryV1))?
        }
        "fine-tune-job-lookup" => {
            serde_json::to_value(schema_for!(hivemind_fine_tune::FineTuneJobLookupV1))?
        }
        "media-job" => serde_json::to_value(schema_for!(hivemind_media::MediaJobV1))?,
        "media-job-init-options" => {
            serde_json::to_value(schema_for!(hivemind_media::MediaJobInitOptionsV1))?
        }
        "media-job-verification" => {
            serde_json::to_value(schema_for!(hivemind_media::MediaJobVerificationV1))?
        }
        "media-execution-plan" => {
            serde_json::to_value(schema_for!(hivemind_media::MediaExecutionPlanV1))?
        }
        "media-job-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_media::MediaJobStoreSummaryV1))?
        }
        "media-job-lookup" => serde_json::to_value(schema_for!(hivemind_media::MediaJobLookupV1))?,
        "realtime-session" => {
            serde_json::to_value(schema_for!(hivemind_realtime::RealtimeSessionV1))?
        }
        "realtime-session-init-options" => {
            serde_json::to_value(schema_for!(hivemind_realtime::RealtimeSessionInitOptionsV1))?
        }
        "realtime-session-verification" => serde_json::to_value(schema_for!(
            hivemind_realtime::RealtimeSessionVerificationV1
        ))?,
        "realtime-connection-plan" => {
            serde_json::to_value(schema_for!(hivemind_realtime::RealtimeConnectionPlanV1))?
        }
        "realtime-session-store-summary" => serde_json::to_value(schema_for!(
            hivemind_realtime::RealtimeSessionStoreSummaryV1
        ))?,
        "realtime-session-lookup" => {
            serde_json::to_value(schema_for!(hivemind_realtime::RealtimeSessionLookupV1))?
        }
        "moderation-policy" => {
            serde_json::to_value(schema_for!(hivemind_moderation::ModerationPolicyManifestV1))?
        }
        "moderation-policy-init-options" => serde_json::to_value(schema_for!(
            hivemind_moderation::ModerationPolicyInitOptionsV1
        ))?,
        "moderation-policy-verification" => serde_json::to_value(schema_for!(
            hivemind_moderation::ModerationPolicyVerificationV1
        ))?,
        "moderation-request" => {
            serde_json::to_value(schema_for!(hivemind_moderation::ModerationRequestV1))?
        }
        "moderation-request-init-options" => serde_json::to_value(schema_for!(
            hivemind_moderation::ModerationRequestInitOptionsV1
        ))?,
        "moderation-request-verification" => serde_json::to_value(schema_for!(
            hivemind_moderation::ModerationRequestVerificationV1
        ))?,
        "moderation-plan-request" => {
            serde_json::to_value(schema_for!(hivemind_moderation::ModerationPlanRequestV1))?
        }
        "moderation-plan" => {
            serde_json::to_value(schema_for!(hivemind_moderation::ModerationPlanV1))?
        }
        "moderation-record-store-summary" => serde_json::to_value(schema_for!(
            hivemind_moderation::ModerationRecordStoreSummaryV1
        ))?,
        "moderation-record-lookup" => {
            serde_json::to_value(schema_for!(hivemind_moderation::ModerationRecordLookupV1))?
        }
        "governance-policy" => {
            serde_json::to_value(schema_for!(hivemind_governance::GovernancePolicyManifestV1))?
        }
        "governance-policy-init-options" => serde_json::to_value(schema_for!(
            hivemind_governance::GovernancePolicyInitOptionsV1
        ))?,
        "governance-policy-verification" => serde_json::to_value(schema_for!(
            hivemind_governance::GovernancePolicyVerificationV1
        ))?,
        "schema-release" => {
            serde_json::to_value(schema_for!(hivemind_governance::SchemaReleaseV1))?
        }
        "schema-release-init-options" => {
            serde_json::to_value(schema_for!(hivemind_governance::SchemaReleaseInitOptionsV1))?
        }
        "schema-release-verification" => serde_json::to_value(schema_for!(
            hivemind_governance::SchemaReleaseVerificationV1
        ))?,
        "security-advisory" => {
            serde_json::to_value(schema_for!(hivemind_governance::SecurityAdvisoryV1))?
        }
        "security-advisory-init-options" => serde_json::to_value(schema_for!(
            hivemind_governance::SecurityAdvisoryInitOptionsV1
        ))?,
        "security-advisory-verification" => serde_json::to_value(schema_for!(
            hivemind_governance::SecurityAdvisoryVerificationV1
        ))?,
        "security-response-plan" => {
            serde_json::to_value(schema_for!(hivemind_governance::SecurityResponsePlanV1))?
        }
        "component-readiness" => {
            serde_json::to_value(schema_for!(hivemind_governance::ComponentReadinessV1))?
        }
        "component-readiness-init-options" => serde_json::to_value(schema_for!(
            hivemind_governance::ComponentReadinessInitOptionsV1
        ))?,
        "component-readiness-verification" => serde_json::to_value(schema_for!(
            hivemind_governance::ComponentReadinessVerificationV1
        ))?,
        "governance-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_governance::GovernanceStoreSummaryV1))?
        }
        "governance-record-lookup" => {
            serde_json::to_value(schema_for!(hivemind_governance::GovernanceRecordLookupV1))?
        }
        "compatibility-report" => {
            serde_json::to_value(schema_for!(hivemind_sdk::CompatibilityReportV1))?
        }
        "compatibility-certification" => {
            serde_json::to_value(schema_for!(hivemind_sdk::CompatibilityCertificationV1))?
        }
        "compatibility-certification-index-entry" => serde_json::to_value(schema_for!(
            hivemind_sdk::CompatibilityCertificationIndexEntryV1
        ))?,
        "compatibility-certification-store-summary" => serde_json::to_value(schema_for!(
            hivemind_sdk::CompatibilityCertificationStoreSummaryV1
        ))?,
        "compatibility-certification-lookup" => serde_json::to_value(schema_for!(
            hivemind_sdk::CompatibilityCertificationLookupV1
        ))?,
        "compatibility-certification-write-result" => serde_json::to_value(schema_for!(
            hivemind_sdk::CompatibilityCertificationWriteResultV1
        ))?,
        "receipt-verification" => {
            serde_json::to_value(schema_for!(hivemind_receipts::ReceiptVerificationV1))?
        }
        "receipt-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_receipts::ReceiptStoreSummaryV1))?
        }
        "receipt-audit-summary" => {
            serde_json::to_value(schema_for!(hivemind_receipts::ReceiptAuditSummaryV1))?
        }
        "receipt-lookup" => {
            serde_json::to_value(schema_for!(hivemind_receipts::ReceiptLookupResultV1))?
        }
        "receipt-upload" => {
            serde_json::to_value(schema_for!(hivemind_receipts::ReceiptUploadResultV1))?
        }
        "receipt-download" => {
            serde_json::to_value(schema_for!(hivemind_receipts::ReceiptDownloadResultV1))?
        }
        "receipt-redaction-policy" => {
            serde_json::to_value(schema_for!(hivemind_receipts::ReceiptRedactionPolicyV1))?
        }
        "receipt-redaction" => {
            serde_json::to_value(schema_for!(hivemind_receipts::RedactedReceiptV1))?
        }
        "receipt-redaction-verification" => serde_json::to_value(schema_for!(
            hivemind_receipts::RedactedReceiptVerificationV1
        ))?,
        "batch-receipt" => serde_json::to_value(schema_for!(hivemind_receipts::BatchReceiptV1))?,
        "batch-receipt-verification" => {
            serde_json::to_value(schema_for!(hivemind_receipts::BatchReceiptVerificationV1))?
        }
        "batch-receipt-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_receipts::BatchReceiptStoreSummaryV1))?
        }
        "batch-receipt-audit-summary" => {
            serde_json::to_value(schema_for!(hivemind_receipts::BatchReceiptAuditSummaryV1))?
        }
        "batch-receipt-lookup" => {
            serde_json::to_value(schema_for!(hivemind_receipts::BatchReceiptLookupV1))?
        }
        "partial-receipt" => {
            serde_json::to_value(schema_for!(hivemind_receipts::PartialReceiptV1))?
        }
        "partial-receipt-verification" => {
            serde_json::to_value(schema_for!(hivemind_receipts::PartialReceiptVerificationV1))?
        }
        "partial-receipt-stream-summary" => serde_json::to_value(schema_for!(
            hivemind_receipts::PartialReceiptStreamSummaryV1
        ))?,
        "receipt-dispute-evidence" => {
            serde_json::to_value(schema_for!(hivemind_receipts::DisputeEvidenceV1))?
        }
        "receipt-dispute-verification" => serde_json::to_value(schema_for!(
            hivemind_receipts::DisputeEvidenceVerificationV1
        ))?,
        "receipt-dispute-store-summary" => serde_json::to_value(schema_for!(
            hivemind_receipts::DisputeEvidenceStoreSummaryV1
        ))?,
        "receipt-dispute-lookup" => serde_json::to_value(schema_for!(
            hivemind_receipts::DisputeEvidenceLookupResultV1
        ))?,
        "execution-receipt-v2" => {
            serde_json::to_value(schema_for!(hivemind_core::ExecutionReceiptV2))?
        }
        "execution-receipt-v2-verification-request" => serde_json::to_value(schema_for!(
            hivemind_receipts::ExecutionReceiptV2VerificationRequestV1
        ))?,
        "execution-receipt-v2-verification" => serde_json::to_value(schema_for!(
            hivemind_receipts::ExecutionReceiptV2VerificationV1
        ))?,
        "receipt-correctness-assessment-request" => serde_json::to_value(schema_for!(
            hivemind_receipts::ReceiptCorrectnessAssessmentRequestV1
        ))?,
        "receipt-correctness-assessment" => serde_json::to_value(schema_for!(
            hivemind_receipts::ReceiptCorrectnessAssessmentV1
        ))?,
        "browser-runner" => {
            serde_json::to_value(schema_for!(hivemind_browser_runner::BrowserRunnerV1))?
        }
        "browser-capabilities" => {
            serde_json::to_value(schema_for!(hivemind_browser_runner::BrowserCapabilitiesV1))?
        }
        "browser-assessment" => {
            serde_json::to_value(schema_for!(hivemind_browser_runner::BrowserRunAssessmentV1))?
        }
        "browser-prepare-plan" => {
            serde_json::to_value(schema_for!(hivemind_browser_runner::BrowserPreparePlanV1))?
        }
        "browser-prepared-package" => serde_json::to_value(schema_for!(
            hivemind_browser_runner::BrowserPreparedPackageV1
        ))?,
        "weeb3-adapter" => serde_json::to_value(schema_for!(
            hivemind_weeb3_adapter::Weeb3AdapterDescriptorV1
        ))?,
        "browser-swarm-provider" => {
            serde_json::to_value(schema_for!(hivemind_weeb3_adapter::BrowserSwarmProviderV1))?
        }
        "browser-swarm-config" => {
            serde_json::to_value(schema_for!(hivemind_weeb3_adapter::BrowserSwarmConfigV1))?
        }
        "browser-swarm-status" => {
            serde_json::to_value(schema_for!(hivemind_weeb3_adapter::BrowserSwarmStatusV1))?
        }
        "browser-swarm-retrieval" => {
            serde_json::to_value(schema_for!(hivemind_weeb3_adapter::BrowserSwarmRetrievalV1))?
        }
        "browser-swarm-compatibility" => serde_json::to_value(schema_for!(
            hivemind_weeb3_adapter::BrowserSwarmCompatibilityReportV1
        ))?,
        "browser-swarm-security-review" => serde_json::to_value(schema_for!(
            hivemind_weeb3_adapter::BrowserSwarmSecurityReviewV1
        ))?,
        "browser-swarm-retrieve-request" => serde_json::to_value(schema_for!(
            hivemind_weeb3_adapter::BrowserSwarmRetrieveRequestV1
        ))?,
        "remote-runner-api" => {
            serde_json::to_value(schema_for!(hivemind_remote_runner::RemoteRunnerApiV1))?
        }
        "remote-health" => {
            serde_json::to_value(schema_for!(hivemind_remote_runner::RemoteRunnerHealthV1))?
        }
        "remote-pricing" => {
            serde_json::to_value(schema_for!(hivemind_remote_runner::RemoteRunnerPricingV1))?
        }
        "remote-prepare-request" => {
            serde_json::to_value(schema_for!(hivemind_remote_runner::RemotePrepareRequestV1))?
        }
        "remote-prepared-package" => {
            serde_json::to_value(schema_for!(hivemind_remote_runner::RemotePreparedPackageV1))?
        }
        "remote-cancel-request" => {
            serde_json::to_value(schema_for!(hivemind_remote_runner::RemoteCancelRequestV1))?
        }
        "remote-cancel-result" => {
            serde_json::to_value(schema_for!(hivemind_remote_runner::RemoteCancelResultV1))?
        }
        "local-runner-install" => {
            serde_json::to_value(schema_for!(hivemind_local_runner::InstalledPackageV1))?
        }
        "local-runner-cache" => serde_json::to_value(schema_for!(
            hivemind_local_runner::LocalRunnerCacheSummaryV1
        ))?,
        "local-runner-cache-clear" => serde_json::to_value(schema_for!(
            hivemind_local_runner::LocalRunnerCacheClearResultV1
        ))?,
        "local-runner-sensitive-cache-marker" => {
            serde_json::to_value(schema_for!(hivemind_local_runner::SensitiveCacheMarkerV1))?
        }
        "runner-capability" => {
            serde_json::to_value(schema_for!(hivemind_core::RunnerCapabilityV1))?
        }
        "runner-capability-v2" => {
            serde_json::to_value(schema_for!(hivemind_core::RunnerCapabilityV2))?
        }
        "job-order" => serde_json::to_value(schema_for!(hivemind_core::JobOrderV1))?,
        "job-access-attachment" => {
            serde_json::to_value(schema_for!(hivemind_core::JobAccessAttachmentV1))?
        }
        "job-record" => serde_json::to_value(schema_for!(hivemind_jobs::JobRecordV1))?,
        "job-store-summary" => serde_json::to_value(schema_for!(hivemind_jobs::JobStoreSummaryV1))?,
        "job-lookup" => serde_json::to_value(schema_for!(hivemind_jobs::JobLookupResultV1))?,
        "job-cancellation-request" => {
            serde_json::to_value(schema_for!(hivemind_jobs::JobCancellationRequestV1))?
        }
        "job-cancellation-result" => {
            serde_json::to_value(schema_for!(hivemind_jobs::JobCancellationResultV1))?
        }
        "job-expiration-sweep-request" => {
            serde_json::to_value(schema_for!(hivemind_jobs::JobExpirationSweepRequestV1))?
        }
        "job-expiration-sweep-result" => {
            serde_json::to_value(schema_for!(hivemind_jobs::JobExpirationSweepResultV1))?
        }
        "job-store-audit-request" => {
            serde_json::to_value(schema_for!(hivemind_jobs::JobStoreAuditRequestV1))?
        }
        "job-store-audit-summary" => {
            serde_json::to_value(schema_for!(hivemind_jobs::JobStoreAuditSummaryV1))?
        }
        "job-evidence-link-request" => {
            serde_json::to_value(schema_for!(hivemind_jobs::JobEvidenceLinkRequestV1))?
        }
        "job-evidence-link-result" => {
            serde_json::to_value(schema_for!(hivemind_jobs::JobEvidenceLinkResultV1))?
        }
        "job-lifecycle-event" => {
            serde_json::to_value(schema_for!(hivemind_jobs::JobLifecycleEventV1))?
        }
        "job-lifecycle-timeline" => {
            serde_json::to_value(schema_for!(hivemind_jobs::JobLifecycleTimelineV1))?
        }
        "job-production-lifecycle" => {
            serde_json::to_value(schema_for!(hivemind_jobs::JobProductionLifecycleV1))?
        }
        "job-production-lifecycle-store-summary" => serde_json::to_value(schema_for!(
            hivemind_jobs::JobProductionLifecycleStoreSummaryV1
        ))?,
        "job-quote" => serde_json::to_value(schema_for!(hivemind_core::JobQuoteV1))?,
        "execution-lease-request" => {
            serde_json::to_value(schema_for!(hivemind_core::ExecutionLeaseRequestV1))?
        }
        "execution-lease" => serde_json::to_value(schema_for!(hivemind_core::ExecutionLeaseV1))?,
        "streaming-event" => serde_json::to_value(schema_for!(hivemind_core::StreamingEventV1))?,
        "stream-event-store" => {
            serde_json::to_value(schema_for!(hivemind_streams::StreamEventStoreSummaryV1))?
        }
        "stream-event-audit-summary" => {
            serde_json::to_value(schema_for!(hivemind_streams::StreamEventAuditSummaryV1))?
        }
        "cost-quote" => serde_json::to_value(schema_for!(hivemind_router::CostQuoteV1))?,
        "runner-reputation-summary" => {
            serde_json::to_value(schema_for!(hivemind_router::RunnerReputationSummaryV1))?
        }
        "route-planner-request" => {
            serde_json::to_value(schema_for!(hivemind_router::RoutePlannerRequestV1))?
        }
        "route-planner-report" => {
            serde_json::to_value(schema_for!(hivemind_router::RoutePlannerReportV1))?
        }
        "route-planner-timing" => {
            serde_json::to_value(schema_for!(hivemind_router::RoutePlannerTimingV1))?
        }
        "route-execution-trace" => {
            serde_json::to_value(schema_for!(hivemind_router::RouteExecutionTraceV1))?
        }
        "route-trace-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_router::RouteTraceStoreSummaryV1))?
        }
        "route-trace-lookup" => {
            serde_json::to_value(schema_for!(hivemind_router::RouteTraceLookupV1))?
        }
        "route-decision-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_router::RouteDecisionStoreSummaryV1))?
        }
        "route-decision-lookup" => {
            serde_json::to_value(schema_for!(hivemind_router::RouteDecisionLookupV1))?
        }
        "route-decision-record" => {
            serde_json::to_value(schema_for!(hivemind_router::RouteDecisionRecordV1))?
        }
        "route-decision-proof" => {
            serde_json::to_value(schema_for!(hivemind_router::RouteDecisionProofV1))?
        }
        "route-decision-proof-verification" => serde_json::to_value(schema_for!(
            hivemind_router::RouteDecisionProofVerificationV1
        ))?,
        "operational-snapshot-request" => serde_json::to_value(schema_for!(
            hivemind_observability::OperationalMetricSnapshotRequestV1
        ))?,
        "operational-snapshot" => serde_json::to_value(schema_for!(
            hivemind_observability::OperationalMetricSnapshotV1
        ))?,
        "operational-snapshot-verification" => serde_json::to_value(schema_for!(
            hivemind_observability::OperationalMetricSnapshotVerificationV1
        ))?,
        "operational-snapshot-store-summary" => serde_json::to_value(schema_for!(
            hivemind_observability::OperationalMetricSnapshotStoreSummaryV1
        ))?,
        "operational-snapshot-lookup" => serde_json::to_value(schema_for!(
            hivemind_observability::OperationalMetricSnapshotLookupV1
        ))?,
        "openai-chat-completion-request" => {
            serde_json::to_value(schema_for!(hivemind_openai_compat::ChatCompletionRequestV1))?
        }
        "openai-chat-completion-response" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::ChatCompletionResponseV1
        ))?,
        "openai-chat-completion-stream-event" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::ChatCompletionStreamEventV1
        ))?,
        "openai-responses-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiResponsesRequestV1
        ))?,
        "openai-responses-response" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiResponsesResponseV1
        ))?,
        "openai-responses-stream-event" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiResponsesStreamEventV1
        ))?,
        "anthropic-message-request" => serde_json::to_value(schema_for!(
            hivemind_provider_compat::AnthropicMessageRequestV1
        ))?,
        "anthropic-message-response" => serde_json::to_value(schema_for!(
            hivemind_provider_compat::AnthropicMessageResponseV1
        ))?,
        "gemini-generate-content-request" => serde_json::to_value(schema_for!(
            hivemind_provider_compat::GeminiGenerateContentRequestV1
        ))?,
        "gemini-generate-content-response" => serde_json::to_value(schema_for!(
            hivemind_provider_compat::GeminiGenerateContentResponseV1
        ))?,
        "gemini-live-session-create-request" => serde_json::to_value(schema_for!(
            hivemind_provider_compat::GeminiLiveSessionCreateRequestV1
        ))?,
        "gemini-live-session" => {
            serde_json::to_value(schema_for!(hivemind_provider_compat::GeminiLiveSessionV1))?
        }
        "huggingface-inference-request" => serde_json::to_value(schema_for!(
            hivemind_provider_compat::HuggingFaceInferenceRequestV1
        ))?,
        "huggingface-inference-response" => serde_json::to_value(schema_for!(
            hivemind_provider_compat::HuggingFaceInferenceResponseV1
        ))?,
        "openai-file-create-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiFileCreateRequestV1
        ))?,
        "openai-file" => serde_json::to_value(schema_for!(hivemind_openai_compat::OpenAiFileV1))?,
        "openai-vector-store-create-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiVectorStoreCreateRequestV1
        ))?,
        "openai-vector-store" => {
            serde_json::to_value(schema_for!(hivemind_openai_compat::OpenAiVectorStoreV1))?
        }
        "openai-vector-store-search-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiVectorStoreSearchRequestV1
        ))?,
        "openai-vector-store-search-response" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiVectorStoreSearchResponseV1
        ))?,
        "openai-batch-create-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiBatchCreateRequestV1
        ))?,
        "openai-batch" => serde_json::to_value(schema_for!(hivemind_openai_compat::OpenAiBatchV1))?,
        "openai-fine-tuning-create-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiFineTuningCreateRequestV1
        ))?,
        "openai-fine-tuning-job" => {
            serde_json::to_value(schema_for!(hivemind_openai_compat::OpenAiFineTuningJobV1))?
        }
        "openai-realtime-session-create-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiRealtimeSessionCreateRequestV1
        ))?,
        "openai-realtime-session" => {
            serde_json::to_value(schema_for!(hivemind_openai_compat::OpenAiRealtimeSessionV1))?
        }
        "openai-eval-create-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiEvalCreateRequestV1
        ))?,
        "openai-eval" => serde_json::to_value(schema_for!(hivemind_openai_compat::OpenAiEvalV1))?,
        "openai-eval-run-create-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiEvalRunCreateRequestV1
        ))?,
        "openai-eval-run" => {
            serde_json::to_value(schema_for!(hivemind_openai_compat::OpenAiEvalRunV1))?
        }
        "openai-image-generation-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiImageGenerationRequestV1
        ))?,
        "openai-image-edit-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiImageEditRequestV1
        ))?,
        "openai-image-generation-response" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiImageGenerationResponseV1
        ))?,
        "openai-audio-transcription-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiAudioTranscriptionRequestV1
        ))?,
        "openai-audio-transcription-response" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiAudioTranscriptionResponseV1
        ))?,
        "openai-audio-speech-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiAudioSpeechRequestV1
        ))?,
        "openai-audio-speech-response" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiAudioSpeechResponseV1
        ))?,
        "openai-model" => serde_json::to_value(schema_for!(hivemind_openai_compat::OpenAiModelV1))?,
        "openai-model-list" => {
            serde_json::to_value(schema_for!(hivemind_openai_compat::OpenAiModelListV1))?
        }
        "openai-embedding-request" => {
            serde_json::to_value(schema_for!(hivemind_openai_compat::EmbeddingRequestV1))?
        }
        "openai-embedding-response" => {
            serde_json::to_value(schema_for!(hivemind_openai_compat::EmbeddingResponseV1))?
        }
        "openai-moderation-request" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiModerationRequestV1
        ))?,
        "openai-moderation-response" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::OpenAiModerationResponseV1
        ))?,
        "openai-error" => {
            serde_json::to_value(schema_for!(hivemind_openai_compat::OpenAiErrorResponseV1))?
        }
        "publication-record" => {
            serde_json::to_value(schema_for!(hivemind_publisher::PublicationRecordV1))?
        }
        "publication-record-store-summary" => serde_json::to_value(schema_for!(
            hivemind_publisher::PublicationRecordStoreSummaryV1
        ))?,
        "publication-record-lookup" => {
            serde_json::to_value(schema_for!(hivemind_publisher::PublicationRecordLookupV1))?
        }
        "package-signature" => {
            serde_json::to_value(schema_for!(hivemind_publisher::PackageSignatureV1))?
        }
        "publication-verification" => {
            serde_json::to_value(schema_for!(hivemind_publisher::PublicationVerificationV1))?
        }
        "publish-result" => serde_json::to_value(schema_for!(hivemind_publisher::PublishResultV1))?,
        "feed-pointer" => serde_json::to_value(schema_for!(hivemind_publisher::FeedPointerV1))?,
        "feed-pointer-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_publisher::FeedPointerStoreSummaryV1))?
        }
        "feed-pointer-lookup" => {
            serde_json::to_value(schema_for!(hivemind_publisher::FeedPointerLookupV1))?
        }
        "feed-update-result" => {
            serde_json::to_value(schema_for!(hivemind_publisher::FeedUpdateResultV1))?
        }
        "feed-verification" => {
            serde_json::to_value(schema_for!(hivemind_publisher::FeedVerificationV1))?
        }
        "feed-resolve-request" => {
            serde_json::to_value(schema_for!(hivemind_publisher::FeedResolveRequestV1))?
        }
        "feed-resolution" => {
            serde_json::to_value(schema_for!(hivemind_publisher::FeedResolutionV1))?
        }
        "receipt" => serde_json::to_value(schema_for!(hivemind_core::ExecutionReceiptV1))?,
        "receipt-v2" => serde_json::to_value(schema_for!(hivemind_core::ExecutionReceiptV2))?,
        "receipt-v2-verification-request" => serde_json::to_value(schema_for!(
            hivemind_receipts::ExecutionReceiptV2VerificationRequestV1
        ))?,
        "receipt-v2-verification" => serde_json::to_value(schema_for!(
            hivemind_receipts::ExecutionReceiptV2VerificationV1
        ))?,
        other => anyhow::bail!(
            "unknown schema {other}; expected package, package-init-options, package-init-result, package-validation-audit-record, package-validation-audit-store-summary, execution-request, ai-request, ai-request-verification, ai-response, ai-response-verification, ai-execution-plan, ai-input-part, ai-output-part, swarm-ai-error, standard-error-code, standard-error-definition, standard-error-catalog, registry-entry, registry-query, registry-search-audit-record, registry-search-audit-store-summary, registry-snapshot, registry-package-lookup, registry-package-lookup-request, registry-publication-status, registry-feed-status, registry-shard, registry-shard-manifest, registry-shard-manifest-comparison, registry-shard-manifest-comparison-request, registry-shard-manifest-verification, registry-shard-manifest-verification-request, registry-shard-write-result, registry-shard-verification, registry-shard-verification-request, storage-status, storage-retry-policy, storage-transfer-metrics, storage-download, storage-upload, storage-local-inspection, storage-local-cache-summary, storage-feed-pointer, storage-feed-update, storage-feed-resolution, storage-pin-result, identity-keypair, identity-public, identity-signature, identity-signature-verification, access-grant, access-grant-verification, access-grant-store-summary, access-grant-lookup, access-grant-revocation, access-grant-revocation-verification, access-grant-revocation-store-summary, access-grant-revocation-lookup, access-revocation-list, access-revocation-list-verification, access-request, license-policy, policy-decision, trust-policy, trust-policy-verification, permission-manifest, policy-inspection, marketplace-listing, marketplace-listing-verification, runner-offer, runner-offer-verification, hardware-resource-offer, hardware-resource-offer-verification, miner-profile, miner-profile-verification, miner-heartbeat, miner-heartbeat-verification, miner-benchmark-result, miner-benchmark-verification, miner-onboarding-plan, miner-dashboard-input, miner-dashboard-summary, miner-record-store-summary, miner-record-lookup, miner-capacity-input, miner-capacity-signal, marketplace-shortlist-request, runner-offer-score, marketplace-shortlist, service-quote, service-quote-verification, service-quote-store-summary, service-quote-lookup, payment-authorization, payment-authorization-verification, payment-authorization-store-summary, payment-authorization-lookup, settlement-event, settlement-event-verification, settlement-verification, settlement-build-result, settlement-resolution, settlement-resolution-verification, settlement-resolution-result, marketplace-audit-summary, settlement-event-lookup, settlement-resolution-lookup, challenge, validation-report, validation-report-verification, validation-report-store-summary, validation-report-lookup, validation-report-upload, validation-report-download, integrity-evidence, integrity-evidence-init-options, integrity-evidence-verification, integrity-evidence-store-summary, integrity-evidence-lookup, reputation-profile, benchmark-package, benchmark-split, benchmark-privacy-rules, benchmark-expected-runtime, benchmark-suite-init-options, benchmark-suite, benchmark-suite-verification, benchmark-suite-store-summary, benchmark-suite-lookup, dataset-entry, scoring-rule, challenge-commitment-init-options, challenge-commitment, challenge-commitment-verification, challenge-commitment-store-summary, challenge-commitment-lookup, evaluation-result, evaluation-result-verification, evaluation-result-store-summary, evaluation-result-lookup, evaluation-cost-v2, evaluation-timing-v2, evaluation-environment-v2, evaluation-error-v2, evaluation-result-v2-context, evaluation-result-v2-projection-request, evaluation-result-v2, evaluation-result-v2-verification, evaluation-result-v2-store-summary, evaluation-result-v2-lookup, evaluation-leaderboard-entry, evaluation-leaderboard, eval-manifest, eval-manifest-init-options, eval-manifest-verification, eval-run, eval-run-init-options, eval-run-verification, eval-run-planning-request, eval-run-plan, eval-record-store-summary, eval-record-lookup, research-experiment, research-experiment-init-options, research-experiment-verification, research-experiment-store-summary, research-experiment-lookup, research-reproduction-plan, research-experiment-run, research-experiment-run-init-options, research-experiment-run-verification, research-experiment-run-store-summary, research-experiment-run-lookup, vector-store, vector-store-init-options, vector-store-verification, vector-store-manifest-store-summary, vector-store-manifest-lookup, vector-search-request, vector-search-planning-request, vector-search-plan, tool-manifest, tool-manifest-init-options, tool-manifest-verification, workflow-manifest, workflow-manifest-init-options, workflow-manifest-verification, workflow-plan-request, workflow-plan, workflow-record-store-summary, workflow-record-lookup, batch-job, batch-job-init-options, batch-job-verification, batch-execution-plan, fine-tune-job, fine-tune-job-init-options, fine-tune-job-verification, fine-tune-execution-plan, media-job, media-job-init-options, media-job-verification, media-execution-plan, realtime-session, realtime-session-init-options, realtime-session-verification, realtime-connection-plan, moderation-policy, moderation-policy-init-options, moderation-policy-verification, moderation-request, moderation-request-init-options, moderation-request-verification, moderation-plan-request, moderation-plan, moderation-record-store-summary, moderation-record-lookup, governance-policy, governance-policy-init-options, governance-policy-verification, schema-release, schema-release-init-options, schema-release-verification, security-advisory, security-advisory-init-options, security-advisory-verification, security-response-plan, governance-store-summary, governance-record-lookup, compatibility-report, compatibility-certification, receipt-verification, receipt-store-summary, receipt-audit-summary, receipt-lookup, receipt-upload, receipt-download, receipt-redaction-policy, receipt-redaction, receipt-redaction-verification, execution-receipt-v2-verification-request, execution-receipt-v2-verification, receipt-v2-verification-request, receipt-v2-verification, batch-receipt, batch-receipt-verification, batch-receipt-store-summary, batch-receipt-audit-summary, batch-receipt-lookup, partial-receipt, partial-receipt-verification, partial-receipt-stream-summary, receipt-dispute-evidence, receipt-dispute-verification, receipt-dispute-store-summary, receipt-dispute-lookup, browser-runner, browser-capabilities, browser-assessment, browser-prepare-plan, browser-prepared-package, weeb3-adapter, browser-swarm-provider, browser-swarm-config, browser-swarm-status, browser-swarm-retrieval, browser-swarm-compatibility, browser-swarm-security-review, browser-swarm-retrieve-request, remote-runner-api, remote-health, remote-pricing, remote-prepare-request, remote-prepared-package, remote-cancel-request, remote-cancel-result, local-runner-install, local-runner-cache, local-runner-cache-clear, local-runner-sensitive-cache-marker, runner-capability, job-order, job-record, job-store-summary, job-lookup, job-cancellation-request, job-cancellation-result, job-expiration-sweep-request, job-expiration-sweep-result, job-store-audit-request, job-store-audit-summary, job-evidence-link-request, job-evidence-link-result, job-quote, execution-lease-request, execution-lease, streaming-event, stream-event-store, cost-quote, runner-reputation-summary, route-planner-request, route-planner-report, route-execution-trace, route-trace-store-summary, route-trace-lookup, route-decision-store-summary, route-decision-lookup, route-decision-record, route-decision-proof, route-decision-proof-verification, openai-chat-completion-request, openai-chat-completion-response, openai-chat-completion-stream-event, openai-responses-request, openai-responses-response, openai-responses-stream-event, anthropic-message-request, anthropic-message-response, gemini-generate-content-request, gemini-generate-content-response, gemini-live-session-create-request, gemini-live-session, huggingface-inference-request, huggingface-inference-response, openai-file-create-request, openai-file, openai-vector-store-create-request, openai-vector-store-search-request, openai-vector-store-search-response, openai-batch-create-request, openai-batch, openai-fine-tuning-create-request, openai-fine-tuning-job, openai-realtime-session-create-request, openai-realtime-session, openai-eval-create-request, openai-eval, openai-eval-run-create-request, openai-eval-run, openai-image-generation-request, openai-image-edit-request, openai-image-generation-response, openai-audio-transcription-request, openai-audio-transcription-response, openai-audio-speech-request, openai-audio-speech-response, openai-model, openai-model-list, openai-embedding-request, openai-embedding-response, openai-moderation-request, openai-moderation-response, openai-error, publication-record, publication-record-store-summary, publication-record-lookup, package-signature, publication-verification, publish-result, feed-pointer, feed-pointer-store-summary, feed-pointer-lookup, feed-update-result, feed-verification, feed-resolve-request, feed-resolution, or receipt"
        ),
    };
    println!("{}", serde_json::to_string_pretty(&schema)?);
    Ok(())
}
