mod api;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hivemind_core::{
    AccessGrantRevocationV1, AccessGrantV1, AccessRevocationListV1, ExecutionOptions,
    ExecutionPrivacy, ExecutionReceiptV1, ExecutionRequestV1, LicenseType, PackageManifestV1,
    RegistryQueryV1,
};
use hivemind_package::{load_package_from_dir, validate_package_dir, validate_package_ref};
use hivemind_registry::{
    IndexedPackage, load_packages_with_all_metadata, load_packages_with_all_metadata_and_feeds,
    registry_package_lookup, registry_package_lookup_for_request, search_registry,
};
use hivemind_storage::{
    BeeHttpStorageProvider, BeeStorageConfig, LocalDirectoryStorageProvider, StorageProvider,
};
use schemars::schema_for;
use serde::Serialize;
use serde_json::{Value, json};
use std::path::PathBuf;
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
    Validate { path: PathBuf },
    /// Validate a package directly from a storage reference.
    ValidateRef {
        reference: String,
        #[arg(long, default_value = "local")]
        provider: String,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:1633")]
        bee_url: String,
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
        target: Option<String>,
        #[arg(long)]
        engine: Option<String>,
        #[arg(long)]
        min_validator_score: Option<f64>,
        #[arg(long)]
        min_benchmark_score: Option<f64>,
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
    /// Run the compatibility validator for a package folder.
    Compat { path: PathBuf },
    /// Run the SDK compatibility certification suite for a package folder.
    Certify { path: PathBuf },
    /// Plan a route across browser, local, and remote runners for a local package.
    Route {
        package: PathBuf,
        #[arg(long, default_value = "embedding")]
        task: String,
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        artifact_group: Option<String>,
        #[arg(long, default_value = "balanced")]
        policy: String,
        #[arg(long, default_value_t = 0)]
        local_queue: u32,
        #[arg(long, default_value_t = 0)]
        remote_queue: u32,
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
    /// Look up a locally stored benchmark evaluation result by evaluation id.
    GetEvaluation {
        evaluation_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/evaluations")]
        results_dir: PathBuf,
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
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/payments")]
        marketplace_payments: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/marketplace/audit")]
        marketplace_audit: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/storage")]
        storage: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/runner")]
        runner_cache: PathBuf,
        #[arg(long, default_value = ".swarm-ai-cache/feeds")]
        feeds: PathBuf,
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
    /// Inspect a local package folder for risk, permissions, and sandbox requirements.
    Inspect {
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
}

#[derive(Debug, Subcommand)]
enum ReceiptCommands {
    /// List locally stored receipts.
    List {
        #[arg(long, default_value = ".swarm-ai-cache/receipts")]
        receipts_dir: PathBuf,
    },
    /// Look up a locally stored receipt by receipt id.
    Get {
        receipt_id: String,
        #[arg(long, default_value = ".swarm-ai-cache/receipts")]
        receipts_dir: PathBuf,
    },
    /// Verify a receipt JSON file.
    Verify { receipt: PathBuf },
    /// Print a receipt and its verification report.
    Inspect { receipt: PathBuf },
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
        #[arg(long, default_value = "examples/registry/index.json")]
        output: PathBuf,
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
    /// Reject an open marketplace dispute and return the settlement to settled status.
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
        Commands::Validate { path } => validate_command(path).await,
        Commands::ValidateRef {
            reference,
            provider,
            storage_dir,
            bee_url,
        } => validate_ref_command(reference, provider, storage_dir, bee_url).await,
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
            target,
            engine,
            min_validator_score,
            min_benchmark_score,
            page_size,
            grant,
            revocations,
            requester,
            requested_use,
            runner_id,
        } => {
            search_command(
                capability,
                target,
                engine,
                min_validator_score,
                min_benchmark_score,
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
        Commands::Install {
            reference,
            provider,
            storage_dir,
            bee_url,
            cache_dir,
            artifact_group,
            grant,
            revocations,
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
        Commands::Certify { path } => certify_command(path).await,
        Commands::Route {
            package,
            task,
            text,
            input,
            artifact_group,
            policy,
            local_queue,
            remote_queue,
        } => {
            route_command(
                package,
                task,
                text,
                input,
                artifact_group,
                policy,
                local_queue,
                remote_queue,
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
        Commands::GetEvaluation {
            evaluation_id,
            results_dir,
        } => get_evaluation_command(evaluation_id, results_dir).await,
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
            records,
            validations,
            evaluations,
            access_grants,
            access_revocations,
            receipts,
            disputes,
            marketplace_payments,
            marketplace_audit,
            storage,
            runner_cache,
            feeds,
            static_dir,
        } => {
            api::serve(api::ServeConfig {
                host,
                port,
                package_dir: packages,
                record_dir: records,
                validation_dir: validations,
                evaluation_dir: evaluations,
                access_grant_dir: access_grants,
                access_revocation_dir: access_revocations,
                receipt_dir: receipts,
                dispute_dir: disputes,
                marketplace_payment_dir: marketplace_payments,
                marketplace_audit_dir: marketplace_audit,
                storage_dir: storage,
                runner_cache_dir: runner_cache,
                feed_dir: feeds,
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

async fn validate_command(path: PathBuf) -> Result<()> {
    let report = validate_package_dir(&path)
        .with_context(|| format!("failed to validate package at {}", path.display()))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

async fn validate_ref_command(
    reference: String,
    provider: String,
    storage_dir: PathBuf,
    bee_url: String,
) -> Result<()> {
    let report = match provider.as_str() {
        "local" => {
            let storage = LocalDirectoryStorageProvider::new(storage_dir);
            validate_package_ref(&reference, &storage)
        }
        "bee" => {
            let storage = BeeHttpStorageProvider::new(BeeStorageConfig {
                api_url: bee_url,
                postage_batch_id: None,
                pin: false,
                deferred_upload: true,
                redundancy_level: 0,
            });
            validate_package_ref(&reference, &storage)
        }
        other => anyhow::bail!("unknown validate-ref provider {other}; expected local or bee"),
    }
    .with_context(|| format!("failed to validate package ref {reference}"))?;
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
    target: Option<String>,
    engine: Option<String>,
    min_validator_score: Option<f64>,
    min_benchmark_score: Option<f64>,
    page_size: usize,
    grant: Option<PathBuf>,
    revocations: Option<PathBuf>,
    requester: Option<String>,
    requested_use: Option<String>,
    runner_id: Option<String>,
) -> Result<()> {
    let access_grant = read_access_grant(grant).await?;
    let access_revocation_list = read_access_revocation_list(revocations).await?;
    let packages = load_packages_with_all_metadata_and_feeds(
        &PathBuf::from("examples/packages"),
        Some(&PathBuf::from(".swarm-ai-cache/publications")),
        Some(&PathBuf::from(".swarm-ai-cache/feeds")),
        Some(&PathBuf::from(".swarm-ai-cache/validations")),
        Some(&PathBuf::from(".swarm-ai-cache/evaluations")),
    )?;
    let query = RegistryQueryV1 {
        schema_version: "swarm-ai.registry.query.v1".to_string(),
        kind: None,
        capability,
        target,
        engine,
        license_type: None,
        min_validator_score,
        min_benchmark_score,
        page_size,
        cursor: None,
        requester,
        requested_use,
        runner_id,
        access_grant,
        access_revocation_list,
    };
    let response = search_registry(&packages, &query);
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
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
    }
}

async fn receipts_command(command: ReceiptCommands) -> Result<()> {
    match command {
        ReceiptCommands::List { receipts_dir } => {
            let summary = hivemind_receipts::list_receipts(&receipts_dir)
                .with_context(|| format!("failed to list {}", receipts_dir.display()))?;
            println!("{}", serde_json::to_string_pretty(&summary)?);
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
        ReceiptCommands::Verify { receipt } => {
            let receipt_value = hivemind_receipts::read_receipt(&receipt)
                .with_context(|| format!("failed to read {}", receipt.display()))?;
            let verification = hivemind_receipts::verify_receipt(&receipt_value);
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

async fn install_command(
    reference: String,
    provider: String,
    storage_dir: PathBuf,
    bee_url: String,
    cache_dir: PathBuf,
    artifact_group: Option<String>,
    grant: Option<PathBuf>,
    revocations: Option<PathBuf>,
) -> Result<()> {
    let access_grant = read_access_grant(grant).await?;
    let access_revocation_list = read_access_revocation_list(revocations).await?;
    let install = match provider.as_str() {
        "local" => {
            let storage = LocalDirectoryStorageProvider::new(storage_dir);
            hivemind_local_runner::install_from_storage_with_revocations(
                &reference,
                &storage,
                &cache_dir,
                artifact_group.as_deref(),
                access_grant.as_ref(),
                access_revocation_list.as_ref(),
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
            hivemind_local_runner::install_from_storage_with_revocations(
                &reference,
                &storage,
                &cache_dir,
                artifact_group.as_deref(),
                access_grant.as_ref(),
                access_revocation_list.as_ref(),
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
            println!("{}", serde_json::to_string_pretty(&descriptor)?);
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
    artifact_group: Option<String>,
    policy: String,
    local_queue: u32,
    remote_queue: u32,
) -> Result<()> {
    let package = load_package_from_dir(&package)
        .with_context(|| format!("failed to load package at {}", package.display()))?;
    let input_value = read_execution_input(text, input).await?;
    let policy_mode = parse_policy_mode(&policy)?;
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
    let runners = routing_runners(local_queue, remote_queue);
    let offers = vec![hivemind_marketplace::default_local_runner_offer(
        &hivemind_local_runner::descriptor(),
        vec![package.package_ref.clone()],
    )];
    let report = hivemind_router::planner_report_with_marketplace_offers(
        &request,
        &package,
        &runners,
        &offers,
        policy_mode,
        3,
    );
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
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
            grant,
            revocations,
            requester,
            requested_use,
            runner_id,
            include_private,
        } => {
            let access_grant = read_access_grant(grant).await?;
            let access_revocation_list = read_access_revocation_list(revocations).await?;
            let indexed = load_packages_with_all_metadata_and_feeds(
                &packages,
                Some(&records),
                Some(&feeds),
                Some(&validations),
                Some(&evaluations),
            )
            .with_context(|| {
                format!(
                    "failed to load registry packages from {}, {}, {}, {}, and {}",
                    packages.display(),
                    records.display(),
                    feeds.display(),
                    validations.display(),
                    evaluations.display()
                )
            })?;
            let raw_snapshot = hivemind_registry::rebuild_registry_snapshot_with_all_sources(
                &packages,
                Some(&records),
                Some(&feeds),
                Some(&validations),
                Some(&evaluations),
            )
            .with_context(|| {
                format!(
                    "failed to rebuild registry from {}, {}, {}, {}, and {}",
                    packages.display(),
                    records.display(),
                    feeds.display(),
                    validations.display(),
                    evaluations.display()
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
            output,
            include_private,
        } => {
            let raw_snapshot = hivemind_registry::rebuild_registry_snapshot_with_all_sources(
                &packages,
                Some(&records),
                Some(&feeds),
                Some(&validations),
                Some(&evaluations),
            )
            .with_context(|| {
                format!(
                    "failed to rebuild registry from {}, {}, {}, {}, and {}",
                    packages.display(),
                    records.display(),
                    feeds.display(),
                    validations.display(),
                    evaluations.display()
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
                    "evaluationResults": snapshot.evaluation_results.len()
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
            println!("{}", serde_json::to_string_pretty(&listings)?);
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
            println!("{}", serde_json::to_string_pretty(&vec![offer])?);
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
            let offer = hivemind_marketplace::default_local_runner_offer(
                &hivemind_local_runner::descriptor(),
                package_refs(&packages),
            );
            let mut shortlist_request = hivemind_marketplace::shortlist_request_from_execution(
                &request,
                policy_mode,
                max_results,
            );
            shortlist_request.include_rejected = include_rejected;
            let shortlist =
                hivemind_marketplace::shortlist_runner_offers(&shortlist_request, &[offer]);
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
        MarketplaceCommands::Quote {
            reference,
            package_id,
            package_version,
            task,
            text,
            input,
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
            let offer = hivemind_marketplace::default_local_runner_offer(
                &hivemind_local_runner::descriptor(),
                vec![reference],
            );
            let mut quote = hivemind_marketplace::quote_execution(&request, &offer, None)
                .context("default local runner offer does not support this request")?;
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

async fn certify_command(path: PathBuf) -> Result<()> {
    let report = hivemind_sdk::certify_package_dir(&path)
        .with_context(|| format!("failed to certify {}", path.display()))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
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

async fn get_evaluation_command(evaluation_id: String, results_dir: PathBuf) -> Result<()> {
    let lookup = hivemind_benchmarks::get_evaluation_result(&results_dir, &evaluation_id)
        .with_context(|| format!("failed to read {}", results_dir.display()))?
        .ok_or_else(|| anyhow::anyhow!("evaluation result {evaluation_id} was not found"))?;
    println!("{}", serde_json::to_string_pretty(&lookup)?);
    Ok(())
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
        "package-init-options" => {
            serde_json::to_value(schema_for!(hivemind_package::PackageInitOptionsV1))?
        }
        "package-init-result" => {
            serde_json::to_value(schema_for!(hivemind_package::PackageInitResultV1))?
        }
        "execution-request" => serde_json::to_value(schema_for!(ExecutionRequestV1))?,
        "registry-entry" => serde_json::to_value(schema_for!(hivemind_core::RegistryEntryV1))?,
        "registry-query" => serde_json::to_value(schema_for!(RegistryQueryV1))?,
        "registry-snapshot" => {
            serde_json::to_value(schema_for!(hivemind_registry::RegistrySnapshotV1))?
        }
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
        "access-grant-verification" => {
            serde_json::to_value(schema_for!(hivemind_access::AccessGrantVerificationV1))?
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
        "access-request" => serde_json::to_value(schema_for!(hivemind_core::AccessRequestV1))?,
        "license-policy" => serde_json::to_value(schema_for!(hivemind_core::LicensePolicyV1))?,
        "policy-decision" => serde_json::to_value(schema_for!(hivemind_core::PolicyDecisionV1))?,
        "permission-manifest" => {
            serde_json::to_value(schema_for!(hivemind_policy::PermissionManifestV1))?
        }
        "policy-inspection" => {
            serde_json::to_value(schema_for!(hivemind_policy::PolicyInspectionV1))?
        }
        "marketplace-listing" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::MarketplaceListingV1))?
        }
        "marketplace-listing-verification" => serde_json::to_value(schema_for!(
            hivemind_marketplace::MarketplaceListingVerificationV1
        ))?,
        "runner-offer" => serde_json::to_value(schema_for!(hivemind_marketplace::RunnerOfferV1))?,
        "runner-offer-verification" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::RunnerOfferVerificationV1))?
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
        "service-quote-verification" => serde_json::to_value(schema_for!(
            hivemind_marketplace::ServiceQuoteVerificationV1
        ))?,
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
        "marketplace-audit-summary" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::MarketplaceAuditSummaryV1))?
        }
        "settlement-event-lookup" => {
            serde_json::to_value(schema_for!(hivemind_marketplace::SettlementEventLookupV1))?
        }
        "settlement-resolution-lookup" => serde_json::to_value(schema_for!(
            hivemind_marketplace::SettlementResolutionLookupV1
        ))?,
        "challenge" => serde_json::to_value(schema_for!(hivemind_validator::ChallengeV1))?,
        "validation-report" => {
            serde_json::to_value(schema_for!(hivemind_validator::ValidationReportV1))?
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
        "reputation-profile" => {
            serde_json::to_value(schema_for!(hivemind_validator::ReputationProfileV1))?
        }
        "benchmark-package" => {
            serde_json::to_value(schema_for!(hivemind_benchmarks::BenchmarkPackageV1))?
        }
        "dataset-entry" => serde_json::to_value(schema_for!(hivemind_benchmarks::DatasetEntryV1))?,
        "scoring-rule" => serde_json::to_value(schema_for!(hivemind_benchmarks::ScoringRuleV1))?,
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
        "compatibility-report" => {
            serde_json::to_value(schema_for!(hivemind_sdk::CompatibilityReportV1))?
        }
        "receipt-verification" => {
            serde_json::to_value(schema_for!(hivemind_receipts::ReceiptVerificationV1))?
        }
        "receipt-store-summary" => {
            serde_json::to_value(schema_for!(hivemind_receipts::ReceiptStoreSummaryV1))?
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
        "cost-quote" => serde_json::to_value(schema_for!(hivemind_router::CostQuoteV1))?,
        "route-planner-report" => {
            serde_json::to_value(schema_for!(hivemind_router::RoutePlannerReportV1))?
        }
        "route-execution-trace" => {
            serde_json::to_value(schema_for!(hivemind_router::RouteExecutionTraceV1))?
        }
        "openai-chat-completion-request" => {
            serde_json::to_value(schema_for!(hivemind_openai_compat::ChatCompletionRequestV1))?
        }
        "openai-chat-completion-response" => serde_json::to_value(schema_for!(
            hivemind_openai_compat::ChatCompletionResponseV1
        ))?,
        "openai-embedding-request" => {
            serde_json::to_value(schema_for!(hivemind_openai_compat::EmbeddingRequestV1))?
        }
        "openai-embedding-response" => {
            serde_json::to_value(schema_for!(hivemind_openai_compat::EmbeddingResponseV1))?
        }
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
        other => anyhow::bail!(
            "unknown schema {other}; expected package, package-init-options, package-init-result, execution-request, registry-entry, registry-query, registry-snapshot, registry-package-lookup, registry-package-lookup-request, registry-publication-status, registry-feed-status, registry-shard, registry-shard-manifest, registry-shard-manifest-comparison, registry-shard-manifest-comparison-request, registry-shard-manifest-verification, registry-shard-manifest-verification-request, registry-shard-write-result, registry-shard-verification, registry-shard-verification-request, storage-status, storage-retry-policy, storage-transfer-metrics, storage-download, storage-upload, storage-local-inspection, storage-local-cache-summary, storage-feed-pointer, storage-feed-update, storage-feed-resolution, storage-pin-result, identity-keypair, identity-public, identity-signature, identity-signature-verification, access-grant, access-grant-verification, access-grant-store-summary, access-grant-lookup, access-grant-revocation, access-grant-revocation-verification, access-grant-revocation-store-summary, access-grant-revocation-lookup, access-revocation-list, access-revocation-list-verification, access-request, license-policy, policy-decision, permission-manifest, policy-inspection, marketplace-listing, marketplace-listing-verification, runner-offer, runner-offer-verification, marketplace-shortlist-request, runner-offer-score, marketplace-shortlist, service-quote, service-quote-verification, payment-authorization, payment-authorization-verification, payment-authorization-store-summary, payment-authorization-lookup, settlement-event, settlement-event-verification, settlement-verification, settlement-build-result, settlement-resolution, settlement-resolution-verification, settlement-resolution-result, marketplace-audit-summary, settlement-event-lookup, settlement-resolution-lookup, challenge, validation-report, validation-report-verification, validation-report-store-summary, validation-report-lookup, validation-report-upload, validation-report-download, reputation-profile, benchmark-package, dataset-entry, scoring-rule, evaluation-result, evaluation-result-verification, evaluation-result-store-summary, evaluation-result-lookup, compatibility-report, receipt-verification, receipt-store-summary, receipt-lookup, receipt-upload, receipt-download, receipt-dispute-evidence, receipt-dispute-verification, receipt-dispute-store-summary, receipt-dispute-lookup, browser-runner, browser-capabilities, browser-assessment, browser-prepare-plan, browser-prepared-package, weeb3-adapter, browser-swarm-provider, browser-swarm-config, browser-swarm-status, browser-swarm-retrieval, browser-swarm-compatibility, browser-swarm-security-review, browser-swarm-retrieve-request, remote-runner-api, remote-health, remote-pricing, remote-prepare-request, remote-prepared-package, remote-cancel-request, remote-cancel-result, local-runner-install, local-runner-cache, local-runner-cache-clear, local-runner-sensitive-cache-marker, cost-quote, route-planner-report, route-execution-trace, openai-chat-completion-request, openai-chat-completion-response, openai-embedding-request, openai-embedding-response, openai-error, publication-record, publication-record-store-summary, publication-record-lookup, package-signature, publication-verification, publish-result, feed-pointer, feed-pointer-store-summary, feed-pointer-lookup, feed-update-result, feed-verification, feed-resolve-request, feed-resolution, or receipt"
        ),
    };
    println!("{}", serde_json::to_string_pretty(&schema)?);
    Ok(())
}
