pub use hivemind_access as access;
pub use hivemind_batch as batch;
pub use hivemind_benchmarks as benchmarks;
pub use hivemind_browser_runner as browser_runner;
pub use hivemind_core as core;
pub use hivemind_evals as evals;
pub use hivemind_fine_tune as fine_tune;
pub use hivemind_local_runner as local_runner;
pub use hivemind_marketplace as marketplace;
pub use hivemind_media as media;
pub use hivemind_moderation as moderation;
pub use hivemind_openai_compat as openai_compat;
pub use hivemind_package as package;
pub use hivemind_policy as policy;
pub use hivemind_publisher as publisher;
pub use hivemind_realtime as realtime;
pub use hivemind_receipts as receipts;
pub use hivemind_registry as registry;
pub use hivemind_remote_runner as remote_runner;
pub use hivemind_research as research;
pub use hivemind_router as router;
pub use hivemind_storage as storage;
pub use hivemind_validator as validator;
pub use hivemind_vector as vector;
pub use hivemind_weeb3_adapter as weeb3_adapter;
pub use hivemind_workflow as workflow;

use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    ArtifactGroup, ErrorCode, ExecutionMetrics, ExecutionOptions, ExecutionPrivacy,
    ExecutionReceiptV1, ExecutionRequestV1, ExecutionResponseV1, ExecutionStatus,
    LEGACY_STREAMING_EVENT_SCHEMA_VERSION, PackageManifestV1, ReceiptDraft, RunnerDescriptorV1,
    STREAMING_EVENT_SCHEMA_VERSION, StreamingEventType, StreamingEventV1, SwarmAiErrorV1,
    ValidationIssue, ValidationReport, canonical_streaming_event_id,
    canonicalize_json as core_canonicalize_json, create_signed_receipt,
    hash_canonical_json as core_hash_canonical_json, select_artifact_group, streaming_event,
    validate_package_manifest_value,
};
use hivemind_identity::{
    IdentityKeypairV1, encode_signature_envelope, sign_value, verify_value_signature_string,
};
use hivemind_publisher::PublicationRecordV1;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use storage::{
    DirectoryManifestV1, DownloadResponseV1, StorageCapabilities, StorageProvider, StorageStatusV1,
    StorageTransferMetricsV1, StoredFileV1, UploadResponseV1,
};
use uuid::Uuid;

pub const COMPATIBILITY_CERTIFICATION_SCHEMA_VERSION: &str =
    "swarm-ai.compatibility-certification.v1";
pub const COMPATIBILITY_CERTIFICATION_SIGNATURE_LABEL: &str = "compatibility-certification";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityResult {
    Passed,
    Failed,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompatibilityTestResultV1 {
    pub name: String,
    pub status: CompatibilityStatus,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct CompatibilityPerformanceV1 {
    #[serde(rename = "manifestParseMs")]
    pub manifest_parse_ms: u64,
    #[serde(rename = "storageDownloadMs")]
    pub storage_download_ms: u64,
    #[serde(rename = "coldStartMs")]
    pub cold_start_ms: u64,
    #[serde(rename = "warmStartMs")]
    pub warm_start_ms: u64,
    #[serde(rename = "executionMs")]
    pub execution_ms: u64,
    #[serde(rename = "receiptCreationMs")]
    pub receipt_creation_ms: u64,
    #[serde(rename = "downloadBytes")]
    pub download_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompatibilityReportV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "componentName")]
    pub component_name: String,
    #[serde(rename = "componentVersion")]
    pub component_version: String,
    #[serde(rename = "interfaceVersion")]
    pub interface_version: String,
    #[serde(rename = "testedAt")]
    pub tested_at: String,
    pub tests: Vec<CompatibilityTestResultV1>,
    pub performance: CompatibilityPerformanceV1,
    pub result: CompatibilityResult,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompatibilityCertificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "componentType")]
    pub component_type: String,
    #[serde(rename = "implementationName")]
    pub implementation_name: String,
    pub version: String,
    #[serde(rename = "supportedSchemas")]
    pub supported_schemas: Vec<String>,
    #[serde(rename = "passedTests")]
    pub passed_tests: Vec<String>,
    #[serde(rename = "failedTests")]
    pub failed_tests: Vec<CompatibilityTestResultV1>,
    #[serde(rename = "performanceResults")]
    pub performance_results: CompatibilityPerformanceV1,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompatibilityCertificationIndexEntryV1 {
    #[serde(rename = "certificationId")]
    pub certification_id: String,
    #[serde(rename = "certificationRef")]
    pub certification_ref: String,
    #[serde(rename = "componentType")]
    pub component_type: String,
    #[serde(rename = "implementationName")]
    pub implementation_name: String,
    pub version: String,
    #[serde(rename = "supportedSchemaCount")]
    pub supported_schema_count: usize,
    #[serde(rename = "passedTestCount")]
    pub passed_test_count: usize,
    #[serde(rename = "failedTestCount")]
    pub failed_test_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "certificationPath")]
    pub certification_path: String,
    pub verification: SdkVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompatibilityCertificationStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "certificationCount")]
    pub certification_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "componentTypeCounts")]
    pub component_type_counts: BTreeMap<String, usize>,
    pub certifications: Vec<CompatibilityCertificationIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompatibilityCertificationLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "certificationId")]
    pub certification_id: String,
    #[serde(rename = "certificationRef")]
    pub certification_ref: String,
    #[serde(rename = "certificationPath")]
    pub certification_path: String,
    pub certification: CompatibilityCertificationV1,
    pub verification: SdkVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompatibilityCertificationWriteResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub stored: bool,
    #[serde(rename = "certificationId")]
    pub certification_id: String,
    #[serde(rename = "certificationRef")]
    pub certification_ref: String,
    #[serde(rename = "certificationPath")]
    pub certification_path: String,
    pub verification: SdkVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SdkVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MockFileV1 {
    pub path: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct MockStorageProvider {
    objects: BTreeMap<String, Vec<u8>>,
    manifests: BTreeMap<String, DirectoryManifestV1>,
}

pub fn parse_package_manifest(value: &Value) -> Result<PackageManifestV1, SwarmAiErrorV1> {
    serde_json::from_value(value.clone()).map_err(|error| {
        SwarmAiErrorV1::new(ErrorCode::InvalidManifest, "JSON is not PackageManifestV1")
            .with_details(json!({ "error": error.to_string() }))
    })
}

pub fn validate_package_manifest(value: &Value) -> ValidationReport {
    validate_package_manifest_value(value)
}

pub fn canonicalize_json(value: &Value) -> Value {
    core_canonicalize_json(value)
}

pub fn hash_canonical(value: &Value) -> String {
    core_hash_canonical_json(value)
}

pub fn verify_publication_record(record: &PublicationRecordV1) -> SdkVerificationV1 {
    let publisher_verification = hivemind_publisher::verify_publication_record(record);
    verification(publisher_verification.issues)
}

pub fn build_route_planner_request(
    request: ExecutionRequestV1,
    policy_mode: hivemind_core::PolicyMode,
    max_marketplace_results: usize,
    trust_policy: Option<hivemind_core::TrustPolicyV1>,
) -> router::RoutePlannerRequestV1 {
    router::RoutePlannerRequestV1 {
        schema_version: "swarm-ai.route-planner-request.v1".to_string(),
        request,
        policy_mode,
        max_marketplace_results,
        trust_policy,
    }
}

pub fn plan_route_report(
    request: &ExecutionRequestV1,
    package: &package::LocalPackage,
    runners: &[RunnerDescriptorV1],
    offers: &[marketplace::RunnerOfferV1],
    policy_mode: hivemind_core::PolicyMode,
    max_marketplace_results: usize,
    trust_policy: Option<&hivemind_core::TrustPolicyV1>,
) -> router::RoutePlannerReportV1 {
    router::planner_report_with_trust_policy(
        request,
        package,
        runners,
        offers,
        &[],
        policy_mode,
        max_marketplace_results,
        &[],
        trust_policy,
    )
}

pub fn build_marketplace_shortlist_request(
    request: &ExecutionRequestV1,
    policy_mode: hivemind_core::PolicyMode,
    max_results: usize,
) -> marketplace::MarketplaceShortlistRequestV1 {
    marketplace::shortlist_request_from_execution(request, policy_mode, max_results)
}

pub fn build_runner_offer_from_descriptor(
    descriptor: &RunnerDescriptorV1,
    runner_descriptor_ref: impl Into<String>,
    supported_package_refs: Vec<String>,
    pricing: marketplace::RunnerPricingV1,
    service_level: marketplace::RunnerServiceLevelV1,
    reputation: marketplace::RunnerReputationV1,
) -> marketplace::RunnerOfferV1 {
    marketplace::offer_from_runner_descriptor(
        descriptor,
        runner_descriptor_ref,
        supported_package_refs,
        pricing,
        service_level,
        reputation,
    )
}

pub fn build_hardware_resource_offer(
    descriptor: &RunnerDescriptorV1,
    operator: impl Into<String>,
) -> marketplace::HardwareResourceOfferV1 {
    marketplace::default_hardware_resource_offer(descriptor, operator)
}

pub fn verify_runner_offer(offer: &marketplace::RunnerOfferV1) -> SdkVerificationV1 {
    marketplace_verification(marketplace::verify_runner_offer(offer).issues)
}

pub fn verify_hardware_resource_offer(
    offer: &marketplace::HardwareResourceOfferV1,
) -> SdkVerificationV1 {
    marketplace_verification(marketplace::verify_hardware_resource_offer(offer).issues)
}

pub fn evaluate_access_for_execution(
    manifest: &PackageManifestV1,
    package_ref: &str,
    request_id: &str,
    requester: &str,
    requested_use: &str,
    runner_id: Option<&str>,
    grant: Option<&hivemind_core::AccessGrantV1>,
    revocation_list: Option<&hivemind_core::AccessRevocationListV1>,
) -> hivemind_core::AccessEvaluationV1 {
    access::evaluate_execution_access_with_revocations(
        manifest,
        package_ref,
        request_id,
        requester,
        requested_use,
        runner_id,
        grant,
        revocation_list,
    )
}

pub fn create_validation_report(
    challenge: &validator::ChallengeV1,
    response: &ExecutionResponseV1,
    runner_id: impl Into<String>,
    evidence_refs: Vec<String>,
) -> validator::ValidationReportV1 {
    validator::score_execution(challenge, response, runner_id, evidence_refs)
}

pub fn verify_validation_report(report: &validator::ValidationReportV1) -> SdkVerificationV1 {
    verification(validator::verify_validation_report(report).issues)
}

pub fn openai_chat_to_ai_request(
    request: &openai_compat::ChatCompletionRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> hivemind_core::AiRequestV1 {
    openai_compat::chat_request_to_ai_request(request, request_id, default_requester)
}

pub fn openai_chat_to_execution_request(
    request: &openai_compat::ChatCompletionRequestV1,
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    request_id: impl Into<String>,
) -> ExecutionRequestV1 {
    openai_compat::chat_request_to_execution(
        request,
        package_ref,
        package_id,
        package_version,
        request_id,
    )
}

pub fn openai_responses_to_ai_request(
    request: &openai_compat::OpenAiResponsesRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> hivemind_core::AiRequestV1 {
    openai_compat::responses_request_to_ai_request(request, request_id, default_requester)
}

pub fn openai_responses_to_execution_request(
    request: &openai_compat::OpenAiResponsesRequestV1,
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    request_id: impl Into<String>,
) -> ExecutionRequestV1 {
    openai_compat::responses_request_to_execution(
        request,
        package_ref,
        package_id,
        package_version,
        request_id,
    )
}

pub fn openai_embedding_to_ai_request(
    request: &openai_compat::EmbeddingRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> hivemind_core::AiRequestV1 {
    openai_compat::embedding_request_to_ai_request(request, request_id, default_requester)
}

pub fn openai_moderation_to_ai_request(
    request: &openai_compat::OpenAiModerationRequestV1,
    request_id: impl Into<String>,
    default_requester: impl Into<String>,
) -> hivemind_core::AiRequestV1 {
    openai_compat::moderation_request_to_ai_request(request, request_id, default_requester)
}

pub fn package_certification_supported_schemas() -> Vec<String> {
    vec![
        "swarm-ai.package.v1",
        "hivemind.package.v2",
        "hivemind.package.v3",
        "hivemind.package_manifest.v4",
        "hivemind.universal-capability.v1",
        "hivemind.asset-descriptor.v1",
        "hivemind.runtime-descriptor.v2",
        "hivemind.capability-set.v1",
        "hivemind.provenance-record.v1",
        "hivemind.package-index-summary.v1",
        "hivemind.browser-publish-profile.v1",
        "hivemind.workload.v1",
        "hivemind.task_envelope.v1",
        "hivemind.task_envelope_verification.v1",
        "hivemind.asset-or-inline-input.v1",
        "hivemind.expected-output-descriptor.v1",
        "hivemind.job-policy.v1",
        "hivemind.privacy-requirement.v1",
        "hivemind.verification-requirement.v1",
        "hivemind.runtime-preferences.v1",
        "hivemind.universal-route-plan.v1",
        core::PRIVACY_TIER_PROFILE_SCHEMA_VERSION,
        core::PRIVACY_TIER_CATALOG_SCHEMA_VERSION,
        core::PRIVACY_REQUIREMENT_ASSESSMENT_REQUEST_SCHEMA_VERSION,
        core::PRIVACY_REQUIREMENT_ASSESSMENT_SCHEMA_VERSION,
        policy::PERMISSION_MANIFEST_V2_SCHEMA_VERSION,
        policy::RISK_INSPECTION_REPORT_SCHEMA_VERSION,
        policy::CONSENT_RECORD_SCHEMA_VERSION,
        policy::TOOL_PERMISSION_GRANT_SCHEMA_VERSION,
        "swarm-ai.execution.request.v1",
        "swarm-ai.execution.response.v1",
        STREAMING_EVENT_SCHEMA_VERSION,
        "swarm-ai.receipt.v1",
        receipts::RECEIPT_CORRECTNESS_ASSESSMENT_REQUEST_SCHEMA_VERSION,
        receipts::RECEIPT_CORRECTNESS_ASSESSMENT_SCHEMA_VERSION,
        "swarm-ai.storage.directory-manifest.v1",
        "hivemind.storage-provider-descriptor.v3",
        "hivemind.browser-storage-consent.v1",
        "hivemind.browser-storage-session.v1",
        "hivemind.storage-event-receipt.v1",
        "hivemind.storage-sponsorship.v1",
        storage::BROWSER_STORAGE_CAPABILITY_PROBE_SCHEMA_VERSION,
        storage::BROWSER_STORAGE_PURCHASE_QUOTE_SCHEMA_VERSION,
        storage::BROWSER_STORAGE_PURCHASE_AUTHORIZATION_SCHEMA_VERSION,
        storage::BROWSER_STORAGE_SESSION_V2_SCHEMA_VERSION,
        storage::STORAGE_EVENT_RECEIPT_V2_SCHEMA_VERSION,
        storage::BROWSER_STORAGE_STATE_REPORT_SCHEMA_VERSION,
        storage::BROWSER_STORAGE_SECURITY_ASSESSMENT_REQUEST_SCHEMA_VERSION,
        storage::BROWSER_STORAGE_SECURITY_ASSESSMENT_SCHEMA_VERSION,
        storage::BROWSER_STORAGE_SECURITY_ASSESSMENT_VERIFICATION_SCHEMA_VERSION,
        "hivemind.browser-swarm-storage-provider.v4",
        "hivemind.browser-swarm-capability-report.v1",
        "hivemind.browser-swarm-provider-conformance.v1",
        "hivemind.browser-swarm-provider-catalog.v4",
        core::LICENSE_POLICY_V2_SCHEMA_VERSION,
        core::ACCESS_POLICY_V2_SCHEMA_VERSION,
        core::ACCESS_POLICY_V2_VERIFICATION_SCHEMA_VERSION,
        core::ASSET_ACCESS_RULE_SCHEMA_VERSION,
        core::ASSET_ACCESS_RULE_V2_SCHEMA_VERSION,
        core::PAID_ACCESS_QUOTE_SCHEMA_VERSION,
        core::ACCESS_EVALUATION_RESULT_SCHEMA_VERSION,
        core::JOB_ACCESS_ATTACHMENT_SCHEMA_VERSION,
        "hivemind.access-grant.v2",
        core::ACCESS_GRANT_V3_SCHEMA_VERSION,
        "hivemind.marketplace_listing.v2",
        "hivemind.marketplace_listing_verification.v2",
        marketplace::ESCROW_RECORD_SCHEMA_VERSION,
        marketplace::ESCROW_RECORD_VERIFICATION_SCHEMA_VERSION,
        marketplace::ESCROW_RELEASE_REQUEST_SCHEMA_VERSION,
        marketplace::ESCROW_RELEASE_RESULT_SCHEMA_VERSION,
        marketplace::REFUND_BUILD_REQUEST_SCHEMA_VERSION,
        marketplace::REFUND_RECORD_SCHEMA_VERSION,
        marketplace::REFUND_RECORD_VERIFICATION_SCHEMA_VERSION,
        marketplace::REFUND_BUILD_RESULT_SCHEMA_VERSION,
        marketplace::SLASHING_BUILD_REQUEST_SCHEMA_VERSION,
        marketplace::SLASHING_RECORD_SCHEMA_VERSION,
        marketplace::SLASHING_RECORD_VERIFICATION_SCHEMA_VERSION,
        marketplace::SLASHING_BUILD_RESULT_SCHEMA_VERSION,
        vector::DOCUMENT_COLLECTION_SCHEMA_VERSION,
        vector::CHUNK_SET_SCHEMA_VERSION,
        vector::EMBEDDING_SET_SCHEMA_VERSION,
        vector::VECTOR_INDEX_V2_SCHEMA_VERSION,
        vector::RETRIEVAL_QUERY_SCHEMA_VERSION,
        vector::RETRIEVAL_PLAN_SCHEMA_VERSION,
        vector::RETRIEVAL_PLANNING_REQUEST_SCHEMA_VERSION,
        vector::RAG_PIPELINE_V2_SCHEMA_VERSION,
        vector::CITATION_TRACE_SCHEMA_VERSION,
        vector::KNOWLEDGE_ASSET_VERIFICATION_SCHEMA_VERSION,
        "hivemind.validation-method-registry.v1",
        "hivemind.benchmark-pack.v1",
        research::EVALUATION_RUN_V2_SCHEMA_VERSION,
        research::EVALUATION_RUN_V2_VERIFICATION_SCHEMA_VERSION,
        research::RESEARCH_RESULT_RECORD_SCHEMA_VERSION,
        research::RESEARCH_RESULT_RECORD_VERIFICATION_SCHEMA_VERSION,
        research::REPRODUCIBILITY_BUNDLE_SCHEMA_VERSION,
        research::REPRODUCIBILITY_BUNDLE_VERIFICATION_SCHEMA_VERSION,
        "swarm-ai.validation-report.v1",
        "swarm-ai.compatibility-report.v1",
        COMPATIBILITY_CERTIFICATION_SCHEMA_VERSION,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

pub fn compatibility_certification_from_report<S, W>(
    report: &CompatibilityReportV1,
    component_type: impl Into<String>,
    implementation_name: impl Into<String>,
    version: impl Into<String>,
    supported_schemas: S,
    warnings: W,
) -> CompatibilityCertificationV1
where
    S: IntoIterator,
    S::Item: Into<String>,
    W: IntoIterator,
    W::Item: Into<String>,
{
    let mut supported_schemas: Vec<String> = supported_schemas
        .into_iter()
        .map(Into::into)
        .filter(|schema| !schema.trim().is_empty())
        .collect();
    supported_schemas.sort();
    supported_schemas.dedup();

    let mut warnings: Vec<String> = warnings
        .into_iter()
        .map(Into::into)
        .filter(|warning| !warning.trim().is_empty())
        .collect();
    warnings.extend(
        report
            .tests
            .iter()
            .filter(|test| test.status == CompatibilityStatus::Skipped)
            .map(|test| format!("skipped compatibility test: {}", test.name)),
    );

    CompatibilityCertificationV1 {
        schema_version: COMPATIBILITY_CERTIFICATION_SCHEMA_VERSION.to_string(),
        component_type: component_type.into(),
        implementation_name: implementation_name.into(),
        version: version.into(),
        supported_schemas,
        passed_tests: report
            .tests
            .iter()
            .filter(|test| test.status == CompatibilityStatus::Passed)
            .map(|test| test.name.clone())
            .collect(),
        failed_tests: report
            .tests
            .iter()
            .filter(|test| test.status == CompatibilityStatus::Failed)
            .cloned()
            .collect(),
        performance_results: report.performance.clone(),
        warnings,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    }
}

pub fn compatibility_certification_payload(
    certification: &CompatibilityCertificationV1,
) -> anyhow::Result<Value> {
    let mut value = serde_json::to_value(certification)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("signature");
    }
    Ok(value)
}

pub fn sign_compatibility_certification(
    certification: &mut CompatibilityCertificationV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<String> {
    certification.signature = None;
    let payload = compatibility_certification_payload(certification)?;
    let envelope = sign_value(
        identity,
        COMPATIBILITY_CERTIFICATION_SIGNATURE_LABEL,
        &payload,
    )?;
    let signature = encode_signature_envelope(&envelope)?;
    certification.signature = Some(signature.clone());
    Ok(signature)
}

pub fn verify_compatibility_certification(
    certification: &CompatibilityCertificationV1,
    expected_signer: Option<&str>,
) -> SdkVerificationV1 {
    let mut issues = Vec::new();
    if certification.schema_version != COMPATIBILITY_CERTIFICATION_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {COMPATIBILITY_CERTIFICATION_SCHEMA_VERSION}"),
        ));
    }
    if certification.component_type.trim().is_empty() {
        issues.push(issue("$.componentType", "componentType is required"));
    }
    if certification.implementation_name.trim().is_empty() {
        issues.push(issue(
            "$.implementationName",
            "implementationName is required",
        ));
    }
    if certification.version.trim().is_empty() {
        issues.push(issue("$.version", "version is required"));
    }
    if certification.supported_schemas.is_empty() {
        issues.push(issue(
            "$.supportedSchemas",
            "At least one supported schema must be declared",
        ));
    }
    if certification.passed_tests.is_empty() && certification.failed_tests.is_empty() {
        issues.push(issue(
            "$.passedTests",
            "Certification must record at least one test result",
        ));
    }
    for (index, test) in certification.failed_tests.iter().enumerate() {
        if test.status != CompatibilityStatus::Failed {
            issues.push(issue(
                format!("$.failedTests[{index}].status"),
                "failedTests entries must have failed status",
            ));
        }
    }

    let payload = match compatibility_certification_payload(certification) {
        Ok(payload) => payload,
        Err(error) => {
            issues.push(issue(
                "$",
                format!("Failed to serialize compatibility certification: {error}"),
            ));
            return verification(issues);
        }
    };

    match certification.signature.as_deref().map(str::trim) {
        Some(signature) if !signature.is_empty() => {
            let signature_verification = verify_value_signature_string(
                signature,
                COMPATIBILITY_CERTIFICATION_SIGNATURE_LABEL,
                &payload,
                expected_signer,
            );
            if !signature_verification.valid {
                issues.extend(
                    signature_verification
                        .issues
                        .into_iter()
                        .map(|signature_issue| {
                            issue(
                                signature_issue_path(&signature_issue.path),
                                signature_issue.message,
                            )
                        }),
                );
            }
        }
        _ => issues.push(issue(
            "$.signature",
            "Compatibility certification must be signed by the test runner",
        )),
    }

    verification(issues)
}

pub fn compatibility_certification_id(
    certification: &CompatibilityCertificationV1,
) -> anyhow::Result<String> {
    let value = serde_json::to_value(certification)?;
    Ok(format!("compat-cert-{}", &hash_canonical(&value)[..24]))
}

pub fn compatibility_certification_ref(certification_id: &str) -> String {
    format!("local://compat/{}", certification_id.trim())
}

pub fn read_compatibility_certification(
    path: &Path,
) -> anyhow::Result<CompatibilityCertificationV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse compatibility certification JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_compatibility_certification(
    certifications_dir: &Path,
    certification: &CompatibilityCertificationV1,
) -> anyhow::Result<CompatibilityCertificationWriteResultV1> {
    fs::create_dir_all(certifications_dir)?;
    let certification_id = compatibility_certification_id(certification)?;
    let path = certifications_dir.join(format!("{}.json", safe_file_component(&certification_id)));
    fs::write(&path, serde_json::to_vec_pretty(certification)?)?;
    Ok(CompatibilityCertificationWriteResultV1 {
        schema_version: "swarm-ai.compatibility-certification-write-result.v1".to_string(),
        stored: true,
        certification_ref: compatibility_certification_ref(&certification_id),
        certification_id,
        certification_path: path.display().to_string(),
        verification: verify_compatibility_certification(certification, None),
    })
}

pub fn list_compatibility_certifications(
    certifications_dir: &Path,
) -> anyhow::Result<CompatibilityCertificationStoreSummaryV1> {
    let mut certifications = Vec::new();
    if certifications_dir.exists() {
        for entry in fs::read_dir(certifications_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
                && let Ok(certification) = read_compatibility_certification(&path)
            {
                certifications.push(compatibility_certification_index_entry(
                    &certification,
                    path.display().to_string(),
                )?);
            }
        }
    }
    certifications.sort_by(|left, right| {
        left.component_type
            .cmp(&right.component_type)
            .then(left.implementation_name.cmp(&right.implementation_name))
            .then(left.version.cmp(&right.version))
            .then(left.created_at.cmp(&right.created_at))
            .then(left.certification_id.cmp(&right.certification_id))
    });
    let valid_count = certifications
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    let mut component_type_counts = BTreeMap::new();
    for certification in &certifications {
        *component_type_counts
            .entry(certification.component_type.clone())
            .or_insert(0) += 1;
    }
    Ok(CompatibilityCertificationStoreSummaryV1 {
        schema_version: "swarm-ai.compatibility-certification-store-summary.v1".to_string(),
        root: certifications_dir.display().to_string(),
        certification_count: certifications.len(),
        valid_count,
        invalid_count: certifications.len().saturating_sub(valid_count),
        component_type_counts,
        certifications,
    })
}

pub fn get_compatibility_certification(
    certifications_dir: &Path,
    certification_id: &str,
) -> anyhow::Result<Option<CompatibilityCertificationLookupV1>> {
    let certification_id = certification_id.trim();
    if certification_id.is_empty() {
        anyhow::bail!("certificationId is required");
    }
    let direct_path =
        certifications_dir.join(format!("{}.json", safe_file_component(certification_id)));
    if direct_path.exists() {
        let certification = read_compatibility_certification(&direct_path)?;
        if compatibility_certification_id(&certification)? == certification_id {
            return Ok(Some(compatibility_certification_lookup(
                certification,
                direct_path,
            )?));
        }
    }

    if !certifications_dir.exists() {
        return Ok(None);
    }

    for entry in fs::read_dir(certifications_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            && let Ok(certification) = read_compatibility_certification(&path)
            && compatibility_certification_id(&certification)? == certification_id
        {
            return Ok(Some(compatibility_certification_lookup(
                certification,
                path,
            )?));
        }
    }
    Ok(None)
}

pub fn certify_package_dir_with_identity(
    path: &Path,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<CompatibilityCertificationV1> {
    let report = certify_package_dir(path)?;
    let mut certification = compatibility_certification_from_report(
        &report,
        "package",
        report.component_name.as_str(),
        report.component_version.as_str(),
        package_certification_supported_schemas(),
        Vec::<String>::new(),
    );
    sign_compatibility_certification(&mut certification, identity)?;
    Ok(certification)
}

pub fn create_execution_request(
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    task: impl Into<String>,
    input: Value,
) -> ExecutionRequestV1 {
    ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: Uuid::new_v4().to_string(),
        package_ref: package_ref.into(),
        package_id: package_id.into(),
        package_version: package_version.into(),
        preferred_artifact_group: None,
        task: task.into(),
        input,
        options: ExecutionOptions::default(),
        privacy: ExecutionPrivacy::default(),
        access_grant: None,
        access_revocation_list: None,
    }
}

pub fn validate_execution_response(
    response: &ExecutionResponseV1,
    request: Option<&ExecutionRequestV1>,
) -> SdkVerificationV1 {
    let mut issues = Vec::new();
    if response.schema_version != "swarm-ai.execution.response.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.execution.response.v1",
        ));
    }
    if let Some(request) = request {
        if response.request_id != request.request_id {
            issues.push(issue(
                "$.requestId",
                "Execution response requestId must match the request",
            ));
        }
    }
    match response.status {
        ExecutionStatus::Succeeded => {
            if response.error.is_some() {
                issues.push(issue(
                    "$.error",
                    "Succeeded execution responses must not include an error",
                ));
            }
        }
        ExecutionStatus::Failed => {
            if response.error.is_none() {
                issues.push(issue(
                    "$.error",
                    "Failed execution responses must include ErrorV1",
                ));
            }
        }
        ExecutionStatus::Cancelled | ExecutionStatus::Partial => {}
    }
    verification(issues)
}

pub fn parse_streaming_events(text: &str) -> anyhow::Result<Vec<StreamingEventV1>> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        match serde_json::from_str::<Value>(trimmed) {
            Ok(value) => return parse_streaming_events_json_value(&value),
            Err(error) if trimmed.starts_with('{') => {
                if !trimmed.lines().skip(1).any(|line| !line.trim().is_empty()) {
                    return Err(error.into());
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    if looks_like_sse(trimmed) {
        parse_streaming_events_sse(trimmed)
    } else {
        parse_streaming_events_json_lines(trimmed)
    }
}

pub fn parse_streaming_events_json_value(value: &Value) -> anyhow::Result<Vec<StreamingEventV1>> {
    if value.is_array() {
        serde_json::from_value(value.clone()).map_err(Into::into)
    } else {
        serde_json::from_value::<StreamingEventV1>(value.clone())
            .map(|event| vec![event])
            .map_err(Into::into)
    }
}

pub fn parse_streaming_events_json_lines(text: &str) -> anyhow::Result<Vec<StreamingEventV1>> {
    let mut events = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line == "[DONE]" {
            continue;
        }
        let event: StreamingEventV1 = serde_json::from_str(line).map_err(|error| {
            anyhow::anyhow!(
                "line {} is not a StreamingEventV1 JSON object: {error}",
                line_index + 1
            )
        })?;
        events.push(event);
    }
    Ok(events)
}

pub fn parse_streaming_events_sse(text: &str) -> anyhow::Result<Vec<StreamingEventV1>> {
    let mut events = Vec::new();
    let mut data_lines = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            push_sse_streaming_event(&mut events, &mut data_lines)?;
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        if let Some(data) = line.strip_prefix("data:") {
            data_lines.push(data.strip_prefix(' ').unwrap_or(data).to_string());
        }
    }
    push_sse_streaming_event(&mut events, &mut data_lines)?;
    Ok(events)
}

pub fn streaming_events_to_sse(events: &[StreamingEventV1]) -> anyhow::Result<String> {
    let mut body = String::new();
    for event in events {
        body.push_str("event: ");
        body.push_str(streaming_event_wire_name(&event.event_type));
        body.push('\n');
        body.push_str("id: ");
        body.push_str(&event.event_id);
        body.push('\n');
        body.push_str("data: ");
        body.push_str(&serde_json::to_string(event)?);
        body.push_str("\n\n");
    }
    Ok(body)
}

pub fn validate_streaming_events(
    events: &[StreamingEventV1],
    expected_request_id: Option<&str>,
    expected_job_id: Option<&str>,
) -> SdkVerificationV1 {
    let mut issues = Vec::new();
    if events.is_empty() {
        issues.push(issue("$", "Streaming event sequence must not be empty"));
        return verification(issues);
    }

    let request_id = expected_request_id.unwrap_or(events[0].request_id.as_str());
    let observed_job_id = expected_job_id.or_else(|| {
        events
            .iter()
            .find_map(|event| event.job_id.as_deref())
            .filter(|value| !value.trim().is_empty())
    });
    let mut event_ids = BTreeSet::new();
    let mut terminal_index = None;

    for (index, event) in events.iter().enumerate() {
        let path = format!("$.events[{index}]");
        if event.schema_version != STREAMING_EVENT_SCHEMA_VERSION
            && event.schema_version != LEGACY_STREAMING_EVENT_SCHEMA_VERSION
        {
            issues.push(issue(
                format!("{path}.schemaVersion"),
                format!(
                    "Expected schemaVersion to be {STREAMING_EVENT_SCHEMA_VERSION} or {LEGACY_STREAMING_EVENT_SCHEMA_VERSION}"
                ),
            ));
        }
        if event.sequence != index as u64 {
            issues.push(issue(
                format!("{path}.sequence"),
                "Streaming event sequence must be contiguous and ordered from 0",
            ));
        }
        if event.request_id != request_id {
            issues.push(issue(
                format!("{path}.requestId"),
                "Streaming event requestId does not match the stream request",
            ));
        }
        if let Some(job_id) = observed_job_id {
            if event.job_id.as_deref() != Some(job_id) {
                issues.push(issue(
                    format!("{path}.jobId"),
                    "Streaming event jobId does not match the stream job",
                ));
            }
        }
        if event.timestamp.trim().is_empty() {
            issues.push(issue(
                format!("{path}.timestamp"),
                "Streaming event timestamp must not be empty",
            ));
        }
        if !event_ids.insert(event.event_id.clone()) {
            issues.push(issue(
                format!("{path}.eventId"),
                "Streaming event eventId must be unique within the stream",
            ));
        }
        match canonical_streaming_event_id(event) {
            Ok(expected_id) if event.event_id == expected_id => {}
            Ok(_) => issues.push(issue(
                format!("{path}.eventId"),
                "Streaming event eventId does not match canonical event content",
            )),
            Err(error) => issues.push(issue(
                format!("{path}.eventId"),
                format!("Streaming event could not be canonicalized: {error}"),
            )),
        }
        if is_terminal_stream_event(&event.event_type) {
            if terminal_index.is_some() {
                issues.push(issue(
                    format!("{path}.type"),
                    "Streaming event sequence must not contain multiple terminal events",
                ));
            }
            terminal_index = Some(index);
        } else if let Some(first_terminal) = terminal_index {
            issues.push(issue(
                format!("{path}.type"),
                format!("Streaming event appears after terminal event at index {first_terminal}"),
            ));
        }
    }
    if let Some(index) = terminal_index {
        if index + 1 != events.len() {
            issues.push(issue(
                format!("$.events[{index}].type"),
                "Terminal streaming event must be the final event",
            ));
        }
    }

    verification(issues)
}

pub fn create_receipt(
    request: &ExecutionRequestV1,
    response: &ExecutionResponseV1,
    manifest: &PackageManifestV1,
    artifact_group: impl AsRef<str>,
    manifest_hash: impl AsRef<str>,
    runner_id: impl AsRef<str>,
) -> ExecutionReceiptV1 {
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    create_signed_receipt(ReceiptDraft {
        request,
        response,
        manifest,
        artifact_group: artifact_group.as_ref(),
        manifest_hash: manifest_hash.as_ref(),
        runner_id: runner_id.as_ref(),
        route_id: None,
        policy: None,
        started_at: &now,
        finished_at: &now,
    })
}

pub fn verify_receipt(receipt: &ExecutionReceiptV1) -> SdkVerificationV1 {
    let receipt_verification = hivemind_receipts::verify_receipt(receipt);
    verification(
        receipt_verification
            .issues
            .into_iter()
            .map(|issue| ValidationIssue {
                path: issue.path,
                message: issue.message,
            })
            .collect(),
    )
}

pub fn load_package(
    storage_provider: &impl StorageProvider,
    package_ref: &str,
) -> anyhow::Result<package::LocalPackage> {
    package::load_package_from_storage(package_ref, storage_provider)
}

pub fn select_artifact_group_for_runner(
    manifest: &PackageManifestV1,
    runner: &RunnerDescriptorV1,
    preferred_artifact_group: Option<&str>,
) -> Option<ArtifactGroup> {
    select_artifact_group(
        manifest,
        preferred_artifact_group,
        &runner.targets,
        &runner.engines,
    )
    .cloned()
}

pub fn create_error(
    code: ErrorCode,
    message: impl Into<String>,
    details: Option<Value>,
) -> SwarmAiErrorV1 {
    let error = SwarmAiErrorV1::new(code, message);
    if let Some(details) = details {
        error.with_details(details)
    } else {
        error
    }
}

pub fn mock_runner_descriptor() -> RunnerDescriptorV1 {
    local_runner::descriptor()
}

pub fn execute_mock_request(request: &ExecutionRequestV1) -> ExecutionResponseV1 {
    let started = Instant::now();
    let output = match request.task.as_str() {
        "embedding" => json!({
            "embedding": deterministic_embedding(&request.input),
            "model": request.package_id,
        }),
        "classification" => json!({ "label": "general", "score": 0.75 }),
        "chat" => json!({
            "message": {
                "role": "assistant",
                "content": "Mock runner response"
            }
        }),
        _ => json!({ "echo": request.input, "task": request.task }),
    };
    let elapsed = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    ExecutionResponseV1::succeeded(
        request.request_id.clone(),
        output,
        ExecutionMetrics {
            queue_ms: 0,
            load_ms: 0,
            compute_ms: elapsed,
            total_ms: elapsed,
            input_tokens: None,
            output_tokens: None,
        },
    )
}

pub fn certify_package_dir(path: &Path) -> anyhow::Result<CompatibilityReportV1> {
    let mut tests = Vec::new();
    let mut performance = CompatibilityPerformanceV1::default();

    let parse_timer = Instant::now();
    let manifest_value = package::read_manifest_value(path)?;
    performance.manifest_parse_ms = elapsed_ms(parse_timer);

    let package_validation = timed_test("validates-package-manifest-v1", || {
        package::validate_package_dir(path)
            .map(|report| {
                if report.valid {
                    Ok(())
                } else {
                    Err(format!(
                        "{} issue(s): {}",
                        report.issues.len(),
                        report
                            .issues
                            .first()
                            .map(|issue| issue.message.clone())
                            .unwrap_or_else(|| "unknown validation error".to_string())
                    ))
                }
            })
            .map_err(|error| error.to_string())?
    });
    tests.push(package_validation);

    tests.push(timed_test("ignores-unknown-optional-fields", || {
        let mut value = manifest_value.clone();
        let Some(object) = value.as_object_mut() else {
            return Err("manifest root is not an object".to_string());
        };
        object.insert(
            "xSdkForwardCompatibilityProbe".to_string(),
            json!({ "ignored": true }),
        );
        let report = validate_package_manifest_value(&value);
        if report.valid {
            Ok(())
        } else {
            Err("manifest with unknown optional field did not validate".to_string())
        }
    }));

    let package = package::load_package_from_dir(path)?;
    let request = create_execution_request(
        package.package_ref.clone(),
        package.manifest.package_id.clone(),
        package.manifest.version.clone(),
        package
            .manifest
            .capabilities
            .first()
            .cloned()
            .unwrap_or_else(|| "embedding".to_string()),
        json!({ "text": "compatibility smoke" }),
    );

    tests.push(timed_test("accepts-execution-request-v1", || {
        let value = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        serde_json::from_value::<ExecutionRequestV1>(value)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }));

    let execution_timer = Instant::now();
    let response = execute_mock_request(&request);
    performance.execution_ms = elapsed_ms(execution_timer);

    tests.push(timed_test("validates-execution-response-v1", || {
        let verification = validate_execution_response(&response, Some(&request));
        if verification.valid {
            Ok(())
        } else {
            Err(verification
                .issues
                .first()
                .map(|issue| issue.message.clone())
                .unwrap_or_else(|| "response validation failed".to_string()))
        }
    }));

    let stream_events = mock_streaming_events(&request.request_id, None);
    tests.push(timed_test("validates-streaming-event-sequence", || {
        let verification =
            validate_streaming_events(&stream_events, Some(&request.request_id), None);
        if verification.valid {
            Ok(())
        } else {
            Err(verification
                .issues
                .first()
                .map(|issue| issue.message.clone())
                .unwrap_or_else(|| "streaming event sequence validation failed".to_string()))
        }
    }));
    tests.push(timed_test("parses-streaming-events-sse", || {
        let sse = streaming_events_to_sse(&stream_events).map_err(|error| error.to_string())?;
        let parsed = parse_streaming_events(&sse).map_err(|error| error.to_string())?;
        let verification = validate_streaming_events(&parsed, Some(&request.request_id), None);
        if verification.valid {
            Ok(())
        } else {
            Err(verification
                .issues
                .first()
                .map(|issue| issue.message.clone())
                .unwrap_or_else(|| "parsed SSE stream validation failed".to_string()))
        }
    }));

    let receipt_timer = Instant::now();
    let artifact_group = package
        .manifest
        .artifact_groups
        .first()
        .map(|group| group.id.as_str())
        .unwrap_or("unknown");
    let receipt = create_receipt(
        &request,
        &response,
        &package.manifest,
        artifact_group,
        &package.manifest_hash,
        "sdk-mock-runner",
    );
    performance.receipt_creation_ms = elapsed_ms(receipt_timer);
    tests.push(timed_test("verifies-receipt-v1", || {
        let verification = verify_receipt(&receipt);
        if verification.valid {
            Ok(())
        } else {
            Err("receipt canonical hash did not verify".to_string())
        }
    }));

    let mut storage = MockStorageProvider::default();
    let storage_timer = Instant::now();
    let upload = storage.upload_directory(path).map_err(|error| {
        anyhow::anyhow!("failed to upload package into SDK mock storage: {error}")
    })?;
    performance.download_bytes = upload.size_bytes as u64;
    let storage_validation = package::validate_package_ref(&upload.reference, &storage)?;
    performance.storage_download_ms = elapsed_ms(storage_timer);
    tests.push(test_result(
        "loads-package-from-mock-storage",
        if storage_validation.valid {
            CompatibilityStatus::Passed
        } else {
            CompatibilityStatus::Failed
        },
        performance.storage_download_ms,
        storage_validation
            .issues
            .first()
            .map(|issue| issue.message.clone()),
    ));

    tests.push(timed_test("selects-artifact-group-for-runner", || {
        select_artifact_group_for_runner(&package.manifest, &mock_runner_descriptor(), None)
            .map(|_| ())
            .ok_or_else(|| "mock runner cannot select a compatible artifact group".to_string())
    }));

    let result = compatibility_result(&tests);
    Ok(CompatibilityReportV1 {
        schema_version: "swarm-ai.compatibility-report.v1".to_string(),
        component_name: "package-and-sdk".to_string(),
        component_version: env!("CARGO_PKG_VERSION").to_string(),
        interface_version: hivemind_core::INTERFACE_VERSION.to_string(),
        tested_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        tests,
        performance,
        result,
    })
}

impl MockStorageProvider {
    pub fn put_directory_files<I>(&mut self, files: I) -> Result<UploadResponseV1, SwarmAiErrorV1>
    where
        I: IntoIterator<Item = MockFileV1>,
    {
        let mut stored_files = Vec::new();
        let mut total_bytes = 0usize;
        for file in files {
            if file.path.trim().is_empty()
                || file.path.starts_with('/')
                || file.path.contains('\\')
                || file
                    .path
                    .split('/')
                    .any(|part| part.is_empty() || part == "..")
            {
                return Err(SwarmAiErrorV1::new(
                    ErrorCode::InvalidRequest,
                    "Mock storage file paths must be relative package paths",
                )
                .with_details(json!({ "path": file.path })));
            }
            total_bytes += file.bytes.len();
            let digest = sha256_hex(&file.bytes);
            let content_ref = format!("bzz://sdk-mock-bytes-{digest}");
            self.objects.insert(content_ref.clone(), file.bytes.clone());
            stored_files.push(StoredFileV1 {
                path: file.path,
                content_ref,
                content_type: file.content_type,
                size_bytes: file.bytes.len(),
                sha256: digest,
            });
        }
        stored_files.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = DirectoryManifestV1 {
            schema_version: "swarm-ai.storage.directory-manifest.v1".to_string(),
            files: stored_files,
            total_bytes,
        };
        let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "Failed to serialize mock manifest",
            )
            .with_details(json!({ "error": error.to_string() }))
        })?;
        let reference = format!("bzz://sdk-mock-dir-{}", sha256_hex(&manifest_bytes));
        self.objects.insert(reference.clone(), manifest_bytes);
        self.manifests.insert(reference.clone(), manifest);
        Ok(upload_response(reference, total_bytes))
    }
}

impl StorageProvider for MockStorageProvider {
    fn get_status(&self) -> StorageStatusV1 {
        StorageStatusV1 {
            schema_version: "swarm-ai.storage.status.v1".to_string(),
            provider: "sdk-mock".to_string(),
            capabilities: StorageCapabilities {
                upload: true,
                download: true,
                feeds: false,
                pinning: false,
                act: false,
                pss: false,
            },
            retry_policy: None,
        }
    }

    fn download_bytes(&self, reference: &str) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let timer = Instant::now();
        let Some(bytes) = self.objects.get(reference) else {
            return Err(not_found(reference));
        };
        Ok(DownloadResponseV1 {
            schema_version: "swarm-ai.storage.download.v1".to_string(),
            reference: reference.to_string(),
            path: None,
            content_type: "application/octet-stream".to_string(),
            size_bytes: bytes.len(),
            sha256: Some(sha256_hex(bytes)),
            metrics: storage_metrics(timer, elapsed_ms(timer), bytes.len()),
            bytes: bytes.clone(),
        })
    }

    fn upload_bytes(&mut self, bytes: Vec<u8>) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let reference = format!("bzz://sdk-mock-bytes-{}", sha256_hex(&bytes));
        let size_bytes = bytes.len();
        self.objects.insert(reference.clone(), bytes);
        Ok(upload_response(reference, size_bytes))
    }

    fn upload_directory(&mut self, root: &Path) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let files = collect_mock_files(root).map_err(|error| {
            SwarmAiErrorV1::new(ErrorCode::InvalidRequest, "Failed to read directory").with_details(
                json!({ "root": root.display().to_string(), "error": error.to_string() }),
            )
        })?;
        self.put_directory_files(files)
    }

    fn download_manifest(&self, reference: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1> {
        self.manifests
            .get(reference)
            .cloned()
            .ok_or_else(|| not_found(reference))
    }

    fn download_file(
        &self,
        reference: &str,
        path: &str,
    ) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let timer = Instant::now();
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
        response.metrics = storage_metrics(timer, elapsed_ms(timer), file.size_bytes);
        Ok(response)
    }
}

fn collect_mock_files(root: &Path) -> anyhow::Result<Vec<MockFileV1>> {
    let mut files = Vec::new();
    collect_mock_files_inner(root, root, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn collect_mock_files_inner(
    root: &Path,
    current: &Path,
    files: &mut Vec<MockFileV1>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_mock_files_inner(root, &path, files)?;
        } else {
            let relative = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            files.push(MockFileV1 {
                path: relative.clone(),
                content_type: content_type_for_path(&relative).to_string(),
                bytes: fs::read(path)?,
            });
        }
    }
    Ok(())
}

fn timed_test(
    name: &'static str,
    test: impl FnOnce() -> Result<(), String>,
) -> CompatibilityTestResultV1 {
    let timer = Instant::now();
    match test() {
        Ok(()) => test_result(name, CompatibilityStatus::Passed, elapsed_ms(timer), None),
        Err(message) => test_result(
            name,
            CompatibilityStatus::Failed,
            elapsed_ms(timer),
            Some(message),
        ),
    }
}

fn test_result(
    name: impl Into<String>,
    status: CompatibilityStatus,
    duration_ms: u64,
    message: Option<String>,
) -> CompatibilityTestResultV1 {
    CompatibilityTestResultV1 {
        name: name.into(),
        status,
        duration_ms,
        message,
    }
}

fn compatibility_result(tests: &[CompatibilityTestResultV1]) -> CompatibilityResult {
    let failed = tests
        .iter()
        .filter(|test| test.status == CompatibilityStatus::Failed)
        .count();
    let skipped = tests
        .iter()
        .filter(|test| test.status == CompatibilityStatus::Skipped)
        .count();
    if failed == 0 && skipped == 0 {
        CompatibilityResult::Passed
    } else if failed == tests.len() {
        CompatibilityResult::Failed
    } else {
        CompatibilityResult::Partial
    }
}

fn looks_like_sse(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("data:")
            || line.starts_with("event:")
            || line.starts_with("id:")
            || line.starts_with("retry:")
    })
}

fn push_sse_streaming_event(
    events: &mut Vec<StreamingEventV1>,
    data_lines: &mut Vec<String>,
) -> anyhow::Result<()> {
    if data_lines.is_empty() {
        return Ok(());
    }
    let data = data_lines.join("\n");
    data_lines.clear();
    if data.trim() == "[DONE]" {
        return Ok(());
    }
    let event = serde_json::from_str::<StreamingEventV1>(data.trim())?;
    events.push(event);
    Ok(())
}

fn streaming_event_wire_name(event_type: &StreamingEventType) -> &'static str {
    match event_type {
        StreamingEventType::Started => "started",
        StreamingEventType::Heartbeat => "heartbeat",
        StreamingEventType::TextDelta => "text_delta",
        StreamingEventType::TokenDelta => "token_delta",
        StreamingEventType::AudioChunk => "audio_chunk",
        StreamingEventType::ImageProgress => "image_progress",
        StreamingEventType::VideoFrame => "video_frame",
        StreamingEventType::EmbeddingProgress => "embedding_progress",
        StreamingEventType::ToolCallRequested => "tool_call_requested",
        StreamingEventType::ToolCallResult => "tool_call_result",
        StreamingEventType::RetrievalEvent => "retrieval_event",
        StreamingEventType::SafetyEvent => "safety_event",
        StreamingEventType::LogEvent => "log_event",
        StreamingEventType::PartialReceipt => "partial_receipt",
        StreamingEventType::Completed => "completed",
        StreamingEventType::Error => "error",
        StreamingEventType::Cancelled => "cancelled",
    }
}

fn is_terminal_stream_event(event_type: &StreamingEventType) -> bool {
    matches!(
        event_type,
        StreamingEventType::Completed | StreamingEventType::Error | StreamingEventType::Cancelled
    )
}

fn mock_streaming_events(request_id: &str, job_id: Option<&str>) -> Vec<StreamingEventV1> {
    vec![
        streaming_event(
            request_id,
            job_id.map(str::to_string),
            0,
            StreamingEventType::TextDelta,
            "2026-06-04T00:00:00Z",
            json!({ "text": "compatibility" }),
        ),
        streaming_event(
            request_id,
            job_id.map(str::to_string),
            1,
            StreamingEventType::Completed,
            "2026-06-04T00:00:01Z",
            json!({ "finishReason": "stop" }),
        ),
    ]
}

fn deterministic_embedding(input: &Value) -> Vec<f32> {
    let bytes = serde_json::to_vec(input).unwrap_or_default();
    let digest = Sha256::digest(bytes);
    digest
        .chunks(4)
        .take(8)
        .map(|chunk| {
            let mut value = 0u32;
            for byte in chunk {
                value = (value << 8) | u32::from(*byte);
            }
            (value as f32 / u32::MAX as f32) * 2.0 - 1.0
        })
        .collect()
}

fn verification(issues: Vec<ValidationIssue>) -> SdkVerificationV1 {
    SdkVerificationV1 {
        schema_version: "swarm-ai.sdk-verification.v1".to_string(),
        valid: issues.is_empty(),
        issues,
    }
}

fn marketplace_verification(
    issues: Vec<marketplace::MarketplaceVerificationIssueV1>,
) -> SdkVerificationV1 {
    verification(
        issues
            .into_iter()
            .map(|issue| ValidationIssue {
                path: issue.path,
                message: issue.message,
            })
            .collect(),
    )
}

fn compatibility_certification_index_entry(
    certification: &CompatibilityCertificationV1,
    certification_path: String,
) -> anyhow::Result<CompatibilityCertificationIndexEntryV1> {
    let certification_id = compatibility_certification_id(certification)?;
    Ok(CompatibilityCertificationIndexEntryV1 {
        certification_ref: compatibility_certification_ref(&certification_id),
        certification_id,
        component_type: certification.component_type.clone(),
        implementation_name: certification.implementation_name.clone(),
        version: certification.version.clone(),
        supported_schema_count: certification.supported_schemas.len(),
        passed_test_count: certification.passed_tests.len(),
        failed_test_count: certification.failed_tests.len(),
        warning_count: certification.warnings.len(),
        created_at: certification.created_at.clone(),
        certification_path,
        verification: verify_compatibility_certification(certification, None),
    })
}

fn compatibility_certification_lookup(
    certification: CompatibilityCertificationV1,
    path: PathBuf,
) -> anyhow::Result<CompatibilityCertificationLookupV1> {
    let certification_id = compatibility_certification_id(&certification)?;
    Ok(CompatibilityCertificationLookupV1 {
        schema_version: "swarm-ai.compatibility-certification-lookup.v1".to_string(),
        certification_ref: compatibility_certification_ref(&certification_id),
        certification_id,
        certification_path: path.display().to_string(),
        verification: verify_compatibility_certification(&certification, None),
        certification,
    })
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn safe_file_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn signature_issue_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix('$') {
        format!("$.signature{rest}")
    } else {
        format!("$.signature.{path}")
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn upload_response(reference: String, size_bytes: usize) -> UploadResponseV1 {
    let timer = Instant::now();
    UploadResponseV1 {
        schema_version: "swarm-ai.storage.upload.v1".to_string(),
        reference,
        size_bytes,
        pinned: false,
        redundancy_level: 0,
        postage_batch_id: None,
        metrics: storage_metrics(timer, elapsed_ms(timer), size_bytes),
    }
}

fn storage_metrics(
    timer: Instant,
    first_byte_ms: u64,
    size_bytes: usize,
) -> StorageTransferMetricsV1 {
    StorageTransferMetricsV1 {
        schema_version: "swarm-ai.storage.transfer-metrics.v1".to_string(),
        resolve_ms: first_byte_ms,
        first_byte_ms,
        total_ms: elapsed_ms(timer),
        size_bytes,
        retry_count: 0,
    }
}

fn not_found(reference: &str) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(
        ErrorCode::PackageNotFound,
        "Mock storage reference not found",
    )
    .with_details(json!({ "ref": reference }))
}

fn content_type_for_path(path: &str) -> &'static str {
    if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".txt") {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn elapsed_ms(timer: Instant) -> u64 {
    timer.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_hashes_match_core_canonicalization() {
        let left = json!({ "b": 1, "a": true });
        let right = json!({ "a": true, "b": 1 });

        assert_eq!(hash_canonical(&left), hash_canonical(&right));
    }

    #[test]
    fn mock_storage_loads_package_ref() {
        let mut storage = MockStorageProvider::default();
        let upload = storage
            .put_directory_files(vec![
                MockFileV1 {
                    path: "swarm-ai.json".to_string(),
                    content_type: "application/json".to_string(),
                    bytes: serde_json::to_vec(&manifest()).unwrap(),
                },
                MockFileV1 {
                    path: "model/config.json".to_string(),
                    content_type: "application/json".to_string(),
                    bytes: br#"{"ok":true}"#.to_vec(),
                },
            ])
            .unwrap();

        let package = load_package(&storage, &upload.reference).unwrap();

        assert_eq!(package.manifest.package_id, "sdk/test");
    }

    #[test]
    fn verifies_receipts_created_by_sdk() {
        let manifest = parse_package_manifest(&manifest()).unwrap();
        let request = create_execution_request(
            "bzz://pkg",
            "sdk/test",
            "0.1.0",
            "embedding",
            json!({ "text": "hello" }),
        );
        let response = execute_mock_request(&request);
        let receipt = create_receipt(
            &request,
            &response,
            &manifest,
            "local",
            "0".repeat(64),
            "runner-1",
        );

        assert!(verify_receipt(&receipt).valid);
    }

    #[test]
    fn parses_and_validates_streaming_events() {
        let events = mock_streaming_events("request-stream-1", Some("job-stream-1"));
        let json_array = serde_json::to_string(&events).unwrap();
        let parsed_array = parse_streaming_events(&json_array).unwrap();
        let sse = streaming_events_to_sse(&events).unwrap();
        let parsed_sse = parse_streaming_events(&sse).unwrap();
        let json_lines = events
            .iter()
            .map(|event| serde_json::to_string(event).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let parsed_lines = parse_streaming_events(&json_lines).unwrap();

        assert_eq!(parsed_array, events);
        assert_eq!(parsed_sse, events);
        assert_eq!(parsed_lines, events);
        let verification =
            validate_streaming_events(&parsed_sse, Some("request-stream-1"), Some("job-stream-1"));
        assert!(verification.valid, "{:?}", verification.issues);
    }

    #[test]
    fn streaming_validation_rejects_sequence_and_terminal_errors() {
        let mut events = mock_streaming_events("request-stream-2", Some("job-stream-2"));
        events.push(streaming_event(
            "request-stream-2",
            Some("job-stream-2".to_string()),
            2,
            StreamingEventType::TextDelta,
            "2026-06-04T00:00:02Z",
            json!({ "text": "late" }),
        ));
        events[1].event_id = events[0].event_id.clone();
        events[2].sequence = 4;

        let verification =
            validate_streaming_events(&events, Some("request-stream-2"), Some("job-stream-2"));

        assert!(!verification.valid);
        assert!(
            verification.issues.iter().any(
                |issue| issue.path == "$.events[1].eventId" && issue.message.contains("unique")
            )
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.events[2].sequence")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.events[2].type"
                    && issue.message.contains("after terminal"))
        );
    }

    #[test]
    fn streaming_validation_rejects_cancellation_not_last() {
        let mut events = vec![
            streaming_event(
                "request-stream-3",
                Some("job-stream-3".to_string()),
                0,
                StreamingEventType::Cancelled,
                "2026-06-04T00:00:00Z",
                json!({ "reason": "user" }),
            ),
            streaming_event(
                "request-stream-3",
                Some("job-stream-3".to_string()),
                1,
                StreamingEventType::TextDelta,
                "2026-06-04T00:00:01Z",
                json!({ "text": "too late" }),
            ),
        ];
        events[0].event_id = canonical_streaming_event_id(&events[0]).unwrap();
        events[1].event_id = canonical_streaming_event_id(&events[1]).unwrap();

        let verification =
            validate_streaming_events(&events, Some("request-stream-3"), Some("job-stream-3"));

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.events[0].type"
                    && issue.message.contains("final event"))
        );
    }

    #[test]
    fn sdk_facades_build_route_marketplace_access_validation_and_openai_objects() {
        let manifest = parse_package_manifest(&manifest()).unwrap();
        let package = package::LocalPackage {
            root: std::path::PathBuf::new(),
            manifest: manifest.clone(),
            manifest_hash: "sdk-test-hash".to_string(),
            package_ref: "bzz://sdk-test-package".to_string(),
        };
        let request = create_execution_request(
            package.package_ref.clone(),
            package.manifest.package_id.clone(),
            package.manifest.version.clone(),
            "embedding",
            json!({ "text": "route me" }),
        );
        let runner = sdk_test_runner();
        let offer = build_runner_offer_from_descriptor(
            &runner,
            "local://runner/sdk",
            vec![package.package_ref.clone()],
            marketplace::RunnerPricingV1 {
                input_token_price: 0.0,
                output_token_price: 0.0,
                currency: "none".to_string(),
            },
            marketplace::RunnerServiceLevelV1 {
                p95_first_token_ms: 250,
                availability_target: 0.99,
            },
            marketplace::RunnerReputationV1 {
                validator_score: 0.9,
                completed_jobs: 7,
            },
        );
        let route_request = build_route_planner_request(
            request.clone(),
            hivemind_core::PolicyMode::Balanced,
            3,
            None,
        );
        let shortlist_request =
            build_marketplace_shortlist_request(&request, hivemind_core::PolicyMode::Balanced, 3);
        let report = plan_route_report(
            &request,
            &package,
            std::slice::from_ref(&runner),
            std::slice::from_ref(&offer),
            hivemind_core::PolicyMode::Balanced,
            3,
            None,
        );
        let hardware_offer = build_hardware_resource_offer(&runner, "sdk-operator");
        let access = evaluate_access_for_execution(
            &package.manifest,
            &package.package_ref,
            &request.request_id,
            "sdk-user",
            "runner-service",
            Some(&runner.runner_id),
            None,
            None,
        );
        let mut response = execute_mock_request(&request);
        let receipt = create_receipt(
            &request,
            &response,
            &package.manifest,
            "local",
            &package.manifest_hash,
            &runner.runner_id,
        );
        response.metadata["receipt"] = json!(receipt);
        let challenge = validator::ChallengeV1 {
            schema_version: "swarm-ai.challenge.v1".to_string(),
            challenge_id: "sdk-challenge".to_string(),
            task: "embedding".to_string(),
            package_ref: package.package_ref.clone(),
            input: json!({ "text": "route me" }),
            scoring_method: validator::ScoringMethod::Exact,
            deadline_ms: 1_000,
            visibility: validator::ChallengeVisibility::Public,
            validator_id: "sdk-validator".to_string(),
        };
        let validation_report =
            create_validation_report(&challenge, &response, &runner.runner_id, Vec::new());
        let chat = openai_compat::ChatCompletionRequestV1 {
            model: "hivemind/hello-chat".to_string(),
            messages: vec![openai_compat::ChatMessageV1 {
                role: "user".to_string(),
                content: json!("hello"),
                name: None,
            }],
            stream: true,
            max_tokens: Some(64),
            temperature: Some(0.2),
            user: Some("sdk-user".to_string()),
            metadata: None,
        };
        let ai_request = openai_chat_to_ai_request(&chat, "sdk-ai-chat", "fallback");
        let execution_request = openai_chat_to_execution_request(
            &chat,
            "bzz://chat-package",
            "hivemind/hello-chat",
            "0.1.0",
            "sdk-chat-execution",
        );

        assert_eq!(route_request.max_marketplace_results, 3);
        assert_eq!(shortlist_request.package_ref, request.package_ref);
        assert!(report.plan.selected_route_id.is_some());
        assert!(verify_runner_offer(&offer).valid);
        assert!(verify_hardware_resource_offer(&hardware_offer).valid);
        assert_eq!(access.decision, hivemind_core::AccessDecision::Granted);
        assert!(verify_validation_report(&validation_report).valid);
        assert_eq!(
            ai_request.api_surface,
            hivemind_core::ApiSurface::OpenAiChatCompletions
        );
        assert_eq!(execution_request.task, "chat");
        assert!(execution_request.options.stream);
    }

    #[test]
    fn signs_and_verifies_compatibility_certification() {
        let identity =
            hivemind_identity::identity_from_seed("sdk-test-runner", b"sdk-certification-runner")
                .unwrap();
        let report = compatibility_report(vec![
            test_result(
                "validates-package-manifest-v1",
                CompatibilityStatus::Passed,
                2,
                None,
            ),
            test_result(
                "large-artifact-production-certification",
                CompatibilityStatus::Skipped,
                0,
                Some("optional production profile".to_string()),
            ),
        ]);
        let mut certification = compatibility_certification_from_report(
            &report,
            "package",
            "sdk-test-package",
            "0.1.0",
            package_certification_supported_schemas(),
            ["cold and warm cache timings are local mock timings"],
        );

        sign_compatibility_certification(&mut certification, &identity).unwrap();
        let verification =
            verify_compatibility_certification(&certification, Some("sdk-test-runner"));

        assert!(verification.valid, "{:?}", verification.issues);
        assert!(certification.signature.is_some());
        assert_eq!(
            certification.passed_tests,
            vec!["validates-package-manifest-v1".to_string()]
        );
        assert!(certification.failed_tests.is_empty());
        assert!(
            certification
                .supported_schemas
                .iter()
                .any(|schema| { schema == COMPATIBILITY_CERTIFICATION_SCHEMA_VERSION })
        );
        assert!(
            certification
                .warnings
                .iter()
                .any(|warning| warning.contains("skipped compatibility test"))
        );
    }

    #[test]
    fn compatibility_certification_requires_signature() {
        let report = compatibility_report(vec![test_result(
            "validates-package-manifest-v1",
            CompatibilityStatus::Passed,
            1,
            None,
        )]);
        let certification = compatibility_certification_from_report(
            &report,
            "package",
            "sdk-test-package",
            "0.1.0",
            package_certification_supported_schemas(),
            Vec::<String>::new(),
        );

        let verification = verify_compatibility_certification(&certification, None);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signature")
        );
    }

    #[test]
    fn compatibility_certification_detects_tampering() {
        let identity =
            hivemind_identity::identity_from_seed("sdk-test-runner", b"sdk-certification-runner")
                .unwrap();
        let report = compatibility_report(vec![test_result(
            "validates-package-manifest-v1",
            CompatibilityStatus::Passed,
            1,
            None,
        )]);
        let mut certification = compatibility_certification_from_report(
            &report,
            "package",
            "sdk-test-package",
            "0.1.0",
            package_certification_supported_schemas(),
            Vec::<String>::new(),
        );
        sign_compatibility_certification(&mut certification, &identity).unwrap();
        certification.version = "0.1.1".to_string();

        let verification =
            verify_compatibility_certification(&certification, Some("sdk-test-runner"));

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signature.payloadHash")
        );
    }

    #[test]
    fn compatibility_certification_store_lists_and_gets_signed_records() {
        let identity =
            hivemind_identity::identity_from_seed("sdk-test-runner", b"sdk-certification-runner")
                .unwrap();
        let report = compatibility_report(vec![test_result(
            "validates-package-manifest-v1",
            CompatibilityStatus::Passed,
            1,
            None,
        )]);
        let mut certification = compatibility_certification_from_report(
            &report,
            "package",
            "sdk-test-package",
            "0.1.0",
            package_certification_supported_schemas(),
            Vec::<String>::new(),
        );
        sign_compatibility_certification(&mut certification, &identity).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "hivemind-sdk-compat-store-{}",
            uuid::Uuid::new_v4()
        ));

        let write = write_compatibility_certification(&dir, &certification).unwrap();
        let summary = list_compatibility_certifications(&dir).unwrap();
        let lookup = get_compatibility_certification(&dir, &write.certification_id)
            .unwrap()
            .unwrap();

        assert!(write.stored);
        assert!(write.certification_ref.starts_with("local://compat/"));
        assert_eq!(summary.certification_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.invalid_count, 0);
        assert_eq!(summary.component_type_counts.get("package"), Some(&1));
        assert_eq!(
            summary.certifications[0].certification_id,
            write.certification_id
        );
        assert_eq!(lookup.certification, certification);
        assert!(lookup.verification.valid);

        let mut tampered = certification.clone();
        tampered.version = "0.1.1".to_string();
        let tampered_path = dir.join("tampered.json");
        fs::write(
            &tampered_path,
            serde_json::to_vec_pretty(&tampered).unwrap(),
        )
        .unwrap();
        let tampered_summary = list_compatibility_certifications(&dir).unwrap();
        assert_eq!(tampered_summary.certification_count, 2);
        assert_eq!(tampered_summary.valid_count, 1);
        assert_eq!(tampered_summary.invalid_count, 1);
        assert!(
            get_compatibility_certification(&dir, "missing-certification")
                .unwrap()
                .is_none()
        );

        fs::remove_dir_all(&dir).ok();
    }

    fn compatibility_report(tests: Vec<CompatibilityTestResultV1>) -> CompatibilityReportV1 {
        CompatibilityReportV1 {
            schema_version: "swarm-ai.compatibility-report.v1".to_string(),
            component_name: "package-and-sdk".to_string(),
            component_version: "0.1.0".to_string(),
            interface_version: hivemind_core::INTERFACE_VERSION.to_string(),
            tested_at: "2026-06-04T00:00:00Z".to_string(),
            tests,
            performance: CompatibilityPerformanceV1::default(),
            result: CompatibilityResult::Passed,
        }
    }

    fn manifest() -> Value {
        json!({
            "schemaVersion": "swarm-ai.package.v1",
            "packageId": "sdk/test",
            "kind": "model",
            "name": "SDK Test",
            "version": "0.1.0",
            "publisher": {"address": "0x0", "displayName": "SDK"},
            "capabilities": ["embedding"],
            "artifactGroups": [{
                "id": "local",
                "target": "local-mock",
                "engine": "rust-mock",
                "format": "json",
                "paths": ["model/config.json"],
                "totalBytes": 1,
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "minimum": {"memoryMB": 1, "webgpu": false}
            }],
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "permissions": [],
            "license": {"type": "open", "name": "Apache-2.0"}
        })
    }

    fn sdk_test_runner() -> RunnerDescriptorV1 {
        RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: "sdk-runner".to_string(),
            runner_type: hivemind_core::RunnerType::Local,
            targets: vec!["local-mock".to_string()],
            engines: vec!["rust-mock".to_string()],
            capabilities: vec!["embedding".to_string(), "chat".to_string()],
            limits: hivemind_core::RunnerLimits {
                max_memory_mb: 4096,
                max_input_bytes: 128 * 1024,
                max_concurrent_jobs: 4,
            },
            queue_depth: 0,
            warm_package_refs: vec!["bzz://sdk-test-package".to_string()],
        }
    }
}
