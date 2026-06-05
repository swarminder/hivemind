use chrono::{DateTime, SecondsFormat, Utc};
use hivemind_core::{
    AccessGrantV1, ExecutionOptions, ExecutionPrivacy, ExecutionReceiptV1, ExecutionRequestV1,
    ExecutionResponseV1, ExecutionStatus, IntegrityTier, PrivacyTier, ValidationIssue,
    ValidationReport as PackageValidationReport, canonicalize_json, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use hivemind_package::validate_package_dir;
use hivemind_storage::{StorageProvider, StorageTransferMetricsV1, UploadResponseV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEV_VALIDATION_SIGNATURE_PREFIX: &str = "dev-signature-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompatibilityTestResultV1 {
    pub name: String,
    pub status: String,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    pub result: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ScoringMethod {
    Exact,
    Semantic,
    Retrieval,
    LatencyAdjusted,
    HumanReview,
    Hybrid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeVisibility {
    Public,
    Hidden,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ReputationSubjectType {
    Runner,
    Package,
    Publisher,
    Validator,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChallengeV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    pub task: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub input: Value,
    #[serde(rename = "scoringMethod")]
    pub scoring_method: ScoringMethod,
    #[serde(rename = "deadlineMs")]
    pub deadline_ms: u64,
    pub visibility: ChallengeVisibility,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct ValidationScoresV1 {
    pub quality: f64,
    pub latency: f64,
    #[serde(rename = "costEfficiency")]
    pub cost_efficiency: f64,
    #[serde(rename = "policyCompliance")]
    pub policy_compliance: f64,
    pub overall: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationReportV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "reportId")]
    pub report_id: String,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    pub scores: ValidationScoresV1,
    #[serde(rename = "evidenceRefs")]
    pub evidence_refs: Vec<String>,
    #[serde(
        rename = "validationElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub validation_elapsed_ms: Option<u64>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationReportVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "reportId")]
    pub report_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationReportIndexEntryV1 {
    #[serde(rename = "reportId")]
    pub report_id: String,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "overallScore")]
    pub overall_score: f64,
    #[serde(
        rename = "validationElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub validation_elapsed_ms: Option<u64>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "reportPath")]
    pub report_path: String,
    pub verification: ValidationReportVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationReportStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "reportCount")]
    pub report_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "withValidationElapsedCount")]
    pub with_validation_elapsed_count: usize,
    #[serde(
        rename = "averageValidationElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub average_validation_elapsed_ms: Option<f64>,
    #[serde(
        rename = "maxValidationElapsedMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_validation_elapsed_ms: Option<u64>,
    pub reports: Vec<ValidationReportIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationReportLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "reportId")]
    pub report_id: String,
    #[serde(rename = "reportPath")]
    pub report_path: String,
    pub report: ValidationReportV1,
    pub verification: ValidationReportVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationReportStorageObjectV1 {
    #[serde(rename = "reportRef")]
    pub report_ref: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<StorageTransferMetricsV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationReportUploadResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "reportId")]
    pub report_id: String,
    #[serde(rename = "reportRef")]
    pub report_ref: String,
    pub storage: ValidationReportStorageObjectV1,
    pub upload: UploadResponseV1,
    pub verification: ValidationReportVerificationV1,
    #[serde(rename = "uploadedAt")]
    pub uploaded_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationReportDownloadResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "reportRef")]
    pub report_ref: String,
    pub storage: ValidationReportStorageObjectV1,
    pub report: ValidationReportV1,
    pub verification: ValidationReportVerificationV1,
    #[serde(rename = "downloadedAt")]
    pub downloaded_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReputationProfileV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "subjectType")]
    pub subject_type: ReputationSubjectType,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(rename = "averageScores")]
    pub average_scores: ValidationScoresV1,
    #[serde(rename = "reportRefs")]
    pub report_refs: Vec<String>,
    #[serde(rename = "reportCount")]
    pub report_count: usize,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationSubjectTypeV2 {
    Receipt,
    Runner,
    Miner,
    Package,
    Publisher,
    Validator,
    Benchmark,
    HardwareOffer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMethodV2 {
    SchemaCheck,
    ManifestCompatibility,
    ArtifactHashCheck,
    BenchmarkRun,
    HiddenChallenge,
    ReceiptCheck,
    RedundantExecutionCompare,
    DeterministicReplay,
    StatisticalSimilarity,
    ReferenceAnswerScore,
    LlmJudgeWithControls,
    LlmJudgeWithDisclosure,
    HumanReview,
    SandboxTraceReview,
    TeeAttestationCheck,
    ZkProofCheck,
    FheResultCheck,
    PolicyComplianceCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationMethodStrengthV1 {
    Strong,
    Statistical,
    Subjective,
    Attestation,
    Cryptographic,
    Policy,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationMethodDescriptorV1 {
    #[serde(rename = "methodId")]
    pub method_id: String,
    pub method: ValidationMethodV2,
    pub strength: ValidationMethodStrengthV1,
    #[serde(rename = "taskClasses")]
    pub task_classes: Vec<String>,
    #[serde(rename = "subjectTypes")]
    pub subject_types: Vec<ValidationSubjectTypeV2>,
    #[serde(rename = "evidenceRequirements")]
    pub evidence_requirements: Vec<String>,
    #[serde(rename = "reportFields")]
    pub report_fields: Vec<String>,
    #[serde(rename = "benchmarkPackRequired")]
    pub benchmark_pack_required: bool,
    #[serde(rename = "hiddenChallengeCompatible")]
    pub hidden_challenge_compatible: bool,
    pub subjective: bool,
    #[serde(rename = "privacyTiers")]
    pub privacy_tiers: Vec<PrivacyTier>,
    #[serde(rename = "integrityTiers")]
    pub integrity_tiers: Vec<IntegrityTier>,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationMethodRegistryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    pub methods: Vec<ValidationMethodDescriptorV1>,
}

pub fn validation_method_registry() -> ValidationMethodRegistryV1 {
    let mut seen = BTreeSet::new();
    let mut methods = all_validation_methods()
        .into_iter()
        .filter(|method| seen.insert(validation_method_id(method).to_string()))
        .map(validation_method_descriptor)
        .collect::<Vec<_>>();
    methods.sort_by(|left, right| left.method_id.cmp(&right.method_id));
    ValidationMethodRegistryV1 {
        schema_version: "hivemind.validation-method-registry.v1".to_string(),
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        methods,
    }
}

pub fn validation_method_descriptor(method: ValidationMethodV2) -> ValidationMethodDescriptorV1 {
    let method_id = validation_method_id(&method).to_string();
    let mut descriptor = match method {
        ValidationMethodV2::SchemaCheck => method_descriptor(
            method,
            ValidationMethodStrengthV1::Strong,
            &["structured-output", "tool", "workflow", "api-adapter"],
            &[
                ValidationSubjectTypeV2::Receipt,
                ValidationSubjectTypeV2::Package,
                ValidationSubjectTypeV2::Benchmark,
            ],
            &["input-schema", "output-schema", "structured-response"],
            &["score", "qualityScore", "evidenceRefs"],
            false,
            false,
            false,
            "Checks JSON/schema conformance for structured AI inputs, outputs, packages, and receipts.",
        ),
        ValidationMethodV2::ManifestCompatibility => method_descriptor(
            method,
            ValidationMethodStrengthV1::Strong,
            &["package", "registry", "publisher"],
            &[ValidationSubjectTypeV2::Package],
            &["package-manifest", "schema-release"],
            &["score", "qualityScore", "evidenceRefs"],
            false,
            false,
            false,
            "Checks package manifests and compatibility contracts before publication or routing.",
        ),
        ValidationMethodV2::ArtifactHashCheck => method_descriptor(
            method,
            ValidationMethodStrengthV1::Strong,
            &["package", "storage", "publication"],
            &[ValidationSubjectTypeV2::Package],
            &["artifact-hash", "storage-ref", "publication-record"],
            &["score", "fraudSignals", "evidenceRefs"],
            false,
            false,
            false,
            "Compares artifact bytes and storage refs against declared hashes.",
        ),
        ValidationMethodV2::BenchmarkRun => method_descriptor(
            ValidationMethodV2::BenchmarkRun,
            ValidationMethodStrengthV1::Statistical,
            &[
                "embedding",
                "classification",
                "retrieval",
                "ocr",
                "generation",
                "agent",
            ],
            &[
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
                ValidationSubjectTypeV2::Package,
                ValidationSubjectTypeV2::Benchmark,
            ],
            &[
                "benchmark-pack",
                "dataset-ref",
                "scoring-function-ref",
                "execution-receipt",
            ],
            &[
                "benchmarkRef",
                "score",
                "latencyScore",
                "qualityScore",
                "costScore",
            ],
            true,
            true,
            false,
            "Runs a task-specific benchmark pack and records score, latency, cost, and evidence refs.",
        ),
        ValidationMethodV2::HiddenChallenge => method_descriptor(
            method,
            ValidationMethodStrengthV1::Strong,
            &[
                "embedding",
                "classification",
                "retrieval",
                "ocr",
                "miner-routing",
            ],
            &[
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
                ValidationSubjectTypeV2::Package,
            ],
            &["challenge-commitment", "execution-receipt", "answer-hash"],
            &[
                "challengeCommitmentRef",
                "score",
                "fraudSignals",
                "evidenceRefs",
            ],
            true,
            true,
            false,
            "Uses committed hidden tasks so miners and packages cannot tune only for public examples.",
        ),
        ValidationMethodV2::ReceiptCheck => method_descriptor(
            method,
            ValidationMethodStrengthV1::Strong,
            &["execution", "settlement", "audit"],
            &[
                ValidationSubjectTypeV2::Receipt,
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
            ],
            &[
                "execution-receipt",
                "lease",
                "route-decision",
                "settlement-ref",
            ],
            &["receiptId", "score", "fraudSignals", "evidenceRefs"],
            false,
            false,
            false,
            "Checks receipt structure, signatures, linked job context, and settlement-facing evidence.",
        ),
        ValidationMethodV2::RedundantExecutionCompare => method_descriptor(
            method,
            ValidationMethodStrengthV1::Strong,
            &["deterministic", "extraction", "classification", "retrieval"],
            &[
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
                ValidationSubjectTypeV2::Package,
            ],
            &["primary-receipt", "comparison-receipt", "output-hash"],
            &["score", "qualityScore", "fraudSignals", "evidenceRefs"],
            false,
            true,
            false,
            "Compares independently executed outputs for tasks where close agreement is expected.",
        ),
        ValidationMethodV2::DeterministicReplay => method_descriptor(
            method,
            ValidationMethodStrengthV1::Strong,
            &["deterministic", "embedding", "classification", "tool"],
            &[
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
                ValidationSubjectTypeV2::Package,
            ],
            &["seed", "input-hash", "output-hash", "execution-receipt"],
            &["score", "qualityScore", "fraudSignals", "evidenceRefs"],
            false,
            true,
            false,
            "Replays deterministic workloads with declared seeds, inputs, and artifact hashes.",
        ),
        ValidationMethodV2::StatisticalSimilarity => method_descriptor(
            method,
            ValidationMethodStrengthV1::Statistical,
            &["embedding", "image", "audio", "generation", "simulation"],
            &[
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
                ValidationSubjectTypeV2::Package,
            ],
            &["reference-distribution", "sample-set", "metric-definition"],
            &["score", "qualityScore", "safetyScore", "evidenceRefs"],
            true,
            false,
            false,
            "Scores outputs against reference distributions when exact answers are not appropriate.",
        ),
        ValidationMethodV2::ReferenceAnswerScore => method_descriptor(
            method,
            ValidationMethodStrengthV1::Strong,
            &["classification", "ocr", "extraction", "qa", "retrieval"],
            &[
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
                ValidationSubjectTypeV2::Package,
                ValidationSubjectTypeV2::Benchmark,
            ],
            &["dataset-ref", "answer-key-ref", "scoring-function-ref"],
            &["benchmarkRef", "score", "qualityScore", "evidenceRefs"],
            true,
            true,
            false,
            "Scores outputs against public or committed reference answers for tasks with known targets.",
        ),
        ValidationMethodV2::LlmJudgeWithControls | ValidationMethodV2::LlmJudgeWithDisclosure => {
            method_descriptor(
                method,
                ValidationMethodStrengthV1::Subjective,
                &[
                    "chat",
                    "creative-writing",
                    "summarization",
                    "agent",
                    "safety",
                ],
                &[
                    ValidationSubjectTypeV2::Runner,
                    ValidationSubjectTypeV2::Miner,
                    ValidationSubjectTypeV2::Package,
                ],
                &[
                    "judge-model-ref",
                    "rubric-ref",
                    "calibration-set-ref",
                    "judge-receipt",
                ],
                &["score", "qualityScore", "safetyScore", "evidenceRefs"],
                true,
                false,
                true,
                "Uses disclosed judge models, rubrics, and calibration controls for subjective tasks.",
            )
        }
        ValidationMethodV2::HumanReview => method_descriptor(
            method,
            ValidationMethodStrengthV1::Subjective,
            &["safety", "policy", "creative", "enterprise-review"],
            &[
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
                ValidationSubjectTypeV2::Package,
                ValidationSubjectTypeV2::Publisher,
            ],
            &["reviewer-id", "rubric-ref", "redacted-sample-ref"],
            &["score", "qualityScore", "safetyScore", "evidenceRefs"],
            false,
            false,
            true,
            "Records human review with explicit rubric, reviewer identity, and redacted evidence refs.",
        ),
        ValidationMethodV2::SandboxTraceReview => method_descriptor(
            method,
            ValidationMethodStrengthV1::Policy,
            &["tool", "agent", "workflow", "browser-runner"],
            &[
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
                ValidationSubjectTypeV2::Package,
            ],
            &[
                "sandbox-trace-ref",
                "permission-manifest",
                "policy-decision",
            ],
            &["score", "safetyScore", "fraudSignals", "evidenceRefs"],
            false,
            false,
            false,
            "Reviews tool, agent, browser, or workflow traces for declared permission and sandbox behavior.",
        ),
        ValidationMethodV2::TeeAttestationCheck => method_descriptor(
            method,
            ValidationMethodStrengthV1::Attestation,
            &["confidential", "private-rag", "regulated"],
            &[
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
                ValidationSubjectTypeV2::HardwareOffer,
            ],
            &[
                "attestation-document",
                "measurement-hash",
                "expected-measurement-ref",
            ],
            &["score", "safetyScore", "fraudSignals", "evidenceRefs"],
            false,
            false,
            false,
            "Checks confidential-compute attestation measurements before trusting private execution claims.",
        ),
        ValidationMethodV2::ZkProofCheck => method_descriptor(
            method,
            ValidationMethodStrengthV1::Cryptographic,
            &["supported-zk-model", "deterministic", "proof-carrying"],
            &[
                ValidationSubjectTypeV2::Receipt,
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
            ],
            &["proof-ref", "verification-key-ref", "public-input-hash"],
            &["score", "fraudSignals", "evidenceRefs"],
            false,
            false,
            false,
            "Verifies zero-knowledge proof hooks for supported model classes.",
        ),
        ValidationMethodV2::FheResultCheck => method_descriptor(
            method,
            ValidationMethodStrengthV1::Cryptographic,
            &["fhe", "encrypted-inference", "supported-model-class"],
            &[
                ValidationSubjectTypeV2::Receipt,
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
            ],
            &["fhe-result-ref", "ciphertext-hash", "verification-key-ref"],
            &["score", "fraudSignals", "evidenceRefs"],
            false,
            false,
            false,
            "Checks FHE result evidence for supported encrypted execution paths.",
        ),
        ValidationMethodV2::PolicyComplianceCheck => method_descriptor(
            method,
            ValidationMethodStrengthV1::Policy,
            &["moderation", "governance", "enterprise", "marketplace"],
            &[
                ValidationSubjectTypeV2::Package,
                ValidationSubjectTypeV2::Publisher,
                ValidationSubjectTypeV2::Runner,
                ValidationSubjectTypeV2::Miner,
            ],
            &[
                "policy-ref",
                "decision-ref",
                "moderation-record-ref",
                "redacted-evidence-ref",
            ],
            &["score", "safetyScore", "fraudSignals", "evidenceRefs"],
            false,
            false,
            true,
            "Checks compliance with declared safety, moderation, marketplace, or enterprise policies.",
        ),
    };
    descriptor.method_id = method_id;
    descriptor
}

fn all_validation_methods() -> Vec<ValidationMethodV2> {
    vec![
        ValidationMethodV2::SchemaCheck,
        ValidationMethodV2::ManifestCompatibility,
        ValidationMethodV2::ArtifactHashCheck,
        ValidationMethodV2::BenchmarkRun,
        ValidationMethodV2::HiddenChallenge,
        ValidationMethodV2::ReceiptCheck,
        ValidationMethodV2::RedundantExecutionCompare,
        ValidationMethodV2::DeterministicReplay,
        ValidationMethodV2::StatisticalSimilarity,
        ValidationMethodV2::ReferenceAnswerScore,
        ValidationMethodV2::LlmJudgeWithControls,
        ValidationMethodV2::LlmJudgeWithDisclosure,
        ValidationMethodV2::HumanReview,
        ValidationMethodV2::SandboxTraceReview,
        ValidationMethodV2::TeeAttestationCheck,
        ValidationMethodV2::ZkProofCheck,
        ValidationMethodV2::FheResultCheck,
        ValidationMethodV2::PolicyComplianceCheck,
    ]
}

#[allow(clippy::too_many_arguments)]
fn method_descriptor(
    method: ValidationMethodV2,
    strength: ValidationMethodStrengthV1,
    task_classes: &[&str],
    subject_types: &[ValidationSubjectTypeV2],
    evidence_requirements: &[&str],
    report_fields: &[&str],
    benchmark_pack_required: bool,
    hidden_challenge_compatible: bool,
    subjective: bool,
    notes: &str,
) -> ValidationMethodDescriptorV1 {
    ValidationMethodDescriptorV1 {
        method_id: validation_method_id(&method).to_string(),
        method,
        strength,
        task_classes: task_classes.iter().copied().map(str::to_string).collect(),
        subject_types: subject_types.to_vec(),
        evidence_requirements: evidence_requirements
            .iter()
            .copied()
            .map(str::to_string)
            .collect(),
        report_fields: report_fields.iter().copied().map(str::to_string).collect(),
        benchmark_pack_required,
        hidden_challenge_compatible,
        subjective,
        privacy_tiers: vec![
            PrivacyTier::Standard,
            PrivacyTier::NoLog,
            PrivacyTier::RedactedInput,
            PrivacyTier::LocalOnly,
            PrivacyTier::TeeConfidential,
        ],
        integrity_tiers: integrity_tiers_for_method(&method),
        notes: notes.to_string(),
    }
}

fn integrity_tiers_for_method(method: &ValidationMethodV2) -> Vec<IntegrityTier> {
    match method {
        ValidationMethodV2::ReceiptCheck => vec![IntegrityTier::ReceiptOnly],
        ValidationMethodV2::RedundantExecutionCompare => vec![IntegrityTier::RedundantExecution],
        ValidationMethodV2::DeterministicReplay => vec![IntegrityTier::DeterministicReplay],
        ValidationMethodV2::TeeAttestationCheck => vec![IntegrityTier::TeeAttested],
        ValidationMethodV2::ZkProofCheck | ValidationMethodV2::FheResultCheck => {
            vec![IntegrityTier::ZkProofWhenSupported]
        }
        _ => vec![
            IntegrityTier::ReceiptOnly,
            IntegrityTier::ValidatorSpotCheck,
        ],
    }
}

pub fn validation_method_id(method: &ValidationMethodV2) -> &'static str {
    match method {
        ValidationMethodV2::SchemaCheck => "schema_check",
        ValidationMethodV2::ManifestCompatibility => "manifest_compatibility",
        ValidationMethodV2::ArtifactHashCheck => "artifact_hash_check",
        ValidationMethodV2::BenchmarkRun => "benchmark_score",
        ValidationMethodV2::HiddenChallenge => "hidden_challenge",
        ValidationMethodV2::ReceiptCheck => "receipt_check",
        ValidationMethodV2::RedundantExecutionCompare => "redundant_execution",
        ValidationMethodV2::DeterministicReplay => "deterministic_replay",
        ValidationMethodV2::StatisticalSimilarity => "statistical_similarity",
        ValidationMethodV2::ReferenceAnswerScore => "reference_answer_score",
        ValidationMethodV2::LlmJudgeWithControls => "llm_judge_with_controls",
        ValidationMethodV2::LlmJudgeWithDisclosure => "llm_judge_with_disclosure",
        ValidationMethodV2::HumanReview => "human_review",
        ValidationMethodV2::SandboxTraceReview => "sandbox_trace_review",
        ValidationMethodV2::TeeAttestationCheck => "tee_attestation_check",
        ValidationMethodV2::ZkProofCheck => "zk_proof_check",
        ValidationMethodV2::FheResultCheck => "fhe_result_check",
        ValidationMethodV2::PolicyComplianceCheck => "policy_compliance_check",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityEvidenceKindV1 {
    TeeAttestation,
    ZkProof,
    FheResult,
    DeterministicReplay,
    RedundantExecution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityEvidenceVerdictV1 {
    Passed,
    Failed,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IntegrityEvidenceInitOptionsV1 {
    #[serde(rename = "evidenceKind")]
    pub evidence_kind: IntegrityEvidenceKindV1,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(rename = "subjectType")]
    pub subject_type: ValidationSubjectTypeV2,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(
        rename = "packageRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_ref: Option<String>,
    #[serde(rename = "receiptId", default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(
        rename = "measurementHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub measurement_hash: Option<String>,
    #[serde(rename = "expectedMeasurementHashes", default)]
    pub expected_measurement_hashes: Vec<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(rename = "proofRefs", default)]
    pub proof_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<ValidationMethodV2>,
    pub verdict: IntegrityEvidenceVerdictV1,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IntegrityEvidenceV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evidenceId")]
    pub evidence_id: String,
    #[serde(rename = "evidenceKind")]
    pub evidence_kind: IntegrityEvidenceKindV1,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(rename = "subjectType")]
    pub subject_type: ValidationSubjectTypeV2,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(
        rename = "packageRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_ref: Option<String>,
    #[serde(rename = "receiptId", default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(
        rename = "measurementHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub measurement_hash: Option<String>,
    #[serde(rename = "expectedMeasurementHashes", default)]
    pub expected_measurement_hashes: Vec<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(rename = "proofRefs", default)]
    pub proof_refs: Vec<String>,
    pub method: ValidationMethodV2,
    pub verdict: IntegrityEvidenceVerdictV1,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IntegrityEvidenceVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evidenceId")]
    pub evidence_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IntegrityEvidenceIndexEntryV1 {
    #[serde(rename = "evidenceId")]
    pub evidence_id: String,
    #[serde(rename = "evidenceKind")]
    pub evidence_kind: IntegrityEvidenceKindV1,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(rename = "subjectType")]
    pub subject_type: ValidationSubjectTypeV2,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    pub method: ValidationMethodV2,
    pub verdict: IntegrityEvidenceVerdictV1,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "evidencePath")]
    pub evidence_path: String,
    pub verification: IntegrityEvidenceVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IntegrityEvidenceStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "evidenceCount")]
    pub evidence_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "passedCount")]
    pub passed_count: usize,
    #[serde(rename = "failedCount")]
    pub failed_count: usize,
    #[serde(rename = "inconclusiveCount")]
    pub inconclusive_count: usize,
    pub evidence: Vec<IntegrityEvidenceIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IntegrityEvidenceLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evidenceId")]
    pub evidence_id: String,
    #[serde(rename = "evidencePath")]
    pub evidence_path: String,
    pub evidence: IntegrityEvidenceV1,
    pub verification: IntegrityEvidenceVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum FraudSignalSeverityV2 {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FraudSignalV2 {
    pub code: String,
    pub severity: FraudSignalSeverityV2,
    pub message: String,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct ValidationReportV2Context {
    #[serde(
        rename = "subjectType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub subject_type: Option<ValidationSubjectTypeV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<ValidationMethodV2>,
    #[serde(
        rename = "benchmarkRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub benchmark_ref: Option<String>,
    #[serde(
        rename = "challengeCommitmentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub challenge_commitment_ref: Option<String>,
    #[serde(
        rename = "safetyScore",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub safety_score: Option<f64>,
    #[serde(rename = "fraudSignals", default)]
    pub fraud_signals: Vec<FraudSignalV2>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationReportV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "reportId")]
    pub report_id: String,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: ValidationSubjectTypeV2,
    #[serde(rename = "receiptId", default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(
        rename = "packageRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_ref: Option<String>,
    #[serde(
        rename = "benchmarkRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub benchmark_ref: Option<String>,
    #[serde(
        rename = "challengeCommitmentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub challenge_commitment_ref: Option<String>,
    pub score: f64,
    #[serde(
        rename = "latencyScore",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub latency_score: Option<f64>,
    #[serde(rename = "costScore", default, skip_serializing_if = "Option::is_none")]
    pub cost_score: Option<f64>,
    #[serde(
        rename = "qualityScore",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub quality_score: Option<f64>,
    #[serde(
        rename = "safetyScore",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub safety_score: Option<f64>,
    #[serde(rename = "fraudSignals")]
    pub fraud_signals: Vec<FraudSignalV2>,
    pub method: ValidationMethodV2,
    #[serde(rename = "evidenceRefs")]
    pub evidence_refs: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReputationScoreSummaryV2 {
    #[serde(rename = "reportCount")]
    pub report_count: usize,
    #[serde(rename = "averageScore")]
    pub average_score: f64,
    #[serde(rename = "averageQuality")]
    pub average_quality: f64,
    #[serde(rename = "averageLatency")]
    pub average_latency: f64,
    #[serde(rename = "averageCost")]
    pub average_cost: f64,
    #[serde(
        rename = "averageSafety",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub average_safety: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReputationUptimeSummaryV2 {
    #[serde(rename = "observedReports")]
    pub observed_reports: usize,
    #[serde(
        rename = "uptimeClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub uptime_claim: Option<f64>,
    #[serde(
        rename = "lastObservedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_observed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ReputationTrustTierV2 {
    Unrated,
    Open,
    Verified,
    ConfidentialEligible,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReputationProfileV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: ReputationSubjectType,
    #[serde(rename = "scoreSummary")]
    pub score_summary: ReputationScoreSummaryV2,
    #[serde(rename = "uptimeSummary")]
    pub uptime_summary: ReputationUptimeSummaryV2,
    #[serde(rename = "completionRate")]
    pub completion_rate: f64,
    #[serde(rename = "disputeRate")]
    pub dispute_rate: f64,
    #[serde(rename = "validationHistoryRefs")]
    pub validation_history_refs: Vec<String>,
    #[serde(rename = "trustTier")]
    pub trust_tier: ReputationTrustTierV2,
    #[serde(rename = "privacyTierEligibility")]
    pub privacy_tier_eligibility: Vec<PrivacyTier>,
    #[serde(rename = "verificationTierEligibility")]
    pub verification_tier_eligibility: Vec<IntegrityTier>,
    #[serde(rename = "recentWarnings")]
    pub recent_warnings: Vec<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    pub signature: String,
}

pub fn validate_package_compatibility(
    path: &Path,
) -> anyhow::Result<(PackageValidationReport, CompatibilityReportV1)> {
    let validation = validate_package_dir(path)?;
    let status = if validation.valid { "passed" } else { "failed" };
    let report = CompatibilityReportV1 {
        schema_version: "swarm-ai.compatibility-report.v1".to_string(),
        component_name: "package-manifest".to_string(),
        component_version: env!("CARGO_PKG_VERSION").to_string(),
        interface_version: hivemind_core::INTERFACE_VERSION.to_string(),
        tested_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        tests: vec![CompatibilityTestResultV1 {
            name: "validates-package-manifest-v1".to_string(),
            status: status.to_string(),
            duration_ms: 0,
        }],
        result: status.to_string(),
    };
    Ok((validation, report))
}

pub fn public_challenge(
    package_ref: impl Into<String>,
    task: impl Into<String>,
    input: Value,
    validator_id: impl Into<String>,
) -> ChallengeV1 {
    let mut challenge = ChallengeV1 {
        schema_version: "swarm-ai.challenge.v1".to_string(),
        challenge_id: String::new(),
        task: task.into(),
        package_ref: package_ref.into(),
        input,
        scoring_method: ScoringMethod::LatencyAdjusted,
        deadline_ms: 30_000,
        visibility: ChallengeVisibility::Public,
        validator_id: validator_id.into(),
    };
    challenge.challenge_id = stable_id("challenge", &challenge);
    challenge
}

pub fn challenge_execution_request(
    challenge: &ChallengeV1,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    access_grant: Option<AccessGrantV1>,
) -> ExecutionRequestV1 {
    ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: challenge.challenge_id.clone(),
        package_ref: challenge.package_ref.clone(),
        package_id: package_id.into(),
        package_version: package_version.into(),
        preferred_artifact_group: None,
        task: challenge.task.clone(),
        input: challenge.input.clone(),
        options: ExecutionOptions {
            stream: false,
            deadline_ms: Some(challenge.deadline_ms),
            deterministic: Some(true),
        },
        privacy: ExecutionPrivacy::default(),
        access_grant,
        access_revocation_list: None,
    }
}

pub fn score_execution(
    challenge: &ChallengeV1,
    response: &ExecutionResponseV1,
    runner_id: impl Into<String>,
    evidence_refs: Vec<String>,
) -> ValidationReportV1 {
    let receipt = receipt_from_response(response);
    let receipt_id = receipt
        .as_ref()
        .map(|receipt| receipt.receipt_id.clone())
        .unwrap_or_else(|| "missing-receipt".to_string());
    let receipt_valid = receipt.as_ref().map(receipt_id_matches).unwrap_or(false);
    let quality = score_quality(&challenge.task, response);
    let latency = score_latency(challenge.deadline_ms, response.metrics.total_ms);
    let cost_efficiency = score_cost_efficiency(response);
    let policy_compliance = score_policy_compliance(response, receipt_valid);
    let overall = weighted_overall(quality, latency, cost_efficiency, policy_compliance);

    let mut report = ValidationReportV1 {
        schema_version: "swarm-ai.validation-report.v1".to_string(),
        report_id: String::new(),
        validator_id: challenge.validator_id.clone(),
        runner_id: runner_id.into(),
        package_ref: challenge.package_ref.clone(),
        challenge_id: challenge.challenge_id.clone(),
        receipt_id,
        scores: ValidationScoresV1 {
            quality,
            latency,
            cost_efficiency,
            policy_compliance,
            overall,
        },
        evidence_refs,
        validation_elapsed_ms: Some(response.metrics.total_ms),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: String::new(),
    };
    sign_validation_report(&mut report);
    report.report_id =
        canonical_validation_report_id(&report).expect("validation report should serialize for id");
    report
}

pub fn sign_validation_report(report: &mut ValidationReportV1) {
    report.signature = expected_validation_report_signature(report);
}

pub fn sign_validation_report_with_identity(
    report: &mut ValidationReportV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != report.validator_id {
        anyhow::bail!(
            "identity subject {} does not match validation report validator {}",
            identity.subject,
            report.validator_id
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "validation-report",
        &validation_signing_value(report),
    )?;
    report.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    report.report_id = canonical_validation_report_id(report)?;
    Ok(envelope)
}

pub fn expected_validation_report_signature(report: &ValidationReportV1) -> String {
    dev_signature(
        "validation-report",
        &report.validator_id,
        &validation_signing_value(report),
    )
}

pub fn canonical_validation_report_id(report: &ValidationReportV1) -> serde_json::Result<String> {
    let mut signed = report.clone();
    signed.report_id.clear();
    let value = serde_json::to_value(signed)?;
    Ok(stable_id_from_value("validation", &value))
}

pub fn verify_validation_report(report: &ValidationReportV1) -> ValidationReportVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if report.schema_version != "swarm-ai.validation-report.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.validation-report.v1",
        ));
    }
    for (path, value, message) in [
        (
            "$.reportId",
            report.report_id.as_str(),
            "Report id is required",
        ),
        (
            "$.validatorId",
            report.validator_id.as_str(),
            "Validator id is required",
        ),
        (
            "$.runnerId",
            report.runner_id.as_str(),
            "Runner id is required",
        ),
        (
            "$.packageRef",
            report.package_ref.as_str(),
            "Package ref is required",
        ),
        (
            "$.challengeId",
            report.challenge_id.as_str(),
            "Challenge id is required",
        ),
        (
            "$.receiptId",
            report.receipt_id.as_str(),
            "Receipt id is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }
    if !report.package_ref.starts_with("bzz://") {
        warnings.push(issue(
            "$.packageRef",
            "Validation packageRef is not a Swarm bzz:// reference",
        ));
    }
    if report.receipt_id == "missing-receipt" {
        issues.push(issue(
            "$.receiptId",
            "Validation report must reference a signed execution receipt",
        ));
    }
    for (path, score) in [
        ("$.scores.quality", report.scores.quality),
        ("$.scores.latency", report.scores.latency),
        ("$.scores.costEfficiency", report.scores.cost_efficiency),
        ("$.scores.policyCompliance", report.scores.policy_compliance),
        ("$.scores.overall", report.scores.overall),
    ] {
        if !(0.0..=1.0).contains(&score) || !score.is_finite() {
            issues.push(issue(path, "Score must be a finite number between 0 and 1"));
        }
    }
    match canonical_validation_report_id(report) {
        Ok(expected_id) if expected_id != report.report_id => {
            issues.push(issue(
                "$.reportId",
                "Report id does not match canonical validation report hash",
            ));
        }
        Ok(_) => {}
        Err(error) => issues.push(issue(
            "$.reportId",
            format!("Could not compute canonical report id: {error}"),
        )),
    }
    let mut expected_signature = expected_validation_report_signature(report);
    if report
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &report.signature,
            "validation-report",
            &validation_signing_value(report),
            Some(&report.validator_id),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if report.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Validation report signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production validator signing",
        ));
    }
    ValidationReportVerificationV1 {
        schema_version: "swarm-ai.validation-report-verification.v1".to_string(),
        report_id: report.report_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn create_integrity_evidence(options: IntegrityEvidenceInitOptionsV1) -> IntegrityEvidenceV1 {
    let mut evidence_refs = options.evidence_refs;
    evidence_refs.sort();
    evidence_refs.dedup();
    let mut proof_refs = options.proof_refs;
    proof_refs.sort();
    proof_refs.dedup();
    let mut expected_measurement_hashes = options.expected_measurement_hashes;
    expected_measurement_hashes.sort();
    expected_measurement_hashes.dedup();

    let method = options
        .method
        .unwrap_or_else(|| default_integrity_evidence_method(&options.evidence_kind));
    let mut evidence = IntegrityEvidenceV1 {
        schema_version: "hivemind.integrity_evidence.v1".to_string(),
        evidence_id: String::new(),
        evidence_kind: options.evidence_kind,
        validator_id: options.validator_id,
        runner_id: options.runner_id,
        subject_type: options.subject_type,
        subject_id: options.subject_id,
        package_ref: options.package_ref,
        receipt_id: options.receipt_id,
        measurement_hash: options.measurement_hash,
        expected_measurement_hashes,
        evidence_refs,
        proof_refs,
        method,
        verdict: options.verdict,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        metadata: options.metadata,
        signature: String::new(),
    };
    sign_integrity_evidence(&mut evidence);
    evidence.evidence_id =
        canonical_integrity_evidence_id(&evidence).expect("integrity evidence should serialize");
    evidence
}

pub fn sign_integrity_evidence(evidence: &mut IntegrityEvidenceV1) {
    evidence.signature = expected_integrity_evidence_signature(evidence);
    evidence.evidence_id =
        canonical_integrity_evidence_id(evidence).expect("integrity evidence should serialize");
}

pub fn sign_integrity_evidence_with_identity(
    evidence: &mut IntegrityEvidenceV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != evidence.validator_id {
        anyhow::bail!(
            "identity subject {} does not match integrity evidence validator {}",
            identity.subject,
            evidence.validator_id
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "integrity-evidence",
        &integrity_evidence_signing_value(evidence),
    )?;
    evidence.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    evidence.evidence_id = canonical_integrity_evidence_id(evidence)?;
    Ok(envelope)
}

pub fn expected_integrity_evidence_signature(evidence: &IntegrityEvidenceV1) -> String {
    dev_signature(
        "integrity-evidence",
        &evidence.validator_id,
        &integrity_evidence_signing_value(evidence),
    )
}

pub fn canonical_integrity_evidence_id(
    evidence: &IntegrityEvidenceV1,
) -> serde_json::Result<String> {
    let mut signed = evidence.clone();
    signed.evidence_id.clear();
    let value = serde_json::to_value(signed)?;
    Ok(stable_id_from_value("integrity", &value))
}

pub fn verify_integrity_evidence(
    evidence: &IntegrityEvidenceV1,
) -> IntegrityEvidenceVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();

    if evidence.schema_version != "hivemind.integrity_evidence.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.integrity_evidence.v1",
        ));
    }
    for (path, value, message) in [
        (
            "$.evidenceId",
            evidence.evidence_id.as_str(),
            "Evidence id is required",
        ),
        (
            "$.validatorId",
            evidence.validator_id.as_str(),
            "Validator id is required",
        ),
        (
            "$.subjectId",
            evidence.subject_id.as_str(),
            "Subject id is required",
        ),
        (
            "$.createdAt",
            evidence.created_at.as_str(),
            "createdAt is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }
    if DateTime::parse_from_rfc3339(&evidence.created_at).is_err() {
        issues.push(issue(
            "$.createdAt",
            "createdAt must be an RFC3339 timestamp",
        ));
    }

    if evidence.method != default_integrity_evidence_method(&evidence.evidence_kind) {
        warnings.push(issue(
            "$.method",
            "Integrity evidence method does not match the default method for its evidenceKind",
        ));
    }

    match &evidence.evidence_kind {
        IntegrityEvidenceKindV1::TeeAttestation => {
            if evidence
                .runner_id
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                issues.push(issue(
                    "$.runnerId",
                    "TEE attestation evidence must identify the runner",
                ));
            }
            if evidence
                .measurement_hash
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                issues.push(issue(
                    "$.measurementHash",
                    "TEE attestation evidence must include a measured environment hash",
                ));
            }
            if evidence.evidence_refs.is_empty() {
                issues.push(issue(
                    "$.evidenceRefs",
                    "TEE attestation evidence must reference the attestation quote or report",
                ));
            }
            if let Some(measurement) = evidence.measurement_hash.as_deref()
                && !evidence.expected_measurement_hashes.is_empty()
                && !evidence
                    .expected_measurement_hashes
                    .iter()
                    .any(|expected| expected == measurement)
            {
                issues.push(issue(
                    "$.measurementHash",
                    "Measured environment hash is not in expectedMeasurementHashes",
                ));
            }
        }
        IntegrityEvidenceKindV1::ZkProof => {
            if evidence.proof_refs.is_empty() {
                issues.push(issue(
                    "$.proofRefs",
                    "ZK proof evidence must reference at least one proof artifact",
                ));
            }
        }
        IntegrityEvidenceKindV1::FheResult => {
            if evidence.proof_refs.is_empty() && evidence.evidence_refs.is_empty() {
                issues.push(issue(
                    "$.proofRefs",
                    "FHE result evidence must reference proof or encrypted-result evidence",
                ));
            }
        }
        IntegrityEvidenceKindV1::DeterministicReplay
        | IntegrityEvidenceKindV1::RedundantExecution => {
            if evidence.receipt_id.is_none() && evidence.evidence_refs.len() < 2 {
                warnings.push(issue(
                    "$.evidenceRefs",
                    "Replay or redundant-execution evidence should include receipt ids or comparison artifacts",
                ));
            }
        }
    }

    for (index, reference) in evidence.evidence_refs.iter().enumerate() {
        warn_for_mutable_reference(&mut warnings, format!("$.evidenceRefs[{index}]"), reference);
    }
    for (index, reference) in evidence.proof_refs.iter().enumerate() {
        warn_for_mutable_reference(&mut warnings, format!("$.proofRefs[{index}]"), reference);
    }

    if matches!(evidence.verdict, IntegrityEvidenceVerdictV1::Passed)
        && matches!(
            &evidence.evidence_kind,
            IntegrityEvidenceKindV1::TeeAttestation
                | IntegrityEvidenceKindV1::ZkProof
                | IntegrityEvidenceKindV1::FheResult
        )
        && evidence.evidence_refs.is_empty()
        && evidence.proof_refs.is_empty()
    {
        issues.push(issue(
            "$.verdict",
            "Passed cryptographic or attestation evidence must include external evidence refs",
        ));
    }

    match canonical_integrity_evidence_id(evidence) {
        Ok(expected_id) if expected_id != evidence.evidence_id => {
            issues.push(issue(
                "$.evidenceId",
                "Evidence id does not match canonical integrity evidence hash",
            ));
        }
        Ok(_) => {}
        Err(error) => issues.push(issue(
            "$.evidenceId",
            format!("Could not compute canonical evidence id: {error}"),
        )),
    }

    let mut expected_signature = expected_integrity_evidence_signature(evidence);
    if evidence
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &evidence.signature,
            "integrity-evidence",
            &integrity_evidence_signing_value(evidence),
            Some(&evidence.validator_id),
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
            "Integrity evidence signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production validator signing",
        ));
    }

    IntegrityEvidenceVerificationV1 {
        schema_version: "hivemind.integrity_evidence_verification.v1".to_string(),
        evidence_id: evidence.evidence_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn validation_report_v2_from_integrity_evidence(
    evidence: &IntegrityEvidenceV1,
) -> ValidationReportV2 {
    let verification = verify_integrity_evidence(evidence);
    let mut evidence_refs = evidence.evidence_refs.clone();
    evidence_refs.extend(evidence.proof_refs.clone());
    evidence_refs.push(format!("local://integrity/{}", evidence.evidence_id));
    evidence_refs.sort();
    evidence_refs.dedup();

    let mut fraud_signals = Vec::new();
    if !verification.valid {
        fraud_signals.push(FraudSignalV2 {
            code: "integrity-evidence-invalid".to_string(),
            severity: FraudSignalSeverityV2::Critical,
            message: "Integrity evidence failed verification".to_string(),
            evidence_refs: evidence_refs.clone(),
        });
    }
    if matches!(
        evidence.verdict,
        IntegrityEvidenceVerdictV1::Failed | IntegrityEvidenceVerdictV1::Inconclusive
    ) {
        fraud_signals.push(FraudSignalV2 {
            code: "integrity-evidence-not-passing".to_string(),
            severity: FraudSignalSeverityV2::Warning,
            message: "Integrity evidence did not produce a passing verdict".to_string(),
            evidence_refs: evidence_refs.clone(),
        });
    }

    let score = match (verification.valid, &evidence.verdict) {
        (true, IntegrityEvidenceVerdictV1::Passed) => 1.0,
        (true, IntegrityEvidenceVerdictV1::Inconclusive) => 0.5,
        _ => 0.0,
    };
    let mut report = ValidationReportV2 {
        schema_version: "hivemind.validation_report.v2".to_string(),
        report_id: stable_id("validation-v2", evidence),
        validator_id: evidence.validator_id.clone(),
        subject_type: evidence.subject_type.clone(),
        receipt_id: evidence.receipt_id.clone(),
        runner_id: evidence.runner_id.clone(),
        package_ref: evidence.package_ref.clone(),
        benchmark_ref: None,
        challenge_commitment_ref: None,
        score,
        latency_score: None,
        cost_score: None,
        quality_score: Some(score),
        safety_score: Some(score),
        fraud_signals,
        method: evidence.method.clone(),
        evidence_refs,
        created_at: evidence.created_at.clone(),
        signature: String::new(),
    };
    report.signature = expected_validation_report_v2_signature(&report);
    report
}

pub fn write_integrity_evidence(
    evidence_dir: &Path,
    evidence: &IntegrityEvidenceV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(evidence_dir)?;
    let path = evidence_dir.join(format!(
        "{}.json",
        safe_file_component(&evidence.evidence_id)
    ));
    fs::write(&path, serde_json::to_vec_pretty(evidence)?)?;
    Ok(path)
}

pub fn read_integrity_evidence(path: &Path) -> anyhow::Result<IntegrityEvidenceV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse integrity evidence JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn list_integrity_evidence(
    evidence_dir: &Path,
) -> anyhow::Result<IntegrityEvidenceStoreSummaryV1> {
    let mut evidence = Vec::new();
    if evidence_dir.exists() {
        for entry in fs::read_dir(evidence_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                if let Ok(record) = read_integrity_evidence(&path) {
                    evidence.push(integrity_evidence_index_entry(
                        &record,
                        path.display().to_string(),
                    ));
                }
            }
        }
    }
    evidence.sort_by(|left, right| {
        left.subject_id
            .cmp(&right.subject_id)
            .then(left.created_at.cmp(&right.created_at))
            .then(left.evidence_id.cmp(&right.evidence_id))
    });
    let valid_count = evidence
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    let passed_count = evidence
        .iter()
        .filter(|entry| entry.verdict == IntegrityEvidenceVerdictV1::Passed)
        .count();
    let failed_count = evidence
        .iter()
        .filter(|entry| entry.verdict == IntegrityEvidenceVerdictV1::Failed)
        .count();
    let inconclusive_count = evidence
        .iter()
        .filter(|entry| entry.verdict == IntegrityEvidenceVerdictV1::Inconclusive)
        .count();
    Ok(IntegrityEvidenceStoreSummaryV1 {
        schema_version: "hivemind.integrity_evidence_store_summary.v1".to_string(),
        root: evidence_dir.display().to_string(),
        evidence_count: evidence.len(),
        valid_count,
        invalid_count: evidence.len().saturating_sub(valid_count),
        passed_count,
        failed_count,
        inconclusive_count,
        evidence,
    })
}

pub fn get_integrity_evidence(
    evidence_dir: &Path,
    evidence_id: &str,
) -> anyhow::Result<Option<IntegrityEvidenceLookupV1>> {
    let evidence_id = evidence_id.trim();
    if evidence_id.is_empty() {
        return Ok(None);
    }
    let direct_path = evidence_dir.join(format!("{}.json", safe_file_component(evidence_id)));
    if direct_path.exists() {
        let evidence = read_integrity_evidence(&direct_path)?;
        if evidence.evidence_id == evidence_id {
            return Ok(Some(integrity_evidence_lookup(evidence, direct_path)));
        }
    }
    if !evidence_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(evidence_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            && let Ok(evidence) = read_integrity_evidence(&path)
            && evidence.evidence_id == evidence_id
        {
            return Ok(Some(integrity_evidence_lookup(evidence, path)));
        }
    }
    Ok(None)
}

pub fn upload_validation_report(
    storage: &mut impl StorageProvider,
    report: &ValidationReportV1,
) -> anyhow::Result<ValidationReportUploadResultV1> {
    let verification = verify_validation_report(report);
    if !verification.valid {
        anyhow::bail!("validation report is invalid and will not be uploaded");
    }
    let bytes = serde_json::to_vec_pretty(report)?;
    let sha256 = Some(hash_bytes(&bytes));
    let upload = storage
        .upload_bytes(bytes)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let report_ref = upload.reference.clone();
    Ok(ValidationReportUploadResultV1 {
        schema_version: "swarm-ai.validation-report-upload.v1".to_string(),
        report_id: report.report_id.clone(),
        report_ref: report_ref.clone(),
        storage: ValidationReportStorageObjectV1 {
            report_ref,
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

pub fn download_validation_report(
    storage: &impl StorageProvider,
    report_ref: &str,
) -> anyhow::Result<ValidationReportDownloadResultV1> {
    let download = storage
        .download_bytes(report_ref)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let report: ValidationReportV1 = serde_json::from_slice(&download.bytes)?;
    let verification = verify_validation_report(&report);
    Ok(ValidationReportDownloadResultV1 {
        schema_version: "swarm-ai.validation-report-download.v1".to_string(),
        report_ref: report_ref.to_string(),
        storage: ValidationReportStorageObjectV1 {
            report_ref: download.reference,
            content_type: download.content_type,
            size_bytes: download.size_bytes,
            sha256: download.sha256,
            metrics: Some(download.metrics),
        },
        report,
        verification,
        downloaded_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn read_validation_report(path: &Path) -> anyhow::Result<ValidationReportV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse validation report JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_validation_report(
    reports_dir: &Path,
    report: &ValidationReportV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(reports_dir)?;
    let path = reports_dir.join(format!("{}.json", safe_file_component(&report.report_id)));
    fs::write(&path, serde_json::to_vec_pretty(report)?)?;
    Ok(path)
}

pub fn get_validation_report(
    reports_dir: &Path,
    report_id: &str,
) -> anyhow::Result<Option<ValidationReportLookupV1>> {
    let direct_path = reports_dir.join(format!("{}.json", safe_file_component(report_id)));
    if direct_path.exists() {
        let report = read_validation_report(&direct_path)?;
        if report.report_id == report_id {
            return Ok(Some(validation_report_lookup(report, direct_path)));
        }
    }

    if !reports_dir.exists() {
        return Ok(None);
    }

    for entry in fs::read_dir(reports_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let report = read_validation_report(&path)?;
            if report.report_id == report_id {
                return Ok(Some(validation_report_lookup(report, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_validation_reports(
    reports_dir: &Path,
) -> anyhow::Result<ValidationReportStoreSummaryV1> {
    let mut reports = Vec::new();
    if reports_dir.exists() {
        for entry in fs::read_dir(reports_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let report = read_validation_report(&path)?;
                reports.push(validation_report_index_entry(
                    &report,
                    path.display().to_string(),
                ));
            }
        }
    }
    reports.sort_by(|left, right| {
        left.package_ref
            .cmp(&right.package_ref)
            .then(left.created_at.cmp(&right.created_at))
            .then(left.report_id.cmp(&right.report_id))
    });
    let valid_count = reports
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    let validation_elapsed_values: Vec<u64> = reports
        .iter()
        .filter(|entry| entry.verification.valid)
        .filter_map(|entry| entry.validation_elapsed_ms)
        .collect();
    Ok(ValidationReportStoreSummaryV1 {
        schema_version: "swarm-ai.validation-report-store-summary.v1".to_string(),
        root: reports_dir.display().to_string(),
        report_count: reports.len(),
        valid_count,
        invalid_count: reports.len().saturating_sub(valid_count),
        with_validation_elapsed_count: validation_elapsed_values.len(),
        average_validation_elapsed_ms: average_u64(&validation_elapsed_values),
        max_validation_elapsed_ms: validation_elapsed_values.iter().copied().max(),
        reports,
    })
}

pub fn reputation_profile_from_store(
    reports_dir: &Path,
    subject_type: ReputationSubjectType,
    subject_id: impl Into<String>,
) -> anyhow::Result<ReputationProfileV1> {
    let subject_id = subject_id.into();
    let mut reports = Vec::new();
    let mut report_refs = Vec::new();
    if reports_dir.exists() {
        for entry in fs::read_dir(reports_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let report = read_validation_report(&path)?;
                if validation_report_matches_subject(&report, &subject_type, &subject_id)
                    && verify_validation_report(&report).valid
                {
                    reports.push(report);
                    report_refs.push(path.display().to_string());
                }
            }
        }
    }
    reports.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.report_id.cmp(&right.report_id))
    });
    report_refs.sort();
    Ok(reputation_profile(
        subject_type,
        subject_id,
        &reports,
        report_refs,
    ))
}

pub fn reputation_profile(
    subject_type: ReputationSubjectType,
    subject_id: impl Into<String>,
    reports: &[ValidationReportV1],
    report_refs: Vec<String>,
) -> ReputationProfileV1 {
    let average_scores = average_scores(reports);
    ReputationProfileV1 {
        schema_version: "swarm-ai.reputation-profile.v1".to_string(),
        subject_type,
        subject_id: subject_id.into(),
        average_scores,
        report_refs,
        report_count: reports.len(),
        updated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn validation_report_v2_from_v1(report: &ValidationReportV1) -> ValidationReportV2 {
    validation_report_v2_from_v1_with_context(report, ValidationReportV2Context::default())
}

pub fn validation_report_v2_from_v1_with_context(
    report: &ValidationReportV1,
    context: ValidationReportV2Context,
) -> ValidationReportV2 {
    let mut evidence_refs = report.evidence_refs.clone();
    evidence_refs.extend(context.evidence_refs);
    evidence_refs.sort();
    evidence_refs.dedup();

    let mut fraud_signals = context.fraud_signals;
    if report.receipt_id == "missing-receipt" || report.scores.policy_compliance < 1.0 {
        fraud_signals.push(FraudSignalV2 {
            code: "receipt-or-policy-risk".to_string(),
            severity: FraudSignalSeverityV2::Warning,
            message: "Report indicates missing receipt evidence or reduced policy compliance"
                .to_string(),
            evidence_refs: evidence_refs.clone(),
        });
    }
    if report.scores.overall < 0.5 {
        fraud_signals.push(FraudSignalV2 {
            code: "low-validation-score".to_string(),
            severity: FraudSignalSeverityV2::Warning,
            message: "Overall validation score is below the local acceptance threshold".to_string(),
            evidence_refs: evidence_refs.clone(),
        });
    }

    let mut report_v2 = ValidationReportV2 {
        schema_version: "hivemind.validation_report.v2".to_string(),
        report_id: report.report_id.clone(),
        validator_id: report.validator_id.clone(),
        subject_type: context
            .subject_type
            .unwrap_or(ValidationSubjectTypeV2::Runner),
        receipt_id: (!report.receipt_id.trim().is_empty()
            && report.receipt_id != "missing-receipt")
            .then(|| report.receipt_id.clone()),
        runner_id: (!report.runner_id.trim().is_empty()).then(|| report.runner_id.clone()),
        package_ref: (!report.package_ref.trim().is_empty()).then(|| report.package_ref.clone()),
        benchmark_ref: context.benchmark_ref,
        challenge_commitment_ref: context.challenge_commitment_ref.or_else(|| {
            (!report.challenge_id.trim().is_empty())
                .then(|| format!("local://challenge/{}", report.challenge_id))
        }),
        score: report.scores.overall,
        latency_score: Some(report.scores.latency),
        cost_score: Some(report.scores.cost_efficiency),
        quality_score: Some(report.scores.quality),
        safety_score: context.safety_score,
        fraud_signals,
        method: context.method.unwrap_or(ValidationMethodV2::ReceiptCheck),
        evidence_refs,
        created_at: report.created_at.clone(),
        signature: String::new(),
    };
    report_v2.signature = expected_validation_report_v2_signature(&report_v2);
    report_v2
}

pub fn expected_validation_report_v2_signature(report: &ValidationReportV2) -> String {
    dev_signature(
        "validation-report-v2",
        &report.validator_id,
        &validation_report_v2_signing_value(report),
    )
}

pub fn reputation_profile_v2_from_store(
    reports_dir: &Path,
    subject_type: ReputationSubjectType,
    subject_id: impl Into<String>,
) -> anyhow::Result<ReputationProfileV2> {
    let subject_id = subject_id.into();
    let mut reports = Vec::new();
    let mut report_refs = Vec::new();
    if reports_dir.exists() {
        for entry in fs::read_dir(reports_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let report = read_validation_report(&path)?;
                if validation_report_matches_subject(&report, &subject_type, &subject_id)
                    && verify_validation_report(&report).valid
                {
                    reports.push(report);
                    report_refs.push(path.display().to_string());
                }
            }
        }
    }
    reports.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.report_id.cmp(&right.report_id))
    });
    report_refs.sort();
    Ok(reputation_profile_v2(
        subject_type,
        subject_id,
        &reports,
        report_refs,
    ))
}

pub fn reputation_profile_v2(
    subject_type: ReputationSubjectType,
    subject_id: impl Into<String>,
    reports: &[ValidationReportV1],
    report_refs: Vec<String>,
) -> ReputationProfileV2 {
    let subject_id = subject_id.into();
    let average_scores = average_scores(reports);
    let valid_completion_count = reports
        .iter()
        .filter(|report| report.scores.overall >= 0.5)
        .count();
    let report_count = reports.len();
    let completion_rate = ratio(valid_completion_count, report_count);
    let last_observed_at = reports.iter().map(|report| report.created_at.clone()).max();
    let recent_warnings = reports
        .iter()
        .filter(|report| report.scores.overall < 0.5 || report.scores.policy_compliance < 1.0)
        .map(|report| {
            format!(
                "Report {} has score {:.3} and policy compliance {:.3}",
                report.report_id, report.scores.overall, report.scores.policy_compliance
            )
        })
        .collect::<Vec<_>>();
    let trust_tier = reputation_trust_tier(report_count, average_scores.overall);
    let mut profile = ReputationProfileV2 {
        schema_version: "hivemind.reputation_profile.v2".to_string(),
        subject_id,
        subject_type,
        score_summary: ReputationScoreSummaryV2 {
            report_count,
            average_score: average_scores.overall,
            average_quality: average_scores.quality,
            average_latency: average_scores.latency,
            average_cost: average_scores.cost_efficiency,
            average_safety: Some(average_scores.policy_compliance),
        },
        uptime_summary: ReputationUptimeSummaryV2 {
            observed_reports: report_count,
            uptime_claim: None,
            last_observed_at,
        },
        completion_rate,
        dispute_rate: 0.0,
        validation_history_refs: report_refs,
        privacy_tier_eligibility: privacy_tier_eligibility(report_count, average_scores.overall),
        verification_tier_eligibility: verification_tier_eligibility(
            report_count,
            average_scores.overall,
        ),
        trust_tier,
        recent_warnings,
        updated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: String::new(),
    };
    profile.signature = expected_reputation_profile_v2_signature(&profile);
    profile
}

pub fn expected_reputation_profile_v2_signature(profile: &ReputationProfileV2) -> String {
    dev_signature(
        "reputation-profile-v2",
        &profile.subject_id,
        &reputation_profile_v2_signing_value(profile),
    )
}

pub fn receipt_from_response(response: &ExecutionResponseV1) -> Option<ExecutionReceiptV1> {
    serde_json::from_value(response.metadata.get("receipt")?.clone()).ok()
}

pub fn receipt_id_matches(receipt: &ExecutionReceiptV1) -> bool {
    hivemind_receipts::verify_receipt(receipt).valid
}

fn score_quality(task: &str, response: &ExecutionResponseV1) -> f64 {
    if response.status != ExecutionStatus::Succeeded || response.error.is_some() {
        return 0.0;
    }

    match task {
        "embedding" => response
            .output
            .get("embedding")
            .and_then(Value::as_array)
            .map(|values| {
                let finite = values
                    .iter()
                    .filter(|value| value.as_f64().is_some_and(f64::is_finite))
                    .count();
                if finite == values.len() && finite >= 4 {
                    1.0
                } else if finite > 0 {
                    0.5
                } else {
                    0.0
                }
            })
            .unwrap_or(0.0),
        "classification" => {
            let has_label = response
                .output
                .get("label")
                .and_then(Value::as_str)
                .is_some_and(|label| !label.trim().is_empty());
            let score_valid = response
                .output
                .get("score")
                .and_then(Value::as_f64)
                .is_some_and(|score| (0.0..=1.0).contains(&score));
            match (has_label, score_valid) {
                (true, true) => 1.0,
                (true, false) => 0.7,
                _ => 0.0,
            }
        }
        "chat" => response
            .output
            .pointer("/message/content")
            .and_then(Value::as_str)
            .is_some_and(|content| !content.trim().is_empty())
            .then_some(1.0)
            .unwrap_or(0.0),
        _ if response.output != json!({}) => 0.75,
        _ => 0.0,
    }
}

fn score_latency(deadline_ms: u64, total_ms: u64) -> f64 {
    if total_ms == 0 || total_ms <= deadline_ms {
        1.0
    } else if deadline_ms == 0 {
        0.0
    } else {
        (deadline_ms as f64 / total_ms as f64).clamp(0.0, 1.0)
    }
}

fn score_cost_efficiency(response: &ExecutionResponseV1) -> f64 {
    if response.status == ExecutionStatus::Succeeded {
        1.0
    } else {
        0.25
    }
}

fn score_policy_compliance(response: &ExecutionResponseV1, receipt_valid: bool) -> f64 {
    if response.error.is_some() {
        return 0.0;
    }
    if receipt_valid { 1.0 } else { 0.5 }
}

fn weighted_overall(
    quality: f64,
    latency: f64,
    cost_efficiency: f64,
    policy_compliance: f64,
) -> f64 {
    (quality * 0.50 + latency * 0.20 + cost_efficiency * 0.10 + policy_compliance * 0.20)
        .clamp(0.0, 1.0)
}

fn average_scores(reports: &[ValidationReportV1]) -> ValidationScoresV1 {
    if reports.is_empty() {
        return ValidationScoresV1::default();
    }
    let count = reports.len() as f64;
    let sum = reports
        .iter()
        .fold(ValidationScoresV1::default(), |mut sum, report| {
            sum.quality += report.scores.quality;
            sum.latency += report.scores.latency;
            sum.cost_efficiency += report.scores.cost_efficiency;
            sum.policy_compliance += report.scores.policy_compliance;
            sum.overall += report.scores.overall;
            sum
        });
    ValidationScoresV1 {
        quality: sum.quality / count,
        latency: sum.latency / count,
        cost_efficiency: sum.cost_efficiency / count,
        policy_compliance: sum.policy_compliance / count,
        overall: sum.overall / count,
    }
}

fn average_u64(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64)
    }
}

fn validation_report_index_entry(
    report: &ValidationReportV1,
    report_path: String,
) -> ValidationReportIndexEntryV1 {
    let verification = verify_validation_report(report);
    ValidationReportIndexEntryV1 {
        report_id: report.report_id.clone(),
        validator_id: report.validator_id.clone(),
        runner_id: report.runner_id.clone(),
        package_ref: report.package_ref.clone(),
        challenge_id: report.challenge_id.clone(),
        receipt_id: report.receipt_id.clone(),
        overall_score: report.scores.overall,
        validation_elapsed_ms: report.validation_elapsed_ms,
        created_at: report.created_at.clone(),
        report_path,
        verification,
    }
}

fn validation_report_lookup(report: ValidationReportV1, path: PathBuf) -> ValidationReportLookupV1 {
    let verification = verify_validation_report(&report);
    ValidationReportLookupV1 {
        schema_version: "swarm-ai.validation-report-lookup.v1".to_string(),
        report_id: report.report_id.clone(),
        report_path: path.display().to_string(),
        report,
        verification,
    }
}

fn integrity_evidence_index_entry(
    evidence: &IntegrityEvidenceV1,
    evidence_path: String,
) -> IntegrityEvidenceIndexEntryV1 {
    let verification = verify_integrity_evidence(evidence);
    IntegrityEvidenceIndexEntryV1 {
        evidence_id: evidence.evidence_id.clone(),
        evidence_kind: evidence.evidence_kind.clone(),
        validator_id: evidence.validator_id.clone(),
        runner_id: evidence.runner_id.clone(),
        subject_type: evidence.subject_type.clone(),
        subject_id: evidence.subject_id.clone(),
        method: evidence.method.clone(),
        verdict: evidence.verdict.clone(),
        created_at: evidence.created_at.clone(),
        evidence_path,
        verification,
    }
}

fn integrity_evidence_lookup(
    evidence: IntegrityEvidenceV1,
    path: PathBuf,
) -> IntegrityEvidenceLookupV1 {
    let verification = verify_integrity_evidence(&evidence);
    IntegrityEvidenceLookupV1 {
        schema_version: "hivemind.integrity_evidence_lookup.v1".to_string(),
        evidence_id: evidence.evidence_id.clone(),
        evidence_path: path.display().to_string(),
        evidence,
        verification,
    }
}

fn validation_report_matches_subject(
    report: &ValidationReportV1,
    subject_type: &ReputationSubjectType,
    subject_id: &str,
) -> bool {
    match subject_type {
        ReputationSubjectType::Runner => report.runner_id == subject_id,
        ReputationSubjectType::Package => report.package_ref == subject_id,
        ReputationSubjectType::Validator => report.validator_id == subject_id,
        ReputationSubjectType::Publisher => false,
    }
}

fn default_integrity_evidence_method(kind: &IntegrityEvidenceKindV1) -> ValidationMethodV2 {
    match kind {
        IntegrityEvidenceKindV1::TeeAttestation => ValidationMethodV2::TeeAttestationCheck,
        IntegrityEvidenceKindV1::ZkProof => ValidationMethodV2::ZkProofCheck,
        IntegrityEvidenceKindV1::FheResult => ValidationMethodV2::FheResultCheck,
        IntegrityEvidenceKindV1::DeterministicReplay => ValidationMethodV2::DeterministicReplay,
        IntegrityEvidenceKindV1::RedundantExecution => {
            ValidationMethodV2::RedundantExecutionCompare
        }
    }
}

fn warn_for_mutable_reference(
    warnings: &mut Vec<ValidationIssue>,
    path: impl Into<String>,
    reference: &str,
) {
    let reference = reference.trim();
    if reference.is_empty() {
        warnings.push(issue(path, "Evidence reference is empty"));
    } else if !(reference.starts_with("bzz://")
        || reference.starts_with("local://")
        || reference.starts_with("receipt://")
        || reference.starts_with("validation://")
        || reference.starts_with("ipfs://")
        || reference.starts_with("sha256:"))
    {
        warnings.push(issue(
            path,
            "Evidence reference is not an immutable or local audit reference",
        ));
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

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("validator object should serialize");
    stable_id_from_value(prefix, &value)
}

fn stable_id_from_value(prefix: &str, value: &Value) -> String {
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(value))[..24]
    )
}

fn validation_signing_value(report: &ValidationReportV1) -> Value {
    let mut value = json!({
        "schemaVersion": report.schema_version,
        "validatorId": report.validator_id,
        "runnerId": report.runner_id,
        "packageRef": report.package_ref,
        "challengeId": report.challenge_id,
        "receiptId": report.receipt_id,
        "scores": report.scores,
        "evidenceRefs": report.evidence_refs,
        "createdAt": report.created_at,
    });
    if let Some(validation_elapsed_ms) = report.validation_elapsed_ms
        && let Some(object) = value.as_object_mut()
    {
        object.insert(
            "validationElapsedMs".to_string(),
            json!(validation_elapsed_ms),
        );
    }
    value
}

fn validation_report_v2_signing_value(report: &ValidationReportV2) -> Value {
    json!({
        "schemaVersion": report.schema_version,
        "reportId": report.report_id,
        "validatorId": report.validator_id,
        "subjectType": report.subject_type,
        "receiptId": report.receipt_id,
        "runnerId": report.runner_id,
        "packageRef": report.package_ref,
        "benchmarkRef": report.benchmark_ref,
        "challengeCommitmentRef": report.challenge_commitment_ref,
        "score": report.score,
        "latencyScore": report.latency_score,
        "costScore": report.cost_score,
        "qualityScore": report.quality_score,
        "safetyScore": report.safety_score,
        "fraudSignals": report.fraud_signals,
        "method": report.method,
        "evidenceRefs": report.evidence_refs,
        "createdAt": report.created_at,
    })
}

fn integrity_evidence_signing_value(evidence: &IntegrityEvidenceV1) -> Value {
    json!({
        "schemaVersion": evidence.schema_version,
        "evidenceKind": evidence.evidence_kind,
        "validatorId": evidence.validator_id,
        "runnerId": evidence.runner_id,
        "subjectType": evidence.subject_type,
        "subjectId": evidence.subject_id,
        "packageRef": evidence.package_ref,
        "receiptId": evidence.receipt_id,
        "measurementHash": evidence.measurement_hash,
        "expectedMeasurementHashes": evidence.expected_measurement_hashes,
        "evidenceRefs": evidence.evidence_refs,
        "proofRefs": evidence.proof_refs,
        "method": evidence.method,
        "verdict": evidence.verdict,
        "createdAt": evidence.created_at,
        "metadata": evidence.metadata,
    })
}

fn reputation_profile_v2_signing_value(profile: &ReputationProfileV2) -> Value {
    json!({
        "schemaVersion": profile.schema_version,
        "subjectId": profile.subject_id,
        "subjectType": profile.subject_type,
        "scoreSummary": profile.score_summary,
        "uptimeSummary": profile.uptime_summary,
        "completionRate": profile.completion_rate,
        "disputeRate": profile.dispute_rate,
        "validationHistoryRefs": profile.validation_history_refs,
        "trustTier": profile.trust_tier,
        "privacyTierEligibility": profile.privacy_tier_eligibility,
        "verificationTierEligibility": profile.verification_tier_eligibility,
        "recentWarnings": profile.recent_warnings,
        "updatedAt": profile.updated_at,
    })
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn reputation_trust_tier(report_count: usize, average_score: f64) -> ReputationTrustTierV2 {
    if report_count == 0 {
        ReputationTrustTierV2::Unrated
    } else if report_count >= 5 && average_score >= 0.95 {
        ReputationTrustTierV2::ConfidentialEligible
    } else if report_count >= 3 && average_score >= 0.85 {
        ReputationTrustTierV2::Verified
    } else if average_score >= 0.5 {
        ReputationTrustTierV2::Open
    } else {
        ReputationTrustTierV2::Unrated
    }
}

fn privacy_tier_eligibility(report_count: usize, average_score: f64) -> Vec<PrivacyTier> {
    let mut tiers = vec![PrivacyTier::Standard];
    if report_count > 0 && average_score >= 0.7 {
        tiers.push(PrivacyTier::NoLog);
        tiers.push(PrivacyTier::RedactedInput);
    }
    if report_count >= 5 && average_score >= 0.95 {
        tiers.push(PrivacyTier::TeeConfidential);
    }
    tiers
}

fn verification_tier_eligibility(report_count: usize, average_score: f64) -> Vec<IntegrityTier> {
    let mut tiers = vec![IntegrityTier::ReceiptOnly];
    if report_count > 0 {
        tiers.push(IntegrityTier::ValidatorSpotCheck);
    }
    if report_count >= 3 && average_score >= 0.85 {
        tiers.push(IntegrityTier::RedundantExecution);
    }
    if report_count >= 5 && average_score >= 0.95 {
        tiers.push(IntegrityTier::DeterministicReplay);
    }
    tiers
}

fn dev_signature(label: &str, validator_id: &str, payload: &Value) -> String {
    let value = json!({
        "label": label,
        "validatorId": validator_id,
        "payload": payload,
    });
    format!(
        "{DEV_VALIDATION_SIGNATURE_PREFIX}:{label}:{}",
        hash_canonical_json(&canonicalize_json(&value))
    )
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

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn hash_bytes(bytes: &[u8]) -> String {
    hex_lower(Sha256::digest(bytes))
}

fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn empty_metadata() -> Value {
    json!({})
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ExecutionMetrics, ExecutionResponseV1, ExecutionStatus, ReceiptDraft, create_signed_receipt,
    };
    use hivemind_storage::MemoryStorageProvider;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn scores_successful_embedding_response() {
        let challenge = public_challenge(
            "bzz://pkg",
            "embedding",
            json!({ "text": "hello validator" }),
            "validator-1",
        );
        let request = challenge_execution_request(&challenge, "hivemind/test", "0.1.0", None);
        let mut response = ExecutionResponseV1 {
            schema_version: "swarm-ai.execution.response.v1".to_string(),
            request_id: request.request_id.clone(),
            status: ExecutionStatus::Succeeded,
            output: json!({ "embedding": [0.1, 0.2, 0.3, 0.4] }),
            metrics: ExecutionMetrics {
                total_ms: 10,
                ..Default::default()
            },
            receipt_ref: None,
            error: None,
            metadata: json!({}),
        };
        let manifest = serde_json::from_value(json!({
            "schemaVersion": "swarm-ai.package.v1",
            "packageId": "hivemind/test",
            "kind": "model",
            "name": "Test",
            "version": "0.1.0",
            "publisher": {"address": "0x0", "displayName": "Test"},
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
        }))
        .unwrap();
        let receipt = create_signed_receipt(ReceiptDraft {
            request: &request,
            response: &response,
            manifest: &manifest,
            artifact_group: "local",
            manifest_hash: &"0".repeat(64),
            runner_id: "runner-1",
            route_id: None,
            policy: None,
            started_at: "2026-05-22T00:00:00Z",
            finished_at: "2026-05-22T00:00:01Z",
        });
        response.metadata["receipt"] = serde_json::to_value(receipt).unwrap();

        let report = score_execution(&challenge, &response, "runner-1", Vec::new());

        assert!(report.scores.overall > 0.95);
        assert!(report.report_id.starts_with("validation-"));
        assert!(verify_validation_report(&report).valid);
    }

    #[test]
    fn identity_signed_validation_report_verifies() {
        let challenge = public_challenge("bzz://pkg", "embedding", json!({}), "validator-1");
        let mut report = ValidationReportV1 {
            schema_version: "swarm-ai.validation-report.v1".to_string(),
            report_id: String::new(),
            validator_id: "validator-1".to_string(),
            runner_id: "runner-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            challenge_id: challenge.challenge_id,
            receipt_id: "receipt-1".to_string(),
            scores: ValidationScoresV1 {
                quality: 0.8,
                latency: 0.9,
                cost_efficiency: 1.0,
                policy_compliance: 1.0,
                overall: 0.87,
            },
            evidence_refs: Vec::new(),
            validation_elapsed_ms: None,
            created_at: "2026-05-22T00:00:00Z".to_string(),
            signature: String::new(),
        };
        sign_validation_report(&mut report);
        report.report_id = canonical_validation_report_id(&report).unwrap();
        let identity =
            hivemind_identity::identity_from_seed("validator-1", b"validator-seed").unwrap();

        let envelope = sign_validation_report_with_identity(&mut report, &identity).unwrap();
        let verification = verify_validation_report(&report);

        assert_eq!(envelope.signer, report.validator_id);
        assert!(
            report
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
    fn identity_signed_receipt_counts_as_valid_evidence() {
        let challenge = public_challenge(
            "bzz://pkg",
            "embedding",
            json!({ "text": "hello validator" }),
            "validator-1",
        );
        let request = challenge_execution_request(&challenge, "hivemind/test", "0.1.0", None);
        let mut response = ExecutionResponseV1 {
            schema_version: "swarm-ai.execution.response.v1".to_string(),
            request_id: request.request_id.clone(),
            status: ExecutionStatus::Succeeded,
            output: json!({ "embedding": [0.1, 0.2, 0.3, 0.4] }),
            metrics: ExecutionMetrics {
                total_ms: 10,
                ..Default::default()
            },
            receipt_ref: None,
            error: None,
            metadata: json!({}),
        };
        let manifest = serde_json::from_value(json!({
            "schemaVersion": "swarm-ai.package.v1",
            "packageId": "hivemind/test",
            "kind": "model",
            "name": "Test",
            "version": "0.1.0",
            "publisher": {"address": "0x0", "displayName": "Test"},
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
        }))
        .unwrap();
        let mut receipt = create_signed_receipt(ReceiptDraft {
            request: &request,
            response: &response,
            manifest: &manifest,
            artifact_group: "local",
            manifest_hash: &"0".repeat(64),
            runner_id: "runner-1",
            route_id: None,
            policy: None,
            started_at: "2026-05-22T00:00:00Z",
            finished_at: "2026-05-22T00:00:01Z",
        });
        let identity = hivemind_identity::identity_from_seed("runner-1", b"runner-seed").unwrap();
        hivemind_receipts::sign_receipt_with_identity(&mut receipt, &identity).unwrap();
        response.metadata["receipt"] = serde_json::to_value(receipt).unwrap();

        let report = score_execution(&challenge, &response, "runner-1", Vec::new());

        assert_eq!(report.scores.policy_compliance, 1.0);
        assert!(verify_validation_report(&report).valid);
    }

    #[test]
    fn validation_method_registry_exposes_task_specific_v03_methods() {
        let registry = validation_method_registry();

        assert_eq!(
            registry.schema_version,
            "hivemind.validation-method-registry.v1"
        );
        assert!(
            registry
                .methods
                .iter()
                .any(|method| method.method_id == "schema_check"
                    && method.strength == ValidationMethodStrengthV1::Strong)
        );
        let benchmark_score = registry
            .methods
            .iter()
            .find(|method| method.method_id == "benchmark_score")
            .unwrap();
        assert!(benchmark_score.benchmark_pack_required);
        assert!(benchmark_score.hidden_challenge_compatible);

        let llm_judge = registry
            .methods
            .iter()
            .find(|method| method.method_id == "llm_judge_with_disclosure")
            .unwrap();
        assert!(llm_judge.subjective);
        assert_eq!(llm_judge.strength, ValidationMethodStrengthV1::Subjective);

        assert!(
            registry
                .methods
                .iter()
                .any(|method| method.method_id == "policy_compliance_check")
        );
    }

    #[test]
    fn reputation_profile_averages_reports() {
        let challenge = public_challenge("bzz://pkg", "embedding", json!({}), "validator-1");
        let mut report = ValidationReportV1 {
            schema_version: "swarm-ai.validation-report.v1".to_string(),
            report_id: String::new(),
            validator_id: "validator-1".to_string(),
            runner_id: "runner-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            challenge_id: challenge.challenge_id,
            receipt_id: "receipt-1".to_string(),
            scores: ValidationScoresV1 {
                quality: 0.5,
                latency: 1.0,
                cost_efficiency: 1.0,
                policy_compliance: 1.0,
                overall: 0.75,
            },
            evidence_refs: Vec::new(),
            validation_elapsed_ms: None,
            created_at: "2026-05-22T00:00:00Z".to_string(),
            signature: String::new(),
        };
        sign_validation_report(&mut report);
        report.report_id = canonical_validation_report_id(&report).unwrap();
        let mut second = report.clone();
        second.scores.overall = 1.0;
        sign_validation_report(&mut second);
        second.report_id = canonical_validation_report_id(&second).unwrap();

        let profile = reputation_profile(
            ReputationSubjectType::Package,
            "bzz://pkg",
            &[report, second],
            vec!["bzz://report-1".to_string(), "bzz://report-2".to_string()],
        );

        assert_eq!(profile.report_count, 2);
        assert_eq!(profile.average_scores.overall, 0.875);
    }

    #[test]
    fn validation_report_v2_projection_preserves_v1_identity_and_scores() {
        let challenge = public_challenge("bzz://pkg", "embedding", json!({}), "validator-1");
        let mut report = ValidationReportV1 {
            schema_version: "swarm-ai.validation-report.v1".to_string(),
            report_id: String::new(),
            validator_id: "validator-1".to_string(),
            runner_id: "runner-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            challenge_id: challenge.challenge_id,
            receipt_id: "receipt-1".to_string(),
            scores: ValidationScoresV1 {
                quality: 0.8,
                latency: 0.9,
                cost_efficiency: 1.0,
                policy_compliance: 1.0,
                overall: 0.87,
            },
            evidence_refs: vec!["bzz://evidence".to_string()],
            validation_elapsed_ms: Some(12),
            created_at: "2026-05-22T00:00:00Z".to_string(),
            signature: String::new(),
        };
        sign_validation_report(&mut report);
        report.report_id = canonical_validation_report_id(&report).unwrap();

        let report_v2 = validation_report_v2_from_v1(&report);

        assert_eq!(report_v2.schema_version, "hivemind.validation_report.v2");
        assert_eq!(report_v2.report_id, report.report_id);
        assert_eq!(report_v2.subject_type, ValidationSubjectTypeV2::Runner);
        assert_eq!(report_v2.receipt_id.as_deref(), Some("receipt-1"));
        assert_eq!(report_v2.runner_id.as_deref(), Some("runner-1"));
        assert_eq!(report_v2.package_ref.as_deref(), Some("bzz://pkg"));
        assert_eq!(report_v2.score, report.scores.overall);
        assert_eq!(report_v2.quality_score, Some(report.scores.quality));
        assert_eq!(report_v2.method, ValidationMethodV2::ReceiptCheck);
        assert_eq!(report_v2.fraud_signals, Vec::new());
        assert_eq!(
            report_v2.signature,
            expected_validation_report_v2_signature(&report_v2)
        );
    }

    #[test]
    fn reputation_profile_v2_derives_tiers_from_valid_reports() {
        let challenge = public_challenge("bzz://pkg", "embedding", json!({}), "validator-1");
        let mut reports = Vec::new();
        for index in 0..5 {
            let mut report = ValidationReportV1 {
                schema_version: "swarm-ai.validation-report.v1".to_string(),
                report_id: String::new(),
                validator_id: "validator-1".to_string(),
                runner_id: "runner-1".to_string(),
                package_ref: "bzz://pkg".to_string(),
                challenge_id: format!("{}-{index}", challenge.challenge_id),
                receipt_id: format!("receipt-{index}"),
                scores: ValidationScoresV1 {
                    quality: 0.96,
                    latency: 0.97,
                    cost_efficiency: 0.98,
                    policy_compliance: 1.0,
                    overall: 0.97,
                },
                evidence_refs: Vec::new(),
                validation_elapsed_ms: None,
                created_at: format!("2026-05-22T00:00:0{index}Z"),
                signature: String::new(),
            };
            sign_validation_report(&mut report);
            report.report_id = canonical_validation_report_id(&report).unwrap();
            reports.push(report);
        }

        let profile = reputation_profile_v2(
            ReputationSubjectType::Runner,
            "runner-1",
            &reports,
            reports
                .iter()
                .map(|report| format!("local://validation/{}", report.report_id))
                .collect(),
        );

        assert_eq!(profile.schema_version, "hivemind.reputation_profile.v2");
        assert_eq!(profile.score_summary.report_count, 5);
        assert_eq!(
            profile.trust_tier,
            ReputationTrustTierV2::ConfidentialEligible
        );
        assert!(
            profile
                .privacy_tier_eligibility
                .contains(&PrivacyTier::TeeConfidential)
        );
        assert!(
            profile
                .verification_tier_eligibility
                .contains(&IntegrityTier::DeterministicReplay)
        );
        assert_eq!(profile.completion_rate, 1.0);
        assert_eq!(
            profile.signature,
            expected_reputation_profile_v2_signature(&profile)
        );
    }

    #[test]
    fn integrity_evidence_verifies_and_projects_to_validation_v2() {
        let evidence = create_integrity_evidence(IntegrityEvidenceInitOptionsV1 {
            evidence_kind: IntegrityEvidenceKindV1::TeeAttestation,
            validator_id: "validator-tee".to_string(),
            runner_id: Some("confidential-runner-1".to_string()),
            subject_type: ValidationSubjectTypeV2::Runner,
            subject_id: "confidential-runner-1".to_string(),
            package_ref: Some("bzz://package".to_string()),
            receipt_id: Some("receipt-tee-1".to_string()),
            measurement_hash: Some("sha256:measured-environment".to_string()),
            expected_measurement_hashes: vec!["sha256:measured-environment".to_string()],
            evidence_refs: vec!["bzz://attestation-quote".to_string()],
            proof_refs: Vec::new(),
            method: None,
            verdict: IntegrityEvidenceVerdictV1::Passed,
            metadata: json!({"attester": "local-dev-tee"}),
        });

        let verification = verify_integrity_evidence(&evidence);
        let report_v2 = validation_report_v2_from_integrity_evidence(&evidence);

        assert!(verification.valid, "{verification:#?}");
        assert!(evidence.evidence_id.starts_with("integrity-"));
        assert_eq!(evidence.method, ValidationMethodV2::TeeAttestationCheck);
        assert_eq!(report_v2.method, ValidationMethodV2::TeeAttestationCheck);
        assert_eq!(report_v2.score, 1.0);
        assert_eq!(
            report_v2.runner_id.as_deref(),
            Some("confidential-runner-1")
        );
        assert!(
            report_v2
                .evidence_refs
                .contains(&format!("local://integrity/{}", evidence.evidence_id))
        );
    }

    #[test]
    fn integrity_evidence_detects_measurement_mismatch_and_tampering() {
        let mut evidence = create_integrity_evidence(IntegrityEvidenceInitOptionsV1 {
            evidence_kind: IntegrityEvidenceKindV1::TeeAttestation,
            validator_id: "validator-tee".to_string(),
            runner_id: Some("confidential-runner-1".to_string()),
            subject_type: ValidationSubjectTypeV2::Runner,
            subject_id: "confidential-runner-1".to_string(),
            package_ref: None,
            receipt_id: None,
            measurement_hash: Some("sha256:unexpected".to_string()),
            expected_measurement_hashes: vec!["sha256:expected".to_string()],
            evidence_refs: vec!["bzz://attestation-quote".to_string()],
            proof_refs: Vec::new(),
            method: None,
            verdict: IntegrityEvidenceVerdictV1::Passed,
            metadata: json!({}),
        });

        let mismatch = verify_integrity_evidence(&evidence);
        assert!(!mismatch.valid);
        assert!(
            mismatch
                .issues
                .iter()
                .any(|issue| issue.path == "$.measurementHash")
        );

        evidence.expected_measurement_hashes = vec!["sha256:unexpected".to_string()];
        sign_integrity_evidence(&mut evidence);
        assert!(verify_integrity_evidence(&evidence).valid);

        evidence.verdict = IntegrityEvidenceVerdictV1::Failed;
        let tampered = verify_integrity_evidence(&evidence);
        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path == "$.evidenceId" || issue.path == "$.signature")
        );
    }

    #[test]
    fn identity_signed_integrity_evidence_verifies() {
        let mut evidence = create_integrity_evidence(IntegrityEvidenceInitOptionsV1 {
            evidence_kind: IntegrityEvidenceKindV1::ZkProof,
            validator_id: "validator-zk".to_string(),
            runner_id: None,
            subject_type: ValidationSubjectTypeV2::Receipt,
            subject_id: "receipt-zk-1".to_string(),
            package_ref: None,
            receipt_id: Some("receipt-zk-1".to_string()),
            measurement_hash: None,
            expected_measurement_hashes: Vec::new(),
            evidence_refs: Vec::new(),
            proof_refs: vec!["bzz://zk-proof".to_string()],
            method: None,
            verdict: IntegrityEvidenceVerdictV1::Passed,
            metadata: json!({}),
        });
        let identity =
            hivemind_identity::identity_from_seed("validator-zk", b"validator-zk-seed").unwrap();

        let envelope = sign_integrity_evidence_with_identity(&mut evidence, &identity).unwrap();
        let verification = verify_integrity_evidence(&evidence);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(envelope.signer, "validator-zk");
        assert!(
            verification
                .expected_signature
                .starts_with("ed25519-payload-hash:")
        );
    }

    #[test]
    fn integrity_evidence_store_lists_and_gets_records() {
        let root = unique_temp_dir("hivemind-integrity-evidence-store-test");
        let evidence = create_integrity_evidence(IntegrityEvidenceInitOptionsV1 {
            evidence_kind: IntegrityEvidenceKindV1::FheResult,
            validator_id: "validator-fhe".to_string(),
            runner_id: Some("runner-fhe".to_string()),
            subject_type: ValidationSubjectTypeV2::Receipt,
            subject_id: "receipt-fhe-1".to_string(),
            package_ref: None,
            receipt_id: Some("receipt-fhe-1".to_string()),
            measurement_hash: None,
            expected_measurement_hashes: Vec::new(),
            evidence_refs: vec!["bzz://encrypted-result".to_string()],
            proof_refs: Vec::new(),
            method: None,
            verdict: IntegrityEvidenceVerdictV1::Inconclusive,
            metadata: json!({}),
        });

        let evidence_path = write_integrity_evidence(&root, &evidence).unwrap();
        let summary = list_integrity_evidence(&root).unwrap();
        let lookup = get_integrity_evidence(&root, &evidence.evidence_id)
            .unwrap()
            .unwrap();

        assert!(evidence_path.exists());
        assert_eq!(summary.evidence_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.inconclusive_count, 1);
        assert_eq!(lookup.evidence.evidence_id, evidence.evidence_id);
        assert!(lookup.verification.valid);
        assert!(get_integrity_evidence(&root, "missing").unwrap().is_none());
    }

    #[test]
    fn validation_report_store_lists_gets_and_builds_reputation() {
        let root = unique_temp_dir("hivemind-validation-report-store-test");
        let challenge = public_challenge("bzz://pkg", "embedding", json!({}), "validator-1");
        let mut report = ValidationReportV1 {
            schema_version: "swarm-ai.validation-report.v1".to_string(),
            report_id: String::new(),
            validator_id: "validator-1".to_string(),
            runner_id: "runner-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            challenge_id: challenge.challenge_id,
            receipt_id: "receipt-1".to_string(),
            scores: ValidationScoresV1 {
                quality: 0.8,
                latency: 0.9,
                cost_efficiency: 1.0,
                policy_compliance: 1.0,
                overall: 0.87,
            },
            evidence_refs: Vec::new(),
            validation_elapsed_ms: Some(17),
            created_at: "2026-05-22T00:00:00Z".to_string(),
            signature: String::new(),
        };
        sign_validation_report(&mut report);
        report.report_id = canonical_validation_report_id(&report).unwrap();

        let report_path = write_validation_report(&root, &report).unwrap();
        let summary = list_validation_reports(&root).unwrap();
        let lookup = get_validation_report(&root, &report.report_id)
            .unwrap()
            .unwrap();
        let missing = get_validation_report(&root, "missing-report").unwrap();
        let runner_profile =
            reputation_profile_from_store(&root, ReputationSubjectType::Runner, "runner-1")
                .unwrap();

        assert_eq!(summary.report_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.with_validation_elapsed_count, 1);
        assert_eq!(summary.average_validation_elapsed_ms, Some(17.0));
        assert_eq!(summary.max_validation_elapsed_ms, Some(17));
        assert_eq!(summary.reports[0].report_id, report.report_id);
        assert_eq!(summary.reports[0].validation_elapsed_ms, Some(17));
        assert_eq!(
            summary.reports[0].report_path,
            report_path.display().to_string()
        );
        assert_eq!(lookup.report.report_id, report.report_id);
        assert!(lookup.verification.valid);
        assert!(missing.is_none());
        assert_eq!(runner_profile.report_count, 1);
        assert_eq!(runner_profile.average_scores.overall, 0.87);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn uploads_and_downloads_verified_validation_report() {
        let challenge = public_challenge("bzz://pkg", "embedding", json!({}), "validator-1");
        let mut report = ValidationReportV1 {
            schema_version: "swarm-ai.validation-report.v1".to_string(),
            report_id: String::new(),
            validator_id: "validator-1".to_string(),
            runner_id: "runner-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            challenge_id: challenge.challenge_id,
            receipt_id: "receipt-1".to_string(),
            scores: ValidationScoresV1 {
                quality: 0.8,
                latency: 0.9,
                cost_efficiency: 1.0,
                policy_compliance: 1.0,
                overall: 0.87,
            },
            evidence_refs: Vec::new(),
            validation_elapsed_ms: None,
            created_at: "2026-05-22T00:00:00Z".to_string(),
            signature: String::new(),
        };
        sign_validation_report(&mut report);
        report.report_id = canonical_validation_report_id(&report).unwrap();
        let mut storage = MemoryStorageProvider::default();

        let upload = upload_validation_report(&mut storage, &report).unwrap();
        let download = download_validation_report(&storage, &upload.report_ref).unwrap();

        assert!(upload.verification.valid);
        assert_eq!(download.report.report_id, report.report_id);
        assert!(download.verification.valid);
        assert_eq!(upload.storage.sha256, download.storage.sha256);
    }

    #[test]
    fn rejects_tampered_validation_report() {
        let challenge = public_challenge("bzz://pkg", "embedding", json!({}), "validator-1");
        let mut report = ValidationReportV1 {
            schema_version: "swarm-ai.validation-report.v1".to_string(),
            report_id: String::new(),
            validator_id: "validator-1".to_string(),
            runner_id: "runner-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            challenge_id: challenge.challenge_id,
            receipt_id: "receipt-1".to_string(),
            scores: ValidationScoresV1 {
                quality: 0.5,
                latency: 1.0,
                cost_efficiency: 1.0,
                policy_compliance: 1.0,
                overall: 0.75,
            },
            evidence_refs: Vec::new(),
            validation_elapsed_ms: None,
            created_at: "2026-05-22T00:00:00Z".to_string(),
            signature: String::new(),
        };
        sign_validation_report(&mut report);
        report.report_id = canonical_validation_report_id(&report).unwrap();
        report.scores.overall = 0.1;

        let verification = verify_validation_report(&report);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signature")
        );
    }

    #[test]
    fn rejects_tampered_identity_signed_validation_report() {
        let challenge = public_challenge("bzz://pkg", "embedding", json!({}), "validator-1");
        let mut report = ValidationReportV1 {
            schema_version: "swarm-ai.validation-report.v1".to_string(),
            report_id: String::new(),
            validator_id: "validator-1".to_string(),
            runner_id: "runner-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            challenge_id: challenge.challenge_id,
            receipt_id: "receipt-1".to_string(),
            scores: ValidationScoresV1 {
                quality: 0.5,
                latency: 1.0,
                cost_efficiency: 1.0,
                policy_compliance: 1.0,
                overall: 0.75,
            },
            evidence_refs: Vec::new(),
            validation_elapsed_ms: None,
            created_at: "2026-05-22T00:00:00Z".to_string(),
            signature: String::new(),
        };
        let identity =
            hivemind_identity::identity_from_seed("validator-1", b"validator-seed").unwrap();
        sign_validation_report_with_identity(&mut report, &identity).unwrap();
        report.scores.overall = 0.1;

        let verification = verify_validation_report(&report);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.reportId" || issue.path == "$.signature.payloadHash")
        );
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }
}
