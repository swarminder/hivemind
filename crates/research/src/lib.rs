use anyhow::Context;
use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    ApiSurface, IntegrityTier, Modality, PriceV1, PrivacyTier, RunnerType, ValidationIssue,
    canonicalize_json, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

const DEV_RESEARCH_EXPERIMENT_SIGNATURE_PREFIX: &str = "dev-research-experiment-signature-v1";
const DEV_RESEARCH_RUN_SIGNATURE_PREFIX: &str = "dev-research-run-signature-v1";
const DEV_EVALUATION_RUN_V2_SIGNATURE_PREFIX: &str = "dev-evaluation-run-v2-signature-v1";
const DEV_RESEARCH_RESULT_RECORD_SIGNATURE_PREFIX: &str = "dev-research-result-record-signature-v1";
const DEV_REPRODUCIBILITY_BUNDLE_SIGNATURE_PREFIX: &str = "dev-reproducibility-bundle-signature-v1";

pub const EVALUATION_RUN_V2_SCHEMA_VERSION: &str = "hivemind.evaluation_run.v2";
pub const EVALUATION_RUN_V2_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.evaluation_run_verification.v2";
pub const RESEARCH_RESULT_RECORD_SCHEMA_VERSION: &str = "hivemind.research_result_record.v1";
pub const RESEARCH_RESULT_RECORD_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.research_result_record_verification.v1";
pub const REPRODUCIBILITY_BUNDLE_SCHEMA_VERSION: &str = "hivemind.reproducibility_bundle.v1";
pub const REPRODUCIBILITY_BUNDLE_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.reproducibility_bundle_verification.v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchRunnerRequirementsV1 {
    #[serde(rename = "allowedRunnerTypes", default)]
    pub allowed_runner_types: Vec<RunnerType>,
    #[serde(rename = "requiredApis", default)]
    pub required_apis: Vec<ApiSurface>,
    #[serde(rename = "requiredModalities", default)]
    pub required_modalities: Vec<Modality>,
    #[serde(rename = "requiredEngines", default)]
    pub required_engines: Vec<String>,
    #[serde(
        rename = "minMemoryMB",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub min_memory_mb: Option<u64>,
    #[serde(rename = "minVramGB", default, skip_serializing_if = "Option::is_none")]
    pub min_vram_gb: Option<f64>,
    #[serde(rename = "gpuRequired", default)]
    pub gpu_required: bool,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "verificationTier")]
    pub verification_tier: IntegrityTier,
}

impl Default for ResearchRunnerRequirementsV1 {
    fn default() -> Self {
        Self {
            allowed_runner_types: vec![RunnerType::Local],
            required_apis: vec![ApiSurface::HivemindNative],
            required_modalities: vec![Modality::Text],
            required_engines: Vec::new(),
            min_memory_mb: None,
            min_vram_gb: None,
            gpu_required: false,
            privacy_tier: PrivacyTier::LocalOnly,
            verification_tier: IntegrityTier::ReceiptOnly,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchReproductionStepV1 {
    pub order: u32,
    pub title: String,
    pub command: String,
    #[serde(rename = "expectedEvidenceRefs", default)]
    pub expected_evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchCostEstimateV1 {
    #[serde(rename = "maxCost", default, skip_serializing_if = "Option::is_none")]
    pub max_cost: Option<PriceV1>,
    #[serde(rename = "estimatedRuns")]
    pub estimated_runs: u32,
    #[serde(rename = "notes", default)]
    pub notes: Vec<String>,
}

impl Default for ResearchCostEstimateV1 {
    fn default() -> Self {
        Self {
            max_cost: None,
            estimated_runs: 1,
            notes: vec!["Local development estimate; update before marketplace runs".to_string()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchExperimentV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "experimentId")]
    pub experiment_id: String,
    pub title: String,
    pub author: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    pub hypothesis: String,
    #[serde(rename = "modelRefs")]
    pub model_refs: Vec<String>,
    #[serde(rename = "datasetRefs")]
    pub dataset_refs: Vec<String>,
    #[serde(rename = "benchmarkRefs")]
    pub benchmark_refs: Vec<String>,
    #[serde(rename = "promptRefs")]
    pub prompt_refs: Vec<String>,
    #[serde(rename = "toolRefs")]
    pub tool_refs: Vec<String>,
    #[serde(rename = "codeRefs")]
    pub code_refs: Vec<String>,
    #[serde(rename = "environmentRefs")]
    pub environment_refs: Vec<String>,
    #[serde(rename = "packageRefs")]
    pub package_refs: Vec<String>,
    #[serde(rename = "runnerRequirements")]
    pub runner_requirements: ResearchRunnerRequirementsV1,
    #[serde(default)]
    pub hyperparameters: Value,
    #[serde(rename = "randomSeeds")]
    pub random_seeds: Vec<u64>,
    #[serde(
        rename = "expectedOutputs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_outputs: Option<Value>,
    #[serde(rename = "scoringMethodRef")]
    pub scoring_method_ref: String,
    #[serde(rename = "reproductionSteps")]
    pub reproduction_steps: Vec<ResearchReproductionStepV1>,
    #[serde(rename = "ethicalNotes", default)]
    pub ethical_notes: Vec<String>,
    #[serde(rename = "privacyNotes", default)]
    pub privacy_notes: Vec<String>,
    #[serde(rename = "costEstimate")]
    pub cost_estimate: ResearchCostEstimateV1,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchExperimentInitOptionsV1 {
    pub title: String,
    pub author: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    pub hypothesis: String,
    #[serde(rename = "packageRefs", default)]
    pub package_refs: Vec<String>,
    #[serde(rename = "modelRefs", default)]
    pub model_refs: Vec<String>,
    #[serde(rename = "datasetRefs", default)]
    pub dataset_refs: Vec<String>,
    #[serde(rename = "benchmarkRefs", default)]
    pub benchmark_refs: Vec<String>,
    #[serde(rename = "scoringMethodRef", default)]
    pub scoring_method_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchExperimentVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "experimentId")]
    pub experiment_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
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
pub struct ResearchReproductionPlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "experimentId")]
    pub experiment_id: String,
    #[serde(rename = "runner")]
    pub runner: String,
    #[serde(rename = "immutableRefs")]
    pub immutable_refs: Vec<String>,
    #[serde(rename = "mutableRefs")]
    pub mutable_refs: Vec<String>,
    pub steps: Vec<ResearchReproductionStepV1>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ResearchRunStatusV1 {
    Planned,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchExperimentRunV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "experimentId")]
    pub experiment_id: String,
    pub requester: String,
    pub runner: String,
    pub status: ResearchRunStatusV1,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "verificationTier")]
    pub verification_tier: IntegrityTier,
    #[serde(rename = "immutableRefs", default)]
    pub immutable_refs: Vec<String>,
    #[serde(rename = "mutableRefs", default)]
    pub mutable_refs: Vec<String>,
    #[serde(rename = "receiptRefs", default)]
    pub receipt_refs: Vec<String>,
    #[serde(rename = "evaluationResultRefs", default)]
    pub evaluation_result_refs: Vec<String>,
    #[serde(rename = "validationReportRefs", default)]
    pub validation_report_refs: Vec<String>,
    #[serde(rename = "outputRefs", default)]
    pub output_refs: Vec<String>,
    #[serde(rename = "cost", default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<PriceV1>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchExperimentRunInitOptionsV1 {
    pub requester: String,
    pub runner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<ResearchRunStatusV1>,
    #[serde(rename = "receiptRefs", default)]
    pub receipt_refs: Vec<String>,
    #[serde(rename = "evaluationResultRefs", default)]
    pub evaluation_result_refs: Vec<String>,
    #[serde(rename = "validationReportRefs", default)]
    pub validation_report_refs: Vec<String>,
    #[serde(rename = "outputRefs", default)]
    pub output_refs: Vec<String>,
    #[serde(rename = "cost", default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<PriceV1>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchExperimentRunVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "experimentId")]
    pub experiment_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
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
pub struct ResearchExperimentIndexEntryV1 {
    #[serde(rename = "experimentId")]
    pub experiment_id: String,
    pub title: String,
    pub author: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "verificationTier")]
    pub verification_tier: IntegrityTier,
    #[serde(rename = "packageRefCount")]
    pub package_ref_count: usize,
    #[serde(rename = "modelRefCount")]
    pub model_ref_count: usize,
    #[serde(rename = "datasetRefCount")]
    pub dataset_ref_count: usize,
    #[serde(rename = "benchmarkRefCount")]
    pub benchmark_ref_count: usize,
    #[serde(rename = "reproductionStepCount")]
    pub reproduction_step_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub valid: bool,
    #[serde(rename = "signaturePresent")]
    pub signature_present: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "experimentPath")]
    pub experiment_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchExperimentStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "experimentCount")]
    pub experiment_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub experiments: Vec<ResearchExperimentIndexEntryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchExperimentLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "experimentId")]
    pub experiment_id: String,
    #[serde(rename = "experimentPath")]
    pub experiment_path: String,
    pub experiment: ResearchExperimentV1,
    pub verification: ResearchExperimentVerificationV1,
    #[serde(rename = "reproductionPlan")]
    pub reproduction_plan: ResearchReproductionPlanV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchExperimentRunIndexEntryV1 {
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "experimentId")]
    pub experiment_id: String,
    pub requester: String,
    pub runner: String,
    pub status: ResearchRunStatusV1,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "verificationTier")]
    pub verification_tier: IntegrityTier,
    #[serde(rename = "receiptRefCount")]
    pub receipt_ref_count: usize,
    #[serde(rename = "evaluationResultRefCount")]
    pub evaluation_result_ref_count: usize,
    #[serde(rename = "validationReportRefCount")]
    pub validation_report_ref_count: usize,
    #[serde(rename = "outputRefCount")]
    pub output_ref_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub valid: bool,
    #[serde(rename = "signaturePresent")]
    pub signature_present: bool,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    #[serde(rename = "runPath")]
    pub run_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchExperimentRunStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "runCount")]
    pub run_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "terminalCount")]
    pub terminal_count: usize,
    #[serde(rename = "receiptLinkedCount")]
    pub receipt_linked_count: usize,
    #[serde(rename = "evaluationLinkedCount")]
    pub evaluation_linked_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub runs: Vec<ResearchExperimentRunIndexEntryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchExperimentRunLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "runPath")]
    pub run_path: String,
    pub run: ResearchExperimentRunV1,
    pub verification: ResearchExperimentRunVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchArtifactRefV1 {
    #[serde(
        rename = "artifactId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub artifact_id: Option<String>,
    pub role: String,
    pub reference: String,
    #[serde(
        rename = "contentHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_hash: Option<String>,
    #[serde(
        rename = "licenseRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub license_ref: Option<String>,
    #[serde(
        rename = "privacyTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub privacy_tier: Option<PrivacyTier>,
    #[serde(rename = "accessPolicyRefs", default)]
    pub access_policy_refs: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationRunV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evaluationRunId")]
    pub evaluation_run_id: String,
    #[serde(
        rename = "experimentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub experiment_id: Option<String>,
    #[serde(rename = "evalId", default, skip_serializing_if = "Option::is_none")]
    pub eval_id: Option<String>,
    #[serde(
        rename = "benchmarkId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub benchmark_id: Option<String>,
    pub requester: String,
    pub runner: String,
    #[serde(rename = "targetRef")]
    pub target_ref: String,
    pub status: ResearchRunStatusV1,
    #[serde(rename = "sampleCount")]
    pub sample_count: u32,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "inputRefs", default)]
    pub input_refs: Vec<String>,
    #[serde(rename = "datasetRefs", default)]
    pub dataset_refs: Vec<String>,
    #[serde(rename = "scoringMethodRefs", default)]
    pub scoring_method_refs: Vec<String>,
    #[serde(rename = "receiptRefs", default)]
    pub receipt_refs: Vec<String>,
    #[serde(rename = "evaluationResultRefs", default)]
    pub evaluation_result_refs: Vec<String>,
    #[serde(rename = "resultRecordRefs", default)]
    pub result_record_refs: Vec<String>,
    #[serde(rename = "validationReportRefs", default)]
    pub validation_report_refs: Vec<String>,
    #[serde(rename = "outputRefs", default)]
    pub output_refs: Vec<String>,
    #[serde(rename = "artifactRefs", default)]
    pub artifact_refs: Vec<ResearchArtifactRefV1>,
    #[serde(rename = "randomSeeds", default)]
    pub random_seeds: Vec<String>,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationRunV2InitOptionsV1 {
    #[serde(
        rename = "experimentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub experiment_id: Option<String>,
    #[serde(rename = "evalId", default, skip_serializing_if = "Option::is_none")]
    pub eval_id: Option<String>,
    #[serde(
        rename = "benchmarkId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub benchmark_id: Option<String>,
    pub requester: String,
    pub runner: String,
    #[serde(rename = "targetRef")]
    pub target_ref: String,
    #[serde(default)]
    pub status: Option<ResearchRunStatusV1>,
    #[serde(rename = "sampleCount", default)]
    pub sample_count: Option<u32>,
    #[serde(rename = "privacyTier", default)]
    pub privacy_tier: Option<PrivacyTier>,
    #[serde(rename = "integrityTier", default)]
    pub integrity_tier: Option<IntegrityTier>,
    #[serde(rename = "inputRefs", default)]
    pub input_refs: Vec<String>,
    #[serde(rename = "datasetRefs", default)]
    pub dataset_refs: Vec<String>,
    #[serde(rename = "scoringMethodRefs", default)]
    pub scoring_method_refs: Vec<String>,
    #[serde(rename = "receiptRefs", default)]
    pub receipt_refs: Vec<String>,
    #[serde(rename = "evaluationResultRefs", default)]
    pub evaluation_result_refs: Vec<String>,
    #[serde(rename = "resultRecordRefs", default)]
    pub result_record_refs: Vec<String>,
    #[serde(rename = "validationReportRefs", default)]
    pub validation_report_refs: Vec<String>,
    #[serde(rename = "outputRefs", default)]
    pub output_refs: Vec<String>,
    #[serde(rename = "artifactRefs", default)]
    pub artifact_refs: Vec<ResearchArtifactRefV1>,
    #[serde(rename = "randomSeeds", default)]
    pub random_seeds: Vec<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationRunV2VerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evaluationRunId")]
    pub evaluation_run_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
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
pub enum ResearchResultKindV1 {
    Positive,
    Negative,
    Inconclusive,
    Regression,
    Benchmark,
    Safety,
    Reproduction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchResultRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "resultId")]
    pub result_id: String,
    #[serde(rename = "resultKind")]
    pub result_kind: ResearchResultKindV1,
    pub title: String,
    pub producer: String,
    #[serde(
        rename = "experimentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub experiment_id: Option<String>,
    #[serde(rename = "runId", default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(
        rename = "evaluationRunId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub evaluation_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothesis: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub metrics: Value,
    #[serde(rename = "resultRefs", default)]
    pub result_refs: Vec<String>,
    #[serde(rename = "receiptRefs", default)]
    pub receipt_refs: Vec<String>,
    #[serde(rename = "evaluationResultRefs", default)]
    pub evaluation_result_refs: Vec<String>,
    #[serde(rename = "validationReportRefs", default)]
    pub validation_report_refs: Vec<String>,
    #[serde(rename = "artifactRefs", default)]
    pub artifact_refs: Vec<ResearchArtifactRefV1>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchResultRecordInitOptionsV1 {
    #[serde(rename = "resultKind")]
    pub result_kind: ResearchResultKindV1,
    pub title: String,
    pub producer: String,
    #[serde(
        rename = "experimentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub experiment_id: Option<String>,
    #[serde(rename = "runId", default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(
        rename = "evaluationRunId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub evaluation_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hypothesis: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub metrics: Option<Value>,
    #[serde(rename = "resultRefs", default)]
    pub result_refs: Vec<String>,
    #[serde(rename = "receiptRefs", default)]
    pub receipt_refs: Vec<String>,
    #[serde(rename = "evaluationResultRefs", default)]
    pub evaluation_result_refs: Vec<String>,
    #[serde(rename = "validationReportRefs", default)]
    pub validation_report_refs: Vec<String>,
    #[serde(rename = "artifactRefs", default)]
    pub artifact_refs: Vec<ResearchArtifactRefV1>,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ResearchResultRecordVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "resultId")]
    pub result_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
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
pub struct ReproducibilityBundleV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "bundleId")]
    pub bundle_id: String,
    pub title: String,
    pub producer: String,
    #[serde(rename = "experimentId")]
    pub experiment_id: String,
    #[serde(
        rename = "experimentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub experiment_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experiment: Option<Box<ResearchExperimentV1>>,
    #[serde(rename = "runRefs", default)]
    pub run_refs: Vec<String>,
    #[serde(default)]
    pub runs: Vec<ResearchExperimentRunV1>,
    #[serde(rename = "evaluationRunRefs", default)]
    pub evaluation_run_refs: Vec<String>,
    #[serde(rename = "evaluationRuns", default)]
    pub evaluation_runs: Vec<EvaluationRunV2>,
    #[serde(rename = "resultRecordRefs", default)]
    pub result_record_refs: Vec<String>,
    #[serde(rename = "resultRecords", default)]
    pub result_records: Vec<ResearchResultRecordV1>,
    #[serde(rename = "receiptRefs", default)]
    pub receipt_refs: Vec<String>,
    #[serde(rename = "validationReportRefs", default)]
    pub validation_report_refs: Vec<String>,
    #[serde(rename = "evaluationResultRefs", default)]
    pub evaluation_result_refs: Vec<String>,
    #[serde(rename = "outputRefs", default)]
    pub output_refs: Vec<String>,
    #[serde(rename = "artifactRefs", default)]
    pub artifact_refs: Vec<ResearchArtifactRefV1>,
    #[serde(rename = "immutableRefs", default)]
    pub immutable_refs: Vec<String>,
    #[serde(rename = "mutableRefs", default)]
    pub mutable_refs: Vec<String>,
    #[serde(rename = "randomSeeds", default)]
    pub random_seeds: Vec<String>,
    #[serde(rename = "reproductionSteps", default)]
    pub reproduction_steps: Vec<ResearchReproductionStepV1>,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "claimsExactReproduction")]
    pub claims_exact_reproduction: bool,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReproducibilityBundleInitOptionsV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub producer: String,
    pub experiment: ResearchExperimentV1,
    #[serde(
        rename = "experimentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub experiment_ref: Option<String>,
    #[serde(rename = "runRefs", default)]
    pub run_refs: Vec<String>,
    #[serde(default)]
    pub runs: Vec<ResearchExperimentRunV1>,
    #[serde(rename = "evaluationRunRefs", default)]
    pub evaluation_run_refs: Vec<String>,
    #[serde(rename = "evaluationRuns", default)]
    pub evaluation_runs: Vec<EvaluationRunV2>,
    #[serde(rename = "resultRecordRefs", default)]
    pub result_record_refs: Vec<String>,
    #[serde(rename = "resultRecords", default)]
    pub result_records: Vec<ResearchResultRecordV1>,
    #[serde(rename = "receiptRefs", default)]
    pub receipt_refs: Vec<String>,
    #[serde(rename = "validationReportRefs", default)]
    pub validation_report_refs: Vec<String>,
    #[serde(rename = "evaluationResultRefs", default)]
    pub evaluation_result_refs: Vec<String>,
    #[serde(rename = "outputRefs", default)]
    pub output_refs: Vec<String>,
    #[serde(rename = "artifactRefs", default)]
    pub artifact_refs: Vec<ResearchArtifactRefV1>,
    #[serde(rename = "immutableRefs", default)]
    pub immutable_refs: Vec<String>,
    #[serde(rename = "mutableRefs", default)]
    pub mutable_refs: Vec<String>,
    #[serde(rename = "randomSeeds", default)]
    pub random_seeds: Vec<String>,
    #[serde(rename = "reproductionSteps", default)]
    pub reproduction_steps: Vec<ResearchReproductionStepV1>,
    #[serde(rename = "claimsExactReproduction", default)]
    pub claims_exact_reproduction: Option<bool>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReproducibilityBundleVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "bundleId")]
    pub bundle_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

pub fn create_research_experiment(
    options: ResearchExperimentInitOptionsV1,
) -> ResearchExperimentV1 {
    let mut package_refs = options.package_refs;
    package_refs.sort();
    package_refs.dedup();
    let mut model_refs = options.model_refs;
    model_refs.sort();
    model_refs.dedup();
    let mut dataset_refs = options.dataset_refs;
    dataset_refs.sort();
    dataset_refs.dedup();
    let mut benchmark_refs = options.benchmark_refs;
    benchmark_refs.sort();
    benchmark_refs.dedup();

    let mut experiment = ResearchExperimentV1 {
        schema_version: "swarm-ai.research-experiment.v1".to_string(),
        experiment_id: String::new(),
        title: options.title,
        author: options.author,
        organization: options.organization,
        hypothesis: options.hypothesis,
        model_refs,
        dataset_refs,
        benchmark_refs,
        prompt_refs: Vec::new(),
        tool_refs: Vec::new(),
        code_refs: Vec::new(),
        environment_refs: Vec::new(),
        package_refs,
        runner_requirements: ResearchRunnerRequirementsV1::default(),
        hyperparameters: json!({}),
        random_seeds: vec![0],
        expected_outputs: None,
        scoring_method_ref: options
            .scoring_method_ref
            .unwrap_or_else(|| "local://scoring/manual-review".to_string()),
        reproduction_steps: default_reproduction_steps(),
        ethical_notes: vec![
            "Review dataset licenses and disclosure limits before publishing".to_string(),
        ],
        privacy_notes: vec![
            "Default local-only reproduction avoids exposing private prompts or datasets to miners"
                .to_string(),
        ],
        cost_estimate: ResearchCostEstimateV1::default(),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_research_experiment(&mut experiment);
    experiment
}

pub fn sign_research_experiment(experiment: &mut ResearchExperimentV1) {
    experiment.signature = Some(expected_research_experiment_signature(experiment));
    experiment.experiment_id = canonical_research_experiment_id(experiment);
}

pub fn sign_research_experiment_with_identity(
    experiment: &mut ResearchExperimentV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != experiment.author {
        anyhow::bail!(
            "identity subject {} does not match research experiment author {}",
            identity.subject,
            experiment.author
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "research-experiment",
        &research_experiment_signing_value(experiment),
    )?;
    experiment.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    experiment.experiment_id = canonical_research_experiment_id(experiment);
    Ok(envelope)
}

pub fn expected_research_experiment_signature(experiment: &ResearchExperimentV1) -> String {
    format!(
        "{DEV_RESEARCH_EXPERIMENT_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&research_experiment_signing_value(
            experiment
        )))
    )
}

pub fn canonical_research_experiment_id(experiment: &ResearchExperimentV1) -> String {
    stable_id("experiment", &research_experiment_signing_value(experiment))
}

pub fn verify_research_experiment(
    experiment: &ResearchExperimentV1,
) -> ResearchExperimentVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_research_experiment_signature(experiment));
    let signature = experiment
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if experiment.schema_version != "swarm-ai.research-experiment.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.research-experiment.v1",
        ));
    }
    require_non_empty(&mut issues, "$.experimentId", &experiment.experiment_id);
    if !experiment.experiment_id.is_empty()
        && experiment.experiment_id != canonical_research_experiment_id(experiment)
    {
        issues.push(issue(
            "$.experimentId",
            "Experiment id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.title", &experiment.title);
    require_non_empty(&mut issues, "$.author", &experiment.author);
    require_non_empty(&mut issues, "$.hypothesis", &experiment.hypothesis);
    require_non_empty(
        &mut issues,
        "$.scoringMethodRef",
        &experiment.scoring_method_ref,
    );
    if experiment.package_refs.is_empty()
        && experiment.model_refs.is_empty()
        && experiment.dataset_refs.is_empty()
        && experiment.benchmark_refs.is_empty()
    {
        issues.push(issue(
            "$.packageRefs",
            "Experiment must reference at least one package, model, dataset, or benchmark",
        ));
    }
    if experiment.reproduction_steps.is_empty() {
        issues.push(issue(
            "$.reproductionSteps",
            "Experiment must include reproduction steps",
        ));
    }
    if experiment.random_seeds.is_empty() {
        warnings.push(issue(
            "$.randomSeeds",
            "Experiment has no random seed; reproducibility may be weaker",
        ));
    }
    if experiment.ethical_notes.is_empty() {
        warnings.push(issue("$.ethicalNotes", "Experiment has no ethical notes"));
    }
    if experiment.privacy_notes.is_empty() {
        warnings.push(issue("$.privacyNotes", "Experiment has no privacy notes"));
    }
    for (path, reference) in experiment_refs(experiment) {
        if reference.trim().is_empty() {
            issues.push(issue(path, "Reference must not be empty"));
        } else if !looks_like_research_ref(&reference) {
            warnings.push(issue(
                path,
                "Reference is not a recognized bzz://, local://, ipfs://, sha256://, or https:// reference",
            ));
        } else if looks_mutable_ref(&reference) {
            warnings.push(issue(
                path,
                "Mutable reference should be resolved to immutable content before exact reproduction",
            ));
        }
    }
    match chrono::DateTime::parse_from_rfc3339(&experiment.created_at) {
        Ok(_) => {}
        Err(_) => issues.push(issue(
            "$.createdAt",
            "createdAt must be an RFC3339 timestamp",
        )),
    }

    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "research-experiment",
                &research_experiment_signing_value(experiment),
                Some(&experiment.author),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(issue(
                "$.signature",
                "Research experiment signature does not match canonical dev signature or Ed25519 author identity envelope",
            ));
        }
    } else {
        warnings.push(issue(
            "$.signature",
            "Research experiment is unsigned; verify author and experimentId through a trusted source",
        ));
    }

    ResearchExperimentVerificationV1 {
        schema_version: "swarm-ai.research-experiment-verification.v1".to_string(),
        experiment_id: experiment.experiment_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn reproduction_plan(
    experiment: &ResearchExperimentV1,
    runner: impl Into<String>,
) -> ResearchReproductionPlanV1 {
    let mut immutable_refs = Vec::new();
    let mut mutable_refs = Vec::new();
    let mut warnings = Vec::new();
    for (path, reference) in experiment_refs(experiment) {
        if looks_mutable_ref(&reference) {
            mutable_refs.push(reference.clone());
            warnings.push(issue(
                path,
                "Resolve mutable reference before claiming exact reproduction",
            ));
        } else {
            immutable_refs.push(reference.clone());
        }
    }
    immutable_refs.sort();
    immutable_refs.dedup();
    mutable_refs.sort();
    mutable_refs.dedup();

    ResearchReproductionPlanV1 {
        schema_version: "swarm-ai.research-reproduction-plan.v1".to_string(),
        experiment_id: experiment.experiment_id.clone(),
        runner: runner.into(),
        immutable_refs,
        mutable_refs,
        steps: experiment.reproduction_steps.clone(),
        warnings,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn create_research_experiment_run(
    experiment: &ResearchExperimentV1,
    options: ResearchExperimentRunInitOptionsV1,
) -> ResearchExperimentRunV1 {
    let runner = options.runner;
    let plan = reproduction_plan(experiment, runner.clone());
    let mut receipt_refs = options.receipt_refs;
    dedup_strings(&mut receipt_refs);
    let mut evaluation_result_refs = options.evaluation_result_refs;
    dedup_strings(&mut evaluation_result_refs);
    let mut validation_report_refs = options.validation_report_refs;
    dedup_strings(&mut validation_report_refs);
    let mut output_refs = options.output_refs;
    dedup_strings(&mut output_refs);
    let status = options.status.unwrap_or_else(|| {
        if receipt_refs.is_empty() && evaluation_result_refs.is_empty() && output_refs.is_empty() {
            ResearchRunStatusV1::Planned
        } else {
            ResearchRunStatusV1::Succeeded
        }
    });
    let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let completed_at = research_run_is_terminal(&status)
        .then(|| Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));

    let mut run = ResearchExperimentRunV1 {
        schema_version: "swarm-ai.research-experiment-run.v1".to_string(),
        run_id: String::new(),
        experiment_id: experiment.experiment_id.clone(),
        requester: options.requester,
        runner,
        status,
        privacy_tier: experiment.runner_requirements.privacy_tier.clone(),
        verification_tier: experiment.runner_requirements.verification_tier.clone(),
        immutable_refs: plan.immutable_refs,
        mutable_refs: plan.mutable_refs,
        receipt_refs,
        evaluation_result_refs,
        validation_report_refs,
        output_refs,
        cost: options.cost,
        notes: options.notes,
        metadata: options.metadata.unwrap_or_else(|| {
            json!({
                "source": "research-experiment-run",
                "experimentTitle": experiment.title,
                "hypothesis": experiment.hypothesis
            })
        }),
        started_at,
        completed_at,
        signature: None,
    };
    sign_research_experiment_run(&mut run);
    run
}

pub fn sign_research_experiment_run(run: &mut ResearchExperimentRunV1) {
    run.signature = Some(expected_research_experiment_run_signature(run));
    run.run_id = canonical_research_experiment_run_id(run);
}

pub fn sign_research_experiment_run_with_identity(
    run: &mut ResearchExperimentRunV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != run.requester {
        anyhow::bail!(
            "identity subject {} does not match research run requester {}",
            identity.subject,
            run.requester
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "research-experiment-run",
        &research_run_signing_value(run),
    )?;
    run.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    run.run_id = canonical_research_experiment_run_id(run);
    Ok(envelope)
}

pub fn expected_research_experiment_run_signature(run: &ResearchExperimentRunV1) -> String {
    format!(
        "{DEV_RESEARCH_RUN_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&research_run_signing_value(run)))
    )
}

pub fn canonical_research_experiment_run_id(run: &ResearchExperimentRunV1) -> String {
    stable_id("experiment-run", &research_run_signing_value(run))
}

pub fn verify_research_experiment_run(
    run: &ResearchExperimentRunV1,
    experiment: Option<&ResearchExperimentV1>,
) -> ResearchExperimentRunVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_research_experiment_run_signature(run));
    let signature = run
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if run.schema_version != "swarm-ai.research-experiment-run.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.research-experiment-run.v1",
        ));
    }
    require_non_empty(&mut issues, "$.runId", &run.run_id);
    if !run.run_id.is_empty() && run.run_id != canonical_research_experiment_run_id(run) {
        issues.push(issue(
            "$.runId",
            "Research run id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.experimentId", &run.experiment_id);
    require_non_empty(&mut issues, "$.requester", &run.requester);
    require_non_empty(&mut issues, "$.runner", &run.runner);
    validate_timestamp(&run.started_at, "$.startedAt", &mut issues);
    if let Some(completed_at) = &run.completed_at {
        validate_timestamp(completed_at, "$.completedAt", &mut issues);
        if completed_at < &run.started_at {
            issues.push(issue(
                "$.completedAt",
                "completedAt must not be earlier than startedAt",
            ));
        }
    }
    if research_run_is_terminal(&run.status) && run.completed_at.is_none() {
        issues.push(issue(
            "$.completedAt",
            "Terminal research runs must include completedAt",
        ));
    }
    if matches!(run.status, ResearchRunStatusV1::Succeeded) && !research_run_has_evidence(run) {
        issues.push(issue(
            "$.receiptRefs",
            "Succeeded research runs must link at least one receipt, evaluation result, validation report, or output reference",
        ));
    }
    if !matches!(run.status, ResearchRunStatusV1::Succeeded) && research_run_has_evidence(run) {
        warnings.push(issue(
            "$.status",
            "Non-succeeded research run carries evidence refs; confirm status before publishing",
        ));
    }
    if !run.mutable_refs.is_empty() {
        warnings.push(issue(
            "$.mutableRefs",
            "Research run still references mutable context; exact reproduction should resolve these to immutable refs",
        ));
    }
    for (path, reference) in research_run_refs(run) {
        if reference.trim().is_empty() {
            issues.push(issue(path, "Reference must not be empty"));
        } else if !looks_like_research_ref(&reference) {
            warnings.push(issue(
                path,
                "Reference is not a recognized bzz://, local://, ipfs://, sha256://, https://, receipt://, evaluation://, or validation:// reference",
            ));
        } else if looks_mutable_ref(&reference) {
            warnings.push(issue(
                path,
                "Mutable reference should be resolved before claiming exact reproduction",
            ));
        }
    }
    if let Some(experiment) = experiment {
        let experiment_verification = verify_research_experiment(experiment);
        if !experiment_verification.valid {
            issues.push(issue(
                "$.experiment",
                "Linked research experiment is not valid",
            ));
        }
        if run.experiment_id != experiment.experiment_id {
            issues.push(issue(
                "$.experimentId",
                "Research run experimentId must match the linked experiment",
            ));
        }
        let plan = reproduction_plan(experiment, run.runner.clone());
        for reference in &plan.immutable_refs {
            if !run.immutable_refs.contains(reference) {
                warnings.push(issue(
                    "$.immutableRefs",
                    format!("Research run is missing immutable experiment ref {reference}"),
                ));
            }
        }
    }

    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                "research-experiment-run",
                &research_run_signing_value(run),
                Some(&run.requester),
            );
            expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(issue(
                "$.signature",
                "Research run signature does not match canonical dev signature or Ed25519 requester identity envelope",
            ));
        }
    } else {
        warnings.push(issue(
            "$.signature",
            "Research run is unsigned; verify requester and runId through a trusted source",
        ));
    }

    ResearchExperimentRunVerificationV1 {
        schema_version: "swarm-ai.research-experiment-run-verification.v1".to_string(),
        run_id: run.run_id.clone(),
        experiment_id: run.experiment_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn create_evaluation_run_v2(options: EvaluationRunV2InitOptionsV1) -> EvaluationRunV2 {
    let mut input_refs = options.input_refs;
    dedup_strings(&mut input_refs);
    let mut dataset_refs = options.dataset_refs;
    dedup_strings(&mut dataset_refs);
    let mut scoring_method_refs = options.scoring_method_refs;
    dedup_strings(&mut scoring_method_refs);
    let mut receipt_refs = options.receipt_refs;
    dedup_strings(&mut receipt_refs);
    let mut evaluation_result_refs = options.evaluation_result_refs;
    dedup_strings(&mut evaluation_result_refs);
    let mut result_record_refs = options.result_record_refs;
    dedup_strings(&mut result_record_refs);
    let mut validation_report_refs = options.validation_report_refs;
    dedup_strings(&mut validation_report_refs);
    let mut output_refs = options.output_refs;
    dedup_strings(&mut output_refs);
    let mut random_seeds = options.random_seeds;
    dedup_strings(&mut random_seeds);
    let status = options.status.unwrap_or_else(|| {
        if receipt_refs.is_empty()
            && evaluation_result_refs.is_empty()
            && result_record_refs.is_empty()
            && validation_report_refs.is_empty()
            && output_refs.is_empty()
        {
            ResearchRunStatusV1::Planned
        } else {
            ResearchRunStatusV1::Succeeded
        }
    });
    let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let completed_at = research_run_is_terminal(&status)
        .then(|| Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));

    let mut run = EvaluationRunV2 {
        schema_version: EVALUATION_RUN_V2_SCHEMA_VERSION.to_string(),
        evaluation_run_id: String::new(),
        experiment_id: options.experiment_id,
        eval_id: options.eval_id,
        benchmark_id: options.benchmark_id,
        requester: options.requester,
        runner: options.runner,
        target_ref: options.target_ref,
        status,
        sample_count: options.sample_count.unwrap_or(1),
        privacy_tier: options.privacy_tier.unwrap_or(PrivacyTier::NoLogRemote),
        integrity_tier: options.integrity_tier.unwrap_or(IntegrityTier::ReceiptOnly),
        input_refs,
        dataset_refs,
        scoring_method_refs,
        receipt_refs,
        evaluation_result_refs,
        result_record_refs,
        validation_report_refs,
        output_refs,
        artifact_refs: options.artifact_refs,
        random_seeds,
        started_at,
        completed_at,
        metadata: options.metadata.unwrap_or_else(|| json!({})),
        signature: None,
    };
    sign_evaluation_run_v2(&mut run);
    run
}

pub fn sign_evaluation_run_v2(run: &mut EvaluationRunV2) {
    run.signature = Some(expected_evaluation_run_v2_signature(run));
    run.evaluation_run_id = canonical_evaluation_run_v2_id(run);
}

pub fn sign_evaluation_run_v2_with_identity(
    run: &mut EvaluationRunV2,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != run.requester {
        anyhow::bail!(
            "identity subject {} does not match evaluation run requester {}",
            identity.subject,
            run.requester
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "evaluation-run-v2",
        &evaluation_run_v2_signing_value(run),
    )?;
    run.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    run.evaluation_run_id = canonical_evaluation_run_v2_id(run);
    Ok(envelope)
}

pub fn expected_evaluation_run_v2_signature(run: &EvaluationRunV2) -> String {
    format!(
        "{DEV_EVALUATION_RUN_V2_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&evaluation_run_v2_signing_value(run)))
    )
}

pub fn canonical_evaluation_run_v2_id(run: &EvaluationRunV2) -> String {
    stable_id("evaluation-run-v2", &evaluation_run_v2_signing_value(run))
}

pub fn verify_evaluation_run_v2(run: &EvaluationRunV2) -> EvaluationRunV2VerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_evaluation_run_v2_signature(run));
    let signature = run
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if run.schema_version != EVALUATION_RUN_V2_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {EVALUATION_RUN_V2_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(&mut issues, "$.evaluationRunId", &run.evaluation_run_id);
    if !run.evaluation_run_id.is_empty()
        && run.evaluation_run_id != canonical_evaluation_run_v2_id(run)
    {
        issues.push(issue(
            "$.evaluationRunId",
            "Evaluation run id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.requester", &run.requester);
    require_non_empty(&mut issues, "$.runner", &run.runner);
    require_non_empty(&mut issues, "$.targetRef", &run.target_ref);
    if run.eval_id.is_none() && run.benchmark_id.is_none() && run.experiment_id.is_none() {
        issues.push(issue(
            "$.evalId",
            "EvaluationRunV2 must link an evalId, benchmarkId, or experimentId",
        ));
    }
    if run.sample_count == 0 {
        issues.push(issue(
            "$.sampleCount",
            "sampleCount must be greater than zero",
        ));
    }
    validate_timestamp(&run.started_at, "$.startedAt", &mut issues);
    if let Some(completed_at) = &run.completed_at {
        validate_timestamp(completed_at, "$.completedAt", &mut issues);
        if completed_at < &run.started_at {
            issues.push(issue(
                "$.completedAt",
                "completedAt must not be earlier than startedAt",
            ));
        }
    }
    if research_run_is_terminal(&run.status) && run.completed_at.is_none() {
        issues.push(issue(
            "$.completedAt",
            "Terminal evaluation runs must include completedAt",
        ));
    }
    if matches!(run.status, ResearchRunStatusV1::Succeeded) && !evaluation_run_v2_has_evidence(run)
    {
        issues.push(issue(
            "$.receiptRefs",
            "Succeeded evaluation runs must link a receipt, evaluation result, result record, validation report, or output ref",
        ));
    }
    if run.random_seeds.is_empty() {
        warnings.push(issue(
            "$.randomSeeds",
            "Evaluation run has no random seed; exact reruns may be weaker",
        ));
    }
    validate_refs(&mut issues, &mut warnings, evaluation_run_v2_refs(run));
    validate_artifact_refs(
        &mut issues,
        &mut warnings,
        "$.artifactRefs",
        &run.artifact_refs,
    );
    verify_optional_signature(
        signature,
        &mut issues,
        &mut warnings,
        &mut expected_signature,
        "evaluation-run-v2",
        &evaluation_run_v2_signing_value(run),
        Some(&run.requester),
        "EvaluationRunV2 signature does not match canonical dev signature or Ed25519 requester identity envelope",
        "EvaluationRunV2 is unsigned; verify requester and evaluationRunId through a trusted source",
    );

    EvaluationRunV2VerificationV1 {
        schema_version: EVALUATION_RUN_V2_VERIFICATION_SCHEMA_VERSION.to_string(),
        evaluation_run_id: run.evaluation_run_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn create_research_result_record(
    options: ResearchResultRecordInitOptionsV1,
) -> ResearchResultRecordV1 {
    let mut result_refs = options.result_refs;
    dedup_strings(&mut result_refs);
    let mut receipt_refs = options.receipt_refs;
    dedup_strings(&mut receipt_refs);
    let mut evaluation_result_refs = options.evaluation_result_refs;
    dedup_strings(&mut evaluation_result_refs);
    let mut validation_report_refs = options.validation_report_refs;
    dedup_strings(&mut validation_report_refs);

    let mut record = ResearchResultRecordV1 {
        schema_version: RESEARCH_RESULT_RECORD_SCHEMA_VERSION.to_string(),
        result_id: String::new(),
        result_kind: options.result_kind,
        title: options.title,
        producer: options.producer,
        experiment_id: options.experiment_id,
        run_id: options.run_id,
        evaluation_run_id: options.evaluation_run_id,
        hypothesis: options.hypothesis,
        summary: options.summary,
        metrics: options.metrics.unwrap_or_else(|| json!({})),
        result_refs,
        receipt_refs,
        evaluation_result_refs,
        validation_report_refs,
        artifact_refs: options.artifact_refs,
        limitations: options.limitations,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_research_result_record(&mut record);
    record
}

pub fn sign_research_result_record(record: &mut ResearchResultRecordV1) {
    record.signature = Some(expected_research_result_record_signature(record));
    record.result_id = canonical_research_result_record_id(record);
}

pub fn sign_research_result_record_with_identity(
    record: &mut ResearchResultRecordV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != record.producer {
        anyhow::bail!(
            "identity subject {} does not match research result producer {}",
            identity.subject,
            record.producer
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "research-result-record",
        &research_result_record_signing_value(record),
    )?;
    record.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    record.result_id = canonical_research_result_record_id(record);
    Ok(envelope)
}

pub fn expected_research_result_record_signature(record: &ResearchResultRecordV1) -> String {
    format!(
        "{DEV_RESEARCH_RESULT_RECORD_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&research_result_record_signing_value(
            record
        )))
    )
}

pub fn canonical_research_result_record_id(record: &ResearchResultRecordV1) -> String {
    stable_id(
        "research-result",
        &research_result_record_signing_value(record),
    )
}

pub fn verify_research_result_record(
    record: &ResearchResultRecordV1,
) -> ResearchResultRecordVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_research_result_record_signature(record));
    let signature = record
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if record.schema_version != RESEARCH_RESULT_RECORD_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {RESEARCH_RESULT_RECORD_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(&mut issues, "$.resultId", &record.result_id);
    if !record.result_id.is_empty()
        && record.result_id != canonical_research_result_record_id(record)
    {
        issues.push(issue(
            "$.resultId",
            "Research result id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.title", &record.title);
    require_non_empty(&mut issues, "$.producer", &record.producer);
    require_non_empty(&mut issues, "$.summary", &record.summary);
    if record.experiment_id.is_none()
        && record.run_id.is_none()
        && record.evaluation_run_id.is_none()
    {
        issues.push(issue(
            "$.experimentId",
            "Research result records must link an experimentId, runId, or evaluationRunId",
        ));
    }
    if !research_result_record_has_evidence(record) {
        issues.push(issue(
            "$.resultRefs",
            "Research result records must include metrics or link result, receipt, evaluation, validation, or artifact refs",
        ));
    }
    if matches!(record.result_kind, ResearchResultKindV1::Negative) && record.limitations.is_empty()
    {
        warnings.push(issue(
            "$.limitations",
            "Negative result records should explain scope, failed assumptions, or reproduction limits",
        ));
    }
    validate_timestamp(&record.created_at, "$.createdAt", &mut issues);
    validate_refs(
        &mut issues,
        &mut warnings,
        research_result_record_refs(record),
    );
    validate_artifact_refs(
        &mut issues,
        &mut warnings,
        "$.artifactRefs",
        &record.artifact_refs,
    );
    verify_optional_signature(
        signature,
        &mut issues,
        &mut warnings,
        &mut expected_signature,
        "research-result-record",
        &research_result_record_signing_value(record),
        Some(&record.producer),
        "Research result signature does not match canonical dev signature or Ed25519 producer identity envelope",
        "Research result record is unsigned; verify producer and resultId through a trusted source",
    );

    ResearchResultRecordVerificationV1 {
        schema_version: RESEARCH_RESULT_RECORD_VERIFICATION_SCHEMA_VERSION.to_string(),
        result_id: record.result_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn create_reproducibility_bundle(
    options: ReproducibilityBundleInitOptionsV1,
) -> ReproducibilityBundleV1 {
    let plan = reproduction_plan(&options.experiment, "local");
    let mut run_refs = options.run_refs;
    dedup_strings(&mut run_refs);
    let mut evaluation_run_refs = options.evaluation_run_refs;
    dedup_strings(&mut evaluation_run_refs);
    let mut result_record_refs = options.result_record_refs;
    dedup_strings(&mut result_record_refs);
    let mut receipt_refs = options.receipt_refs;
    dedup_strings(&mut receipt_refs);
    let mut validation_report_refs = options.validation_report_refs;
    dedup_strings(&mut validation_report_refs);
    let mut evaluation_result_refs = options.evaluation_result_refs;
    dedup_strings(&mut evaluation_result_refs);
    let mut output_refs = options.output_refs;
    dedup_strings(&mut output_refs);
    let mut immutable_refs = plan.immutable_refs;
    immutable_refs.extend(options.immutable_refs);
    dedup_strings(&mut immutable_refs);
    let mut mutable_refs = plan.mutable_refs;
    mutable_refs.extend(options.mutable_refs);
    dedup_strings(&mut mutable_refs);
    let mut random_seeds = options
        .experiment
        .random_seeds
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>();
    random_seeds.extend(options.random_seeds);
    dedup_strings(&mut random_seeds);
    let reproduction_steps = if options.reproduction_steps.is_empty() {
        options.experiment.reproduction_steps.clone()
    } else {
        options.reproduction_steps
    };

    let mut bundle = ReproducibilityBundleV1 {
        schema_version: REPRODUCIBILITY_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id: String::new(),
        title: options
            .title
            .unwrap_or_else(|| format!("Reproducibility bundle for {}", options.experiment.title)),
        producer: options.producer,
        experiment_id: options.experiment.experiment_id.clone(),
        experiment_ref: options.experiment_ref,
        privacy_tier: options.experiment.runner_requirements.privacy_tier.clone(),
        integrity_tier: options
            .experiment
            .runner_requirements
            .verification_tier
            .clone(),
        experiment: Some(Box::new(options.experiment)),
        run_refs,
        runs: options.runs,
        evaluation_run_refs,
        evaluation_runs: options.evaluation_runs,
        result_record_refs,
        result_records: options.result_records,
        receipt_refs,
        validation_report_refs,
        evaluation_result_refs,
        output_refs,
        artifact_refs: options.artifact_refs,
        immutable_refs,
        mutable_refs,
        random_seeds,
        reproduction_steps,
        claims_exact_reproduction: options.claims_exact_reproduction.unwrap_or(true),
        notes: options.notes,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_reproducibility_bundle(&mut bundle);
    bundle
}

pub fn sign_reproducibility_bundle(bundle: &mut ReproducibilityBundleV1) {
    bundle.signature = Some(expected_reproducibility_bundle_signature(bundle));
    bundle.bundle_id = canonical_reproducibility_bundle_id(bundle);
}

pub fn sign_reproducibility_bundle_with_identity(
    bundle: &mut ReproducibilityBundleV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != bundle.producer {
        anyhow::bail!(
            "identity subject {} does not match reproducibility bundle producer {}",
            identity.subject,
            bundle.producer
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "reproducibility-bundle",
        &reproducibility_bundle_signing_value(bundle),
    )?;
    bundle.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    bundle.bundle_id = canonical_reproducibility_bundle_id(bundle);
    Ok(envelope)
}

pub fn expected_reproducibility_bundle_signature(bundle: &ReproducibilityBundleV1) -> String {
    format!(
        "{DEV_REPRODUCIBILITY_BUNDLE_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&reproducibility_bundle_signing_value(
            bundle
        )))
    )
}

pub fn canonical_reproducibility_bundle_id(bundle: &ReproducibilityBundleV1) -> String {
    stable_id(
        "repro-bundle",
        &reproducibility_bundle_signing_value(bundle),
    )
}

pub fn verify_reproducibility_bundle(
    bundle: &ReproducibilityBundleV1,
) -> ReproducibilityBundleVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_reproducibility_bundle_signature(bundle));
    let signature = bundle
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if bundle.schema_version != REPRODUCIBILITY_BUNDLE_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {REPRODUCIBILITY_BUNDLE_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(&mut issues, "$.bundleId", &bundle.bundle_id);
    if !bundle.bundle_id.is_empty()
        && bundle.bundle_id != canonical_reproducibility_bundle_id(bundle)
    {
        issues.push(issue(
            "$.bundleId",
            "Reproducibility bundle id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.title", &bundle.title);
    require_non_empty(&mut issues, "$.producer", &bundle.producer);
    require_non_empty(&mut issues, "$.experimentId", &bundle.experiment_id);
    if bundle.experiment_ref.is_none() && bundle.experiment.is_none() {
        issues.push(issue(
            "$.experimentRef",
            "Reproducibility bundles must include either experimentRef or an embedded experiment",
        ));
    }
    if let Some(experiment) = bundle.experiment.as_deref() {
        let experiment_verification = verify_research_experiment(experiment);
        if !experiment_verification.valid {
            issues.push(issue(
                "$.experiment",
                "Embedded research experiment is not valid",
            ));
        }
        if bundle.experiment_id != experiment.experiment_id {
            issues.push(issue(
                "$.experimentId",
                "Bundle experimentId must match embedded experiment",
            ));
        }
    }
    if bundle.reproduction_steps.is_empty() {
        issues.push(issue(
            "$.reproductionSteps",
            "Reproducibility bundles must include scriptable reproduction steps",
        ));
    }
    if bundle.random_seeds.is_empty() {
        warnings.push(issue(
            "$.randomSeeds",
            "Bundle has no random seeds; exact reproduction may be weaker",
        ));
    }
    if bundle.claims_exact_reproduction && !bundle.mutable_refs.is_empty() {
        issues.push(issue(
            "$.mutableRefs",
            "Bundles claiming exact reproduction must resolve mutable refs to immutable Swarm/content refs",
        ));
    }
    if bundle.claims_exact_reproduction && bundle.immutable_refs.is_empty() {
        warnings.push(issue(
            "$.immutableRefs",
            "Exact-reproduction bundles should list immutable package, dataset, code, environment, or artifact refs",
        ));
    }
    validate_timestamp(&bundle.created_at, "$.createdAt", &mut issues);
    validate_refs(
        &mut issues,
        &mut warnings,
        reproducibility_bundle_refs(bundle),
    );
    validate_artifact_refs(
        &mut issues,
        &mut warnings,
        "$.artifactRefs",
        &bundle.artifact_refs,
    );

    for (index, run) in bundle.runs.iter().enumerate() {
        let verification = verify_research_experiment_run(run, bundle.experiment.as_deref());
        if !verification.valid {
            issues.push(issue(
                format!("$.runs[{index}]"),
                "Embedded research run is not valid",
            ));
        }
        if run.experiment_id != bundle.experiment_id {
            issues.push(issue(
                format!("$.runs[{index}].experimentId"),
                "Embedded research run experimentId must match bundle experimentId",
            ));
        }
    }
    for (index, run) in bundle.evaluation_runs.iter().enumerate() {
        let verification = verify_evaluation_run_v2(run);
        if !verification.valid {
            issues.push(issue(
                format!("$.evaluationRuns[{index}]"),
                "Embedded EvaluationRunV2 is not valid",
            ));
        }
        if let Some(experiment_id) = &run.experiment_id {
            if experiment_id != &bundle.experiment_id {
                issues.push(issue(
                    format!("$.evaluationRuns[{index}].experimentId"),
                    "Embedded EvaluationRunV2 experimentId must match bundle experimentId",
                ));
            }
        }
    }
    for (index, record) in bundle.result_records.iter().enumerate() {
        let verification = verify_research_result_record(record);
        if !verification.valid {
            issues.push(issue(
                format!("$.resultRecords[{index}]"),
                "Embedded research result record is not valid",
            ));
        }
        if let Some(experiment_id) = &record.experiment_id {
            if experiment_id != &bundle.experiment_id {
                issues.push(issue(
                    format!("$.resultRecords[{index}].experimentId"),
                    "Embedded research result record experimentId must match bundle experimentId",
                ));
            }
        }
        if record.signature.is_none() {
            issues.push(issue(
                format!("$.resultRecords[{index}].signature"),
                "Result records inside a reproducibility bundle must be signed",
            ));
        }
    }
    if !reproducibility_bundle_has_execution_evidence(bundle) {
        warnings.push(issue(
            "$.receiptRefs",
            "Bundle has no linked runs, receipts, validations, evaluation results, result records, or outputs yet",
        ));
    }

    verify_optional_signature(
        signature,
        &mut issues,
        &mut warnings,
        &mut expected_signature,
        "reproducibility-bundle",
        &reproducibility_bundle_signing_value(bundle),
        Some(&bundle.producer),
        "Reproducibility bundle signature does not match canonical dev signature or Ed25519 producer identity envelope",
        "Reproducibility bundle is unsigned; verify producer and bundleId through a trusted source",
    );

    ReproducibilityBundleVerificationV1 {
        schema_version: REPRODUCIBILITY_BUNDLE_VERIFICATION_SCHEMA_VERSION.to_string(),
        bundle_id: bundle.bundle_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn write_research_experiment_run(
    runs_dir: &Path,
    run: &ResearchExperimentRunV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(runs_dir)?;
    let path = runs_dir.join(format!("{}.json", safe_file_component(&run.run_id)));
    fs::write(&path, serde_json::to_vec_pretty(run)?)?;
    Ok(path)
}

pub fn list_research_experiments(
    experiment_dir: &Path,
) -> anyhow::Result<ResearchExperimentStoreSummaryV1> {
    let mut files = Vec::new();
    collect_research_experiment_files(experiment_dir, &mut files)?;
    files.sort();

    let mut experiments = Vec::new();
    let mut valid_count = 0;
    let mut mutable_ref_count = 0;
    let mut warning_count = 0;

    for path in files {
        let Some(experiment) = read_research_experiment_file(&path)? else {
            continue;
        };
        let verification = verify_research_experiment(&experiment);
        let plan = reproduction_plan(&experiment, "local");
        if verification.valid {
            valid_count += 1;
        }
        mutable_ref_count += plan.mutable_refs.len();
        warning_count += verification.warnings.len() + plan.warnings.len();
        experiments.push(research_experiment_index_entry(
            &experiment,
            &verification,
            &plan,
            path.display().to_string(),
        ));
    }
    experiments.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.experiment_id.cmp(&right.experiment_id))
            .then(left.experiment_path.cmp(&right.experiment_path))
    });

    Ok(ResearchExperimentStoreSummaryV1 {
        schema_version: "swarm-ai.research-experiment-store-summary.v1".to_string(),
        root: experiment_dir.display().to_string(),
        experiment_count: experiments.len(),
        valid_count,
        invalid_count: experiments.len().saturating_sub(valid_count),
        mutable_ref_count,
        warning_count,
        experiments,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn get_research_experiment(
    experiment_dir: &Path,
    experiment_id: &str,
) -> anyhow::Result<Option<ResearchExperimentLookupV1>> {
    let experiment_id = experiment_id.trim();
    if experiment_id.is_empty() {
        anyhow::bail!("experimentId is required");
    }
    let mut files = Vec::new();
    collect_research_experiment_files(experiment_dir, &mut files)?;
    files.sort();

    for path in files {
        let Some(experiment) = read_research_experiment_file(&path)? else {
            continue;
        };
        if experiment.experiment_id == experiment_id {
            let verification = verify_research_experiment(&experiment);
            let reproduction_plan = reproduction_plan(&experiment, "local");
            return Ok(Some(ResearchExperimentLookupV1 {
                schema_version: "swarm-ai.research-experiment-lookup.v1".to_string(),
                experiment_id: experiment.experiment_id.clone(),
                experiment_path: path.display().to_string(),
                experiment,
                verification,
                reproduction_plan,
            }));
        }
    }

    Ok(None)
}

pub fn list_research_experiment_runs(
    runs_dir: &Path,
) -> anyhow::Result<ResearchExperimentRunStoreSummaryV1> {
    let mut files = Vec::new();
    collect_research_experiment_files(runs_dir, &mut files)?;
    files.sort();

    let mut runs = Vec::new();
    let mut valid_count = 0;
    let mut terminal_count = 0;
    let mut receipt_linked_count = 0;
    let mut evaluation_linked_count = 0;
    let mut mutable_ref_count = 0;
    let mut warning_count = 0;

    for path in files {
        let Some(run) = read_research_run_file(&path)? else {
            continue;
        };
        let verification = verify_research_experiment_run(&run, None);
        if verification.valid {
            valid_count += 1;
        }
        if research_run_is_terminal(&run.status) {
            terminal_count += 1;
        }
        if !run.receipt_refs.is_empty() {
            receipt_linked_count += 1;
        }
        if !run.evaluation_result_refs.is_empty() {
            evaluation_linked_count += 1;
        }
        mutable_ref_count += run.mutable_refs.len();
        warning_count += verification.warnings.len();
        runs.push(research_run_index_entry(
            &run,
            &verification,
            path.display().to_string(),
        ));
    }
    runs.sort_by(|left, right| {
        left.started_at
            .cmp(&right.started_at)
            .then(left.experiment_id.cmp(&right.experiment_id))
            .then(left.run_id.cmp(&right.run_id))
            .then(left.run_path.cmp(&right.run_path))
    });

    Ok(ResearchExperimentRunStoreSummaryV1 {
        schema_version: "swarm-ai.research-experiment-run-store-summary.v1".to_string(),
        root: runs_dir.display().to_string(),
        run_count: runs.len(),
        valid_count,
        invalid_count: runs.len().saturating_sub(valid_count),
        terminal_count,
        receipt_linked_count,
        evaluation_linked_count,
        mutable_ref_count,
        warning_count,
        runs,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn get_research_experiment_run(
    runs_dir: &Path,
    run_id: &str,
) -> anyhow::Result<Option<ResearchExperimentRunLookupV1>> {
    let run_id = run_id.trim();
    if run_id.is_empty() {
        anyhow::bail!("runId is required");
    }
    let mut files = Vec::new();
    collect_research_experiment_files(runs_dir, &mut files)?;
    files.sort();

    for path in files {
        let Some(run) = read_research_run_file(&path)? else {
            continue;
        };
        if run.run_id == run_id {
            let verification = verify_research_experiment_run(&run, None);
            return Ok(Some(ResearchExperimentRunLookupV1 {
                schema_version: "swarm-ai.research-experiment-run-lookup.v1".to_string(),
                run_id: run.run_id.clone(),
                run_path: path.display().to_string(),
                run,
                verification,
            }));
        }
    }

    Ok(None)
}

fn collect_research_experiment_files(
    experiment_dir: &Path,
    files: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    if !experiment_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(experiment_dir)
        .with_context(|| format!("failed to read {}", experiment_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_research_experiment_files(&path, files)?;
        } else if file_type.is_file() && is_json_path(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_json_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
}

fn read_research_experiment_file(path: &Path) -> anyhow::Result<Option<ResearchExperimentV1>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let Some(schema_version) = value.get("schemaVersion").and_then(Value::as_str) else {
        return Ok(None);
    };
    if schema_version != "swarm-ai.research-experiment.v1" {
        return Ok(None);
    }
    serde_json::from_value(value)
        .map(Some)
        .with_context(|| format!("failed to parse research experiment {}", path.display()))
}

fn read_research_run_file(path: &Path) -> anyhow::Result<Option<ResearchExperimentRunV1>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let Some(schema_version) = value.get("schemaVersion").and_then(Value::as_str) else {
        return Ok(None);
    };
    if schema_version != "swarm-ai.research-experiment-run.v1" {
        return Ok(None);
    }
    serde_json::from_value(value)
        .map(Some)
        .with_context(|| format!("failed to parse research experiment run {}", path.display()))
}

fn research_experiment_index_entry(
    experiment: &ResearchExperimentV1,
    verification: &ResearchExperimentVerificationV1,
    plan: &ResearchReproductionPlanV1,
    experiment_path: String,
) -> ResearchExperimentIndexEntryV1 {
    ResearchExperimentIndexEntryV1 {
        experiment_id: experiment.experiment_id.clone(),
        title: experiment.title.clone(),
        author: experiment.author.clone(),
        organization: experiment.organization.clone(),
        privacy_tier: experiment.runner_requirements.privacy_tier.clone(),
        verification_tier: experiment.runner_requirements.verification_tier.clone(),
        package_ref_count: experiment.package_refs.len(),
        model_ref_count: experiment.model_refs.len(),
        dataset_ref_count: experiment.dataset_refs.len(),
        benchmark_ref_count: experiment.benchmark_refs.len(),
        reproduction_step_count: experiment.reproduction_steps.len(),
        mutable_ref_count: plan.mutable_refs.len(),
        warning_count: verification.warnings.len() + plan.warnings.len(),
        valid: verification.valid,
        signature_present: experiment.signature.is_some(),
        created_at: experiment.created_at.clone(),
        experiment_path,
    }
}

fn research_run_index_entry(
    run: &ResearchExperimentRunV1,
    verification: &ResearchExperimentRunVerificationV1,
    run_path: String,
) -> ResearchExperimentRunIndexEntryV1 {
    ResearchExperimentRunIndexEntryV1 {
        run_id: run.run_id.clone(),
        experiment_id: run.experiment_id.clone(),
        requester: run.requester.clone(),
        runner: run.runner.clone(),
        status: run.status.clone(),
        privacy_tier: run.privacy_tier.clone(),
        verification_tier: run.verification_tier.clone(),
        receipt_ref_count: run.receipt_refs.len(),
        evaluation_result_ref_count: run.evaluation_result_refs.len(),
        validation_report_ref_count: run.validation_report_refs.len(),
        output_ref_count: run.output_refs.len(),
        mutable_ref_count: run.mutable_refs.len(),
        warning_count: verification.warnings.len(),
        valid: verification.valid,
        signature_present: run.signature.is_some(),
        started_at: run.started_at.clone(),
        completed_at: run.completed_at.clone(),
        run_path,
    }
}

fn default_reproduction_steps() -> Vec<ResearchReproductionStepV1> {
    vec![
        ResearchReproductionStepV1 {
            order: 1,
            title: "Resolve immutable references".to_string(),
            command: "swarm-ai registry get <package-id-or-ref>".to_string(),
            expected_evidence_refs: Vec::new(),
        },
        ResearchReproductionStepV1 {
            order: 2,
            title: "Run benchmark or experiment package".to_string(),
            command: "swarm-ai run-ref <package-ref> --task embedding --text \"reproduce\""
                .to_string(),
            expected_evidence_refs: vec!["receipt".to_string()],
        },
        ResearchReproductionStepV1 {
            order: 3,
            title: "Verify receipts and evaluation results".to_string(),
            command: "swarm-ai receipts verify <receipt.json>".to_string(),
            expected_evidence_refs: vec!["receipt".to_string(), "evaluation-result".to_string()],
        },
    ]
}

fn research_experiment_signing_value(experiment: &ResearchExperimentV1) -> Value {
    let mut value = serde_json::to_value(experiment).expect("research experiment should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("experimentId");
        object.remove("signature");
    }
    value
}

fn research_run_signing_value(run: &ResearchExperimentRunV1) -> Value {
    let mut value = serde_json::to_value(run).expect("research run should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("runId");
        object.remove("signature");
    }
    value
}

fn evaluation_run_v2_signing_value(run: &EvaluationRunV2) -> Value {
    let mut value = serde_json::to_value(run).expect("evaluation run v2 should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("evaluationRunId");
        object.remove("signature");
    }
    value
}

fn research_result_record_signing_value(record: &ResearchResultRecordV1) -> Value {
    let mut value = serde_json::to_value(record).expect("research result record should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("resultId");
        object.remove("signature");
    }
    value
}

fn reproducibility_bundle_signing_value(bundle: &ReproducibilityBundleV1) -> Value {
    let mut value = serde_json::to_value(bundle).expect("reproducibility bundle should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("bundleId");
        object.remove("signature");
    }
    value
}

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("research object should serialize");
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

fn require_non_empty(issues: &mut Vec<ValidationIssue>, path: &'static str, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value is required"));
    }
}

fn validate_timestamp(when: &str, path: &'static str, issues: &mut Vec<ValidationIssue>) {
    if chrono::DateTime::parse_from_rfc3339(when).is_err() {
        issues.push(issue(path, "Timestamp must be RFC3339"));
    }
}

fn experiment_refs(experiment: &ResearchExperimentV1) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    append_refs(&mut refs, "$.modelRefs", &experiment.model_refs);
    append_refs(&mut refs, "$.datasetRefs", &experiment.dataset_refs);
    append_refs(&mut refs, "$.benchmarkRefs", &experiment.benchmark_refs);
    append_refs(&mut refs, "$.promptRefs", &experiment.prompt_refs);
    append_refs(&mut refs, "$.toolRefs", &experiment.tool_refs);
    append_refs(&mut refs, "$.codeRefs", &experiment.code_refs);
    append_refs(&mut refs, "$.environmentRefs", &experiment.environment_refs);
    append_refs(&mut refs, "$.packageRefs", &experiment.package_refs);
    refs.push((
        "$.scoringMethodRef".to_string(),
        experiment.scoring_method_ref.clone(),
    ));
    refs
}

fn research_run_refs(run: &ResearchExperimentRunV1) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    append_refs(&mut refs, "$.immutableRefs", &run.immutable_refs);
    append_refs(&mut refs, "$.mutableRefs", &run.mutable_refs);
    append_refs(&mut refs, "$.receiptRefs", &run.receipt_refs);
    append_refs(
        &mut refs,
        "$.evaluationResultRefs",
        &run.evaluation_result_refs,
    );
    append_refs(
        &mut refs,
        "$.validationReportRefs",
        &run.validation_report_refs,
    );
    append_refs(&mut refs, "$.outputRefs", &run.output_refs);
    refs
}

fn evaluation_run_v2_refs(run: &EvaluationRunV2) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    if !run.target_ref.is_empty() {
        refs.push(("$.targetRef".to_string(), run.target_ref.clone()));
    }
    append_refs(&mut refs, "$.inputRefs", &run.input_refs);
    append_refs(&mut refs, "$.datasetRefs", &run.dataset_refs);
    append_refs(&mut refs, "$.scoringMethodRefs", &run.scoring_method_refs);
    append_refs(&mut refs, "$.receiptRefs", &run.receipt_refs);
    append_refs(
        &mut refs,
        "$.evaluationResultRefs",
        &run.evaluation_result_refs,
    );
    append_refs(&mut refs, "$.resultRecordRefs", &run.result_record_refs);
    append_refs(
        &mut refs,
        "$.validationReportRefs",
        &run.validation_report_refs,
    );
    append_refs(&mut refs, "$.outputRefs", &run.output_refs);
    refs
}

fn research_result_record_refs(record: &ResearchResultRecordV1) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    append_refs(&mut refs, "$.resultRefs", &record.result_refs);
    append_refs(&mut refs, "$.receiptRefs", &record.receipt_refs);
    append_refs(
        &mut refs,
        "$.evaluationResultRefs",
        &record.evaluation_result_refs,
    );
    append_refs(
        &mut refs,
        "$.validationReportRefs",
        &record.validation_report_refs,
    );
    refs
}

fn reproducibility_bundle_refs(bundle: &ReproducibilityBundleV1) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    if let Some(reference) = &bundle.experiment_ref {
        refs.push(("$.experimentRef".to_string(), reference.clone()));
    }
    append_refs(&mut refs, "$.runRefs", &bundle.run_refs);
    append_refs(
        &mut refs,
        "$.evaluationRunRefs",
        &bundle.evaluation_run_refs,
    );
    append_refs(&mut refs, "$.resultRecordRefs", &bundle.result_record_refs);
    append_refs(&mut refs, "$.receiptRefs", &bundle.receipt_refs);
    append_refs(
        &mut refs,
        "$.validationReportRefs",
        &bundle.validation_report_refs,
    );
    append_refs(
        &mut refs,
        "$.evaluationResultRefs",
        &bundle.evaluation_result_refs,
    );
    append_refs(&mut refs, "$.outputRefs", &bundle.output_refs);
    append_refs(&mut refs, "$.immutableRefs", &bundle.immutable_refs);
    append_refs(&mut refs, "$.mutableRefs", &bundle.mutable_refs);
    refs
}

fn append_refs(refs: &mut Vec<(String, String)>, base_path: &str, values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        refs.push((format!("{base_path}[{index}]"), value.clone()));
    }
}

fn validate_refs(
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
    refs: Vec<(String, String)>,
) {
    for (path, reference) in refs {
        if reference.trim().is_empty() {
            issues.push(issue(path, "Reference must not be empty"));
        } else if !looks_like_research_ref(&reference) {
            warnings.push(issue(
                path,
                "Reference is not a recognized bzz://, feed://, local://, ipfs://, sha256://, https://, receipt://, evaluation://, validation://, result://, or research:// reference",
            ));
        } else if looks_mutable_ref(&reference) {
            warnings.push(issue(
                path,
                "Mutable reference should be resolved before claiming exact reproduction",
            ));
        }
    }
}

fn validate_artifact_refs(
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
    base_path: &str,
    artifacts: &[ResearchArtifactRefV1],
) {
    for (index, artifact) in artifacts.iter().enumerate() {
        let role_path = format!("{base_path}[{index}].role");
        if artifact.role.trim().is_empty() {
            issues.push(issue(role_path, "Artifact role is required"));
        }
        let reference_path = format!("{base_path}[{index}].reference");
        if artifact.reference.trim().is_empty() {
            issues.push(issue(reference_path, "Artifact reference is required"));
        } else if !looks_like_research_ref(&artifact.reference) {
            warnings.push(issue(
                reference_path,
                "Artifact reference is not a recognized Swarm, feed, local, IPFS, hash, HTTPS, receipt, evaluation, validation, result, or research reference",
            ));
        } else if looks_mutable_ref(&artifact.reference) {
            warnings.push(issue(
                reference_path,
                "Artifact reference is mutable; exact reproduction should use immutable content refs",
            ));
        }
        if artifact_role_requires_license(&artifact.role) && artifact.license_ref.is_none() {
            issues.push(issue(
                format!("{base_path}[{index}].licenseRef"),
                "Dataset, benchmark, model, and code artifacts must include a licenseRef",
            ));
        }
        for (policy_index, reference) in artifact.access_policy_refs.iter().enumerate() {
            validate_refs(
                issues,
                warnings,
                vec![(
                    format!("{base_path}[{index}].accessPolicyRefs[{policy_index}]"),
                    reference.clone(),
                )],
            );
        }
    }
}

fn artifact_role_requires_license(role: &str) -> bool {
    let role = role.to_ascii_lowercase();
    role.contains("dataset")
        || role.contains("benchmark")
        || role.contains("model")
        || role.contains("code")
        || role.contains("notebook")
}

fn looks_like_research_ref(reference: &str) -> bool {
    reference.starts_with("bzz://")
        || reference.starts_with("feed://")
        || reference.starts_with("local://")
        || reference.starts_with("ipfs://")
        || reference.starts_with("sha256://")
        || reference.starts_with("https://")
        || reference.starts_with("receipt://")
        || reference.starts_with("evaluation://")
        || reference.starts_with("validation://")
        || reference.starts_with("result://")
        || reference.starts_with("research://")
}

fn looks_mutable_ref(reference: &str) -> bool {
    reference.starts_with("https://")
        || reference.starts_with("feed://")
        || reference.contains(":latest")
        || reference.contains("/latest")
        || reference.contains(":stable")
        || reference.contains("/stable")
}

fn research_run_is_terminal(status: &ResearchRunStatusV1) -> bool {
    matches!(
        status,
        ResearchRunStatusV1::Succeeded
            | ResearchRunStatusV1::Failed
            | ResearchRunStatusV1::Cancelled
    )
}

fn research_run_has_evidence(run: &ResearchExperimentRunV1) -> bool {
    !run.receipt_refs.is_empty()
        || !run.evaluation_result_refs.is_empty()
        || !run.validation_report_refs.is_empty()
        || !run.output_refs.is_empty()
}

fn evaluation_run_v2_has_evidence(run: &EvaluationRunV2) -> bool {
    !run.receipt_refs.is_empty()
        || !run.evaluation_result_refs.is_empty()
        || !run.result_record_refs.is_empty()
        || !run.validation_report_refs.is_empty()
        || !run.output_refs.is_empty()
}

fn research_result_record_has_evidence(record: &ResearchResultRecordV1) -> bool {
    non_empty_json(&record.metrics)
        || !record.result_refs.is_empty()
        || !record.receipt_refs.is_empty()
        || !record.evaluation_result_refs.is_empty()
        || !record.validation_report_refs.is_empty()
        || !record.artifact_refs.is_empty()
}

fn reproducibility_bundle_has_execution_evidence(bundle: &ReproducibilityBundleV1) -> bool {
    !bundle.runs.is_empty()
        || !bundle.run_refs.is_empty()
        || !bundle.evaluation_runs.is_empty()
        || !bundle.evaluation_run_refs.is_empty()
        || !bundle.result_records.is_empty()
        || !bundle.result_record_refs.is_empty()
        || !bundle.receipt_refs.is_empty()
        || !bundle.validation_report_refs.is_empty()
        || !bundle.evaluation_result_refs.is_empty()
        || !bundle.output_refs.is_empty()
}

fn non_empty_json(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(values) => !values.is_empty(),
        Value::Object(values) => !values.is_empty(),
        Value::String(value) => !value.trim().is_empty(),
        Value::Bool(_) | Value::Number(_) => true,
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_optional_signature(
    signature: Option<&str>,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
    expected_signature: &mut Option<String>,
    scope: &str,
    signing_value: &Value,
    expected_signer: Option<&str>,
    mismatch_message: &str,
    unsigned_message: &str,
) {
    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                scope,
                signing_value,
                expected_signer,
            );
            *expected_signature = Some(format!(
                "ed25519-payload-hash:{}",
                verification.payload_hash
            ));
            for signature_issue in verification.issues {
                issues.push(issue(
                    signature_issue_path(&signature_issue.path),
                    signature_issue.message,
                ));
            }
        } else if Some(signature) != expected_signature.as_deref() {
            issues.push(issue("$.signature", mismatch_message));
        }
    } else {
        warnings.push(issue("$.signature", unsigned_message));
    }
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut normalized = values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    *values = normalized;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_signed_research_experiment_with_reproduction_steps() {
        let experiment = create_research_experiment(ResearchExperimentInitOptionsV1 {
            title: "Compare embedding models".to_string(),
            author: "0xResearcher".to_string(),
            organization: Some("Hivemind Lab".to_string()),
            hypothesis: "Model A has better retrieval quality than Model B".to_string(),
            package_refs: vec!["bzz://experiment-package".to_string()],
            model_refs: vec!["bzz://model-a".to_string(), "bzz://model-b".to_string()],
            dataset_refs: vec!["bzz://dataset".to_string()],
            benchmark_refs: vec!["bzz://benchmark".to_string()],
            scoring_method_ref: Some("bzz://scoring-method".to_string()),
        });

        let verification = verify_research_experiment(&experiment);

        assert!(verification.valid, "{verification:#?}");
        assert!(experiment.experiment_id.starts_with("experiment-"));
        assert_eq!(
            experiment.signature.as_deref(),
            Some(expected_research_experiment_signature(&experiment).as_str())
        );
        assert!(!experiment.reproduction_steps.is_empty());
    }

    #[test]
    fn identity_signed_research_experiment_verifies_and_detects_tampering() {
        let mut experiment = create_research_experiment(ResearchExperimentInitOptionsV1 {
            title: "Privacy method comparison".to_string(),
            author: "0xResearcher".to_string(),
            organization: None,
            hypothesis: "TEE execution lowers privacy risk with acceptable latency".to_string(),
            package_refs: vec!["bzz://experiment-package".to_string()],
            model_refs: Vec::new(),
            dataset_refs: vec!["bzz://private-dataset".to_string()],
            benchmark_refs: Vec::new(),
            scoring_method_ref: None,
        });
        let identity =
            hivemind_identity::identity_from_seed("0xResearcher", b"researcher-seed").unwrap();

        let envelope = sign_research_experiment_with_identity(&mut experiment, &identity).unwrap();
        let verification = verify_research_experiment(&experiment);

        assert_eq!(envelope.signer, experiment.author);
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .as_deref()
                .unwrap()
                .starts_with("ed25519-payload-hash:")
        );

        experiment.hypothesis = "changed after signing".to_string();
        let tampered = verify_research_experiment(&experiment);
        assert!(!tampered.valid);
        assert!(tampered.issues.iter().any(|issue| {
            issue.path == "$.experimentId" || issue.path == "$.signature.payloadHash"
        }));
    }

    #[test]
    fn unsigned_research_experiment_still_requires_canonical_id() {
        let mut experiment = create_research_experiment(ResearchExperimentInitOptionsV1 {
            title: "Unsigned canonical id test".to_string(),
            author: "0xResearcher".to_string(),
            organization: None,
            hypothesis: "Unsigned experiments still need stable identity".to_string(),
            package_refs: vec!["bzz://experiment-package".to_string()],
            model_refs: Vec::new(),
            dataset_refs: Vec::new(),
            benchmark_refs: Vec::new(),
            scoring_method_ref: None,
        });
        experiment.signature = None;
        experiment.hypothesis = "changed after removing signature".to_string();

        let verification = verify_research_experiment(&experiment);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.experimentId")
        );
    }

    #[test]
    fn reproduction_plan_separates_mutable_refs() {
        let mut experiment = create_research_experiment(ResearchExperimentInitOptionsV1 {
            title: "Mutable ref test".to_string(),
            author: "0xResearcher".to_string(),
            organization: None,
            hypothesis: "Mutable refs should be visible".to_string(),
            package_refs: vec![
                "bzz://immutable".to_string(),
                "https://example.com/run".to_string(),
            ],
            model_refs: Vec::new(),
            dataset_refs: Vec::new(),
            benchmark_refs: Vec::new(),
            scoring_method_ref: Some("local://scoring/stable".to_string()),
        });
        sign_research_experiment(&mut experiment);

        let plan = reproduction_plan(&experiment, "local");

        assert!(plan.immutable_refs.contains(&"bzz://immutable".to_string()));
        assert!(
            plan.mutable_refs
                .contains(&"https://example.com/run".to_string())
        );
        assert!(
            plan.mutable_refs
                .contains(&"local://scoring/stable".to_string())
        );
        assert!(!plan.warnings.is_empty());
    }

    #[test]
    fn creates_receipt_linked_research_run() {
        let experiment = create_research_experiment(ResearchExperimentInitOptionsV1 {
            title: "Receipt linked run".to_string(),
            author: "0xResearcher".to_string(),
            organization: None,
            hypothesis: "Run evidence should be audit-linked".to_string(),
            package_refs: vec!["bzz://immutable-experiment".to_string()],
            model_refs: vec!["bzz://model".to_string()],
            dataset_refs: vec!["bzz://dataset".to_string()],
            benchmark_refs: vec!["bzz://benchmark".to_string()],
            scoring_method_ref: Some("bzz://scoring".to_string()),
        });

        let run = create_research_experiment_run(
            &experiment,
            ResearchExperimentRunInitOptionsV1 {
                requester: "0xRunnerRequester".to_string(),
                runner: "local".to_string(),
                status: None,
                receipt_refs: vec!["receipt://receipt-1".to_string()],
                evaluation_result_refs: vec!["evaluation://evaluation-1".to_string()],
                validation_report_refs: vec!["validation://validation-1".to_string()],
                output_refs: vec!["bzz://run-output".to_string()],
                cost: None,
                notes: vec!["local reproduction completed".to_string()],
                metadata: None,
            },
        );
        let verification = verify_research_experiment_run(&run, Some(&experiment));

        assert_eq!(run.status, ResearchRunStatusV1::Succeeded);
        assert!(run.run_id.starts_with("experiment-run-"));
        assert_eq!(run.experiment_id, experiment.experiment_id);
        assert_eq!(run.receipt_refs, vec!["receipt://receipt-1"]);
        assert!(run.completed_at.is_some());
        assert!(verification.valid, "{verification:#?}");
        assert_eq!(
            run.signature.as_deref(),
            Some(expected_research_experiment_run_signature(&run).as_str())
        );
    }

    #[test]
    fn identity_signed_research_run_verifies_and_detects_tampering() {
        let experiment = create_research_experiment(ResearchExperimentInitOptionsV1 {
            title: "Identity signed run".to_string(),
            author: "0xResearcher".to_string(),
            organization: None,
            hypothesis: "Requester identity should sign run attempts".to_string(),
            package_refs: vec!["bzz://immutable-experiment".to_string()],
            model_refs: Vec::new(),
            dataset_refs: vec!["bzz://dataset".to_string()],
            benchmark_refs: Vec::new(),
            scoring_method_ref: Some("bzz://scoring".to_string()),
        });
        let mut run = create_research_experiment_run(
            &experiment,
            ResearchExperimentRunInitOptionsV1 {
                requester: "0xRunnerRequester".to_string(),
                runner: "marketplace".to_string(),
                status: None,
                receipt_refs: vec!["receipt://receipt-1".to_string()],
                evaluation_result_refs: Vec::new(),
                validation_report_refs: Vec::new(),
                output_refs: vec!["bzz://output".to_string()],
                cost: None,
                notes: Vec::new(),
                metadata: None,
            },
        );
        let identity =
            hivemind_identity::identity_from_seed("0xRunnerRequester", b"run-requester").unwrap();

        let envelope = sign_research_experiment_run_with_identity(&mut run, &identity).unwrap();
        let verification = verify_research_experiment_run(&run, Some(&experiment));

        assert_eq!(envelope.signer, run.requester);
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .as_deref()
                .unwrap()
                .starts_with("ed25519-payload-hash:")
        );

        run.output_refs.push("bzz://changed-output".to_string());
        let tampered = verify_research_experiment_run(&run, Some(&experiment));
        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path == "$.runId" || issue.path == "$.signature.payloadHash")
        );
    }

    #[test]
    fn research_run_store_lists_and_gets_runs() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("hivemind-research-run-store-{unique}"));
        fs::create_dir_all(dir.join("nested")).unwrap();

        let experiment = create_research_experiment(ResearchExperimentInitOptionsV1 {
            title: "Run store".to_string(),
            author: "0xResearcher".to_string(),
            organization: None,
            hypothesis: "Run store should ignore experiment JSON while listing runs".to_string(),
            package_refs: vec!["bzz://immutable-experiment".to_string()],
            model_refs: Vec::new(),
            dataset_refs: vec!["bzz://dataset".to_string()],
            benchmark_refs: Vec::new(),
            scoring_method_ref: Some("bzz://scoring".to_string()),
        });
        let run = create_research_experiment_run(
            &experiment,
            ResearchExperimentRunInitOptionsV1 {
                requester: "0xRunnerRequester".to_string(),
                runner: "local".to_string(),
                status: None,
                receipt_refs: vec!["receipt://receipt-1".to_string()],
                evaluation_result_refs: vec!["evaluation://evaluation-1".to_string()],
                validation_report_refs: Vec::new(),
                output_refs: Vec::new(),
                cost: None,
                notes: Vec::new(),
                metadata: None,
            },
        );
        fs::write(
            dir.join("experiment.json"),
            serde_json::to_vec_pretty(&experiment).unwrap(),
        )
        .unwrap();
        let run_path = write_research_experiment_run(&dir.join("nested"), &run).unwrap();

        let summary = list_research_experiment_runs(&dir).unwrap();
        assert_eq!(summary.run_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.terminal_count, 1);
        assert_eq!(summary.receipt_linked_count, 1);
        assert_eq!(summary.evaluation_linked_count, 1);
        assert_eq!(summary.runs[0].run_id, run.run_id);
        assert_eq!(summary.runs[0].run_path, run_path.display().to_string());

        let lookup = get_research_experiment_run(&dir, &run.run_id)
            .unwrap()
            .unwrap();
        assert_eq!(lookup.run.run_id, run.run_id);
        assert!(lookup.verification.valid, "{:#?}", lookup.verification);
        assert!(
            get_research_experiment_run(&dir, "missing")
                .unwrap()
                .is_none()
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn research_experiment_store_lists_and_gets_experiments() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("hivemind-research-store-{unique}"));
        fs::create_dir_all(dir.join("nested")).unwrap();

        let experiment = create_research_experiment(ResearchExperimentInitOptionsV1 {
            title: "RAG quality comparison".to_string(),
            author: "0xResearcher".to_string(),
            organization: Some("Hivemind Lab".to_string()),
            hypothesis: "Chunk strategy A improves answer quality".to_string(),
            package_refs: vec![
                "bzz://immutable-experiment".to_string(),
                "https://example.com/dataset/latest".to_string(),
            ],
            model_refs: vec!["bzz://model-a".to_string()],
            dataset_refs: vec!["bzz://dataset".to_string()],
            benchmark_refs: vec!["bzz://benchmark".to_string()],
            scoring_method_ref: Some("bzz://scoring".to_string()),
        });
        fs::write(
            dir.join("nested").join("experiment.json"),
            serde_json::to_vec_pretty(&experiment).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("identity.json"),
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": "swarm-ai.identity.keypair.v1",
                "subject": "0xResearcher"
            }))
            .unwrap(),
        )
        .unwrap();

        let summary = list_research_experiments(&dir).unwrap();
        assert_eq!(summary.experiment_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.invalid_count, 0);
        assert_eq!(summary.mutable_ref_count, 1);
        assert!(summary.warning_count > 0);
        assert_eq!(
            summary.experiments[0].experiment_id,
            experiment.experiment_id
        );
        assert_eq!(summary.experiments[0].package_ref_count, 2);
        assert!(summary.experiments[0].signature_present);

        let lookup = get_research_experiment(&dir, &experiment.experiment_id)
            .unwrap()
            .unwrap();
        assert_eq!(lookup.experiment.experiment_id, experiment.experiment_id);
        assert!(lookup.verification.valid, "{:#?}", lookup.verification);
        assert_eq!(lookup.reproduction_plan.mutable_refs.len(), 1);
        assert!(get_research_experiment(&dir, "missing").unwrap().is_none());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn evaluation_run_v2_links_results_and_detects_tampering() {
        let mut run = create_evaluation_run_v2(EvaluationRunV2InitOptionsV1 {
            experiment_id: Some("experiment-local".to_string()),
            eval_id: Some("eval/retrieval-quality".to_string()),
            benchmark_id: None,
            requester: "0xResearcher".to_string(),
            runner: "local".to_string(),
            target_ref: "bzz://package-under-test".to_string(),
            status: Some(ResearchRunStatusV1::Succeeded),
            sample_count: Some(12),
            privacy_tier: Some(PrivacyTier::LocalOnly),
            integrity_tier: Some(IntegrityTier::DeterministicReplay),
            input_refs: vec!["bzz://eval-inputs".to_string()],
            dataset_refs: vec!["bzz://licensed-dataset".to_string()],
            scoring_method_refs: vec!["bzz://scoring".to_string()],
            receipt_refs: vec!["receipt://receipt-1".to_string()],
            evaluation_result_refs: vec!["evaluation://evaluation-v2-1".to_string()],
            result_record_refs: Vec::new(),
            validation_report_refs: vec!["validation://report-1".to_string()],
            output_refs: vec!["bzz://outputs".to_string()],
            artifact_refs: vec![ResearchArtifactRefV1 {
                artifact_id: Some("dataset".to_string()),
                role: "dataset".to_string(),
                reference: "bzz://licensed-dataset".to_string(),
                content_hash: Some("sha256:dataset".to_string()),
                license_ref: Some("bzz://dataset-license".to_string()),
                privacy_tier: Some(PrivacyTier::LocalOnly),
                access_policy_refs: Vec::new(),
                notes: Vec::new(),
            }],
            random_seeds: vec!["42".to_string()],
            metadata: None,
        });

        let verification = verify_evaluation_run_v2(&run);
        assert!(verification.valid, "{verification:#?}");
        assert!(run.evaluation_run_id.starts_with("evaluation-run-v2-"));
        assert_eq!(
            run.signature.as_deref(),
            Some(expected_evaluation_run_v2_signature(&run).as_str())
        );

        run.sample_count = 0;
        let tampered = verify_evaluation_run_v2(&run);
        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path == "$.sampleCount" || issue.path == "$.evaluationRunId")
        );
    }

    #[test]
    fn research_result_records_are_signed_and_negative_results_are_supported() {
        let record = create_research_result_record(ResearchResultRecordInitOptionsV1 {
            result_kind: ResearchResultKindV1::Negative,
            title: "Embedding model did not improve retrieval".to_string(),
            producer: "0xResearcher".to_string(),
            experiment_id: Some("experiment-local".to_string()),
            run_id: None,
            evaluation_run_id: Some("evaluation-run-v2-local".to_string()),
            hypothesis: Some("Model A improves retrieval quality".to_string()),
            summary: "The measured quality did not exceed the baseline.".to_string(),
            metrics: Some(json!({ "ndcg_at_10": 0.41, "baseline_ndcg_at_10": 0.43 })),
            result_refs: vec!["result://result-table".to_string()],
            receipt_refs: vec!["receipt://receipt-1".to_string()],
            evaluation_result_refs: vec!["evaluation://evaluation-v2-1".to_string()],
            validation_report_refs: vec!["validation://report-1".to_string()],
            artifact_refs: Vec::new(),
            limitations: vec![
                "Small dataset; rerun on larger corpus before publication".to_string(),
            ],
        });

        let verification = verify_research_result_record(&record);
        assert!(verification.valid, "{verification:#?}");
        assert!(record.result_id.starts_with("research-result-"));
        assert_eq!(
            record.signature.as_deref(),
            Some(expected_research_result_record_signature(&record).as_str())
        );
    }

    #[test]
    fn reproducibility_bundle_collects_research_objects_and_requires_licensed_data() {
        let experiment = create_research_experiment(ResearchExperimentInitOptionsV1 {
            title: "Compare embedding models".to_string(),
            author: "0xResearcher".to_string(),
            organization: Some("Hivemind Lab".to_string()),
            hypothesis: "Model A has better retrieval quality than Model B".to_string(),
            package_refs: vec!["bzz://experiment-package".to_string()],
            model_refs: vec!["bzz://model-a".to_string()],
            dataset_refs: vec!["bzz://dataset".to_string()],
            benchmark_refs: vec!["bzz://benchmark".to_string()],
            scoring_method_ref: Some("bzz://scoring-method".to_string()),
        });
        let run = create_research_experiment_run(
            &experiment,
            ResearchExperimentRunInitOptionsV1 {
                requester: "0xResearcher".to_string(),
                runner: "local".to_string(),
                status: Some(ResearchRunStatusV1::Succeeded),
                receipt_refs: vec!["receipt://receipt-1".to_string()],
                evaluation_result_refs: Vec::new(),
                validation_report_refs: vec!["validation://report-1".to_string()],
                output_refs: vec!["bzz://outputs".to_string()],
                cost: None,
                notes: Vec::new(),
                metadata: None,
            },
        );
        let result = create_research_result_record(ResearchResultRecordInitOptionsV1 {
            result_kind: ResearchResultKindV1::Reproduction,
            title: "Local reproduction succeeded".to_string(),
            producer: "0xResearcher".to_string(),
            experiment_id: Some(experiment.experiment_id.clone()),
            run_id: Some(run.run_id.clone()),
            evaluation_run_id: None,
            hypothesis: Some(experiment.hypothesis.clone()),
            summary: "The local run reproduced the recorded output shape.".to_string(),
            metrics: Some(json!({ "matches_expected_shape": true })),
            result_refs: vec!["result://local-reproduction".to_string()],
            receipt_refs: vec!["receipt://receipt-1".to_string()],
            evaluation_result_refs: Vec::new(),
            validation_report_refs: vec!["validation://report-1".to_string()],
            artifact_refs: Vec::new(),
            limitations: Vec::new(),
        });

        let mut bundle = create_reproducibility_bundle(ReproducibilityBundleInitOptionsV1 {
            title: None,
            producer: "0xResearcher".to_string(),
            experiment,
            experiment_ref: Some("bzz://experiment-manifest".to_string()),
            run_refs: Vec::new(),
            runs: vec![run],
            evaluation_run_refs: Vec::new(),
            evaluation_runs: Vec::new(),
            result_record_refs: Vec::new(),
            result_records: vec![result],
            receipt_refs: vec!["receipt://receipt-1".to_string()],
            validation_report_refs: vec!["validation://report-1".to_string()],
            evaluation_result_refs: Vec::new(),
            output_refs: vec!["bzz://outputs".to_string()],
            artifact_refs: vec![ResearchArtifactRefV1 {
                artifact_id: Some("dataset".to_string()),
                role: "dataset".to_string(),
                reference: "bzz://dataset".to_string(),
                content_hash: Some("sha256:dataset".to_string()),
                license_ref: Some("bzz://dataset-license".to_string()),
                privacy_tier: Some(PrivacyTier::LocalOnly),
                access_policy_refs: Vec::new(),
                notes: Vec::new(),
            }],
            immutable_refs: Vec::new(),
            mutable_refs: Vec::new(),
            random_seeds: Vec::new(),
            reproduction_steps: Vec::new(),
            claims_exact_reproduction: Some(true),
            notes: Vec::new(),
        });

        let verification = verify_reproducibility_bundle(&bundle);
        assert!(verification.valid, "{verification:#?}");
        assert!(bundle.bundle_id.starts_with("repro-bundle-"));

        bundle.artifact_refs[0].license_ref = None;
        bundle
            .mutable_refs
            .push("feed://latest-experiment".to_string());
        sign_reproducibility_bundle(&mut bundle);
        let invalid = verify_reproducibility_bundle(&bundle);
        assert!(!invalid.valid);
        assert!(invalid.issues.iter().any(|issue| {
            issue.path == "$.artifactRefs[0].licenseRef" || issue.path == "$.mutableRefs"
        }));
    }
}
