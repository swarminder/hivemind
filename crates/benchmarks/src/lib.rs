use chrono::{DateTime, SecondsFormat, Utc};
use hivemind_core::{
    AccessGrantV1, ExecutionOptions, ExecutionPrivacy, ExecutionRequestV1, ExecutionResponseV1,
    ExecutionStatus, LicenseInfo, LicenseType, ValidationIssue, canonicalize_json,
    hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const DEV_EVALUATION_SIGNATURE_PREFIX: &str = "dev-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkVisibility {
    Public,
    Private,
    Hidden,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BenchmarkScoringMethod {
    RecallAtK,
    ExactMatch,
    EmbeddingShape,
    Latency,
    Hybrid,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ScoringRuleV1 {
    pub id: String,
    pub method: BenchmarkScoringMethod,
    #[serde(default)]
    pub parameters: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkPackageV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    pub name: String,
    pub task: String,
    pub version: String,
    #[serde(rename = "datasetRefs")]
    pub dataset_refs: Vec<String>,
    #[serde(rename = "scoringRules")]
    pub scoring_rules: Vec<ScoringRuleV1>,
    pub visibility: BenchmarkVisibility,
    pub license: LicenseInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkSplitV1 {
    pub name: String,
    #[serde(rename = "datasetRefs")]
    pub dataset_refs: Vec<String>,
    #[serde(default = "default_weight")]
    pub weight: f64,
    #[serde(default)]
    pub hidden: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkPrivacyRulesV1 {
    #[serde(rename = "requiredTier")]
    pub required_tier: String,
    #[serde(rename = "allowPublicResults", default = "default_true")]
    pub allow_public_results: bool,
    #[serde(rename = "allowRemoteRunners", default = "default_true")]
    pub allow_remote_runners: bool,
    #[serde(rename = "requireResultRedaction", default)]
    pub require_result_redaction: bool,
    #[serde(rename = "accessPolicyRefs", default)]
    pub access_policy_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkExpectedRuntimeV1 {
    #[serde(rename = "p50Ms", default)]
    pub p50_ms: u64,
    #[serde(rename = "p95Ms", default)]
    pub p95_ms: u64,
    #[serde(rename = "maxMs")]
    pub max_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkSuiteInitOptionsV1 {
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    pub name: String,
    pub task: String,
    pub version: String,
    #[serde(rename = "maintainerId")]
    pub maintainer_id: String,
    #[serde(default)]
    pub modalities: Vec<String>,
    #[serde(rename = "datasetRefs", default)]
    pub dataset_refs: Vec<String>,
    #[serde(rename = "scoringMethodRef")]
    pub scoring_method_ref: String,
    #[serde(default)]
    pub splits: Vec<BenchmarkSplitV1>,
    #[serde(rename = "allowedModelRefs", default)]
    pub allowed_model_refs: Vec<String>,
    #[serde(rename = "allowedRuntimes", default)]
    pub allowed_runtimes: Vec<String>,
    #[serde(rename = "privacyRules", default = "default_benchmark_privacy_rules")]
    pub privacy_rules: BenchmarkPrivacyRulesV1,
    #[serde(
        rename = "expectedRuntime",
        default = "default_benchmark_expected_runtime"
    )]
    pub expected_runtime: BenchmarkExpectedRuntimeV1,
    #[serde(rename = "metricNames", default)]
    pub metric_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseInfo>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkSuiteV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "suiteId")]
    pub suite_id: String,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    pub name: String,
    pub task: String,
    pub version: String,
    #[serde(rename = "maintainerId")]
    pub maintainer_id: String,
    pub modalities: Vec<String>,
    #[serde(rename = "datasetRefs")]
    pub dataset_refs: Vec<String>,
    #[serde(rename = "scoringMethodRef")]
    pub scoring_method_ref: String,
    pub splits: Vec<BenchmarkSplitV1>,
    #[serde(rename = "allowedModelRefs")]
    pub allowed_model_refs: Vec<String>,
    #[serde(rename = "allowedRuntimes")]
    pub allowed_runtimes: Vec<String>,
    #[serde(rename = "privacyRules")]
    pub privacy_rules: BenchmarkPrivacyRulesV1,
    #[serde(rename = "expectedRuntime")]
    pub expected_runtime: BenchmarkExpectedRuntimeV1,
    #[serde(rename = "metricNames")]
    pub metric_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseInfo>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkSuiteVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "suiteId")]
    pub suite_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkPackContextV1 {
    #[serde(rename = "suiteRef", default, skip_serializing_if = "Option::is_none")]
    pub suite_ref: Option<String>,
    #[serde(rename = "hiddenChallengeCommitmentRefs", default)]
    pub hidden_challenge_commitment_refs: Vec<String>,
    #[serde(rename = "validationMethodRefs", default)]
    pub validation_method_refs: Vec<String>,
    #[serde(
        rename = "reportSchema",
        default = "default_benchmark_pack_report_schema"
    )]
    pub report_schema: Value,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

impl Default for BenchmarkPackContextV1 {
    fn default() -> Self {
        Self {
            suite_ref: None,
            hidden_challenge_commitment_refs: Vec::new(),
            validation_method_refs: Vec::new(),
            report_schema: default_benchmark_pack_report_schema(),
            metadata: empty_metadata(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkPackProjectionRequestV1 {
    pub suite: BenchmarkSuiteV1,
    #[serde(default)]
    pub context: BenchmarkPackContextV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkPackV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packId")]
    pub pack_id: String,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    pub name: String,
    pub task: String,
    pub version: String,
    #[serde(rename = "maintainerId")]
    pub maintainer_id: String,
    #[serde(rename = "suiteRef", default, skip_serializing_if = "Option::is_none")]
    pub suite_ref: Option<String>,
    #[serde(rename = "datasetRefs")]
    pub dataset_refs: Vec<String>,
    #[serde(rename = "hiddenChallengeCommitmentRefs")]
    pub hidden_challenge_commitment_refs: Vec<String>,
    #[serde(rename = "scoringFunctionRef")]
    pub scoring_function_ref: String,
    #[serde(rename = "allowedRuntimes")]
    pub allowed_runtimes: Vec<String>,
    #[serde(rename = "privacyRules")]
    pub privacy_rules: BenchmarkPrivacyRulesV1,
    #[serde(rename = "reportSchema")]
    pub report_schema: Value,
    #[serde(rename = "validationMethodRefs")]
    pub validation_method_refs: Vec<String>,
    #[serde(rename = "metricNames")]
    pub metric_names: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkPackVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packId")]
    pub pack_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkPackProjectionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub pack: BenchmarkPackV1,
    pub verification: BenchmarkPackVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkSuiteIndexEntryV1 {
    #[serde(rename = "suiteId")]
    pub suite_id: String,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    pub name: String,
    pub task: String,
    pub version: String,
    #[serde(rename = "maintainerId")]
    pub maintainer_id: String,
    #[serde(rename = "metricNames")]
    pub metric_names: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "suitePath")]
    pub suite_path: String,
    pub verification: BenchmarkSuiteVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkSuiteStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "suiteCount")]
    pub suite_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub suites: Vec<BenchmarkSuiteIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkSuiteLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "suiteId")]
    pub suite_id: String,
    #[serde(rename = "suitePath")]
    pub suite_path: String,
    pub suite: BenchmarkSuiteV1,
    pub verification: BenchmarkSuiteVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DatasetEntryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "entryId")]
    pub entry_id: String,
    pub task: String,
    pub input: Value,
    #[serde(rename = "expectedOutput")]
    pub expected_output: Value,
    #[serde(default = "default_weight")]
    pub weight: f64,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct EvaluationScoresV1 {
    pub quality: f64,
    pub latency: f64,
    pub overall: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct EvaluationMetricsV1 {
    pub samples: u64,
    pub succeeded: u64,
    pub failed: u64,
    #[serde(rename = "totalMs")]
    pub total_ms: u64,
    #[serde(rename = "averageMs")]
    pub average_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationSampleResultV1 {
    #[serde(rename = "entryId")]
    pub entry_id: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub status: ExecutionStatus,
    pub quality: f64,
    pub latency: f64,
    #[serde(rename = "totalMs")]
    pub total_ms: u64,
    #[serde(rename = "receiptId", default)]
    pub receipt_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evaluationId")]
    pub evaluation_id: String,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    #[serde(rename = "benchmarkVersion")]
    pub benchmark_version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId", default)]
    pub runner_id: Option<String>,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    pub scores: EvaluationScoresV1,
    pub metrics: EvaluationMetricsV1,
    #[serde(rename = "resultRefs")]
    pub result_refs: Vec<String>,
    #[serde(rename = "sampleResults")]
    pub sample_results: Vec<EvaluationSampleResultV1>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResultVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evaluationId")]
    pub evaluation_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResultIndexEntryV1 {
    #[serde(rename = "evaluationId")]
    pub evaluation_id: String,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    #[serde(rename = "benchmarkVersion")]
    pub benchmark_version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId", default)]
    pub runner_id: Option<String>,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    #[serde(rename = "overallScore")]
    pub overall_score: f64,
    #[serde(rename = "qualityScore")]
    pub quality_score: f64,
    #[serde(rename = "latencyScore")]
    pub latency_score: f64,
    #[serde(rename = "sampleCount")]
    pub sample_count: u64,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "resultPath")]
    pub result_path: String,
    pub verification: EvaluationResultVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResultStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "evaluationCount")]
    pub evaluation_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub evaluations: Vec<EvaluationResultIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResultLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evaluationId")]
    pub evaluation_id: String,
    #[serde(rename = "resultPath")]
    pub result_path: String,
    pub evaluation: EvaluationResultV1,
    pub verification: EvaluationResultVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct EvaluationCostV2 {
    pub amount: f64,
    pub currency: String,
    #[serde(
        rename = "pricingRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pricing_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct EvaluationTimingV2 {
    #[serde(rename = "startedAt", default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<String>,
    #[serde(rename = "totalMs")]
    pub total_ms: u64,
    #[serde(rename = "averageMs")]
    pub average_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationEnvironmentV2 {
    #[serde(
        rename = "runnerType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub runner_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(rename = "hardwareRefs", default)]
    pub hardware_refs: Vec<String>,
    #[serde(rename = "softwareRefs", default)]
    pub software_refs: Vec<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

impl Default for EvaluationEnvironmentV2 {
    fn default() -> Self {
        Self {
            runner_type: None,
            os: None,
            architecture: None,
            hardware_refs: Vec::new(),
            software_refs: Vec::new(),
            metadata: json!({}),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct EvaluationErrorV2 {
    #[serde(rename = "sampleId", default, skip_serializing_if = "Option::is_none")]
    pub sample_id: Option<String>,
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResultV2ContextV1 {
    #[serde(rename = "suiteId", default, skip_serializing_if = "Option::is_none")]
    pub suite_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing: Option<EvaluationTimingV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<EvaluationCostV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<EvaluationEnvironmentV2>,
    #[serde(rename = "artifactRefs", default)]
    pub artifact_refs: Vec<String>,
    #[serde(rename = "randomSeeds", default)]
    pub random_seeds: Vec<String>,
    #[serde(default)]
    pub errors: Vec<EvaluationErrorV2>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

impl Default for EvaluationResultV2ContextV1 {
    fn default() -> Self {
        Self {
            suite_id: None,
            timing: None,
            cost: None,
            environment: None,
            artifact_refs: Vec::new(),
            random_seeds: Vec::new(),
            errors: Vec::new(),
            metadata: json!({}),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResultV2ProjectionRequestV1 {
    pub result: EvaluationResultV1,
    #[serde(default)]
    pub context: EvaluationResultV2ContextV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResultV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evaluationId")]
    pub evaluation_id: String,
    #[serde(
        rename = "sourceEvaluationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_evaluation_id: Option<String>,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    #[serde(rename = "benchmarkVersion")]
    pub benchmark_version: String,
    #[serde(rename = "suiteId", default, skip_serializing_if = "Option::is_none")]
    pub suite_id: Option<String>,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    pub score: f64,
    pub scores: EvaluationScoresV1,
    pub metrics: EvaluationMetricsV1,
    pub timing: EvaluationTimingV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<EvaluationCostV2>,
    pub environment: EvaluationEnvironmentV2,
    #[serde(rename = "artifactRefs")]
    pub artifact_refs: Vec<String>,
    #[serde(rename = "resultRefs")]
    pub result_refs: Vec<String>,
    #[serde(rename = "randomSeeds")]
    pub random_seeds: Vec<String>,
    pub errors: Vec<EvaluationErrorV2>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResultV2VerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evaluationId")]
    pub evaluation_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResultV2IndexEntryV1 {
    #[serde(rename = "evaluationId")]
    pub evaluation_id: String,
    #[serde(
        rename = "sourceEvaluationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_evaluation_id: Option<String>,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    #[serde(rename = "benchmarkVersion")]
    pub benchmark_version: String,
    #[serde(rename = "suiteId", default, skip_serializing_if = "Option::is_none")]
    pub suite_id: Option<String>,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    pub score: f64,
    #[serde(rename = "sampleCount")]
    pub sample_count: u64,
    #[serde(rename = "totalMs")]
    pub total_ms: u64,
    #[serde(
        rename = "costAmount",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cost_amount: Option<f64>,
    #[serde(
        rename = "costCurrency",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cost_currency: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "resultPath")]
    pub result_path: String,
    pub verification: EvaluationResultV2VerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResultV2StoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "evaluationCount")]
    pub evaluation_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub evaluations: Vec<EvaluationResultV2IndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationResultV2LookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evaluationId")]
    pub evaluation_id: String,
    #[serde(rename = "resultPath")]
    pub result_path: String,
    pub evaluation: EvaluationResultV2,
    pub verification: EvaluationResultV2VerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationLeaderboardEntryV1 {
    pub rank: u32,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    #[serde(rename = "benchmarkVersion")]
    pub benchmark_version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(rename = "overallScore")]
    pub overall_score: f64,
    #[serde(rename = "qualityScore")]
    pub quality_score: f64,
    #[serde(rename = "latencyScore")]
    pub latency_score: f64,
    #[serde(rename = "averageMs")]
    pub average_ms: f64,
    #[serde(rename = "sampleCount")]
    pub sample_count: u64,
    #[serde(rename = "succeededSampleCount")]
    pub succeeded_sample_count: u64,
    #[serde(rename = "failedSampleCount")]
    pub failed_sample_count: u64,
    #[serde(rename = "evaluationCount")]
    pub evaluation_count: usize,
    #[serde(rename = "validatorCount")]
    pub validator_count: usize,
    #[serde(rename = "evaluationIds")]
    pub evaluation_ids: Vec<String>,
    #[serde(rename = "validatorIds")]
    pub validator_ids: Vec<String>,
    #[serde(rename = "receiptIds")]
    pub receipt_ids: Vec<String>,
    #[serde(rename = "resultRefs")]
    pub result_refs: Vec<String>,
    #[serde(rename = "resultPaths")]
    pub result_paths: Vec<String>,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    #[serde(rename = "firstEvaluatedAt")]
    pub first_evaluated_at: String,
    #[serde(rename = "latestEvaluatedAt")]
    pub latest_evaluated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvaluationLeaderboardV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "benchmarkCount")]
    pub benchmark_count: usize,
    #[serde(rename = "evaluationCount")]
    pub evaluation_count: usize,
    #[serde(rename = "validEvaluationCount")]
    pub valid_evaluation_count: usize,
    #[serde(rename = "invalidEvaluationCount")]
    pub invalid_evaluation_count: usize,
    #[serde(rename = "entryCount")]
    pub entry_count: usize,
    pub entries: Vec<EvaluationLeaderboardEntryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChallengeCommitmentInitOptionsV1 {
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    #[serde(rename = "benchmarkVersion")]
    pub benchmark_version: String,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    #[serde(rename = "challengeSetHash")]
    pub challenge_set_hash: String,
    #[serde(
        rename = "answerSetHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub answer_set_hash: Option<String>,
    #[serde(rename = "saltHash")]
    pub salt_hash: String,
    #[serde(rename = "challengeCount")]
    pub challenge_count: u64,
    #[serde(rename = "publicDatasetRefs", default)]
    pub public_dataset_refs: Vec<String>,
    #[serde(rename = "hiddenRefCommitments", default)]
    pub hidden_ref_commitments: Vec<String>,
    #[serde(rename = "scoringRuleRefs", default)]
    pub scoring_rule_refs: Vec<String>,
    #[serde(
        rename = "revealAfter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reveal_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChallengeCommitmentV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "commitmentId")]
    pub commitment_id: String,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    #[serde(rename = "benchmarkVersion")]
    pub benchmark_version: String,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    #[serde(rename = "challengeSetHash")]
    pub challenge_set_hash: String,
    #[serde(
        rename = "answerSetHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub answer_set_hash: Option<String>,
    #[serde(rename = "saltHash")]
    pub salt_hash: String,
    #[serde(rename = "challengeCount")]
    pub challenge_count: u64,
    #[serde(rename = "publicDatasetRefs")]
    pub public_dataset_refs: Vec<String>,
    #[serde(rename = "hiddenRefCommitments")]
    pub hidden_ref_commitments: Vec<String>,
    #[serde(rename = "scoringRuleRefs")]
    pub scoring_rule_refs: Vec<String>,
    #[serde(
        rename = "revealAfter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reveal_after: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default = "empty_metadata")]
    pub metadata: Value,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChallengeCommitmentVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "commitmentId")]
    pub commitment_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChallengeCommitmentIndexEntryV1 {
    #[serde(rename = "commitmentId")]
    pub commitment_id: String,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    #[serde(rename = "benchmarkVersion")]
    pub benchmark_version: String,
    #[serde(rename = "validatorId")]
    pub validator_id: String,
    #[serde(rename = "challengeCount")]
    pub challenge_count: u64,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "commitmentPath")]
    pub commitment_path: String,
    pub verification: ChallengeCommitmentVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChallengeCommitmentStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "commitmentCount")]
    pub commitment_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub commitments: Vec<ChallengeCommitmentIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ChallengeCommitmentLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "commitmentId")]
    pub commitment_id: String,
    #[serde(rename = "commitmentPath")]
    pub commitment_path: String,
    pub commitment: ChallengeCommitmentV1,
    pub verification: ChallengeCommitmentVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct BenchmarkMetricsV1 {
    #[serde(rename = "manifestParseMs")]
    pub manifest_parse_ms: u64,
    #[serde(rename = "storageDownloadMs")]
    pub storage_download_ms: u64,
    #[serde(rename = "coldModelLoadMs")]
    pub cold_model_load_ms: u64,
    #[serde(rename = "warmModelLoadMs")]
    pub warm_model_load_ms: u64,
    #[serde(rename = "executionMs")]
    pub execution_ms: u64,
    #[serde(rename = "receiptCreationMs")]
    pub receipt_creation_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BenchmarkReportV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub metrics: BenchmarkMetricsV1,
    pub result: String,
}

pub fn mini_embedding_benchmark() -> BenchmarkPackageV1 {
    BenchmarkPackageV1 {
        schema_version: "swarm-ai.benchmark-package.v1".to_string(),
        benchmark_id: "commons/embedding-basic-v1".to_string(),
        name: "Basic Embedding Shape Benchmark".to_string(),
        task: "embedding".to_string(),
        version: "1.0.0".to_string(),
        dataset_refs: vec!["local://datasets/embedding-basic-v1".to_string()],
        scoring_rules: vec![
            ScoringRuleV1 {
                id: "embedding-shape".to_string(),
                method: BenchmarkScoringMethod::EmbeddingShape,
                parameters: json!({ "minDimensions": 4 }),
            },
            ScoringRuleV1 {
                id: "latency".to_string(),
                method: BenchmarkScoringMethod::Latency,
                parameters: json!({ "deadlineMs": 30000 }),
            },
        ],
        visibility: BenchmarkVisibility::Public,
        license: LicenseInfo {
            license_type: LicenseType::Open,
            name: Some("Apache-2.0".to_string()),
            url: None,
        },
    }
}

pub fn mini_embedding_benchmark_suite() -> BenchmarkSuiteV1 {
    create_benchmark_suite(BenchmarkSuiteInitOptionsV1 {
        benchmark_id: "commons/embedding-basic-v1".to_string(),
        name: "Basic Embedding Shape Benchmark".to_string(),
        task: "embedding".to_string(),
        version: "1.0.0".to_string(),
        maintainer_id: "local-dev-validator".to_string(),
        modalities: vec!["text".to_string(), "embedding".to_string()],
        dataset_refs: vec!["local://datasets/embedding-basic-v1".to_string()],
        scoring_method_ref: "local://scoring/embedding-shape".to_string(),
        splits: vec![BenchmarkSplitV1 {
            name: "smoke".to_string(),
            dataset_refs: vec!["local://datasets/embedding-basic-v1".to_string()],
            weight: 1.0,
            hidden: false,
        }],
        allowed_model_refs: vec!["package-kind://model".to_string()],
        allowed_runtimes: vec!["browser".to_string(), "local".to_string()],
        privacy_rules: BenchmarkPrivacyRulesV1 {
            required_tier: "public".to_string(),
            allow_public_results: true,
            allow_remote_runners: true,
            require_result_redaction: false,
            access_policy_refs: Vec::new(),
        },
        expected_runtime: BenchmarkExpectedRuntimeV1 {
            p50_ms: 1_000,
            p95_ms: 5_000,
            max_ms: 30_000,
        },
        metric_names: vec![
            "quality".to_string(),
            "latency".to_string(),
            "overall".to_string(),
        ],
        license: Some(LicenseInfo {
            license_type: LicenseType::Open,
            name: Some("Apache-2.0".to_string()),
            url: None,
        }),
        metadata: json!({ "source": "mini-embedding-benchmark" }),
    })
}

pub fn mini_embedding_dataset() -> Vec<DatasetEntryV1> {
    vec![
        dataset_entry(
            "embedding-basic-001",
            json!({ "text": "hello benchmark commons" }),
            vec!["smoke", "short-text"],
        ),
        dataset_entry(
            "embedding-basic-002",
            json!({ "text": "decentralized package registry" }),
            vec!["smoke", "domain-text"],
        ),
        dataset_entry(
            "embedding-basic-003",
            json!({ "text": "rust wasm local runner" }),
            vec!["smoke", "technical-text"],
        ),
    ]
}

pub fn benchmark_execution_request(
    benchmark: &BenchmarkPackageV1,
    entry: &DatasetEntryV1,
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    access_grant: Option<AccessGrantV1>,
) -> ExecutionRequestV1 {
    let package_ref = package_ref.into();
    let request_seed = json!({
        "benchmarkId": benchmark.benchmark_id,
        "benchmarkVersion": benchmark.version,
        "entryId": entry.entry_id,
        "packageRef": package_ref,
    });
    ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: stable_id("benchmark-request", &request_seed),
        package_ref,
        package_id: package_id.into(),
        package_version: package_version.into(),
        preferred_artifact_group: None,
        task: benchmark.task.clone(),
        input: entry.input.clone(),
        options: ExecutionOptions {
            stream: false,
            deadline_ms: Some(scoring_deadline_ms(benchmark)),
            deterministic: Some(true),
        },
        privacy: ExecutionPrivacy::default(),
        access_grant,
        access_revocation_list: None,
    }
}

pub fn sample_result_from_response(
    entry: &DatasetEntryV1,
    response: &ExecutionResponseV1,
    deadline_ms: u64,
) -> EvaluationSampleResultV1 {
    EvaluationSampleResultV1 {
        entry_id: entry.entry_id.clone(),
        request_id: response.request_id.clone(),
        status: response.status.clone(),
        quality: score_quality(entry, response),
        latency: score_latency(deadline_ms, response.metrics.total_ms),
        total_ms: response.metrics.total_ms,
        receipt_id: response_receipt_id(response),
    }
}

pub fn create_benchmark_suite(options: BenchmarkSuiteInitOptionsV1) -> BenchmarkSuiteV1 {
    let mut modalities = normalize_string_list(options.modalities);
    if modalities.is_empty() && !options.task.trim().is_empty() {
        modalities.push(options.task.clone());
    }
    let dataset_refs = normalize_string_list(options.dataset_refs);
    let mut splits = options.splits;
    if splits.is_empty() && !dataset_refs.is_empty() {
        splits.push(BenchmarkSplitV1 {
            name: "default".to_string(),
            dataset_refs: dataset_refs.clone(),
            weight: 1.0,
            hidden: false,
        });
    }
    for split in &mut splits {
        split.dataset_refs = normalize_string_list(std::mem::take(&mut split.dataset_refs));
    }
    splits.sort_by(|left, right| left.name.cmp(&right.name));
    let mut suite = BenchmarkSuiteV1 {
        schema_version: "hivemind.benchmark_suite.v1".to_string(),
        suite_id: String::new(),
        benchmark_id: options.benchmark_id,
        name: options.name,
        task: options.task,
        version: options.version,
        maintainer_id: options.maintainer_id,
        modalities,
        dataset_refs,
        scoring_method_ref: options.scoring_method_ref,
        splits,
        allowed_model_refs: normalize_string_list(options.allowed_model_refs),
        allowed_runtimes: normalize_string_list(options.allowed_runtimes),
        privacy_rules: normalize_benchmark_privacy_rules(options.privacy_rules),
        expected_runtime: options.expected_runtime,
        metric_names: normalize_string_list(options.metric_names),
        license: options.license,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        metadata: options.metadata,
        signature: String::new(),
    };
    sign_benchmark_suite(&mut suite);
    suite.suite_id = canonical_benchmark_suite_id(&suite)
        .expect("benchmark suite should serialize for canonical id");
    suite
}

pub fn sign_benchmark_suite(suite: &mut BenchmarkSuiteV1) {
    suite.signature = expected_benchmark_suite_signature(suite);
}

pub fn sign_benchmark_suite_with_identity(
    suite: &mut BenchmarkSuiteV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != suite.maintainer_id {
        anyhow::bail!(
            "identity subject {} does not match benchmark suite maintainer {}",
            identity.subject,
            suite.maintainer_id
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "benchmark-suite",
        &benchmark_suite_signing_value(suite),
    )?;
    suite.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    suite.suite_id = canonical_benchmark_suite_id(suite)?;
    Ok(envelope)
}

pub fn expected_benchmark_suite_signature(suite: &BenchmarkSuiteV1) -> String {
    dev_signature(
        "benchmark-suite",
        &suite.maintainer_id,
        &benchmark_suite_signing_value(suite),
    )
}

pub fn canonical_benchmark_suite_id(suite: &BenchmarkSuiteV1) -> serde_json::Result<String> {
    let mut signed = suite.clone();
    signed.suite_id.clear();
    let value = serde_json::to_value(signed)?;
    Ok(stable_id_from_value("benchmark-suite", &value))
}

pub fn verify_benchmark_suite(suite: &BenchmarkSuiteV1) -> BenchmarkSuiteVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if suite.schema_version != "hivemind.benchmark_suite.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.benchmark_suite.v1",
        ));
    }
    for (path, value, message) in [
        ("$.suiteId", suite.suite_id.as_str(), "Suite id is required"),
        (
            "$.benchmarkId",
            suite.benchmark_id.as_str(),
            "Benchmark id is required",
        ),
        (
            "$.name",
            suite.name.as_str(),
            "Benchmark suite name is required",
        ),
        (
            "$.task",
            suite.task.as_str(),
            "Benchmark suite task is required",
        ),
        (
            "$.version",
            suite.version.as_str(),
            "Benchmark suite version is required",
        ),
        (
            "$.maintainerId",
            suite.maintainer_id.as_str(),
            "Benchmark suite maintainer id is required",
        ),
        (
            "$.scoringMethodRef",
            suite.scoring_method_ref.as_str(),
            "Benchmark suite scoring method ref is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }
    if suite.modalities.is_empty() {
        issues.push(issue(
            "$.modalities",
            "Benchmark suite must declare at least one modality",
        ));
    }
    validate_non_empty_string_list(&suite.modalities, "$.modalities", &mut issues);
    if suite.dataset_refs.is_empty() {
        issues.push(issue(
            "$.datasetRefs",
            "Benchmark suite must include at least one dataset reference",
        ));
    }
    validate_reference_list(
        &suite.dataset_refs,
        "$.datasetRefs",
        "Dataset reference",
        &mut issues,
        &mut warnings,
    );
    if !looks_like_reference(&suite.scoring_method_ref)
        && !looks_like_hash_ref(&suite.scoring_method_ref)
    {
        warnings.push(issue(
            "$.scoringMethodRef",
            "Scoring method ref is not a recognized content, local, web, file, or hash reference",
        ));
    }
    validate_benchmark_splits(&suite.splits, &mut issues, &mut warnings);
    if suite.allowed_model_refs.is_empty() {
        issues.push(issue(
            "$.allowedModelRefs",
            "Benchmark suite must declare allowed model refs or package-kind selectors",
        ));
    }
    validate_reference_list(
        &suite.allowed_model_refs,
        "$.allowedModelRefs",
        "Allowed model ref",
        &mut issues,
        &mut warnings,
    );
    if suite.allowed_runtimes.is_empty() {
        issues.push(issue(
            "$.allowedRuntimes",
            "Benchmark suite must declare at least one allowed runtime",
        ));
    }
    validate_non_empty_string_list(&suite.allowed_runtimes, "$.allowedRuntimes", &mut issues);
    validate_benchmark_privacy_rules(&suite.privacy_rules, &mut issues, &mut warnings);
    validate_benchmark_expected_runtime(&suite.expected_runtime, &mut issues, &mut warnings);
    if suite.metric_names.is_empty() {
        issues.push(issue(
            "$.metricNames",
            "Benchmark suite must declare at least one metric name",
        ));
    }
    validate_non_empty_string_list(&suite.metric_names, "$.metricNames", &mut issues);
    if DateTime::parse_from_rfc3339(&suite.created_at).is_err() {
        issues.push(issue(
            "$.createdAt",
            "Benchmark suite createdAt must be an RFC3339 timestamp",
        ));
    }
    match canonical_benchmark_suite_id(suite) {
        Ok(expected_id) if expected_id != suite.suite_id => issues.push(issue(
            "$.suiteId",
            "Benchmark suite id does not match canonical suite hash",
        )),
        Ok(_) => {}
        Err(error) => issues.push(issue(
            "$.suiteId",
            format!("Could not compute canonical suite id: {error}"),
        )),
    }
    let mut expected_signature = expected_benchmark_suite_signature(suite);
    if suite
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &suite.signature,
            "benchmark-suite",
            &benchmark_suite_signing_value(suite),
            Some(&suite.maintainer_id),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if suite.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Benchmark suite signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production maintainer signing",
        ));
    }
    BenchmarkSuiteVerificationV1 {
        schema_version: "hivemind.benchmark_suite_verification.v1".to_string(),
        suite_id: suite.suite_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn benchmark_pack_projection(
    request: BenchmarkPackProjectionRequestV1,
) -> BenchmarkPackProjectionV1 {
    let pack = benchmark_pack_from_suite(&request.suite, request.context);
    let verification = verify_benchmark_pack(&pack);
    BenchmarkPackProjectionV1 {
        schema_version: "hivemind.benchmark-pack-projection.v1".to_string(),
        pack,
        verification,
    }
}

pub fn benchmark_pack_from_suite(
    suite: &BenchmarkSuiteV1,
    context: BenchmarkPackContextV1,
) -> BenchmarkPackV1 {
    let mut hidden_challenge_commitment_refs = context.hidden_challenge_commitment_refs;
    for split in &suite.splits {
        if split.hidden {
            hidden_challenge_commitment_refs.extend(split.dataset_refs.clone());
        }
    }
    hidden_challenge_commitment_refs = normalize_string_list(hidden_challenge_commitment_refs);

    let mut validation_method_refs = normalize_string_list(context.validation_method_refs);
    if validation_method_refs.is_empty() {
        validation_method_refs.push("benchmark_score".to_string());
        if !hidden_challenge_commitment_refs.is_empty() {
            validation_method_refs.push("hidden_challenge".to_string());
        }
    }
    validation_method_refs.sort();
    validation_method_refs.dedup();

    let report_schema = if context.report_schema.is_null() {
        default_benchmark_pack_report_schema()
    } else {
        context.report_schema
    };

    let mut pack = BenchmarkPackV1 {
        schema_version: "hivemind.benchmark-pack.v1".to_string(),
        pack_id: String::new(),
        benchmark_id: suite.benchmark_id.clone(),
        name: suite.name.clone(),
        task: suite.task.clone(),
        version: suite.version.clone(),
        maintainer_id: suite.maintainer_id.clone(),
        suite_ref: context.suite_ref,
        dataset_refs: suite.dataset_refs.clone(),
        hidden_challenge_commitment_refs,
        scoring_function_ref: suite.scoring_method_ref.clone(),
        allowed_runtimes: suite.allowed_runtimes.clone(),
        privacy_rules: suite.privacy_rules.clone(),
        report_schema,
        validation_method_refs,
        metric_names: suite.metric_names.clone(),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        metadata: context.metadata,
        signature: String::new(),
    };
    sign_benchmark_pack(&mut pack);
    pack.pack_id = canonical_benchmark_pack_id(&pack)
        .expect("benchmark pack should serialize for canonical id");
    pack
}

pub fn sign_benchmark_pack(pack: &mut BenchmarkPackV1) {
    pack.signature = expected_benchmark_pack_signature(pack);
}

pub fn expected_benchmark_pack_signature(pack: &BenchmarkPackV1) -> String {
    dev_signature(
        "benchmark-pack",
        &pack.maintainer_id,
        &benchmark_pack_signing_value(pack),
    )
}

pub fn canonical_benchmark_pack_id(pack: &BenchmarkPackV1) -> serde_json::Result<String> {
    let mut signed = pack.clone();
    signed.pack_id.clear();
    let value = serde_json::to_value(signed)?;
    Ok(stable_id_from_value("benchmark-pack", &value))
}

pub fn verify_benchmark_pack(pack: &BenchmarkPackV1) -> BenchmarkPackVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if pack.schema_version != "hivemind.benchmark-pack.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.benchmark-pack.v1",
        ));
    }
    for (path, value, message) in [
        (
            "$.packId",
            pack.pack_id.as_str(),
            "Benchmark pack id is required",
        ),
        (
            "$.benchmarkId",
            pack.benchmark_id.as_str(),
            "Benchmark id is required",
        ),
        (
            "$.name",
            pack.name.as_str(),
            "Benchmark pack name is required",
        ),
        (
            "$.task",
            pack.task.as_str(),
            "Benchmark pack task is required",
        ),
        (
            "$.version",
            pack.version.as_str(),
            "Benchmark pack version is required",
        ),
        (
            "$.maintainerId",
            pack.maintainer_id.as_str(),
            "Benchmark pack maintainer id is required",
        ),
        (
            "$.scoringFunctionRef",
            pack.scoring_function_ref.as_str(),
            "Benchmark pack scoringFunctionRef is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }
    if let Some(suite_ref) = &pack.suite_ref
        && !looks_like_reference(suite_ref)
        && !looks_like_hash_ref(suite_ref)
    {
        warnings.push(issue(
            "$.suiteRef",
            "Suite ref is not a recognized content, local, web, file, selector, or hash reference",
        ));
    }
    if pack.dataset_refs.is_empty() {
        issues.push(issue(
            "$.datasetRefs",
            "Benchmark pack must include at least one dataset ref",
        ));
    }
    validate_reference_list(
        &pack.dataset_refs,
        "$.datasetRefs",
        "Dataset ref",
        &mut issues,
        &mut warnings,
    );
    validate_hidden_challenge_commitment_refs(
        &pack.hidden_challenge_commitment_refs,
        &mut issues,
        &mut warnings,
    );
    if !looks_like_reference(&pack.scoring_function_ref)
        && !looks_like_hash_ref(&pack.scoring_function_ref)
    {
        warnings.push(issue(
            "$.scoringFunctionRef",
            "Scoring function ref is not a recognized content, local, web, file, selector, or hash reference",
        ));
    }
    if pack.allowed_runtimes.is_empty() {
        issues.push(issue(
            "$.allowedRuntimes",
            "Benchmark pack must declare at least one allowed runtime",
        ));
    }
    validate_non_empty_string_list(&pack.allowed_runtimes, "$.allowedRuntimes", &mut issues);
    validate_benchmark_privacy_rules(&pack.privacy_rules, &mut issues, &mut warnings);
    if !pack.report_schema.is_object() {
        issues.push(issue(
            "$.reportSchema",
            "Benchmark pack reportSchema must be a JSON object",
        ));
    }
    if pack.validation_method_refs.is_empty() {
        issues.push(issue(
            "$.validationMethodRefs",
            "Benchmark pack must declare at least one validation method ref",
        ));
    }
    validate_non_empty_string_list(
        &pack.validation_method_refs,
        "$.validationMethodRefs",
        &mut issues,
    );
    if pack.metric_names.is_empty() {
        issues.push(issue(
            "$.metricNames",
            "Benchmark pack must declare at least one metric name",
        ));
    }
    validate_non_empty_string_list(&pack.metric_names, "$.metricNames", &mut issues);
    if DateTime::parse_from_rfc3339(&pack.created_at).is_err() {
        issues.push(issue(
            "$.createdAt",
            "Benchmark pack createdAt must be an RFC3339 timestamp",
        ));
    }
    match canonical_benchmark_pack_id(pack) {
        Ok(expected_id) if expected_id != pack.pack_id => issues.push(issue(
            "$.packId",
            "Benchmark pack id does not match canonical pack hash",
        )),
        Ok(_) => {}
        Err(error) => issues.push(issue(
            "$.packId",
            format!("Could not compute canonical pack id: {error}"),
        )),
    }
    let mut expected_signature = expected_benchmark_pack_signature(pack);
    if pack
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &pack.signature,
            "benchmark-pack",
            &benchmark_pack_signing_value(pack),
            Some(&pack.maintainer_id),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if pack.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Benchmark pack signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production maintainer signing",
        ));
    }

    BenchmarkPackVerificationV1 {
        schema_version: "hivemind.benchmark-pack-verification.v1".to_string(),
        pack_id: pack.pack_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn read_benchmark_suite(path: &Path) -> anyhow::Result<BenchmarkSuiteV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse benchmark suite JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_benchmark_suite(
    suites_dir: &Path,
    suite: &BenchmarkSuiteV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(suites_dir)?;
    let path = suites_dir.join(format!("{}.json", safe_file_component(&suite.suite_id)));
    fs::write(&path, serde_json::to_vec_pretty(suite)?)?;
    Ok(path)
}

pub fn get_benchmark_suite(
    suites_dir: &Path,
    suite_id: &str,
) -> anyhow::Result<Option<BenchmarkSuiteLookupV1>> {
    let direct_path = suites_dir.join(format!("{}.json", safe_file_component(suite_id)));
    if direct_path.exists()
        && let Ok(suite) = read_benchmark_suite(&direct_path)
        && suite.suite_id == suite_id
    {
        return Ok(Some(benchmark_suite_lookup(suite, direct_path)));
    }
    if !suites_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(suites_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            && let Ok(suite) = read_benchmark_suite(&path)
            && suite.suite_id == suite_id
        {
            return Ok(Some(benchmark_suite_lookup(suite, path)));
        }
    }
    Ok(None)
}

pub fn list_benchmark_suites(suites_dir: &Path) -> anyhow::Result<BenchmarkSuiteStoreSummaryV1> {
    let mut suites = Vec::new();
    if suites_dir.exists() {
        for entry in fs::read_dir(suites_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
                && let Ok(suite) = read_benchmark_suite(&path)
            {
                suites.push(benchmark_suite_index_entry(
                    &suite,
                    path.display().to_string(),
                ));
            }
        }
    }
    suites.sort_by(|left, right| {
        left.task
            .cmp(&right.task)
            .then(left.benchmark_id.cmp(&right.benchmark_id))
            .then(left.version.cmp(&right.version))
            .then(left.suite_id.cmp(&right.suite_id))
    });
    let valid_count = suites
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    Ok(BenchmarkSuiteStoreSummaryV1 {
        schema_version: "hivemind.benchmark_suite_store_summary.v1".to_string(),
        root: suites_dir.display().to_string(),
        suite_count: suites.len(),
        valid_count,
        invalid_count: suites.len().saturating_sub(valid_count),
        suites,
    })
}

pub fn evaluation_result(
    benchmark: &BenchmarkPackageV1,
    package_ref: impl Into<String>,
    runner_id: Option<String>,
    validator_id: impl Into<String>,
    sample_results: Vec<EvaluationSampleResultV1>,
    result_refs: Vec<String>,
) -> EvaluationResultV1 {
    let package_ref = package_ref.into();
    let scores = aggregate_scores(&sample_results);
    let metrics = aggregate_metrics(&sample_results);
    let mut result = EvaluationResultV1 {
        schema_version: "swarm-ai.evaluation-result.v1".to_string(),
        evaluation_id: String::new(),
        benchmark_id: benchmark.benchmark_id.clone(),
        benchmark_version: benchmark.version.clone(),
        package_ref,
        runner_id,
        validator_id: validator_id.into(),
        scores,
        metrics,
        result_refs,
        sample_results,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: String::new(),
    };
    sign_evaluation_result(&mut result);
    result.evaluation_id =
        canonical_evaluation_result_id(&result).expect("evaluation result should serialize for id");
    result
}

pub fn sign_evaluation_result(result: &mut EvaluationResultV1) {
    result.signature = expected_evaluation_result_signature(result);
}

pub fn sign_evaluation_result_with_identity(
    result: &mut EvaluationResultV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != result.validator_id {
        anyhow::bail!(
            "identity subject {} does not match evaluation validator {}",
            identity.subject,
            result.validator_id
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "evaluation-result",
        &evaluation_signing_value(result),
    )?;
    result.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    result.evaluation_id = canonical_evaluation_result_id(result)?;
    Ok(envelope)
}

pub fn expected_evaluation_result_signature(result: &EvaluationResultV1) -> String {
    dev_signature(
        "evaluation-result",
        &result.validator_id,
        &evaluation_signing_value(result),
    )
}

pub fn canonical_evaluation_result_id(result: &EvaluationResultV1) -> serde_json::Result<String> {
    let mut signed = result.clone();
    signed.evaluation_id.clear();
    let value = serde_json::to_value(signed)?;
    Ok(stable_id_from_value("evaluation", &value))
}

pub fn verify_evaluation_result(result: &EvaluationResultV1) -> EvaluationResultVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if result.schema_version != "swarm-ai.evaluation-result.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.evaluation-result.v1",
        ));
    }
    for (path, value, message) in [
        (
            "$.evaluationId",
            result.evaluation_id.as_str(),
            "Evaluation id is required",
        ),
        (
            "$.benchmarkId",
            result.benchmark_id.as_str(),
            "Benchmark id is required",
        ),
        (
            "$.benchmarkVersion",
            result.benchmark_version.as_str(),
            "Benchmark version is required",
        ),
        (
            "$.packageRef",
            result.package_ref.as_str(),
            "Package ref is required",
        ),
        (
            "$.validatorId",
            result.validator_id.as_str(),
            "Validator id is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }
    if !result.package_ref.starts_with("bzz://") {
        warnings.push(issue(
            "$.packageRef",
            "Evaluation packageRef is not a Swarm bzz:// reference",
        ));
    }
    for (path, score) in [
        ("$.scores.quality", result.scores.quality),
        ("$.scores.latency", result.scores.latency),
        ("$.scores.overall", result.scores.overall),
    ] {
        if !(0.0..=1.0).contains(&score) || !score.is_finite() {
            issues.push(issue(path, "Score must be a finite number between 0 and 1"));
        }
    }
    if result.metrics.samples == 0 {
        issues.push(issue(
            "$.metrics.samples",
            "Evaluation result must include at least one sample",
        ));
    }
    match canonical_evaluation_result_id(result) {
        Ok(expected_id) if expected_id != result.evaluation_id => {
            issues.push(issue(
                "$.evaluationId",
                "Evaluation id does not match canonical evaluation result hash",
            ));
        }
        Ok(_) => {}
        Err(error) => issues.push(issue(
            "$.evaluationId",
            format!("Could not compute canonical evaluation id: {error}"),
        )),
    }
    let mut expected_signature = expected_evaluation_result_signature(result);
    if result
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &result.signature,
            "evaluation-result",
            &evaluation_signing_value(result),
            Some(&result.validator_id),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if result.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Evaluation result signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production validator signing",
        ));
    }
    EvaluationResultVerificationV1 {
        schema_version: "swarm-ai.evaluation-result-verification.v1".to_string(),
        evaluation_id: result.evaluation_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn read_evaluation_result(path: &Path) -> anyhow::Result<EvaluationResultV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse evaluation result JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_evaluation_result(
    results_dir: &Path,
    result: &EvaluationResultV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(results_dir)?;
    let path = results_dir.join(format!(
        "{}.json",
        safe_file_component(&result.evaluation_id)
    ));
    fs::write(&path, serde_json::to_vec_pretty(result)?)?;
    Ok(path)
}

pub fn get_evaluation_result(
    results_dir: &Path,
    evaluation_id: &str,
) -> anyhow::Result<Option<EvaluationResultLookupV1>> {
    let direct_path = results_dir.join(format!("{}.json", safe_file_component(evaluation_id)));
    if direct_path.exists() {
        let result = read_evaluation_result(&direct_path)?;
        if result.evaluation_id == evaluation_id {
            return Ok(Some(evaluation_result_lookup(result, direct_path)));
        }
    }

    if !results_dir.exists() {
        return Ok(None);
    }

    for entry in fs::read_dir(results_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let result = read_evaluation_result(&path)?;
            if result.evaluation_id == evaluation_id {
                return Ok(Some(evaluation_result_lookup(result, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_evaluation_results(
    results_dir: &Path,
) -> anyhow::Result<EvaluationResultStoreSummaryV1> {
    let mut evaluations = Vec::new();
    if results_dir.exists() {
        for entry in fs::read_dir(results_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let result = read_evaluation_result(&path)?;
                evaluations.push(evaluation_result_index_entry(
                    &result,
                    path.display().to_string(),
                ));
            }
        }
    }
    evaluations.sort_by(|left, right| {
        left.package_ref
            .cmp(&right.package_ref)
            .then(left.benchmark_id.cmp(&right.benchmark_id))
            .then(left.created_at.cmp(&right.created_at))
            .then(left.evaluation_id.cmp(&right.evaluation_id))
    });
    let valid_count = evaluations
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    Ok(EvaluationResultStoreSummaryV1 {
        schema_version: "swarm-ai.evaluation-result-store-summary.v1".to_string(),
        root: results_dir.display().to_string(),
        evaluation_count: evaluations.len(),
        valid_count,
        invalid_count: evaluations.len().saturating_sub(valid_count),
        evaluations,
    })
}

pub fn evaluation_result_v2_from_v1(
    result: &EvaluationResultV1,
    context: EvaluationResultV2ContextV1,
) -> EvaluationResultV2 {
    let context = normalize_evaluation_result_v2_context(context);
    let timing = context.timing.unwrap_or_else(|| EvaluationTimingV2 {
        started_at: None,
        completed_at: Some(result.created_at.clone()),
        total_ms: result.metrics.total_ms,
        average_ms: result.metrics.average_ms,
    });
    let environment = context.environment.unwrap_or_default();
    let mut result_v2 = EvaluationResultV2 {
        schema_version: "hivemind.evaluation_result.v2".to_string(),
        evaluation_id: String::new(),
        source_evaluation_id: Some(result.evaluation_id.clone()),
        benchmark_id: result.benchmark_id.clone(),
        benchmark_version: result.benchmark_version.clone(),
        suite_id: context.suite_id,
        package_ref: result.package_ref.clone(),
        runner_id: result.runner_id.clone(),
        validator_id: result.validator_id.clone(),
        score: result.scores.overall,
        scores: result.scores.clone(),
        metrics: result.metrics.clone(),
        timing,
        cost: context.cost,
        environment,
        artifact_refs: context.artifact_refs,
        result_refs: result.result_refs.clone(),
        random_seeds: context.random_seeds,
        errors: context.errors,
        created_at: result.created_at.clone(),
        metadata: context.metadata,
        signature: String::new(),
    };
    sign_evaluation_result_v2(&mut result_v2);
    result_v2.evaluation_id = canonical_evaluation_result_v2_id(&result_v2)
        .expect("evaluation result v2 should serialize for id");
    result_v2
}

pub fn sign_evaluation_result_v2(result: &mut EvaluationResultV2) {
    result.signature = expected_evaluation_result_v2_signature(result);
}

pub fn sign_evaluation_result_v2_with_identity(
    result: &mut EvaluationResultV2,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != result.validator_id {
        anyhow::bail!(
            "identity subject {} does not match evaluation validator {}",
            identity.subject,
            result.validator_id
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "evaluation-result-v2",
        &evaluation_result_v2_signing_value(result),
    )?;
    result.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    result.evaluation_id = canonical_evaluation_result_v2_id(result)?;
    Ok(envelope)
}

pub fn expected_evaluation_result_v2_signature(result: &EvaluationResultV2) -> String {
    dev_signature(
        "evaluation-result-v2",
        &result.validator_id,
        &evaluation_result_v2_signing_value(result),
    )
}

pub fn canonical_evaluation_result_v2_id(
    result: &EvaluationResultV2,
) -> serde_json::Result<String> {
    let mut signed = result.clone();
    signed.evaluation_id.clear();
    let value = serde_json::to_value(signed)?;
    Ok(stable_id_from_value("evaluation-v2", &value))
}

pub fn verify_evaluation_result_v2(
    result: &EvaluationResultV2,
) -> EvaluationResultV2VerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if result.schema_version != "hivemind.evaluation_result.v2" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.evaluation_result.v2",
        ));
    }
    for (path, value, message) in [
        (
            "$.evaluationId",
            result.evaluation_id.as_str(),
            "Evaluation id is required",
        ),
        (
            "$.benchmarkId",
            result.benchmark_id.as_str(),
            "Benchmark id is required",
        ),
        (
            "$.benchmarkVersion",
            result.benchmark_version.as_str(),
            "Benchmark version is required",
        ),
        (
            "$.packageRef",
            result.package_ref.as_str(),
            "Package ref is required",
        ),
        (
            "$.validatorId",
            result.validator_id.as_str(),
            "Validator id is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }
    if let Some(source_id) = &result.source_evaluation_id {
        if source_id.trim().is_empty() {
            issues.push(issue(
                "$.sourceEvaluationId",
                "Source evaluation id must not be empty when present",
            ));
        }
    }
    if let Some(suite_id) = &result.suite_id {
        if suite_id.trim().is_empty() {
            issues.push(issue(
                "$.suiteId",
                "Suite id must not be empty when present",
            ));
        }
    }
    if !result.package_ref.starts_with("bzz://") {
        warnings.push(issue(
            "$.packageRef",
            "Evaluation packageRef is not a Swarm bzz:// reference",
        ));
    }
    validate_score("$.score", result.score, &mut issues);
    for (path, score) in [
        ("$.scores.quality", result.scores.quality),
        ("$.scores.latency", result.scores.latency),
        ("$.scores.overall", result.scores.overall),
    ] {
        validate_score(path, score, &mut issues);
    }
    if (result.score - result.scores.overall).abs() > 0.0001 {
        issues.push(issue(
            "$.score",
            "Evaluation score must match scores.overall",
        ));
    }
    if result.metrics.samples == 0 {
        issues.push(issue(
            "$.metrics.samples",
            "Evaluation result must include at least one sample",
        ));
    }
    if result
        .metrics
        .succeeded
        .saturating_add(result.metrics.failed)
        != result.metrics.samples
    {
        issues.push(issue(
            "$.metrics",
            "Succeeded and failed sample counts must add up to samples",
        ));
    }
    if !result.metrics.average_ms.is_finite() || result.metrics.average_ms < 0.0 {
        issues.push(issue(
            "$.metrics.averageMs",
            "Average latency must be a non-negative finite number",
        ));
    }
    validate_evaluation_timing_v2(&result.timing, &mut issues, &mut warnings);
    if result.timing.total_ms > 0 && result.metrics.total_ms > 0 {
        let timing_delta = result.timing.total_ms.abs_diff(result.metrics.total_ms);
        if timing_delta > result.metrics.total_ms.max(1) / 5 {
            warnings.push(issue(
                "$.timing.totalMs",
                "Evaluation lifecycle timing diverges significantly from aggregate sample metrics",
            ));
        }
    }
    if let Some(cost) = &result.cost {
        validate_evaluation_cost_v2(cost, &mut issues, &mut warnings);
    }
    validate_evaluation_environment_v2(&result.environment, &mut issues, &mut warnings);
    validate_reference_list(
        &result.artifact_refs,
        "$.artifactRefs",
        "Artifact ref",
        &mut issues,
        &mut warnings,
    );
    validate_reference_list(
        &result.result_refs,
        "$.resultRefs",
        "Result ref",
        &mut issues,
        &mut warnings,
    );
    validate_non_empty_string_list(&result.random_seeds, "$.randomSeeds", &mut issues);
    if result.random_seeds.is_empty() {
        warnings.push(issue(
            "$.randomSeeds",
            "Evaluation result does not record random seeds; deterministic reruns may be harder to reproduce",
        ));
    }
    validate_evaluation_errors_v2(&result.errors, &mut issues);
    if result.metrics.failed > 0 && result.errors.is_empty() {
        warnings.push(issue(
            "$.errors",
            "Evaluation metrics report failed samples but no structured errors are attached",
        ));
    }
    if result.metrics.failed == 0 && !result.errors.is_empty() {
        warnings.push(issue(
            "$.errors",
            "Evaluation result includes errors even though metrics.failed is zero",
        ));
    }
    validate_rfc3339_optional("$.createdAt", Some(result.created_at.as_str()), &mut issues);
    match canonical_evaluation_result_v2_id(result) {
        Ok(expected_id) if expected_id != result.evaluation_id => {
            issues.push(issue(
                "$.evaluationId",
                "Evaluation id does not match canonical evaluation result v2 hash",
            ));
        }
        Ok(_) => {}
        Err(error) => issues.push(issue(
            "$.evaluationId",
            format!("Could not compute canonical evaluation result v2 id: {error}"),
        )),
    }
    let mut expected_signature = expected_evaluation_result_v2_signature(result);
    if result
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &result.signature,
            "evaluation-result-v2",
            &evaluation_result_v2_signing_value(result),
            Some(&result.validator_id),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if result.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Evaluation result v2 signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production validator signing",
        ));
    }
    EvaluationResultV2VerificationV1 {
        schema_version: "hivemind.evaluation_result_v2_verification.v1".to_string(),
        evaluation_id: result.evaluation_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn read_evaluation_result_v2(path: &Path) -> anyhow::Result<EvaluationResultV2> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse evaluation result v2 JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_evaluation_result_v2(
    results_dir: &Path,
    result: &EvaluationResultV2,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(results_dir)?;
    let path = results_dir.join(format!(
        "{}.json",
        safe_file_component(&result.evaluation_id)
    ));
    fs::write(&path, serde_json::to_vec_pretty(result)?)?;
    Ok(path)
}

pub fn get_evaluation_result_v2(
    results_dir: &Path,
    evaluation_id: &str,
) -> anyhow::Result<Option<EvaluationResultV2LookupV1>> {
    let direct_path = results_dir.join(format!("{}.json", safe_file_component(evaluation_id)));
    if direct_path.exists() {
        let result = read_evaluation_result_v2(&direct_path)?;
        if result.evaluation_id == evaluation_id {
            return Ok(Some(evaluation_result_v2_lookup(result, direct_path)));
        }
    }

    if !results_dir.exists() {
        return Ok(None);
    }

    for entry in fs::read_dir(results_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let result = read_evaluation_result_v2(&path)?;
            if result.evaluation_id == evaluation_id {
                return Ok(Some(evaluation_result_v2_lookup(result, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_evaluation_results_v2(
    results_dir: &Path,
) -> anyhow::Result<EvaluationResultV2StoreSummaryV1> {
    let mut evaluations = Vec::new();
    if results_dir.exists() {
        for entry in fs::read_dir(results_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let result = read_evaluation_result_v2(&path)?;
                evaluations.push(evaluation_result_v2_index_entry(
                    &result,
                    path.display().to_string(),
                ));
            }
        }
    }
    evaluations.sort_by(|left, right| {
        left.package_ref
            .cmp(&right.package_ref)
            .then(left.benchmark_id.cmp(&right.benchmark_id))
            .then(left.created_at.cmp(&right.created_at))
            .then(left.evaluation_id.cmp(&right.evaluation_id))
    });
    let valid_count = evaluations
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    Ok(EvaluationResultV2StoreSummaryV1 {
        schema_version: "hivemind.evaluation_result_v2_store_summary.v1".to_string(),
        root: results_dir.display().to_string(),
        evaluation_count: evaluations.len(),
        valid_count,
        invalid_count: evaluations.len().saturating_sub(valid_count),
        evaluations,
    })
}

pub fn evaluation_leaderboard(results_dir: &Path) -> anyhow::Result<EvaluationLeaderboardV1> {
    let mut evaluation_count = 0;
    let mut valid_evaluation_count = 0;
    let mut invalid_evaluation_count = 0;
    let mut benchmark_scopes = BTreeSet::new();
    let mut accumulators: BTreeMap<LeaderboardKey, LeaderboardAccumulator> = BTreeMap::new();

    if results_dir.exists() {
        for entry in fs::read_dir(results_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !entry.file_type()?.is_file()
                || path.extension().and_then(|extension| extension.to_str()) != Some("json")
            {
                continue;
            }

            let result = read_evaluation_result(&path)?;
            evaluation_count += 1;
            let verification = verify_evaluation_result(&result);
            if !verification.valid {
                invalid_evaluation_count += 1;
                continue;
            }

            valid_evaluation_count += 1;
            benchmark_scopes.insert((
                result.benchmark_id.clone(),
                result.benchmark_version.clone(),
            ));
            let key = LeaderboardKey {
                benchmark_id: result.benchmark_id.clone(),
                benchmark_version: result.benchmark_version.clone(),
                package_ref: result.package_ref.clone(),
                runner_id: result.runner_id.clone(),
            };
            accumulators
                .entry(key.clone())
                .or_insert_with(|| LeaderboardAccumulator::new(key))
                .push(&result, &verification, path.display().to_string());
        }
    }

    let mut entries: Vec<_> = accumulators
        .into_values()
        .map(LeaderboardAccumulator::into_entry)
        .collect();
    entries.sort_by(compare_leaderboard_entries);
    apply_leaderboard_ranks(&mut entries);

    Ok(EvaluationLeaderboardV1 {
        schema_version: "swarm-ai.evaluation-leaderboard.v1".to_string(),
        root: results_dir.display().to_string(),
        benchmark_count: benchmark_scopes.len(),
        evaluation_count,
        valid_evaluation_count,
        invalid_evaluation_count,
        entry_count: entries.len(),
        entries,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn create_challenge_commitment(
    options: ChallengeCommitmentInitOptionsV1,
) -> ChallengeCommitmentV1 {
    let mut public_dataset_refs = options.public_dataset_refs;
    public_dataset_refs.sort();
    public_dataset_refs.dedup();
    let mut hidden_ref_commitments = options.hidden_ref_commitments;
    hidden_ref_commitments.sort();
    hidden_ref_commitments.dedup();
    let mut scoring_rule_refs = options.scoring_rule_refs;
    scoring_rule_refs.sort();
    scoring_rule_refs.dedup();
    let mut commitment = ChallengeCommitmentV1 {
        schema_version: "hivemind.challenge_commitment.v1".to_string(),
        commitment_id: String::new(),
        benchmark_id: options.benchmark_id,
        benchmark_version: options.benchmark_version,
        validator_id: options.validator_id,
        challenge_set_hash: options.challenge_set_hash,
        answer_set_hash: options.answer_set_hash,
        salt_hash: options.salt_hash,
        challenge_count: options.challenge_count,
        public_dataset_refs,
        hidden_ref_commitments,
        scoring_rule_refs,
        reveal_after: options.reveal_after,
        expires_at: options.expires_at,
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        metadata: options.metadata,
        signature: String::new(),
    };
    sign_challenge_commitment(&mut commitment);
    commitment.commitment_id = canonical_challenge_commitment_id(&commitment)
        .expect("challenge commitment should serialize for id");
    commitment
}

pub fn sign_challenge_commitment(commitment: &mut ChallengeCommitmentV1) {
    commitment.signature = expected_challenge_commitment_signature(commitment);
}

pub fn sign_challenge_commitment_with_identity(
    commitment: &mut ChallengeCommitmentV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != commitment.validator_id {
        anyhow::bail!(
            "identity subject {} does not match challenge commitment validator {}",
            identity.subject,
            commitment.validator_id
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "challenge-commitment",
        &challenge_commitment_signing_value(commitment),
    )?;
    commitment.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    commitment.commitment_id = canonical_challenge_commitment_id(commitment)?;
    Ok(envelope)
}

pub fn expected_challenge_commitment_signature(commitment: &ChallengeCommitmentV1) -> String {
    dev_signature(
        "challenge-commitment",
        &commitment.validator_id,
        &challenge_commitment_signing_value(commitment),
    )
}

pub fn canonical_challenge_commitment_id(
    commitment: &ChallengeCommitmentV1,
) -> serde_json::Result<String> {
    let mut signed = commitment.clone();
    signed.commitment_id.clear();
    let value = serde_json::to_value(signed)?;
    Ok(stable_id_from_value("challenge-commitment", &value))
}

pub fn verify_challenge_commitment(
    commitment: &ChallengeCommitmentV1,
) -> ChallengeCommitmentVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if commitment.schema_version != "hivemind.challenge_commitment.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.challenge_commitment.v1",
        ));
    }
    for (path, value, message) in [
        (
            "$.commitmentId",
            commitment.commitment_id.as_str(),
            "Commitment id is required",
        ),
        (
            "$.benchmarkId",
            commitment.benchmark_id.as_str(),
            "Benchmark id is required",
        ),
        (
            "$.benchmarkVersion",
            commitment.benchmark_version.as_str(),
            "Benchmark version is required",
        ),
        (
            "$.validatorId",
            commitment.validator_id.as_str(),
            "Validator id is required",
        ),
        (
            "$.challengeSetHash",
            commitment.challenge_set_hash.as_str(),
            "Challenge set hash is required",
        ),
        (
            "$.saltHash",
            commitment.salt_hash.as_str(),
            "Salt hash is required",
        ),
    ] {
        if value.trim().is_empty() {
            issues.push(issue(path, message));
        }
    }
    if commitment.challenge_count == 0 {
        issues.push(issue(
            "$.challengeCount",
            "Challenge commitment must cover at least one challenge",
        ));
    }
    for (path, hash) in [
        ("$.challengeSetHash", commitment.challenge_set_hash.as_str()),
        ("$.saltHash", commitment.salt_hash.as_str()),
    ] {
        if !looks_like_hash_ref(hash) {
            issues.push(issue(
                path,
                "Value must be a sha256 hash or sha256 reference",
            ));
        }
    }
    if let Some(answer_hash) = &commitment.answer_set_hash
        && !looks_like_hash_ref(answer_hash)
    {
        issues.push(issue(
            "$.answerSetHash",
            "Value must be a sha256 hash or sha256 reference",
        ));
    }
    for (index, reference) in commitment.public_dataset_refs.iter().enumerate() {
        if reference.trim().is_empty() {
            issues.push(issue(
                format!("$.publicDatasetRefs[{index}]"),
                "Public dataset reference must not be empty",
            ));
        } else if !looks_like_reference(reference) {
            warnings.push(issue(
                format!("$.publicDatasetRefs[{index}]"),
                "Public dataset reference is not a recognized bzz://, local://, ipfs://, http(s)://, or file reference",
            ));
        }
    }
    for (index, reference) in commitment.hidden_ref_commitments.iter().enumerate() {
        if reference.trim().is_empty() {
            issues.push(issue(
                format!("$.hiddenRefCommitments[{index}]"),
                "Hidden reference commitment must not be empty",
            ));
        } else if !looks_like_hash_ref(reference) {
            issues.push(issue(
                format!("$.hiddenRefCommitments[{index}]"),
                "Hidden reference commitments must be hashes, not raw hidden dataset refs",
            ));
        }
    }
    for (index, reference) in commitment.scoring_rule_refs.iter().enumerate() {
        if reference.trim().is_empty() {
            issues.push(issue(
                format!("$.scoringRuleRefs[{index}]"),
                "Scoring rule reference must not be empty",
            ));
        } else if !looks_like_reference(reference) && !looks_like_hash_ref(reference) {
            warnings.push(issue(
                format!("$.scoringRuleRefs[{index}]"),
                "Scoring rule reference is not a recognized content, local, web, file, or hash reference",
            ));
        }
    }
    if DateTime::parse_from_rfc3339(&commitment.created_at).is_err() {
        issues.push(issue(
            "$.createdAt",
            "Commitment createdAt must be an RFC3339 timestamp",
        ));
    }
    for (path, timestamp) in [
        ("$.revealAfter", commitment.reveal_after.as_ref()),
        ("$.expiresAt", commitment.expires_at.as_ref()),
    ] {
        if let Some(timestamp) = timestamp
            && DateTime::parse_from_rfc3339(timestamp).is_err()
        {
            issues.push(issue(path, "Commitment timestamp must be RFC3339"));
        }
    }
    if let (Some(reveal_after), Some(expires_at)) =
        (&commitment.reveal_after, &commitment.expires_at)
        && let (Ok(reveal_after), Ok(expires_at)) = (
            DateTime::parse_from_rfc3339(reveal_after),
            DateTime::parse_from_rfc3339(expires_at),
        )
        && expires_at < reveal_after
    {
        issues.push(issue(
            "$.expiresAt",
            "Commitment expiresAt must not be earlier than revealAfter",
        ));
    }
    if commitment.answer_set_hash.is_none() {
        warnings.push(issue(
            "$.answerSetHash",
            "Commitment does not include an answer-set hash; later reveal can only prove the challenge set, not expected answers",
        ));
    }
    match canonical_challenge_commitment_id(commitment) {
        Ok(expected_id) if expected_id != commitment.commitment_id => issues.push(issue(
            "$.commitmentId",
            "Commitment id does not match canonical challenge commitment hash",
        )),
        Ok(_) => {}
        Err(error) => issues.push(issue(
            "$.commitmentId",
            format!("Could not compute canonical commitment id: {error}"),
        )),
    }
    let mut expected_signature = expected_challenge_commitment_signature(commitment);
    if commitment
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &commitment.signature,
            "challenge-commitment",
            &challenge_commitment_signing_value(commitment),
            Some(&commitment.validator_id),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if commitment.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Challenge commitment signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production validator signing",
        ));
    }

    ChallengeCommitmentVerificationV1 {
        schema_version: "hivemind.challenge_commitment_verification.v1".to_string(),
        commitment_id: commitment.commitment_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn read_challenge_commitment(path: &Path) -> anyhow::Result<ChallengeCommitmentV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse challenge commitment JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_challenge_commitment(
    commitments_dir: &Path,
    commitment: &ChallengeCommitmentV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(commitments_dir)?;
    let path = commitments_dir.join(format!(
        "{}.json",
        safe_file_component(&commitment.commitment_id)
    ));
    fs::write(&path, serde_json::to_vec_pretty(commitment)?)?;
    Ok(path)
}

pub fn get_challenge_commitment(
    commitments_dir: &Path,
    commitment_id: &str,
) -> anyhow::Result<Option<ChallengeCommitmentLookupV1>> {
    let direct_path = commitments_dir.join(format!("{}.json", safe_file_component(commitment_id)));
    if direct_path.exists()
        && let Ok(commitment) = read_challenge_commitment(&direct_path)
        && commitment.commitment_id == commitment_id
    {
        return Ok(Some(challenge_commitment_lookup(commitment, direct_path)));
    }
    if !commitments_dir.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(commitments_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            && let Ok(commitment) = read_challenge_commitment(&path)
            && commitment.commitment_id == commitment_id
        {
            return Ok(Some(challenge_commitment_lookup(commitment, path)));
        }
    }
    Ok(None)
}

pub fn list_challenge_commitments(
    commitments_dir: &Path,
) -> anyhow::Result<ChallengeCommitmentStoreSummaryV1> {
    let mut commitments = Vec::new();
    if commitments_dir.exists() {
        for entry in fs::read_dir(commitments_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
                && let Ok(commitment) = read_challenge_commitment(&path)
            {
                commitments.push(challenge_commitment_index_entry(
                    &commitment,
                    path.display().to_string(),
                ));
            }
        }
    }
    commitments.sort_by(|left, right| {
        left.benchmark_id
            .cmp(&right.benchmark_id)
            .then(left.created_at.cmp(&right.created_at))
            .then(left.commitment_id.cmp(&right.commitment_id))
    });
    let valid_count = commitments
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    Ok(ChallengeCommitmentStoreSummaryV1 {
        schema_version: "hivemind.challenge_commitment_store_summary.v1".to_string(),
        root: commitments_dir.display().to_string(),
        commitment_count: commitments.len(),
        valid_count,
        invalid_count: commitments.len().saturating_sub(valid_count),
        commitments,
    })
}

pub fn empty_report(package_id: impl Into<String>) -> BenchmarkReportV1 {
    BenchmarkReportV1 {
        schema_version: "swarm-ai.benchmark-report.v1".to_string(),
        package_id: package_id.into(),
        metrics: BenchmarkMetricsV1::default(),
        result: "not-run".to_string(),
    }
}

pub fn scoring_deadline_ms(benchmark: &BenchmarkPackageV1) -> u64 {
    benchmark
        .scoring_rules
        .iter()
        .find(|rule| rule.method == BenchmarkScoringMethod::Latency)
        .and_then(|rule| rule.parameters.get("deadlineMs"))
        .and_then(Value::as_u64)
        .unwrap_or(30_000)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LeaderboardKey {
    benchmark_id: String,
    benchmark_version: String,
    package_ref: String,
    runner_id: Option<String>,
}

#[derive(Debug, Clone)]
struct LeaderboardAccumulator {
    key: LeaderboardKey,
    evaluation_ids: BTreeSet<String>,
    validator_ids: BTreeSet<String>,
    receipt_ids: BTreeSet<String>,
    result_refs: BTreeSet<String>,
    result_paths: BTreeSet<String>,
    evaluation_count: usize,
    warning_count: usize,
    sample_count: u64,
    succeeded_sample_count: u64,
    failed_sample_count: u64,
    total_ms: u64,
    weighted_quality: f64,
    weighted_latency: f64,
    weighted_overall: f64,
    first_evaluated_at: Option<String>,
    latest_evaluated_at: Option<String>,
}

impl LeaderboardAccumulator {
    fn new(key: LeaderboardKey) -> Self {
        Self {
            key,
            evaluation_ids: BTreeSet::new(),
            validator_ids: BTreeSet::new(),
            receipt_ids: BTreeSet::new(),
            result_refs: BTreeSet::new(),
            result_paths: BTreeSet::new(),
            evaluation_count: 0,
            warning_count: 0,
            sample_count: 0,
            succeeded_sample_count: 0,
            failed_sample_count: 0,
            total_ms: 0,
            weighted_quality: 0.0,
            weighted_latency: 0.0,
            weighted_overall: 0.0,
            first_evaluated_at: None,
            latest_evaluated_at: None,
        }
    }

    fn push(
        &mut self,
        result: &EvaluationResultV1,
        verification: &EvaluationResultVerificationV1,
        result_path: String,
    ) {
        self.evaluation_count += 1;
        self.warning_count += verification.warnings.len();
        self.evaluation_ids.insert(result.evaluation_id.clone());
        self.validator_ids.insert(result.validator_id.clone());
        self.result_paths.insert(result_path);
        self.result_refs.extend(result.result_refs.iter().cloned());
        self.receipt_ids.extend(
            result
                .sample_results
                .iter()
                .filter_map(|sample| sample.receipt_id.clone()),
        );

        let samples = result.metrics.samples.max(1);
        self.sample_count += result.metrics.samples;
        self.succeeded_sample_count += result.metrics.succeeded;
        self.failed_sample_count += result.metrics.failed;
        self.total_ms += result.metrics.total_ms;
        self.weighted_quality += result.scores.quality * samples as f64;
        self.weighted_latency += result.scores.latency * samples as f64;
        self.weighted_overall += result.scores.overall * samples as f64;
        self.first_evaluated_at = earliest_timestamp(
            self.first_evaluated_at.take(),
            Some(result.created_at.clone()),
        );
        self.latest_evaluated_at = latest_timestamp(
            self.latest_evaluated_at.take(),
            Some(result.created_at.clone()),
        );
    }

    fn into_entry(self) -> EvaluationLeaderboardEntryV1 {
        let weight = self.sample_count.max(self.evaluation_count as u64).max(1) as f64;
        EvaluationLeaderboardEntryV1 {
            rank: 0,
            benchmark_id: self.key.benchmark_id,
            benchmark_version: self.key.benchmark_version,
            package_ref: self.key.package_ref,
            runner_id: self.key.runner_id,
            overall_score: round_score(self.weighted_overall / weight),
            quality_score: round_score(self.weighted_quality / weight),
            latency_score: round_score(self.weighted_latency / weight),
            average_ms: if self.sample_count == 0 {
                0.0
            } else {
                round_score(self.total_ms as f64 / self.sample_count as f64)
            },
            sample_count: self.sample_count,
            succeeded_sample_count: self.succeeded_sample_count,
            failed_sample_count: self.failed_sample_count,
            evaluation_count: self.evaluation_count,
            validator_count: self.validator_ids.len(),
            evaluation_ids: self.evaluation_ids.into_iter().collect(),
            validator_ids: self.validator_ids.into_iter().collect(),
            receipt_ids: self.receipt_ids.into_iter().collect(),
            result_refs: self.result_refs.into_iter().collect(),
            result_paths: self.result_paths.into_iter().collect(),
            warning_count: self.warning_count,
            first_evaluated_at: self.first_evaluated_at.unwrap_or_default(),
            latest_evaluated_at: self.latest_evaluated_at.unwrap_or_default(),
        }
    }
}

fn compare_leaderboard_entries(
    left: &EvaluationLeaderboardEntryV1,
    right: &EvaluationLeaderboardEntryV1,
) -> std::cmp::Ordering {
    left.benchmark_id
        .cmp(&right.benchmark_id)
        .then(left.benchmark_version.cmp(&right.benchmark_version))
        .then_with(|| score_cmp(right.overall_score, left.overall_score))
        .then_with(|| score_cmp(right.quality_score, left.quality_score))
        .then_with(|| score_cmp(right.latency_score, left.latency_score))
        .then_with(|| right.latest_evaluated_at.cmp(&left.latest_evaluated_at))
        .then(left.package_ref.cmp(&right.package_ref))
        .then(left.runner_id.cmp(&right.runner_id))
}

fn score_cmp(left: f64, right: f64) -> std::cmp::Ordering {
    left.partial_cmp(&right)
        .unwrap_or(std::cmp::Ordering::Equal)
}

fn apply_leaderboard_ranks(entries: &mut [EvaluationLeaderboardEntryV1]) {
    let mut current_scope: Option<(String, String)> = None;
    let mut rank = 0;
    for entry in entries {
        let scope = (entry.benchmark_id.clone(), entry.benchmark_version.clone());
        if current_scope.as_ref() != Some(&scope) {
            current_scope = Some(scope);
            rank = 1;
        } else {
            rank += 1;
        }
        entry.rank = rank;
    }
}

fn earliest_timestamp(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn latest_timestamp(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn dataset_entry(id: &str, input: Value, tags: Vec<&str>) -> DatasetEntryV1 {
    DatasetEntryV1 {
        schema_version: "swarm-ai.dataset-entry.v1".to_string(),
        entry_id: id.to_string(),
        task: "embedding".to_string(),
        input,
        expected_output: json!({ "minDimensions": 4 }),
        weight: 1.0,
        tags: tags.into_iter().map(str::to_string).collect(),
    }
}

fn score_quality(entry: &DatasetEntryV1, response: &ExecutionResponseV1) -> f64 {
    if response.status != ExecutionStatus::Succeeded || response.error.is_some() {
        return 0.0;
    }

    match entry.task.as_str() {
        "embedding" => score_embedding_shape(&entry.expected_output, &response.output),
        "classification" => score_classification(&entry.expected_output, &response.output),
        _ if response.output != json!({}) => 0.75,
        _ => 0.0,
    }
}

fn score_embedding_shape(expected: &Value, output: &Value) -> f64 {
    let min_dimensions = expected
        .get("minDimensions")
        .and_then(Value::as_u64)
        .unwrap_or(4) as usize;
    let Some(values) = output.get("embedding").and_then(Value::as_array) else {
        return 0.0;
    };
    if values.is_empty() {
        return 0.0;
    }
    let finite = values
        .iter()
        .filter(|value| value.as_f64().is_some_and(f64::is_finite))
        .count();
    if finite == values.len() && finite >= min_dimensions {
        1.0
    } else if finite > 0 {
        0.5
    } else {
        0.0
    }
}

fn score_classification(expected: &Value, output: &Value) -> f64 {
    let expected_label = expected.get("label").and_then(Value::as_str);
    let actual_label = output.get("label").and_then(Value::as_str);
    match (expected_label, actual_label) {
        (Some(expected), Some(actual)) if expected == actual => 1.0,
        (None, Some(actual)) if !actual.trim().is_empty() => 0.75,
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

fn aggregate_scores(samples: &[EvaluationSampleResultV1]) -> EvaluationScoresV1 {
    if samples.is_empty() {
        return EvaluationScoresV1::default();
    }
    let count = samples.len() as f64;
    let quality = samples.iter().map(|sample| sample.quality).sum::<f64>() / count;
    let latency = samples.iter().map(|sample| sample.latency).sum::<f64>() / count;
    let overall = (quality * 0.75 + latency * 0.25).clamp(0.0, 1.0);
    EvaluationScoresV1 {
        quality: round_score(quality),
        latency: round_score(latency),
        overall: round_score(overall),
    }
}

fn aggregate_metrics(samples: &[EvaluationSampleResultV1]) -> EvaluationMetricsV1 {
    let total_ms = samples.iter().map(|sample| sample.total_ms).sum::<u64>();
    let succeeded = samples
        .iter()
        .filter(|sample| sample.status == ExecutionStatus::Succeeded)
        .count() as u64;
    let samples_count = samples.len() as u64;
    EvaluationMetricsV1 {
        samples: samples_count,
        succeeded,
        failed: samples_count.saturating_sub(succeeded),
        total_ms,
        average_ms: if samples_count == 0 {
            0.0
        } else {
            round_score(total_ms as f64 / samples_count as f64)
        },
    }
}

fn evaluation_result_index_entry(
    result: &EvaluationResultV1,
    result_path: String,
) -> EvaluationResultIndexEntryV1 {
    let verification = verify_evaluation_result(result);
    EvaluationResultIndexEntryV1 {
        evaluation_id: result.evaluation_id.clone(),
        benchmark_id: result.benchmark_id.clone(),
        benchmark_version: result.benchmark_version.clone(),
        package_ref: result.package_ref.clone(),
        runner_id: result.runner_id.clone(),
        validator_id: result.validator_id.clone(),
        overall_score: result.scores.overall,
        quality_score: result.scores.quality,
        latency_score: result.scores.latency,
        sample_count: result.metrics.samples,
        created_at: result.created_at.clone(),
        result_path,
        verification,
    }
}

fn evaluation_result_lookup(result: EvaluationResultV1, path: PathBuf) -> EvaluationResultLookupV1 {
    let verification = verify_evaluation_result(&result);
    EvaluationResultLookupV1 {
        schema_version: "swarm-ai.evaluation-result-lookup.v1".to_string(),
        evaluation_id: result.evaluation_id.clone(),
        result_path: path.display().to_string(),
        evaluation: result,
        verification,
    }
}

fn evaluation_result_v2_index_entry(
    result: &EvaluationResultV2,
    result_path: String,
) -> EvaluationResultV2IndexEntryV1 {
    let verification = verify_evaluation_result_v2(result);
    EvaluationResultV2IndexEntryV1 {
        evaluation_id: result.evaluation_id.clone(),
        source_evaluation_id: result.source_evaluation_id.clone(),
        benchmark_id: result.benchmark_id.clone(),
        benchmark_version: result.benchmark_version.clone(),
        suite_id: result.suite_id.clone(),
        package_ref: result.package_ref.clone(),
        runner_id: result.runner_id.clone(),
        validator_id: result.validator_id.clone(),
        score: result.score,
        sample_count: result.metrics.samples,
        total_ms: result.timing.total_ms,
        cost_amount: result.cost.as_ref().map(|cost| cost.amount),
        cost_currency: result.cost.as_ref().map(|cost| cost.currency.clone()),
        created_at: result.created_at.clone(),
        result_path,
        verification,
    }
}

fn evaluation_result_v2_lookup(
    result: EvaluationResultV2,
    path: PathBuf,
) -> EvaluationResultV2LookupV1 {
    let verification = verify_evaluation_result_v2(&result);
    EvaluationResultV2LookupV1 {
        schema_version: "hivemind.evaluation_result_v2_lookup.v1".to_string(),
        evaluation_id: result.evaluation_id.clone(),
        result_path: path.display().to_string(),
        evaluation: result,
        verification,
    }
}

fn benchmark_suite_index_entry(
    suite: &BenchmarkSuiteV1,
    suite_path: String,
) -> BenchmarkSuiteIndexEntryV1 {
    let verification = verify_benchmark_suite(suite);
    BenchmarkSuiteIndexEntryV1 {
        suite_id: suite.suite_id.clone(),
        benchmark_id: suite.benchmark_id.clone(),
        name: suite.name.clone(),
        task: suite.task.clone(),
        version: suite.version.clone(),
        maintainer_id: suite.maintainer_id.clone(),
        metric_names: suite.metric_names.clone(),
        created_at: suite.created_at.clone(),
        suite_path,
        verification,
    }
}

fn benchmark_suite_lookup(suite: BenchmarkSuiteV1, path: PathBuf) -> BenchmarkSuiteLookupV1 {
    let verification = verify_benchmark_suite(&suite);
    BenchmarkSuiteLookupV1 {
        schema_version: "hivemind.benchmark_suite_lookup.v1".to_string(),
        suite_id: suite.suite_id.clone(),
        suite_path: path.display().to_string(),
        suite,
        verification,
    }
}

fn challenge_commitment_index_entry(
    commitment: &ChallengeCommitmentV1,
    commitment_path: String,
) -> ChallengeCommitmentIndexEntryV1 {
    let verification = verify_challenge_commitment(commitment);
    ChallengeCommitmentIndexEntryV1 {
        commitment_id: commitment.commitment_id.clone(),
        benchmark_id: commitment.benchmark_id.clone(),
        benchmark_version: commitment.benchmark_version.clone(),
        validator_id: commitment.validator_id.clone(),
        challenge_count: commitment.challenge_count,
        created_at: commitment.created_at.clone(),
        commitment_path,
        verification,
    }
}

fn challenge_commitment_lookup(
    commitment: ChallengeCommitmentV1,
    path: PathBuf,
) -> ChallengeCommitmentLookupV1 {
    let verification = verify_challenge_commitment(&commitment);
    ChallengeCommitmentLookupV1 {
        schema_version: "hivemind.challenge_commitment_lookup.v1".to_string(),
        commitment_id: commitment.commitment_id.clone(),
        commitment_path: path.display().to_string(),
        commitment,
        verification,
    }
}

fn response_receipt_id(response: &ExecutionResponseV1) -> Option<String> {
    response
        .metadata
        .get("receipt")
        .and_then(|receipt| receipt.get("receiptId"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn round_score(score: f64) -> f64 {
    (score * 10_000.0).round() / 10_000.0
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
    let value = serde_json::to_value(value).expect("benchmark object should serialize");
    stable_id_from_value(prefix, &value)
}

fn stable_id_from_value(prefix: &str, value: &Value) -> String {
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(value))[..24]
    )
}

fn evaluation_signing_value(result: &EvaluationResultV1) -> Value {
    json!({
        "schemaVersion": result.schema_version,
        "benchmarkId": result.benchmark_id,
        "benchmarkVersion": result.benchmark_version,
        "packageRef": result.package_ref,
        "runnerId": result.runner_id,
        "validatorId": result.validator_id,
        "scores": result.scores,
        "metrics": result.metrics,
        "resultRefs": result.result_refs,
        "sampleResults": result.sample_results,
        "createdAt": result.created_at,
    })
}

fn evaluation_result_v2_signing_value(result: &EvaluationResultV2) -> Value {
    json!({
        "schemaVersion": result.schema_version,
        "sourceEvaluationId": result.source_evaluation_id,
        "benchmarkId": result.benchmark_id,
        "benchmarkVersion": result.benchmark_version,
        "suiteId": result.suite_id,
        "packageRef": result.package_ref,
        "runnerId": result.runner_id,
        "validatorId": result.validator_id,
        "score": result.score,
        "scores": result.scores,
        "metrics": result.metrics,
        "timing": result.timing,
        "cost": result.cost,
        "environment": result.environment,
        "artifactRefs": result.artifact_refs,
        "resultRefs": result.result_refs,
        "randomSeeds": result.random_seeds,
        "errors": result.errors,
        "createdAt": result.created_at,
        "metadata": result.metadata,
    })
}

fn benchmark_suite_signing_value(suite: &BenchmarkSuiteV1) -> Value {
    json!({
        "schemaVersion": suite.schema_version,
        "benchmarkId": suite.benchmark_id,
        "name": suite.name,
        "task": suite.task,
        "version": suite.version,
        "maintainerId": suite.maintainer_id,
        "modalities": suite.modalities,
        "datasetRefs": suite.dataset_refs,
        "scoringMethodRef": suite.scoring_method_ref,
        "splits": suite.splits,
        "allowedModelRefs": suite.allowed_model_refs,
        "allowedRuntimes": suite.allowed_runtimes,
        "privacyRules": suite.privacy_rules,
        "expectedRuntime": suite.expected_runtime,
        "metricNames": suite.metric_names,
        "license": suite.license,
        "createdAt": suite.created_at,
        "metadata": suite.metadata,
    })
}

fn benchmark_pack_signing_value(pack: &BenchmarkPackV1) -> Value {
    json!({
        "schemaVersion": pack.schema_version,
        "benchmarkId": pack.benchmark_id,
        "name": pack.name,
        "task": pack.task,
        "version": pack.version,
        "maintainerId": pack.maintainer_id,
        "suiteRef": pack.suite_ref,
        "datasetRefs": pack.dataset_refs,
        "hiddenChallengeCommitmentRefs": pack.hidden_challenge_commitment_refs,
        "scoringFunctionRef": pack.scoring_function_ref,
        "allowedRuntimes": pack.allowed_runtimes,
        "privacyRules": pack.privacy_rules,
        "reportSchema": pack.report_schema,
        "validationMethodRefs": pack.validation_method_refs,
        "metricNames": pack.metric_names,
        "createdAt": pack.created_at,
        "metadata": pack.metadata,
    })
}

fn challenge_commitment_signing_value(commitment: &ChallengeCommitmentV1) -> Value {
    json!({
        "schemaVersion": commitment.schema_version,
        "benchmarkId": commitment.benchmark_id,
        "benchmarkVersion": commitment.benchmark_version,
        "validatorId": commitment.validator_id,
        "challengeSetHash": commitment.challenge_set_hash,
        "answerSetHash": commitment.answer_set_hash,
        "saltHash": commitment.salt_hash,
        "challengeCount": commitment.challenge_count,
        "publicDatasetRefs": commitment.public_dataset_refs,
        "hiddenRefCommitments": commitment.hidden_ref_commitments,
        "scoringRuleRefs": commitment.scoring_rule_refs,
        "revealAfter": commitment.reveal_after,
        "expiresAt": commitment.expires_at,
        "createdAt": commitment.created_at,
        "metadata": commitment.metadata,
    })
}

fn dev_signature(label: &str, validator_id: &str, payload: &Value) -> String {
    let value = json!({
        "label": label,
        "validatorId": validator_id,
        "payload": payload,
    });
    format!(
        "{DEV_EVALUATION_SIGNATURE_PREFIX}:{label}:{}",
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

fn normalize_evaluation_result_v2_context(
    mut context: EvaluationResultV2ContextV1,
) -> EvaluationResultV2ContextV1 {
    context.suite_id = context
        .suite_id
        .and_then(|value| non_empty_trimmed_string(value));
    context.artifact_refs = normalize_string_list(context.artifact_refs);
    context.random_seeds = normalize_string_list(context.random_seeds);
    if let Some(cost) = &mut context.cost {
        cost.currency = cost.currency.trim().to_ascii_uppercase();
        cost.pricing_ref = cost.pricing_ref.take().and_then(non_empty_trimmed_string);
    }
    if let Some(environment) = &mut context.environment {
        environment.runner_type = environment
            .runner_type
            .take()
            .and_then(non_empty_trimmed_string);
        environment.os = environment.os.take().and_then(non_empty_trimmed_string);
        environment.architecture = environment
            .architecture
            .take()
            .and_then(non_empty_trimmed_string);
        environment.hardware_refs = normalize_string_list(environment.hardware_refs.clone());
        environment.software_refs = normalize_string_list(environment.software_refs.clone());
    }
    for error in &mut context.errors {
        error.sample_id = error.sample_id.take().and_then(non_empty_trimmed_string);
        error.code = error.code.trim().to_string();
        error.message = error.message.trim().to_string();
    }
    context
}

fn validate_score(path: &str, score: f64, issues: &mut Vec<ValidationIssue>) {
    if !(0.0..=1.0).contains(&score) || !score.is_finite() {
        issues.push(issue(path, "Score must be a finite number between 0 and 1"));
    }
}

fn validate_evaluation_timing_v2(
    timing: &EvaluationTimingV2,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if timing.total_ms == 0 {
        warnings.push(issue(
            "$.timing.totalMs",
            "Evaluation lifecycle totalMs is zero",
        ));
    }
    if !timing.average_ms.is_finite() || timing.average_ms < 0.0 {
        issues.push(issue(
            "$.timing.averageMs",
            "Evaluation lifecycle averageMs must be a non-negative finite number",
        ));
    }
    let started =
        validate_rfc3339_optional("$.timing.startedAt", timing.started_at.as_deref(), issues);
    let completed = validate_rfc3339_optional(
        "$.timing.completedAt",
        timing.completed_at.as_deref(),
        issues,
    );
    if let (Some(started), Some(completed)) = (started, completed) {
        if completed < started {
            issues.push(issue(
                "$.timing.completedAt",
                "Evaluation completedAt must not be before startedAt",
            ));
        }
    }
    if timing.started_at.is_none() && timing.completed_at.is_none() {
        warnings.push(issue(
            "$.timing",
            "Evaluation lifecycle timing does not include startedAt or completedAt",
        ));
    }
}

fn validate_evaluation_cost_v2(
    cost: &EvaluationCostV2,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if !cost.amount.is_finite() || cost.amount < 0.0 {
        issues.push(issue(
            "$.cost.amount",
            "Evaluation cost amount must be a non-negative finite number",
        ));
    }
    if cost.currency.trim().is_empty() {
        issues.push(issue(
            "$.cost.currency",
            "Evaluation cost currency is required",
        ));
    } else if cost.currency.len() != 3 || !cost.currency.chars().all(|ch| ch.is_ascii_uppercase()) {
        warnings.push(issue(
            "$.cost.currency",
            "Evaluation cost currency should use a three-letter uppercase code",
        ));
    }
    if let Some(pricing_ref) = &cost.pricing_ref {
        if pricing_ref.trim().is_empty() {
            issues.push(issue(
                "$.cost.pricingRef",
                "Pricing ref must not be empty when present",
            ));
        } else if !looks_like_reference(pricing_ref) && !looks_like_hash_ref(pricing_ref) {
            warnings.push(issue(
                "$.cost.pricingRef",
                "Pricing ref is not a recognized content, local, web, file, selector, or hash reference",
            ));
        }
    }
}

fn validate_evaluation_environment_v2(
    environment: &EvaluationEnvironmentV2,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    validate_reference_list(
        &environment.hardware_refs,
        "$.environment.hardwareRefs",
        "Hardware ref",
        issues,
        warnings,
    );
    validate_reference_list(
        &environment.software_refs,
        "$.environment.softwareRefs",
        "Software ref",
        issues,
        warnings,
    );
    if environment.runner_type.is_none()
        && environment.os.is_none()
        && environment.architecture.is_none()
        && environment.hardware_refs.is_empty()
        && environment.software_refs.is_empty()
    {
        warnings.push(issue(
            "$.environment",
            "Evaluation environment does not identify runner type, platform, hardware, or software",
        ));
    }
    if !environment.metadata.is_object() {
        warnings.push(issue(
            "$.environment.metadata",
            "Evaluation environment metadata is usually expected to be an object",
        ));
    }
}

fn validate_evaluation_errors_v2(errors: &[EvaluationErrorV2], issues: &mut Vec<ValidationIssue>) {
    for (index, error) in errors.iter().enumerate() {
        if let Some(sample_id) = &error.sample_id {
            if sample_id.trim().is_empty() {
                issues.push(issue(
                    format!("$.errors[{index}].sampleId"),
                    "Evaluation error sampleId must not be empty when present",
                ));
            }
        }
        if error.code.trim().is_empty() {
            issues.push(issue(
                format!("$.errors[{index}].code"),
                "Evaluation error code is required",
            ));
        }
        if error.message.trim().is_empty() {
            issues.push(issue(
                format!("$.errors[{index}].message"),
                "Evaluation error message is required",
            ));
        }
    }
}

fn validate_rfc3339_optional(
    path: &str,
    value: Option<&str>,
    issues: &mut Vec<ValidationIssue>,
) -> Option<DateTime<chrono::FixedOffset>> {
    let value = value?;
    match DateTime::parse_from_rfc3339(value) {
        Ok(parsed) => Some(parsed),
        Err(error) => {
            issues.push(issue(path, format!("Timestamp must be RFC3339: {error}")));
            None
        }
    }
}

fn non_empty_trimmed_string(value: String) -> Option<String> {
    let value = value.trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn normalize_string_list(values: Vec<String>) -> Vec<String> {
    let mut values: Vec<_> = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    values.sort();
    values.dedup();
    values
}

fn normalize_benchmark_privacy_rules(
    mut rules: BenchmarkPrivacyRulesV1,
) -> BenchmarkPrivacyRulesV1 {
    rules.required_tier = rules.required_tier.trim().to_string();
    rules.access_policy_refs = normalize_string_list(rules.access_policy_refs);
    rules
}

fn validate_non_empty_string_list(
    values: &[String],
    path: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    for (index, value) in values.iter().enumerate() {
        if value.trim().is_empty() {
            issues.push(issue(
                format!("{path}[{index}]"),
                "List entry must not be empty",
            ));
        }
    }
}

fn validate_reference_list(
    refs: &[String],
    path: &str,
    label: &str,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    for (index, reference) in refs.iter().enumerate() {
        if reference.trim().is_empty() {
            issues.push(issue(
                format!("{path}[{index}]"),
                format!("{label} must not be empty"),
            ));
        } else if !looks_like_reference(reference) && !looks_like_hash_ref(reference) {
            warnings.push(issue(
                format!("{path}[{index}]"),
                format!("{label} is not a recognized content, local, web, file, selector, or hash reference"),
            ));
        }
    }
}

fn validate_benchmark_splits(
    splits: &[BenchmarkSplitV1],
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if splits.is_empty() {
        issues.push(issue(
            "$.splits",
            "Benchmark suite must include at least one split definition",
        ));
        return;
    }
    let mut total_weight = 0.0;
    for (index, split) in splits.iter().enumerate() {
        if split.name.trim().is_empty() {
            issues.push(issue(
                format!("$.splits[{index}].name"),
                "Benchmark split name is required",
            ));
        }
        if !split.weight.is_finite() || split.weight <= 0.0 {
            issues.push(issue(
                format!("$.splits[{index}].weight"),
                "Benchmark split weight must be a positive finite number",
            ));
        } else {
            total_weight += split.weight;
        }
        if split.dataset_refs.is_empty() {
            issues.push(issue(
                format!("$.splits[{index}].datasetRefs"),
                "Benchmark split must include at least one dataset reference",
            ));
        }
        for (ref_index, reference) in split.dataset_refs.iter().enumerate() {
            let path = format!("$.splits[{index}].datasetRefs[{ref_index}]");
            if reference.trim().is_empty() {
                issues.push(issue(path, "Benchmark split dataset reference is required"));
            } else if split.hidden
                && !looks_like_hash_ref(reference)
                && !looks_like_commitment_ref(reference)
            {
                issues.push(issue(
                    path,
                    "Hidden split dataset refs must be challenge commitments or hashes, not raw hidden dataset refs",
                ));
            } else if !looks_like_reference(reference)
                && !looks_like_hash_ref(reference)
                && !looks_like_commitment_ref(reference)
            {
                warnings.push(issue(
                    path,
                    "Benchmark split dataset reference is not a recognized content, local, web, file, selector, commitment, or hash reference",
                ));
            }
        }
    }
    if total_weight > 0.0 && (total_weight - 1.0).abs() > 0.001 {
        warnings.push(issue(
            "$.splits",
            "Benchmark split weights usually should sum to 1.0",
        ));
    }
}

fn validate_hidden_challenge_commitment_refs(
    refs: &[String],
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    for (index, reference) in refs.iter().enumerate() {
        let path = format!("$.hiddenChallengeCommitmentRefs[{index}]");
        if reference.trim().is_empty() {
            issues.push(issue(path, "Hidden challenge commitment ref is required"));
        } else if looks_like_hash_ref(reference) || looks_like_commitment_ref(reference) {
            continue;
        } else if reference.starts_with("local://")
            || reference.starts_with("bzz://")
            || reference.starts_with("ipfs://")
        {
            warnings.push(issue(
                path,
                "Hidden challenge ref should point to a commitment object, not raw hidden challenge data",
            ));
        } else {
            warnings.push(issue(
                path,
                "Hidden challenge commitment ref is not a recognized commitment, hash, local, Swarm, or IPFS reference",
            ));
        }
    }
}

fn validate_benchmark_privacy_rules(
    rules: &BenchmarkPrivacyRulesV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if rules.required_tier.trim().is_empty() {
        issues.push(issue(
            "$.privacyRules.requiredTier",
            "Benchmark privacy rules must declare a required privacy tier",
        ));
    } else if !matches!(
        rules.required_tier.as_str(),
        "public"
            | "no-log"
            | "local-only"
            | "tee-confidential"
            | "zk-verified"
            | "fhe"
            | "internal-audit"
    ) {
        warnings.push(issue(
            "$.privacyRules.requiredTier",
            "Benchmark privacy tier is not one of the currently recognized v0.2 tier names",
        ));
    }
    validate_reference_list(
        &rules.access_policy_refs,
        "$.privacyRules.accessPolicyRefs",
        "Access policy ref",
        issues,
        warnings,
    );
}

fn validate_benchmark_expected_runtime(
    runtime: &BenchmarkExpectedRuntimeV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if runtime.max_ms == 0 {
        issues.push(issue(
            "$.expectedRuntime.maxMs",
            "Benchmark expected runtime maxMs must be greater than zero",
        ));
    }
    if runtime.p95_ms > 0 && runtime.p50_ms > runtime.p95_ms {
        issues.push(issue(
            "$.expectedRuntime.p50Ms",
            "Benchmark expected runtime p50Ms must not exceed p95Ms",
        ));
    }
    if runtime.p95_ms > runtime.max_ms {
        issues.push(issue(
            "$.expectedRuntime.p95Ms",
            "Benchmark expected runtime p95Ms must not exceed maxMs",
        ));
    }
    if runtime.p50_ms == 0 || runtime.p95_ms == 0 {
        warnings.push(issue(
            "$.expectedRuntime",
            "Benchmark expected runtime is missing p50Ms or p95Ms guidance",
        ));
    }
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn looks_like_hash_ref(value: &str) -> bool {
    let value = value.trim();
    is_sha256_hex(value) || value.starts_with("sha256:") || value.starts_with("sha256://")
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit())
}

fn looks_like_reference(value: &str) -> bool {
    value.starts_with("bzz://")
        || value.starts_with("local://")
        || value.starts_with("ipfs://")
        || value.starts_with("http://")
        || value.starts_with("https://")
        || value.starts_with("file:")
        || value.starts_with("package-kind://")
        || value.starts_with("model://")
        || value.starts_with("dataset://")
        || value.starts_with("benchmark://")
        || value.starts_with("eval://")
        || value.starts_with("receipt://")
}

fn looks_like_commitment_ref(value: &str) -> bool {
    value.starts_with("challenge-commitment://")
        || value.starts_with("challenge-commitment:")
        || value.starts_with("commitment://")
        || value.starts_with("commitment:")
}

fn empty_metadata() -> Value {
    json!({})
}

fn default_true() -> bool {
    true
}

fn default_benchmark_privacy_rules() -> BenchmarkPrivacyRulesV1 {
    BenchmarkPrivacyRulesV1 {
        required_tier: "public".to_string(),
        allow_public_results: true,
        allow_remote_runners: true,
        require_result_redaction: false,
        access_policy_refs: Vec::new(),
    }
}

fn default_benchmark_expected_runtime() -> BenchmarkExpectedRuntimeV1 {
    BenchmarkExpectedRuntimeV1 {
        p50_ms: 0,
        p95_ms: 0,
        max_ms: 30_000,
    }
}

fn default_benchmark_pack_report_schema() -> Value {
    json!({
        "schemaVersion": "hivemind.validation_report.v2",
        "requiredFields": [
            "reportId",
            "validatorId",
            "subjectType",
            "method",
            "score",
            "evidenceRefs",
            "createdAt",
            "signature"
        ],
        "recommendedFields": [
            "benchmarkRef",
            "challengeCommitmentRef",
            "latencyScore",
            "costScore",
            "qualityScore",
            "safetyScore",
            "fraudSignals"
        ]
    })
}

fn default_weight() -> f64 {
    1.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::ExecutionMetrics;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn mini_benchmark_has_public_embedding_contract() {
        let benchmark = mini_embedding_benchmark();
        let dataset = mini_embedding_dataset();
        let suite = mini_embedding_benchmark_suite();

        assert_eq!(benchmark.schema_version, "swarm-ai.benchmark-package.v1");
        assert_eq!(benchmark.task, "embedding");
        assert_eq!(dataset.len(), 3);
        assert_eq!(suite.schema_version, "hivemind.benchmark_suite.v1");
        assert_eq!(suite.benchmark_id, benchmark.benchmark_id);
        assert!(verify_benchmark_suite(&suite).valid);
    }

    #[test]
    fn benchmark_suite_verifies_and_round_trips_store() {
        let root = unique_temp_dir("hivemind-benchmark-suite-store-test");
        let suite = create_benchmark_suite(BenchmarkSuiteInitOptionsV1 {
            benchmark_id: "commons/rag-answer-v1".to_string(),
            name: "RAG Answer Quality".to_string(),
            task: "rag".to_string(),
            version: "1.0.0".to_string(),
            maintainer_id: "validator-1".to_string(),
            modalities: vec!["text".to_string()],
            dataset_refs: vec!["bzz://rag-public-dataset".to_string()],
            scoring_method_ref: "bzz://rag-scoring-method".to_string(),
            splits: vec![
                BenchmarkSplitV1 {
                    name: "public".to_string(),
                    dataset_refs: vec!["bzz://rag-public-dataset".to_string()],
                    weight: 0.7,
                    hidden: false,
                },
                BenchmarkSplitV1 {
                    name: "hidden".to_string(),
                    dataset_refs: vec!["challenge-commitment://hidden-suite".to_string()],
                    weight: 0.3,
                    hidden: true,
                },
            ],
            allowed_model_refs: vec!["package-kind://model".to_string()],
            allowed_runtimes: vec!["local".to_string(), "remote".to_string()],
            privacy_rules: BenchmarkPrivacyRulesV1 {
                required_tier: "no-log".to_string(),
                allow_public_results: false,
                allow_remote_runners: true,
                require_result_redaction: true,
                access_policy_refs: vec!["bzz://benchmark-access-policy".to_string()],
            },
            expected_runtime: BenchmarkExpectedRuntimeV1 {
                p50_ms: 1_000,
                p95_ms: 5_000,
                max_ms: 30_000,
            },
            metric_names: vec!["faithfulness".to_string(), "latency".to_string()],
            license: None,
            metadata: json!({ "purpose": "suite store smoke" }),
        });

        let verification = verify_benchmark_suite(&suite);
        let path = write_benchmark_suite(&root, &suite).unwrap();
        let summary = list_benchmark_suites(&root).unwrap();
        let lookup = get_benchmark_suite(&root, &suite.suite_id)
            .unwrap()
            .unwrap();

        assert!(verification.valid, "{verification:#?}");
        assert!(suite.suite_id.starts_with("benchmark-suite-"));
        assert_eq!(summary.suite_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.suites[0].suite_path, path.display().to_string());
        assert_eq!(lookup.suite.suite_id, suite.suite_id);
        assert!(lookup.verification.valid);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn identity_signed_benchmark_suite_verifies() {
        let mut suite = mini_embedding_benchmark_suite();
        suite.maintainer_id = "validator-1".to_string();
        sign_benchmark_suite(&mut suite);
        suite.suite_id = canonical_benchmark_suite_id(&suite).unwrap();
        let identity =
            hivemind_identity::identity_from_seed("validator-1", b"validator-seed").unwrap();

        let envelope = sign_benchmark_suite_with_identity(&mut suite, &identity).unwrap();
        let verification = verify_benchmark_suite(&suite);

        assert_eq!(envelope.signer, suite.maintainer_id);
        assert!(
            suite
                .signature
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .starts_with("ed25519-payload-hash:")
        );
    }

    #[test]
    fn benchmark_suite_detects_hidden_split_leakage_and_tampering() {
        let mut suite = create_benchmark_suite(BenchmarkSuiteInitOptionsV1 {
            benchmark_id: "commons/hidden-v1".to_string(),
            name: "Hidden Suite".to_string(),
            task: "classification".to_string(),
            version: "1.0.0".to_string(),
            maintainer_id: "validator-1".to_string(),
            modalities: vec!["text".to_string()],
            dataset_refs: vec!["bzz://public-dataset".to_string()],
            scoring_method_ref: "local://scoring/exact-match".to_string(),
            splits: vec![BenchmarkSplitV1 {
                name: "hidden".to_string(),
                dataset_refs: vec!["bzz://raw-hidden-dataset".to_string()],
                weight: 1.0,
                hidden: true,
            }],
            allowed_model_refs: vec!["package-kind://model".to_string()],
            allowed_runtimes: vec!["local".to_string()],
            privacy_rules: default_benchmark_privacy_rules(),
            expected_runtime: BenchmarkExpectedRuntimeV1 {
                p50_ms: 100,
                p95_ms: 500,
                max_ms: 1_000,
            },
            metric_names: vec!["exact_match".to_string()],
            license: None,
            metadata: json!({}),
        });

        let leaked = verify_benchmark_suite(&suite);
        assert!(!leaked.valid);
        assert!(
            leaked
                .issues
                .iter()
                .any(|issue| issue.path == "$.splits[0].datasetRefs[0]")
        );

        suite.splits[0].dataset_refs = vec!["challenge-commitment://hidden-suite".to_string()];
        sign_benchmark_suite(&mut suite);
        suite.suite_id = canonical_benchmark_suite_id(&suite).unwrap();
        assert!(verify_benchmark_suite(&suite).valid);

        suite.metric_names.push("leaked_metric".to_string());
        let tampered = verify_benchmark_suite(&suite);
        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path == "$.suiteId" || issue.path == "$.signature")
        );
    }

    #[test]
    fn benchmark_pack_projects_task_specific_suite_and_detects_tampering() {
        let suite = create_benchmark_suite(BenchmarkSuiteInitOptionsV1 {
            benchmark_id: "commons/ocr-invoice-v1".to_string(),
            name: "Invoice OCR Extraction".to_string(),
            task: "ocr.extract.invoice".to_string(),
            version: "1.0.0".to_string(),
            maintainer_id: "validator-1".to_string(),
            modalities: vec!["document".to_string(), "text".to_string()],
            dataset_refs: vec!["bzz://invoice-public-set".to_string()],
            scoring_method_ref: "local://scoring/reference-answer-score".to_string(),
            splits: vec![
                BenchmarkSplitV1 {
                    name: "public".to_string(),
                    dataset_refs: vec!["bzz://invoice-public-set".to_string()],
                    weight: 0.8,
                    hidden: false,
                },
                BenchmarkSplitV1 {
                    name: "hidden".to_string(),
                    dataset_refs: vec!["challenge-commitment://invoice-hidden".to_string()],
                    weight: 0.2,
                    hidden: true,
                },
            ],
            allowed_model_refs: vec!["package-kind://model".to_string()],
            allowed_runtimes: vec!["browser".to_string(), "local".to_string()],
            privacy_rules: BenchmarkPrivacyRulesV1 {
                required_tier: "no-log".to_string(),
                allow_public_results: false,
                allow_remote_runners: true,
                require_result_redaction: true,
                access_policy_refs: vec!["local://access/benchmark-policy".to_string()],
            },
            expected_runtime: BenchmarkExpectedRuntimeV1 {
                p50_ms: 500,
                p95_ms: 2_000,
                max_ms: 5_000,
            },
            metric_names: vec!["field_f1".to_string(), "latency".to_string()],
            license: None,
            metadata: json!({}),
        });

        let projection = benchmark_pack_projection(BenchmarkPackProjectionRequestV1 {
            suite: suite.clone(),
            context: BenchmarkPackContextV1 {
                suite_ref: Some(format!("local://benchmark-suite/{}", suite.suite_id)),
                hidden_challenge_commitment_refs: vec![
                    "challenge-commitment://invoice-private-v2".to_string(),
                ],
                ..Default::default()
            },
        });

        assert_eq!(
            projection.schema_version,
            "hivemind.benchmark-pack-projection.v1"
        );
        assert!(projection.verification.valid, "{projection:#?}");
        assert_eq!(projection.pack.schema_version, "hivemind.benchmark-pack.v1");
        assert!(projection.pack.pack_id.starts_with("benchmark-pack-"));
        assert!(
            projection
                .pack
                .validation_method_refs
                .contains(&"benchmark_score".to_string())
        );
        assert!(
            projection
                .pack
                .validation_method_refs
                .contains(&"hidden_challenge".to_string())
        );
        assert_eq!(projection.pack.hidden_challenge_commitment_refs.len(), 2);

        let mut tampered = projection.pack.clone();
        tampered.metric_names.push("extra_metric".to_string());
        let verification = verify_benchmark_pack(&tampered);
        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.packId" || issue.path == "$.signature")
        );
    }

    #[test]
    fn scores_embedding_evaluation_result() {
        let benchmark = mini_embedding_benchmark();
        let mut dataset = mini_embedding_dataset();
        let entry = dataset.remove(0);
        let request = benchmark_execution_request(
            &benchmark,
            &entry,
            "bzz://pkg",
            "hivemind/test",
            "0.1.0",
            None,
        );
        let response = ExecutionResponseV1::succeeded(
            request.request_id,
            json!({ "embedding": [0.1, 0.2, 0.3, 0.4] }),
            ExecutionMetrics {
                total_ms: 12,
                ..Default::default()
            },
        );
        let sample =
            sample_result_from_response(&entry, &response, scoring_deadline_ms(&benchmark));
        let result = evaluation_result(
            &benchmark,
            "bzz://pkg",
            Some("runner-1".to_string()),
            "validator-1",
            vec![sample],
            Vec::new(),
        );

        assert_eq!(result.metrics.samples, 1);
        assert_eq!(result.scores.overall, 1.0);
        assert!(result.evaluation_id.starts_with("evaluation-"));
        assert!(verify_evaluation_result(&result).valid);
    }

    #[test]
    fn evaluation_result_store_lists_and_gets_results() {
        let root = unique_temp_dir("hivemind-evaluation-result-store-test");
        let benchmark = mini_embedding_benchmark();
        let mut dataset = mini_embedding_dataset();
        let entry = dataset.remove(0);
        let request = benchmark_execution_request(
            &benchmark,
            &entry,
            "bzz://pkg",
            "hivemind/test",
            "0.1.0",
            None,
        );
        let response = ExecutionResponseV1::succeeded(
            request.request_id,
            json!({ "embedding": [0.1, 0.2, 0.3, 0.4] }),
            ExecutionMetrics {
                total_ms: 12,
                ..Default::default()
            },
        );
        let sample =
            sample_result_from_response(&entry, &response, scoring_deadline_ms(&benchmark));
        let result = evaluation_result(
            &benchmark,
            "bzz://pkg",
            Some("runner-1".to_string()),
            "validator-1",
            vec![sample],
            Vec::new(),
        );

        let result_path = write_evaluation_result(&root, &result).unwrap();
        let summary = list_evaluation_results(&root).unwrap();
        let lookup = get_evaluation_result(&root, &result.evaluation_id)
            .unwrap()
            .unwrap();
        let missing = get_evaluation_result(&root, "missing-evaluation").unwrap();

        assert_eq!(summary.evaluation_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.evaluations[0].evaluation_id, result.evaluation_id);
        assert_eq!(
            summary.evaluations[0].result_path,
            result_path.display().to_string()
        );
        assert_eq!(lookup.evaluation.evaluation_id, result.evaluation_id);
        assert!(lookup.verification.valid);
        assert!(missing.is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn evaluation_leaderboard_ranks_valid_results_with_evidence() {
        let root = unique_temp_dir("hivemind-evaluation-leaderboard-test");
        let benchmark = mini_embedding_benchmark();

        let result_a = evaluation_result(
            &benchmark,
            "bzz://pkg-a",
            Some("runner-a".to_string()),
            "validator-1",
            vec![sample_result("sample-a", 1.0, 1.0, 10, Some("receipt-a"))],
            vec!["bzz://result-a".to_string()],
        );
        let result_b = evaluation_result(
            &benchmark,
            "bzz://pkg-b",
            Some("runner-b".to_string()),
            "validator-2",
            vec![sample_result("sample-b", 0.5, 1.0, 20, Some("receipt-b"))],
            vec!["bzz://result-b".to_string()],
        );
        let mut invalid_result = evaluation_result(
            &benchmark,
            "bzz://pkg-c",
            Some("runner-c".to_string()),
            "validator-3",
            vec![sample_result("sample-c", 1.0, 1.0, 10, None)],
            Vec::new(),
        );
        invalid_result.scores.overall = 99.0;

        write_evaluation_result(&root, &result_b).unwrap();
        write_evaluation_result(&root, &result_a).unwrap();
        write_evaluation_result(&root, &invalid_result).unwrap();

        let leaderboard = evaluation_leaderboard(&root).unwrap();

        assert_eq!(
            leaderboard.schema_version,
            "swarm-ai.evaluation-leaderboard.v1"
        );
        assert_eq!(leaderboard.evaluation_count, 3);
        assert_eq!(leaderboard.valid_evaluation_count, 2);
        assert_eq!(leaderboard.invalid_evaluation_count, 1);
        assert_eq!(leaderboard.benchmark_count, 1);
        assert_eq!(leaderboard.entry_count, 2);
        assert_eq!(leaderboard.entries[0].rank, 1);
        assert_eq!(leaderboard.entries[0].package_ref, "bzz://pkg-a");
        assert_eq!(leaderboard.entries[0].receipt_ids, vec!["receipt-a"]);
        assert_eq!(leaderboard.entries[0].result_refs, vec!["bzz://result-a"]);
        assert_eq!(leaderboard.entries[1].rank, 2);
        assert_eq!(leaderboard.entries[1].package_ref, "bzz://pkg-b");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn evaluation_result_v2_projection_verifies_and_round_trips_store() {
        let root = unique_temp_dir("hivemind-evaluation-result-v2-store-test");
        let benchmark = mini_embedding_benchmark();
        let source = evaluation_result(
            &benchmark,
            "bzz://pkg",
            Some("runner-1".to_string()),
            "validator-1",
            vec![sample_result("sample-a", 1.0, 1.0, 10, Some("receipt-a"))],
            vec!["bzz://result-a".to_string()],
        );

        let result = evaluation_result_v2_from_v1(
            &source,
            EvaluationResultV2ContextV1 {
                suite_id: Some("suite-embedding-basic".to_string()),
                timing: Some(EvaluationTimingV2 {
                    started_at: Some("2026-06-02T00:00:00Z".to_string()),
                    completed_at: Some("2026-06-02T00:00:01Z".to_string()),
                    total_ms: 10,
                    average_ms: 10.0,
                }),
                cost: Some(EvaluationCostV2 {
                    amount: 0.01,
                    currency: "usd".to_string(),
                    pricing_ref: Some("local://pricing/free-tier".to_string()),
                }),
                environment: Some(EvaluationEnvironmentV2 {
                    runner_type: Some("local".to_string()),
                    os: Some("linux".to_string()),
                    architecture: Some("x86_64".to_string()),
                    hardware_refs: vec!["local://hardware/cpu".to_string()],
                    software_refs: vec!["bzz://software-lockfile".to_string()],
                    metadata: json!({ "runtime": "test" }),
                }),
                artifact_refs: vec!["bzz://artifact-a".to_string()],
                random_seeds: vec!["seed-1".to_string()],
                errors: Vec::new(),
                metadata: json!({ "scenario": "projection" }),
            },
        );

        let verification = verify_evaluation_result_v2(&result);
        let path = write_evaluation_result_v2(&root, &result).unwrap();
        let summary = list_evaluation_results_v2(&root).unwrap();
        let lookup = get_evaluation_result_v2(&root, &result.evaluation_id)
            .unwrap()
            .unwrap();

        assert!(verification.valid, "{verification:#?}");
        assert!(result.evaluation_id.starts_with("evaluation-v2-"));
        assert_eq!(result.source_evaluation_id, Some(source.evaluation_id));
        assert_eq!(
            result.cost.as_ref().map(|cost| cost.currency.as_str()),
            Some("USD")
        );
        assert_eq!(summary.evaluation_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(
            summary.evaluations[0].result_path,
            path.display().to_string()
        );
        assert_eq!(lookup.evaluation.evaluation_id, result.evaluation_id);
        assert!(lookup.verification.valid);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn identity_signed_evaluation_result_v2_verifies() {
        let benchmark = mini_embedding_benchmark();
        let source = evaluation_result(
            &benchmark,
            "bzz://pkg",
            Some("runner-1".to_string()),
            "validator-1",
            vec![sample_result("sample-a", 1.0, 1.0, 10, Some("receipt-a"))],
            vec!["bzz://result-a".to_string()],
        );
        let mut result = evaluation_result_v2_from_v1(
            &source,
            EvaluationResultV2ContextV1 {
                environment: Some(EvaluationEnvironmentV2 {
                    runner_type: Some("browser".to_string()),
                    ..Default::default()
                }),
                random_seeds: vec!["seed-1".to_string()],
                ..Default::default()
            },
        );
        let identity =
            hivemind_identity::identity_from_seed("validator-1", b"validator-seed").unwrap();

        let envelope = sign_evaluation_result_v2_with_identity(&mut result, &identity).unwrap();
        let verification = verify_evaluation_result_v2(&result);

        assert_eq!(envelope.signer, result.validator_id);
        assert!(
            result
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
    fn evaluation_result_v2_detects_bad_cost_and_tampering() {
        let benchmark = mini_embedding_benchmark();
        let source = evaluation_result(
            &benchmark,
            "bzz://pkg",
            Some("runner-1".to_string()),
            "validator-1",
            vec![sample_result("sample-a", 1.0, 1.0, 10, Some("receipt-a"))],
            vec!["bzz://result-a".to_string()],
        );
        let mut result = evaluation_result_v2_from_v1(
            &source,
            EvaluationResultV2ContextV1 {
                cost: Some(EvaluationCostV2 {
                    amount: -1.0,
                    currency: "USD".to_string(),
                    pricing_ref: None,
                }),
                environment: Some(EvaluationEnvironmentV2 {
                    runner_type: Some("local".to_string()),
                    ..Default::default()
                }),
                random_seeds: vec!["seed-1".to_string()],
                ..Default::default()
            },
        );
        let bad_cost = verify_evaluation_result_v2(&result);
        assert!(!bad_cost.valid);
        assert!(
            bad_cost
                .issues
                .iter()
                .any(|issue| issue.path == "$.cost.amount")
        );

        result.cost = Some(EvaluationCostV2 {
            amount: 0.0,
            currency: "USD".to_string(),
            pricing_ref: None,
        });
        sign_evaluation_result_v2(&mut result);
        result.evaluation_id = canonical_evaluation_result_v2_id(&result).unwrap();
        assert!(verify_evaluation_result_v2(&result).valid);

        result.score = 0.1;
        let tampered = verify_evaluation_result_v2(&result);
        assert!(!tampered.valid);
        assert!(tampered.issues.iter().any(|issue| {
            issue.path == "$.score" || issue.path == "$.evaluationId" || issue.path == "$.signature"
        }));
    }

    #[test]
    fn challenge_commitment_verifies_and_round_trips_store() {
        let root = unique_temp_dir("hivemind-challenge-commitment-store-test");
        let commitment = create_challenge_commitment(ChallengeCommitmentInitOptionsV1 {
            benchmark_id: "commons/embedding-basic-v1".to_string(),
            benchmark_version: "1.0.0".to_string(),
            validator_id: "validator-1".to_string(),
            challenge_set_hash: "a".repeat(64),
            answer_set_hash: Some("sha256:answers".to_string()),
            salt_hash: "b".repeat(64),
            challenge_count: 12,
            public_dataset_refs: vec!["bzz://public-dataset".to_string()],
            hidden_ref_commitments: vec!["c".repeat(64)],
            scoring_rule_refs: vec!["local://scoring/embedding-shape".to_string()],
            reveal_after: Some("2026-06-02T00:00:00Z".to_string()),
            expires_at: Some("2026-06-03T00:00:00Z".to_string()),
            metadata: json!({ "purpose": "hidden validator smoke" }),
        });

        let verification = verify_challenge_commitment(&commitment);
        let path = write_challenge_commitment(&root, &commitment).unwrap();
        let summary = list_challenge_commitments(&root).unwrap();
        let lookup = get_challenge_commitment(&root, &commitment.commitment_id)
            .unwrap()
            .unwrap();

        assert!(verification.valid, "{verification:#?}");
        assert!(
            commitment
                .commitment_id
                .starts_with("challenge-commitment-")
        );
        assert_eq!(summary.commitment_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(
            summary.commitments[0].commitment_path,
            path.display().to_string()
        );
        assert_eq!(lookup.commitment.commitment_id, commitment.commitment_id);
        assert!(lookup.verification.valid);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn identity_signed_challenge_commitment_verifies() {
        let mut commitment = create_challenge_commitment(ChallengeCommitmentInitOptionsV1 {
            benchmark_id: "commons/embedding-basic-v1".to_string(),
            benchmark_version: "1.0.0".to_string(),
            validator_id: "validator-1".to_string(),
            challenge_set_hash: "a".repeat(64),
            answer_set_hash: Some("b".repeat(64)),
            salt_hash: "c".repeat(64),
            challenge_count: 3,
            public_dataset_refs: Vec::new(),
            hidden_ref_commitments: vec!["d".repeat(64)],
            scoring_rule_refs: Vec::new(),
            reveal_after: None,
            expires_at: None,
            metadata: json!({}),
        });
        let identity =
            hivemind_identity::identity_from_seed("validator-1", b"validator-seed").unwrap();

        let envelope = sign_challenge_commitment_with_identity(&mut commitment, &identity).unwrap();
        let verification = verify_challenge_commitment(&commitment);

        assert_eq!(envelope.signer, commitment.validator_id);
        assert!(
            commitment
                .signature
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .starts_with("ed25519-payload-hash:")
        );
    }

    #[test]
    fn challenge_commitment_detects_hidden_ref_leakage_and_tampering() {
        let mut commitment = create_challenge_commitment(ChallengeCommitmentInitOptionsV1 {
            benchmark_id: "commons/embedding-basic-v1".to_string(),
            benchmark_version: "1.0.0".to_string(),
            validator_id: "validator-1".to_string(),
            challenge_set_hash: "a".repeat(64),
            answer_set_hash: Some("b".repeat(64)),
            salt_hash: "c".repeat(64),
            challenge_count: 1,
            public_dataset_refs: Vec::new(),
            hidden_ref_commitments: vec!["bzz://hidden-dataset".to_string()],
            scoring_rule_refs: Vec::new(),
            reveal_after: None,
            expires_at: None,
            metadata: json!({}),
        });
        let leaked = verify_challenge_commitment(&commitment);
        assert!(!leaked.valid);
        assert!(
            leaked
                .issues
                .iter()
                .any(|issue| issue.path == "$.hiddenRefCommitments[0]")
        );

        commitment.hidden_ref_commitments = vec!["d".repeat(64)];
        sign_challenge_commitment(&mut commitment);
        commitment.commitment_id = canonical_challenge_commitment_id(&commitment).unwrap();
        assert!(verify_challenge_commitment(&commitment).valid);

        commitment.challenge_count = 2;
        let tampered = verify_challenge_commitment(&commitment);
        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path == "$.commitmentId" || issue.path == "$.signature")
        );
    }

    #[test]
    fn identity_signed_evaluation_result_verifies() {
        let benchmark = mini_embedding_benchmark();
        let mut dataset = mini_embedding_dataset();
        let entry = dataset.remove(0);
        let request = benchmark_execution_request(
            &benchmark,
            &entry,
            "bzz://pkg",
            "hivemind/test",
            "0.1.0",
            None,
        );
        let response = ExecutionResponseV1::succeeded(
            request.request_id,
            json!({ "embedding": [0.1, 0.2, 0.3, 0.4] }),
            ExecutionMetrics {
                total_ms: 12,
                ..Default::default()
            },
        );
        let sample =
            sample_result_from_response(&entry, &response, scoring_deadline_ms(&benchmark));
        let mut result = evaluation_result(
            &benchmark,
            "bzz://pkg",
            Some("runner-1".to_string()),
            "validator-1",
            vec![sample],
            Vec::new(),
        );
        let identity =
            hivemind_identity::identity_from_seed("validator-1", b"validator-seed").unwrap();

        let envelope = sign_evaluation_result_with_identity(&mut result, &identity).unwrap();
        let verification = verify_evaluation_result(&result);

        assert_eq!(envelope.signer, result.validator_id);
        assert!(
            result
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
    fn rejects_tampered_evaluation_result() {
        let benchmark = mini_embedding_benchmark();
        let mut dataset = mini_embedding_dataset();
        let entry = dataset.remove(0);
        let request = benchmark_execution_request(
            &benchmark,
            &entry,
            "bzz://pkg",
            "hivemind/test",
            "0.1.0",
            None,
        );
        let response = ExecutionResponseV1::succeeded(
            request.request_id,
            json!({ "embedding": [0.1, 0.2, 0.3, 0.4] }),
            ExecutionMetrics {
                total_ms: 12,
                ..Default::default()
            },
        );
        let sample =
            sample_result_from_response(&entry, &response, scoring_deadline_ms(&benchmark));
        let mut result = evaluation_result(
            &benchmark,
            "bzz://pkg",
            Some("runner-1".to_string()),
            "validator-1",
            vec![sample],
            Vec::new(),
        );
        result.scores.overall = 0.1;

        let verification = verify_evaluation_result(&result);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signature")
        );
    }

    #[test]
    fn rejects_tampered_identity_signed_evaluation_result() {
        let benchmark = mini_embedding_benchmark();
        let mut dataset = mini_embedding_dataset();
        let entry = dataset.remove(0);
        let request = benchmark_execution_request(
            &benchmark,
            &entry,
            "bzz://pkg",
            "hivemind/test",
            "0.1.0",
            None,
        );
        let response = ExecutionResponseV1::succeeded(
            request.request_id,
            json!({ "embedding": [0.1, 0.2, 0.3, 0.4] }),
            ExecutionMetrics {
                total_ms: 12,
                ..Default::default()
            },
        );
        let sample =
            sample_result_from_response(&entry, &response, scoring_deadline_ms(&benchmark));
        let mut result = evaluation_result(
            &benchmark,
            "bzz://pkg",
            Some("runner-1".to_string()),
            "validator-1",
            vec![sample],
            Vec::new(),
        );
        let identity =
            hivemind_identity::identity_from_seed("validator-1", b"validator-seed").unwrap();
        sign_evaluation_result_with_identity(&mut result, &identity).unwrap();
        result.scores.overall = 0.1;

        let verification = verify_evaluation_result(&result);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.evaluationId"
                    || issue.path == "$.signature.payloadHash")
        );
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }

    fn sample_result(
        entry_id: &str,
        quality: f64,
        latency: f64,
        total_ms: u64,
        receipt_id: Option<&str>,
    ) -> EvaluationSampleResultV1 {
        EvaluationSampleResultV1 {
            entry_id: entry_id.to_string(),
            request_id: format!("request-{entry_id}"),
            status: ExecutionStatus::Succeeded,
            quality,
            latency,
            total_ms,
            receipt_id: receipt_id.map(str::to_string),
        }
    }
}
