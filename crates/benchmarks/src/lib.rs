use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    AccessGrantV1, ExecutionOptions, ExecutionPrivacy, ExecutionRequestV1, ExecutionResponseV1,
    ExecutionStatus, LicenseInfo, LicenseType, ValidationIssue, canonicalize_json,
    hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
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

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
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

        assert_eq!(benchmark.schema_version, "swarm-ai.benchmark-package.v1");
        assert_eq!(benchmark.task, "embedding");
        assert_eq!(dataset.len(), 3);
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
}
