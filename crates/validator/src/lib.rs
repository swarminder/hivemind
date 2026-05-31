use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    AccessGrantV1, ExecutionOptions, ExecutionPrivacy, ExecutionReceiptV1, ExecutionRequestV1,
    ExecutionResponseV1, ExecutionStatus, ValidationIssue,
    ValidationReport as PackageValidationReport, canonicalize_json, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use hivemind_package::validate_package_dir;
use hivemind_storage::{StorageProvider, UploadResponseV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
    Ok(ValidationReportStoreSummaryV1 {
        schema_version: "swarm-ai.validation-report-store-summary.v1".to_string(),
        root: reports_dir.display().to_string(),
        report_count: reports.len(),
        valid_count,
        invalid_count: reports.len().saturating_sub(valid_count),
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
    json!({
        "schemaVersion": report.schema_version,
        "validatorId": report.validator_id,
        "runnerId": report.runner_id,
        "packageRef": report.package_ref,
        "challengeId": report.challenge_id,
        "receiptId": report.receipt_id,
        "scores": report.scores,
        "evidenceRefs": report.evidence_refs,
        "createdAt": report.created_at,
    })
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
        assert_eq!(summary.reports[0].report_id, report.report_id);
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
