use anyhow::Context;
use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    ApiSurface, DataRetentionRule, IntegrityTier, LoggingRule, PriceV1, PrivacyTier,
    ValidationIssue, canonicalize_json, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEV_FINE_TUNE_JOB_SIGNATURE_PREFIX: &str = "dev-fine-tune-job-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum FineTuneOutputArtifactKind {
    AdapterOrLora,
    FullModel,
    MergedModel,
    CheckpointSet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum FineTuneOutputVisibility {
    Private,
    Organization,
    Public,
    TokenGated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FineTuneOutputPolicyV1 {
    #[serde(rename = "artifactKind")]
    pub artifact_kind: FineTuneOutputArtifactKind,
    #[serde(rename = "outputRef", default, skip_serializing_if = "Option::is_none")]
    pub output_ref: Option<String>,
    #[serde(rename = "checkpointRefs", default)]
    pub checkpoint_refs: Vec<String>,
    #[serde(rename = "publishPackage")]
    pub publish_package: bool,
    pub visibility: FineTuneOutputVisibility,
    #[serde(
        rename = "licenseRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub license_ref: Option<String>,
    #[serde(rename = "retainIntermediateCheckpoints")]
    pub retain_intermediate_checkpoints: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FineTunePrivacyV1 {
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "dataRetentionRule")]
    pub data_retention_rule: DataRetentionRule,
    #[serde(rename = "loggingRule")]
    pub logging_rule: LoggingRule,
    #[serde(rename = "confidentialComputeRequired")]
    pub confidential_compute_required: bool,
}

impl Default for FineTunePrivacyV1 {
    fn default() -> Self {
        Self {
            privacy_tier: PrivacyTier::LocalOnly,
            data_retention_rule: DataRetentionRule::DeleteAfterJob,
            logging_rule: LoggingRule::NoPromptOrOutputLogs,
            confidential_compute_required: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FineTuneValidationPolicyV1 {
    pub required: bool,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "evaluationDatasetRefs", default)]
    pub evaluation_dataset_refs: Vec<String>,
    #[serde(rename = "validatorRefs", default)]
    pub validator_refs: Vec<String>,
    #[serde(
        rename = "minimumScore",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub minimum_score: Option<f64>,
    #[serde(rename = "reproducibilityRequired")]
    pub reproducibility_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FineTuneJobV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "fineTuneJobId")]
    pub fine_tune_job_id: String,
    pub requester: String,
    #[serde(rename = "baseModelRef")]
    pub base_model_ref: String,
    #[serde(rename = "trainingDatasetRefs")]
    pub training_dataset_refs: Vec<String>,
    #[serde(rename = "validationDatasetRefs")]
    pub validation_dataset_refs: Vec<String>,
    #[serde(rename = "recipeRef")]
    pub recipe_ref: String,
    #[serde(default)]
    pub hyperparameters: Value,
    #[serde(rename = "outputPolicy")]
    pub output_policy: FineTuneOutputPolicyV1,
    pub privacy: FineTunePrivacyV1,
    #[serde(rename = "maxCost", default, skip_serializing_if = "Option::is_none")]
    pub max_cost: Option<PriceV1>,
    #[serde(rename = "validationPolicy")]
    pub validation_policy: FineTuneValidationPolicyV1,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FineTuneJobInitOptionsV1 {
    pub requester: String,
    #[serde(rename = "baseModelRef")]
    pub base_model_ref: String,
    #[serde(rename = "trainingDatasetRefs", default)]
    pub training_dataset_refs: Vec<String>,
    #[serde(rename = "validationDatasetRefs", default)]
    pub validation_dataset_refs: Vec<String>,
    #[serde(rename = "recipeRef", default)]
    pub recipe_ref: Option<String>,
    #[serde(default)]
    pub hyperparameters: Option<Value>,
    #[serde(rename = "outputRef", default)]
    pub output_ref: Option<String>,
    #[serde(rename = "artifactKind", default)]
    pub artifact_kind: Option<FineTuneOutputArtifactKind>,
    #[serde(rename = "outputVisibility", default)]
    pub output_visibility: Option<FineTuneOutputVisibility>,
    #[serde(rename = "privacyTier", default)]
    pub privacy_tier: Option<PrivacyTier>,
    #[serde(rename = "integrityTier", default)]
    pub integrity_tier: Option<IntegrityTier>,
    #[serde(rename = "maxCost", default)]
    pub max_cost: Option<PriceV1>,
    #[serde(rename = "validationRequired", default)]
    pub validation_required: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FineTuneJobVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "fineTuneJobId")]
    pub fine_tune_job_id: String,
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
pub struct FineTuneExecutionPlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "fineTuneJobId")]
    pub fine_tune_job_id: String,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    #[serde(rename = "baseModelRef")]
    pub base_model_ref: String,
    #[serde(rename = "recipeRef")]
    pub recipe_ref: String,
    #[serde(rename = "trainingDatasetRefs")]
    pub training_dataset_refs: Vec<String>,
    #[serde(rename = "validationDatasetRefs")]
    pub validation_dataset_refs: Vec<String>,
    #[serde(rename = "immutableRefs")]
    pub immutable_refs: Vec<String>,
    #[serde(rename = "mutableRefs")]
    pub mutable_refs: Vec<String>,
    #[serde(rename = "outputPolicy")]
    pub output_policy: FineTuneOutputPolicyV1,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "validationRequired")]
    pub validation_required: bool,
    #[serde(rename = "leaseRequired")]
    pub lease_required: bool,
    #[serde(rename = "settlementMethod")]
    pub settlement_method: String,
    #[serde(rename = "maxCost", default, skip_serializing_if = "Option::is_none")]
    pub max_cost: Option<PriceV1>,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FineTuneJobIndexEntryV1 {
    #[serde(rename = "fineTuneJobId")]
    pub fine_tune_job_id: String,
    pub requester: String,
    #[serde(rename = "baseModelRef")]
    pub base_model_ref: String,
    #[serde(rename = "recipeRef")]
    pub recipe_ref: String,
    #[serde(rename = "trainingDatasetCount")]
    pub training_dataset_count: usize,
    #[serde(rename = "validationDatasetCount")]
    pub validation_dataset_count: usize,
    #[serde(rename = "artifactKind")]
    pub artifact_kind: FineTuneOutputArtifactKind,
    #[serde(rename = "outputVisibility")]
    pub output_visibility: FineTuneOutputVisibility,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "validationRequired")]
    pub validation_required: bool,
    #[serde(rename = "leaseRequired")]
    pub lease_required: bool,
    #[serde(rename = "confidentialComputeRequired")]
    pub confidential_compute_required: bool,
    #[serde(rename = "maxCost", default, skip_serializing_if = "Option::is_none")]
    pub max_cost: Option<PriceV1>,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub valid: bool,
    #[serde(rename = "signaturePresent")]
    pub signature_present: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "jobPath")]
    pub job_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FineTuneJobStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "jobCount")]
    pub job_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "validationRequiredCount")]
    pub validation_required_count: usize,
    #[serde(rename = "leaseRequiredCount")]
    pub lease_required_count: usize,
    #[serde(rename = "confidentialComputeRequiredCount")]
    pub confidential_compute_required_count: usize,
    #[serde(rename = "publicOutputCount")]
    pub public_output_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub jobs: Vec<FineTuneJobIndexEntryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FineTuneJobLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "fineTuneJobId")]
    pub fine_tune_job_id: String,
    #[serde(rename = "jobPath")]
    pub job_path: String,
    pub job: FineTuneJobV1,
    pub verification: FineTuneJobVerificationV1,
    #[serde(rename = "executionPlan")]
    pub execution_plan: FineTuneExecutionPlanV1,
}

pub fn create_fine_tune_job(options: FineTuneJobInitOptionsV1) -> FineTuneJobV1 {
    let mut training_dataset_refs = options.training_dataset_refs;
    dedup(&mut training_dataset_refs);
    let mut validation_dataset_refs = options.validation_dataset_refs;
    dedup(&mut validation_dataset_refs);
    let integrity_tier = options.integrity_tier.unwrap_or(IntegrityTier::ReceiptOnly);
    let mut job = FineTuneJobV1 {
        schema_version: "swarm-ai.fine-tune-job.v1".to_string(),
        fine_tune_job_id: String::new(),
        requester: options.requester,
        base_model_ref: options.base_model_ref,
        training_dataset_refs,
        validation_dataset_refs,
        recipe_ref: options
            .recipe_ref
            .unwrap_or_else(|| "local://fine-tune/recipe/default".to_string()),
        hyperparameters: options
            .hyperparameters
            .unwrap_or_else(|| json!({ "epochs": 1 })),
        output_policy: FineTuneOutputPolicyV1 {
            artifact_kind: options
                .artifact_kind
                .unwrap_or(FineTuneOutputArtifactKind::AdapterOrLora),
            output_ref: options.output_ref,
            checkpoint_refs: Vec::new(),
            publish_package: false,
            visibility: options
                .output_visibility
                .unwrap_or(FineTuneOutputVisibility::Private),
            license_ref: None,
            retain_intermediate_checkpoints: false,
        },
        privacy: FineTunePrivacyV1 {
            privacy_tier: options.privacy_tier.unwrap_or(PrivacyTier::LocalOnly),
            ..FineTunePrivacyV1::default()
        },
        max_cost: options.max_cost,
        validation_policy: FineTuneValidationPolicyV1 {
            required: options.validation_required.unwrap_or(false),
            integrity_tier,
            evaluation_dataset_refs: Vec::new(),
            validator_refs: Vec::new(),
            minimum_score: None,
            reproducibility_required: true,
        },
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_fine_tune_job(&mut job);
    job
}

pub fn sign_fine_tune_job(job: &mut FineTuneJobV1) {
    job.signature = Some(expected_fine_tune_job_signature(job));
    job.fine_tune_job_id = canonical_fine_tune_job_id(job);
}

pub fn sign_fine_tune_job_with_identity(
    job: &mut FineTuneJobV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != job.requester {
        anyhow::bail!(
            "identity subject {} does not match fine-tune requester {}",
            identity.subject,
            job.requester
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "fine-tune-job",
        &fine_tune_job_signing_value(job),
    )?;
    job.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    job.fine_tune_job_id = canonical_fine_tune_job_id(job);
    Ok(envelope)
}

pub fn expected_fine_tune_job_signature(job: &FineTuneJobV1) -> String {
    format!(
        "{DEV_FINE_TUNE_JOB_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&fine_tune_job_signing_value(job)))
    )
}

pub fn canonical_fine_tune_job_id(job: &FineTuneJobV1) -> String {
    stable_id("fine-tune", &fine_tune_job_signing_value(job))
}

pub fn verify_fine_tune_job(job: &FineTuneJobV1) -> FineTuneJobVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_fine_tune_job_signature(job));
    let signature = job
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if job.schema_version != "swarm-ai.fine-tune-job.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.fine-tune-job.v1",
        ));
    }
    require_non_empty(&mut issues, "$.fineTuneJobId", &job.fine_tune_job_id);
    if !job.fine_tune_job_id.is_empty() && job.fine_tune_job_id != canonical_fine_tune_job_id(job) {
        issues.push(issue(
            "$.fineTuneJobId",
            "Fine-tune job id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.requester", &job.requester);
    require_non_empty(&mut issues, "$.baseModelRef", &job.base_model_ref);
    require_non_empty(&mut issues, "$.recipeRef", &job.recipe_ref);
    if job.training_dataset_refs.is_empty() {
        issues.push(issue(
            "$.trainingDatasetRefs",
            "Fine-tune job must include at least one training dataset ref",
        ));
    }
    if !job.hyperparameters.is_object() {
        issues.push(issue(
            "$.hyperparameters",
            "hyperparameters must be a JSON object",
        ));
    }
    validate_output_policy(&job.output_policy, &mut issues, &mut warnings);
    validate_privacy(&job.privacy, &mut warnings);
    validate_validation_policy(&job.validation_policy, &mut issues, &mut warnings);
    validate_max_cost(&job.max_cost, &mut issues);
    for (path, reference) in fine_tune_refs(job) {
        validate_ref(path, &reference, &mut issues, &mut warnings);
    }
    validate_created_at(&job.created_at, "$.createdAt", &mut issues);
    verify_signature(
        signature,
        "fine-tune-job",
        &fine_tune_job_signing_value(job),
        &job.requester,
        &mut expected_signature,
        &mut issues,
        "Fine-tune job signature does not match canonical dev signature or Ed25519 requester identity envelope",
    );
    if signature.is_none() {
        warnings.push(issue(
            "$.signature",
            "Fine-tune job is unsigned; verify requester and fineTuneJobId through a trusted source",
        ));
    }

    FineTuneJobVerificationV1 {
        schema_version: "swarm-ai.fine-tune-job-verification.v1".to_string(),
        fine_tune_job_id: job.fine_tune_job_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn fine_tune_execution_plan(job: &FineTuneJobV1) -> FineTuneExecutionPlanV1 {
    let verification = verify_fine_tune_job(job);
    let mut immutable_refs = Vec::new();
    let mut mutable_refs = Vec::new();
    for (_, reference) in fine_tune_refs(job) {
        if looks_mutable_ref(&reference) {
            mutable_refs.push(reference);
        } else {
            immutable_refs.push(reference);
        }
    }
    dedup(&mut immutable_refs);
    dedup(&mut mutable_refs);

    FineTuneExecutionPlanV1 {
        schema_version: "swarm-ai.fine-tune-execution-plan.v1".to_string(),
        fine_tune_job_id: job.fine_tune_job_id.clone(),
        api_surface: ApiSurface::OpenAiFineTuning,
        base_model_ref: job.base_model_ref.clone(),
        recipe_ref: job.recipe_ref.clone(),
        training_dataset_refs: job.training_dataset_refs.clone(),
        validation_dataset_refs: job.validation_dataset_refs.clone(),
        immutable_refs,
        mutable_refs,
        output_policy: job.output_policy.clone(),
        privacy_tier: job.privacy.privacy_tier.clone(),
        integrity_tier: job.validation_policy.integrity_tier.clone(),
        validation_required: job.validation_policy.required,
        lease_required: true,
        settlement_method: "fine-tune-lease".to_string(),
        max_cost: job.max_cost.clone(),
        valid: verification.valid,
        issues: verification.issues,
        warnings: verification.warnings,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn list_fine_tune_jobs(job_dir: &Path) -> anyhow::Result<FineTuneJobStoreSummaryV1> {
    let mut files = Vec::new();
    collect_fine_tune_job_files(job_dir, &mut files)?;
    files.sort();

    let mut jobs = Vec::new();
    let mut valid_count = 0;
    let mut validation_required_count = 0;
    let mut lease_required_count = 0;
    let mut confidential_compute_required_count = 0;
    let mut public_output_count = 0;
    let mut mutable_ref_count = 0;
    let mut warning_count = 0;

    for path in files {
        let Some(job) = read_fine_tune_job_file(&path)? else {
            continue;
        };
        let verification = verify_fine_tune_job(&job);
        let execution_plan = fine_tune_execution_plan(&job);
        if verification.valid {
            valid_count += 1;
        }
        if execution_plan.validation_required {
            validation_required_count += 1;
        }
        if execution_plan.lease_required {
            lease_required_count += 1;
        }
        if job.privacy.confidential_compute_required {
            confidential_compute_required_count += 1;
        }
        if matches!(
            job.output_policy.visibility,
            FineTuneOutputVisibility::Public
        ) {
            public_output_count += 1;
        }
        mutable_ref_count += execution_plan.mutable_refs.len();
        warning_count += execution_plan.warnings.len();
        jobs.push(fine_tune_job_index_entry(
            &job,
            &verification,
            &execution_plan,
            path.display().to_string(),
        ));
    }

    jobs.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.fine_tune_job_id.cmp(&right.fine_tune_job_id))
            .then(left.job_path.cmp(&right.job_path))
    });

    Ok(FineTuneJobStoreSummaryV1 {
        schema_version: "swarm-ai.fine-tune-job-store-summary.v1".to_string(),
        root: job_dir.display().to_string(),
        job_count: jobs.len(),
        valid_count,
        invalid_count: jobs.len().saturating_sub(valid_count),
        validation_required_count,
        lease_required_count,
        confidential_compute_required_count,
        public_output_count,
        mutable_ref_count,
        warning_count,
        jobs,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn get_fine_tune_job(
    job_dir: &Path,
    fine_tune_job_id: &str,
) -> anyhow::Result<Option<FineTuneJobLookupV1>> {
    let fine_tune_job_id = fine_tune_job_id.trim();
    if fine_tune_job_id.is_empty() {
        anyhow::bail!("fineTuneJobId is required");
    }

    let mut files = Vec::new();
    collect_fine_tune_job_files(job_dir, &mut files)?;
    files.sort();

    for path in files {
        let Some(job) = read_fine_tune_job_file(&path)? else {
            continue;
        };
        if job.fine_tune_job_id == fine_tune_job_id {
            let verification = verify_fine_tune_job(&job);
            let execution_plan = fine_tune_execution_plan(&job);
            return Ok(Some(FineTuneJobLookupV1 {
                schema_version: "swarm-ai.fine-tune-job-lookup.v1".to_string(),
                fine_tune_job_id: job.fine_tune_job_id.clone(),
                job_path: path.display().to_string(),
                job,
                verification,
                execution_plan,
            }));
        }
    }

    Ok(None)
}

fn collect_fine_tune_job_files(job_dir: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    if !job_dir.exists() {
        return Ok(());
    }
    for entry in
        fs::read_dir(job_dir).with_context(|| format!("failed to read {}", job_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_fine_tune_job_files(&path, files)?;
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

fn read_fine_tune_job_file(path: &Path) -> anyhow::Result<Option<FineTuneJobV1>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let Some(schema_version) = value.get("schemaVersion").and_then(Value::as_str) else {
        return Ok(None);
    };
    if schema_version != "swarm-ai.fine-tune-job.v1" {
        return Ok(None);
    }
    serde_json::from_value(value)
        .map(Some)
        .with_context(|| format!("failed to parse fine-tune job {}", path.display()))
}

fn fine_tune_job_index_entry(
    job: &FineTuneJobV1,
    verification: &FineTuneJobVerificationV1,
    execution_plan: &FineTuneExecutionPlanV1,
    job_path: String,
) -> FineTuneJobIndexEntryV1 {
    FineTuneJobIndexEntryV1 {
        fine_tune_job_id: job.fine_tune_job_id.clone(),
        requester: job.requester.clone(),
        base_model_ref: job.base_model_ref.clone(),
        recipe_ref: job.recipe_ref.clone(),
        training_dataset_count: job.training_dataset_refs.len(),
        validation_dataset_count: job.validation_dataset_refs.len(),
        artifact_kind: job.output_policy.artifact_kind.clone(),
        output_visibility: job.output_policy.visibility.clone(),
        privacy_tier: job.privacy.privacy_tier.clone(),
        integrity_tier: job.validation_policy.integrity_tier.clone(),
        validation_required: execution_plan.validation_required,
        lease_required: execution_plan.lease_required,
        confidential_compute_required: job.privacy.confidential_compute_required,
        max_cost: job.max_cost.clone(),
        mutable_ref_count: execution_plan.mutable_refs.len(),
        warning_count: execution_plan.warnings.len(),
        valid: verification.valid,
        signature_present: job.signature.is_some(),
        created_at: job.created_at.clone(),
        job_path,
    }
}

fn validate_output_policy(
    policy: &FineTuneOutputPolicyV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if policy.publish_package && policy.output_ref.as_deref().unwrap_or_default().is_empty() {
        warnings.push(issue(
            "$.outputPolicy.outputRef",
            "Publishing output as a package should include an outputRef before execution",
        ));
    }
    if policy.visibility != FineTuneOutputVisibility::Private && policy.license_ref.is_none() {
        warnings.push(issue(
            "$.outputPolicy.licenseRef",
            "Non-private fine-tune outputs should declare a licenseRef before publication",
        ));
    }
    if policy.checkpoint_refs.is_empty() && policy.retain_intermediate_checkpoints {
        warnings.push(issue(
            "$.outputPolicy.checkpointRefs",
            "Intermediate checkpoint retention is enabled but no checkpoint refs are declared yet",
        ));
    }
    for (index, checkpoint_ref) in policy.checkpoint_refs.iter().enumerate() {
        validate_ref(
            format!("$.outputPolicy.checkpointRefs[{index}]"),
            checkpoint_ref,
            issues,
            warnings,
        );
    }
}

fn validate_privacy(privacy: &FineTunePrivacyV1, warnings: &mut Vec<ValidationIssue>) {
    if privacy.confidential_compute_required
        && !matches!(privacy.privacy_tier, PrivacyTier::TeeConfidential)
    {
        warnings.push(issue(
            "$.privacy.privacyTier",
            "confidentialComputeRequired is set; tee-confidential privacy is usually expected",
        ));
    }
}

fn validate_validation_policy(
    policy: &FineTuneValidationPolicyV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if let Some(minimum_score) = policy.minimum_score {
        if !(0.0..=1.0).contains(&minimum_score) {
            issues.push(issue(
                "$.validationPolicy.minimumScore",
                "minimumScore must be between 0.0 and 1.0",
            ));
        }
    }
    if policy.required
        && policy.evaluation_dataset_refs.is_empty()
        && policy.validator_refs.is_empty()
        && policy.minimum_score.is_none()
    {
        warnings.push(issue(
            "$.validationPolicy",
            "Validation is required but no evaluation datasets, validators, or minimum score are declared",
        ));
    }
    for (index, dataset_ref) in policy.evaluation_dataset_refs.iter().enumerate() {
        validate_ref(
            format!("$.validationPolicy.evaluationDatasetRefs[{index}]"),
            dataset_ref,
            issues,
            warnings,
        );
    }
    for (index, validator_ref) in policy.validator_refs.iter().enumerate() {
        validate_ref(
            format!("$.validationPolicy.validatorRefs[{index}]"),
            validator_ref,
            issues,
            warnings,
        );
    }
}

fn validate_max_cost(max_cost: &Option<PriceV1>, issues: &mut Vec<ValidationIssue>) {
    if let Some(max_cost) = max_cost {
        if max_cost.amount <= 0.0 {
            issues.push(issue(
                "$.maxCost.amount",
                "maxCost amount must be greater than zero",
            ));
        }
        if max_cost.currency.trim().is_empty() {
            issues.push(issue("$.maxCost.currency", "maxCost currency is required"));
        }
    }
}

fn fine_tune_refs(job: &FineTuneJobV1) -> Vec<(String, String)> {
    let mut refs = vec![
        ("$.baseModelRef".to_string(), job.base_model_ref.clone()),
        ("$.recipeRef".to_string(), job.recipe_ref.clone()),
    ];
    for (index, reference) in job.training_dataset_refs.iter().enumerate() {
        refs.push((format!("$.trainingDatasetRefs[{index}]"), reference.clone()));
    }
    for (index, reference) in job.validation_dataset_refs.iter().enumerate() {
        refs.push((
            format!("$.validationDatasetRefs[{index}]"),
            reference.clone(),
        ));
    }
    if let Some(output_ref) = &job.output_policy.output_ref {
        refs.push(("$.outputPolicy.outputRef".to_string(), output_ref.clone()));
    }
    if let Some(license_ref) = &job.output_policy.license_ref {
        refs.push(("$.outputPolicy.licenseRef".to_string(), license_ref.clone()));
    }
    for (index, reference) in job.output_policy.checkpoint_refs.iter().enumerate() {
        refs.push((
            format!("$.outputPolicy.checkpointRefs[{index}]"),
            reference.clone(),
        ));
    }
    for (index, reference) in job
        .validation_policy
        .evaluation_dataset_refs
        .iter()
        .enumerate()
    {
        refs.push((
            format!("$.validationPolicy.evaluationDatasetRefs[{index}]"),
            reference.clone(),
        ));
    }
    for (index, reference) in job.validation_policy.validator_refs.iter().enumerate() {
        refs.push((
            format!("$.validationPolicy.validatorRefs[{index}]"),
            reference.clone(),
        ));
    }
    refs
}

fn fine_tune_job_signing_value(job: &FineTuneJobV1) -> Value {
    let mut value = serde_json::to_value(job).expect("fine-tune job should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("fineTuneJobId");
        object.remove("signature");
    }
    value
}

fn require_non_empty(issues: &mut Vec<ValidationIssue>, path: &'static str, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value is required"));
    }
}

fn validate_ref(
    path: String,
    reference: &str,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if reference.trim().is_empty() {
        issues.push(issue(path, "Reference must not be empty"));
    } else if !looks_like_ref(reference) {
        warnings.push(issue(
            path,
            "Reference is not a recognized bzz://, local://, ipfs://, sha256://, or https:// reference",
        ));
    } else if looks_mutable_ref(reference) {
        warnings.push(issue(
            path,
            "Mutable reference should be resolved to immutable content before exact replay",
        ));
    }
}

fn validate_created_at(created_at: &str, path: &'static str, issues: &mut Vec<ValidationIssue>) {
    if chrono::DateTime::parse_from_rfc3339(created_at).is_err() {
        issues.push(issue(path, "createdAt must be an RFC3339 timestamp"));
    }
}

fn verify_signature(
    signature: Option<&str>,
    domain: &str,
    signing_value: &Value,
    expected_signer: &str,
    expected_signature: &mut Option<String>,
    issues: &mut Vec<ValidationIssue>,
    mismatch_message: &'static str,
) {
    let Some(signature) = signature else {
        return;
    };
    if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
        let verification = hivemind_identity::verify_value_signature_string(
            signature,
            domain,
            signing_value,
            Some(expected_signer),
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

fn looks_like_ref(reference: &str) -> bool {
    reference.starts_with("bzz://")
        || reference.starts_with("local://")
        || reference.starts_with("ipfs://")
        || reference.starts_with("sha256://")
        || reference.starts_with("https://")
}

fn looks_mutable_ref(reference: &str) -> bool {
    reference.starts_with("https://")
        || reference.contains(":latest")
        || reference.contains("/latest")
        || reference.contains(":stable")
        || reference.contains("/stable")
}

fn dedup(values: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("fine-tune object should serialize");
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
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
    fn creates_signed_fine_tune_job_and_plan() {
        let job = fine_tune_job();
        let verification = verify_fine_tune_job(&job);
        let plan = fine_tune_execution_plan(&job);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(
            job.signature.as_deref(),
            Some(expected_fine_tune_job_signature(&job).as_str())
        );
        assert!(job.fine_tune_job_id.starts_with("fine-tune-"));
        assert_eq!(plan.api_surface, ApiSurface::OpenAiFineTuning);
        assert!(plan.lease_required);
        assert_eq!(plan.privacy_tier, PrivacyTier::LocalOnly);
        assert!(
            plan.immutable_refs
                .contains(&"bzz://base-model".to_string())
        );
        assert!(
            plan.immutable_refs
                .contains(&"bzz://training-dataset".to_string())
        );
    }

    #[test]
    fn identity_signed_fine_tune_job_verifies_and_detects_tampering() {
        let mut job = fine_tune_job();
        let identity =
            hivemind_identity::identity_from_seed("0xRequester", b"fine-tune-seed").unwrap();

        let envelope = sign_fine_tune_job_with_identity(&mut job, &identity).unwrap();
        let verification = verify_fine_tune_job(&job);

        assert_eq!(envelope.signer, job.requester);
        assert!(verification.valid, "{verification:#?}");

        job.hyperparameters = json!({ "epochs": 3 });
        let tampered = verify_fine_tune_job(&job);
        assert!(!tampered.valid);
        assert!(tampered.issues.iter().any(|issue| {
            issue.path == "$.fineTuneJobId" || issue.path == "$.signature.payloadHash"
        }));
    }

    #[test]
    fn rejects_missing_training_refs_and_invalid_cost() {
        let mut job = fine_tune_job();
        job.training_dataset_refs.clear();
        job.max_cost = Some(PriceV1 {
            amount: 0.0,
            currency: String::new(),
        });
        sign_fine_tune_job(&mut job);

        let verification = verify_fine_tune_job(&job);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.trainingDatasetRefs")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.maxCost.amount")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.maxCost.currency")
        );
    }

    #[test]
    fn unsigned_fine_tune_job_still_requires_canonical_id() {
        let mut job = fine_tune_job();
        job.signature = None;
        job.recipe_ref = "bzz://changed-recipe".to_string();

        let verification = verify_fine_tune_job(&job);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.fineTuneJobId")
        );
    }

    #[test]
    fn plan_separates_mutable_refs_and_carries_validation_policy() {
        let mut job = fine_tune_job();
        job.validation_dataset_refs = vec!["https://example.com/datasets/latest".to_string()];
        job.validation_policy.required = true;
        job.validation_policy.integrity_tier = IntegrityTier::DeterministicReplay;
        job.validation_policy.minimum_score = Some(0.8);
        sign_fine_tune_job(&mut job);

        let plan = fine_tune_execution_plan(&job);

        assert!(plan.valid, "{plan:#?}");
        assert!(plan.validation_required);
        assert_eq!(plan.integrity_tier, IntegrityTier::DeterministicReplay);
        assert!(
            plan.mutable_refs
                .contains(&"https://example.com/datasets/latest".to_string())
        );
    }

    #[test]
    fn fine_tune_job_store_lists_and_gets_jobs() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("hivemind-fine-tune-store-{unique}"));
        fs::create_dir_all(dir.join("nested")).unwrap();

        let mut job = fine_tune_job();
        job.base_model_ref = "https://example.com/models/base/latest".to_string();
        job.validation_policy.required = true;
        job.validation_policy.minimum_score = Some(0.8);
        job.privacy.confidential_compute_required = true;
        job.output_policy.visibility = FineTuneOutputVisibility::Public;
        job.output_policy.license_ref = Some("bzz://license".to_string());
        sign_fine_tune_job(&mut job);

        fs::write(
            dir.join("nested").join("adapter.fine-tune.json"),
            serde_json::to_vec_pretty(&job).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("identity.json"),
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": "swarm-ai.identity.keypair.v1",
                "subject": "0xRequester"
            }))
            .unwrap(),
        )
        .unwrap();

        let summary = list_fine_tune_jobs(&dir).unwrap();
        assert_eq!(summary.job_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.invalid_count, 0);
        assert_eq!(summary.validation_required_count, 1);
        assert_eq!(summary.lease_required_count, 1);
        assert_eq!(summary.confidential_compute_required_count, 1);
        assert_eq!(summary.public_output_count, 1);
        assert_eq!(summary.mutable_ref_count, 1);
        assert!(summary.warning_count > 0);
        assert_eq!(summary.jobs[0].fine_tune_job_id, job.fine_tune_job_id);
        assert!(summary.jobs[0].signature_present);

        let lookup = get_fine_tune_job(&dir, &job.fine_tune_job_id)
            .unwrap()
            .unwrap();
        assert_eq!(lookup.job.fine_tune_job_id, job.fine_tune_job_id);
        assert!(lookup.verification.valid, "{:#?}", lookup.verification);
        assert!(lookup.execution_plan.valid, "{:#?}", lookup.execution_plan);
        assert!(lookup.execution_plan.validation_required);
        assert_eq!(lookup.execution_plan.mutable_refs.len(), 1);
        assert!(get_fine_tune_job(&dir, "missing").unwrap().is_none());

        let _ = fs::remove_dir_all(dir);
    }

    fn fine_tune_job() -> FineTuneJobV1 {
        create_fine_tune_job(FineTuneJobInitOptionsV1 {
            requester: "0xRequester".to_string(),
            base_model_ref: "bzz://base-model".to_string(),
            training_dataset_refs: vec!["bzz://training-dataset".to_string()],
            validation_dataset_refs: vec!["bzz://validation-dataset".to_string()],
            recipe_ref: Some("bzz://fine-tune-recipe".to_string()),
            hyperparameters: Some(json!({ "epochs": 1, "learningRate": 0.0001 })),
            output_ref: Some("local://fine-tune/output".to_string()),
            artifact_kind: Some(FineTuneOutputArtifactKind::AdapterOrLora),
            output_visibility: Some(FineTuneOutputVisibility::Private),
            privacy_tier: Some(PrivacyTier::LocalOnly),
            integrity_tier: Some(IntegrityTier::ReceiptOnly),
            max_cost: Some(PriceV1 {
                amount: 10.0,
                currency: "USD".to_string(),
            }),
            validation_required: Some(false),
        })
    }
}
