use anyhow::Context;
use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    ApiSurface, IntegrityTier, PrivacyTier, ValidationIssue, canonicalize_json, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEV_BATCH_JOB_SIGNATURE_PREFIX: &str = "dev-batch-job-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BatchPartialResultPolicy {
    None,
    OnCheckpoint,
    OnItemCompletion,
    OnFailureAndCheckpoint,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchJobTemplateV1 {
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    pub task: String,
    #[serde(rename = "inputSchema", default)]
    pub input_schema: Value,
    #[serde(
        rename = "outputSchemaRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_schema_ref: Option<String>,
    #[serde(
        rename = "preferredArtifactGroup",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub preferred_artifact_group: Option<String>,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "requiredIntegrityTier")]
    pub required_integrity_tier: IntegrityTier,
    #[serde(
        rename = "deadlineMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deadline_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deterministic: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchItemV1 {
    #[serde(rename = "itemId")]
    pub item_id: String,
    #[serde(default)]
    pub input: Value,
    #[serde(rename = "inputRef", default, skip_serializing_if = "Option::is_none")]
    pub input_ref: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchCheckpointPolicyV1 {
    pub enabled: bool,
    #[serde(rename = "everyItems")]
    pub every_items: u32,
    #[serde(
        rename = "storageRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub storage_ref: Option<String>,
    #[serde(rename = "retainCompletedItemRefs")]
    pub retain_completed_item_refs: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchValidationPolicyV1 {
    pub required: bool,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "sampleRate")]
    pub sample_rate: f64,
    #[serde(rename = "validatorRefs", default)]
    pub validator_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchJobV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "batchId")]
    pub batch_id: String,
    pub requester: String,
    #[serde(rename = "jobTemplate")]
    pub job_template: BatchJobTemplateV1,
    pub items: Vec<BatchItemV1>,
    #[serde(rename = "maxConcurrency")]
    pub max_concurrency: u32,
    #[serde(rename = "checkpointPolicy")]
    pub checkpoint_policy: BatchCheckpointPolicyV1,
    #[serde(rename = "partialResultPolicy")]
    pub partial_result_policy: BatchPartialResultPolicy,
    #[serde(rename = "settlementMethod")]
    pub settlement_method: String,
    #[serde(rename = "validationPolicy")]
    pub validation_policy: BatchValidationPolicyV1,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchJobInitOptionsV1 {
    pub requester: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    pub task: String,
    #[serde(rename = "apiSurface", default)]
    pub api_surface: Option<ApiSurface>,
    #[serde(default)]
    pub items: Vec<Value>,
    #[serde(rename = "maxConcurrency")]
    pub max_concurrency: u32,
    #[serde(rename = "checkpointEveryItems", default)]
    pub checkpoint_every_items: Option<u32>,
    #[serde(rename = "partialResultPolicy", default)]
    pub partial_result_policy: Option<BatchPartialResultPolicy>,
    #[serde(rename = "settlementMethod", default)]
    pub settlement_method: Option<String>,
    #[serde(rename = "privacyTier", default)]
    pub privacy_tier: Option<PrivacyTier>,
    #[serde(rename = "integrityTier", default)]
    pub integrity_tier: Option<IntegrityTier>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchJobVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "batchId")]
    pub batch_id: String,
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
pub struct BatchPlannedItemV1 {
    #[serde(rename = "itemId")]
    pub item_id: String,
    pub sequence: u32,
    #[serde(rename = "inputHash")]
    pub input_hash: String,
    #[serde(rename = "inputRef", default, skip_serializing_if = "Option::is_none")]
    pub input_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchExecutionPlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "batchId")]
    pub batch_id: String,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    #[serde(rename = "itemApiSurface")]
    pub item_api_surface: ApiSurface,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub task: String,
    #[serde(rename = "itemCount")]
    pub item_count: u32,
    pub parallelism: u32,
    #[serde(
        rename = "checkpointEveryItems",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub checkpoint_every_items: Option<u32>,
    #[serde(rename = "estimatedCheckpoints")]
    pub estimated_checkpoints: u32,
    #[serde(rename = "partialResultsAllowed")]
    pub partial_results_allowed: bool,
    #[serde(rename = "partialResultPolicy")]
    pub partial_result_policy: BatchPartialResultPolicy,
    #[serde(rename = "validationRequired")]
    pub validation_required: bool,
    #[serde(rename = "validationTier")]
    pub validation_tier: IntegrityTier,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "settlementMethod")]
    pub settlement_method: String,
    #[serde(rename = "orderedItems")]
    pub ordered_items: Vec<BatchPlannedItemV1>,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchJobIndexEntryV1 {
    #[serde(rename = "batchId")]
    pub batch_id: String,
    pub requester: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub task: String,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    #[serde(rename = "itemCount")]
    pub item_count: u32,
    pub parallelism: u32,
    #[serde(rename = "estimatedCheckpoints")]
    pub estimated_checkpoints: u32,
    #[serde(rename = "partialResultsAllowed")]
    pub partial_results_allowed: bool,
    #[serde(rename = "validationRequired")]
    pub validation_required: bool,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub valid: bool,
    #[serde(rename = "signaturePresent")]
    pub signature_present: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "batchPath")]
    pub batch_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchJobStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "batchCount")]
    pub batch_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "itemCount")]
    pub item_count: u32,
    #[serde(rename = "partialResultsAllowedCount")]
    pub partial_results_allowed_count: usize,
    #[serde(rename = "validationRequiredCount")]
    pub validation_required_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub batches: Vec<BatchJobIndexEntryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BatchJobLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "batchId")]
    pub batch_id: String,
    #[serde(rename = "batchPath")]
    pub batch_path: String,
    pub batch: BatchJobV1,
    pub verification: BatchJobVerificationV1,
    #[serde(rename = "executionPlan")]
    pub execution_plan: BatchExecutionPlanV1,
}

pub fn create_batch_job(options: BatchJobInitOptionsV1) -> BatchJobV1 {
    let items = if options.items.is_empty() {
        vec![json!({ "text": "batch item" })]
    } else {
        options.items
    };
    let item_count = items.len() as u32;
    let integrity_tier = options.integrity_tier.unwrap_or(IntegrityTier::ReceiptOnly);
    let mut job = BatchJobV1 {
        schema_version: "swarm-ai.batch-job.v1".to_string(),
        batch_id: String::new(),
        requester: options.requester,
        job_template: BatchJobTemplateV1 {
            package_ref: options.package_ref,
            package_id: options.package_id,
            package_version: options.package_version,
            api_surface: options
                .api_surface
                .unwrap_or_else(|| default_item_api_surface(&options.task)),
            task: options.task,
            input_schema: json!({ "type": "object" }),
            output_schema_ref: None,
            preferred_artifact_group: None,
            privacy_tier: options.privacy_tier.unwrap_or(PrivacyTier::Standard),
            required_integrity_tier: integrity_tier.clone(),
            deadline_ms: None,
            deterministic: Some(true),
        },
        items: items
            .into_iter()
            .enumerate()
            .map(|(index, input)| BatchItemV1 {
                item_id: format!("item-{index:06}", index = index + 1),
                input,
                input_ref: None,
                metadata: json!({}),
            })
            .collect(),
        max_concurrency: options.max_concurrency.max(1),
        checkpoint_policy: BatchCheckpointPolicyV1 {
            enabled: true,
            every_items: options
                .checkpoint_every_items
                .unwrap_or(item_count.max(1).min(100)),
            storage_ref: None,
            retain_completed_item_refs: true,
        },
        partial_result_policy: options
            .partial_result_policy
            .unwrap_or(BatchPartialResultPolicy::OnCheckpoint),
        settlement_method: options
            .settlement_method
            .unwrap_or_else(|| "free-local-dev".to_string()),
        validation_policy: BatchValidationPolicyV1 {
            required: false,
            integrity_tier,
            sample_rate: 0.0,
            validator_refs: Vec::new(),
        },
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_batch_job(&mut job);
    job
}

pub fn sign_batch_job(job: &mut BatchJobV1) {
    job.signature = Some(expected_batch_job_signature(job));
    job.batch_id = canonical_batch_job_id(job);
}

pub fn sign_batch_job_with_identity(
    job: &mut BatchJobV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != job.requester {
        anyhow::bail!(
            "identity subject {} does not match batch requester {}",
            identity.subject,
            job.requester
        );
    }
    let envelope =
        hivemind_identity::sign_value(identity, "batch-job", &batch_job_signing_value(job))?;
    job.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    job.batch_id = canonical_batch_job_id(job);
    Ok(envelope)
}

pub fn expected_batch_job_signature(job: &BatchJobV1) -> String {
    format!(
        "{DEV_BATCH_JOB_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&batch_job_signing_value(job)))
    )
}

pub fn canonical_batch_job_id(job: &BatchJobV1) -> String {
    stable_id("batch", &batch_job_signing_value(job))
}

pub fn verify_batch_job(job: &BatchJobV1) -> BatchJobVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_batch_job_signature(job));
    let signature = job
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if job.schema_version != "swarm-ai.batch-job.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.batch-job.v1",
        ));
    }
    require_non_empty(&mut issues, "$.batchId", &job.batch_id);
    if !job.batch_id.is_empty() && job.batch_id != canonical_batch_job_id(job) {
        issues.push(issue(
            "$.batchId",
            "Batch id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.requester", &job.requester);
    validate_template(&job.job_template, &mut issues, &mut warnings);
    validate_items(job, &mut issues, &mut warnings);
    validate_batch_policy(job, &mut issues, &mut warnings);
    validate_created_at(&job.created_at, "$.createdAt", &mut issues);
    verify_signature(
        signature,
        "batch-job",
        &batch_job_signing_value(job),
        &job.requester,
        &mut expected_signature,
        &mut issues,
        "Batch job signature does not match canonical dev signature or Ed25519 requester identity envelope",
    );
    if signature.is_none() {
        warnings.push(issue(
            "$.signature",
            "Batch job is unsigned; verify requester and batchId through a trusted source",
        ));
    }

    BatchJobVerificationV1 {
        schema_version: "swarm-ai.batch-job-verification.v1".to_string(),
        batch_id: job.batch_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn batch_execution_plan(job: &BatchJobV1) -> BatchExecutionPlanV1 {
    let verification = verify_batch_job(job);
    let item_count = job.items.len() as u32;
    let parallelism = job.max_concurrency.max(1).min(item_count.max(1));
    let checkpoint_every_items = if job.checkpoint_policy.enabled {
        Some(job.checkpoint_policy.every_items.max(1))
    } else {
        None
    };
    let estimated_checkpoints = checkpoint_every_items
        .map(|every| item_count.div_ceil(every))
        .unwrap_or(0);
    let ordered_items = job
        .items
        .iter()
        .enumerate()
        .map(|(index, item)| BatchPlannedItemV1 {
            item_id: item.item_id.clone(),
            sequence: (index + 1) as u32,
            input_hash: hash_canonical_json(&canonicalize_json(&item_input_hash_value(item))),
            input_ref: item.input_ref.clone(),
        })
        .collect();

    BatchExecutionPlanV1 {
        schema_version: "swarm-ai.batch-execution-plan.v1".to_string(),
        batch_id: job.batch_id.clone(),
        api_surface: ApiSurface::OpenAiBatches,
        item_api_surface: job.job_template.api_surface.clone(),
        package_ref: job.job_template.package_ref.clone(),
        task: job.job_template.task.clone(),
        item_count,
        parallelism,
        checkpoint_every_items,
        estimated_checkpoints,
        partial_results_allowed: job.partial_result_policy != BatchPartialResultPolicy::None,
        partial_result_policy: job.partial_result_policy.clone(),
        validation_required: job.validation_policy.required,
        validation_tier: job.validation_policy.integrity_tier.clone(),
        privacy_tier: job.job_template.privacy_tier.clone(),
        settlement_method: job.settlement_method.clone(),
        ordered_items,
        valid: verification.valid,
        issues: verification.issues,
        warnings: verification.warnings,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn list_batch_jobs(batch_dir: &Path) -> anyhow::Result<BatchJobStoreSummaryV1> {
    let mut files = Vec::new();
    collect_batch_job_files(batch_dir, &mut files)?;
    files.sort();

    let mut batches = Vec::new();
    let mut valid_count = 0;
    let mut item_count = 0u32;
    let mut partial_results_allowed_count = 0;
    let mut validation_required_count = 0;
    let mut mutable_ref_count = 0;
    let mut warning_count = 0;

    for path in files {
        let Some(batch) = read_batch_job_file(&path)? else {
            continue;
        };
        let verification = verify_batch_job(&batch);
        let execution_plan = batch_execution_plan(&batch);
        let mutable_refs = mutable_batch_refs(&batch);
        if verification.valid {
            valid_count += 1;
        }
        if execution_plan.partial_results_allowed {
            partial_results_allowed_count += 1;
        }
        if execution_plan.validation_required {
            validation_required_count += 1;
        }
        item_count = item_count.saturating_add(execution_plan.item_count);
        mutable_ref_count += mutable_refs.len();
        warning_count += verification.warnings.len() + execution_plan.warnings.len();
        batches.push(batch_job_index_entry(
            &batch,
            &verification,
            &execution_plan,
            mutable_refs.len(),
            path.display().to_string(),
        ));
    }

    batches.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.batch_id.cmp(&right.batch_id))
            .then(left.batch_path.cmp(&right.batch_path))
    });

    Ok(BatchJobStoreSummaryV1 {
        schema_version: "swarm-ai.batch-job-store-summary.v1".to_string(),
        root: batch_dir.display().to_string(),
        batch_count: batches.len(),
        valid_count,
        invalid_count: batches.len().saturating_sub(valid_count),
        item_count,
        partial_results_allowed_count,
        validation_required_count,
        mutable_ref_count,
        warning_count,
        batches,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn get_batch_job(batch_dir: &Path, batch_id: &str) -> anyhow::Result<Option<BatchJobLookupV1>> {
    let batch_id = batch_id.trim();
    if batch_id.is_empty() {
        anyhow::bail!("batchId is required");
    }

    let mut files = Vec::new();
    collect_batch_job_files(batch_dir, &mut files)?;
    files.sort();

    for path in files {
        let Some(batch) = read_batch_job_file(&path)? else {
            continue;
        };
        if batch.batch_id == batch_id {
            let verification = verify_batch_job(&batch);
            let execution_plan = batch_execution_plan(&batch);
            return Ok(Some(BatchJobLookupV1 {
                schema_version: "swarm-ai.batch-job-lookup.v1".to_string(),
                batch_id: batch.batch_id.clone(),
                batch_path: path.display().to_string(),
                batch,
                verification,
                execution_plan,
            }));
        }
    }

    Ok(None)
}

fn collect_batch_job_files(batch_dir: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    if !batch_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(batch_dir)
        .with_context(|| format!("failed to read {}", batch_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_batch_job_files(&path, files)?;
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

fn read_batch_job_file(path: &Path) -> anyhow::Result<Option<BatchJobV1>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let Some(schema_version) = value.get("schemaVersion").and_then(Value::as_str) else {
        return Ok(None);
    };
    if schema_version != "swarm-ai.batch-job.v1" {
        return Ok(None);
    }
    serde_json::from_value(value)
        .map(Some)
        .with_context(|| format!("failed to parse batch job {}", path.display()))
}

fn batch_job_index_entry(
    batch: &BatchJobV1,
    verification: &BatchJobVerificationV1,
    execution_plan: &BatchExecutionPlanV1,
    mutable_ref_count: usize,
    batch_path: String,
) -> BatchJobIndexEntryV1 {
    BatchJobIndexEntryV1 {
        batch_id: batch.batch_id.clone(),
        requester: batch.requester.clone(),
        package_ref: batch.job_template.package_ref.clone(),
        package_id: batch.job_template.package_id.clone(),
        task: batch.job_template.task.clone(),
        api_surface: batch.job_template.api_surface.clone(),
        item_count: execution_plan.item_count,
        parallelism: execution_plan.parallelism,
        estimated_checkpoints: execution_plan.estimated_checkpoints,
        partial_results_allowed: execution_plan.partial_results_allowed,
        validation_required: execution_plan.validation_required,
        privacy_tier: batch.job_template.privacy_tier.clone(),
        integrity_tier: batch.job_template.required_integrity_tier.clone(),
        mutable_ref_count,
        warning_count: verification.warnings.len() + execution_plan.warnings.len(),
        valid: verification.valid,
        signature_present: batch.signature.is_some(),
        created_at: batch.created_at.clone(),
        batch_path,
    }
}

fn mutable_batch_refs(batch: &BatchJobV1) -> Vec<String> {
    let mut refs = Vec::new();
    push_mutable_ref(&mut refs, &batch.job_template.package_ref);
    if let Some(output_schema_ref) = &batch.job_template.output_schema_ref {
        push_mutable_ref(&mut refs, output_schema_ref);
    }
    if let Some(preferred_artifact_group) = &batch.job_template.preferred_artifact_group {
        push_mutable_ref(&mut refs, preferred_artifact_group);
    }
    for item in &batch.items {
        if let Some(input_ref) = &item.input_ref {
            push_mutable_ref(&mut refs, input_ref);
        }
    }
    if let Some(storage_ref) = &batch.checkpoint_policy.storage_ref {
        push_mutable_ref(&mut refs, storage_ref);
    }
    for validator_ref in &batch.validation_policy.validator_refs {
        push_mutable_ref(&mut refs, validator_ref);
    }
    refs.sort();
    refs.dedup();
    refs
}

fn push_mutable_ref(refs: &mut Vec<String>, reference: &str) {
    if looks_like_ref(reference) && looks_mutable_ref(reference) {
        refs.push(reference.to_string());
    }
}

fn default_item_api_surface(task: &str) -> ApiSurface {
    match task {
        "embedding" | "embeddings" => ApiSurface::OpenAiEmbeddings,
        "chat" => ApiSurface::OpenAiChatCompletions,
        "responses" => ApiSurface::OpenAiResponses,
        "image" | "image-generation" => ApiSurface::OpenAiImages,
        "speech-to-text" | "text-to-speech" | "audio" => ApiSurface::OpenAiAudio,
        "vector-search" => ApiSurface::VectorSearch,
        _ => ApiSurface::HivemindNative,
    }
}

fn validate_template(
    template: &BatchJobTemplateV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    require_non_empty(issues, "$.jobTemplate.packageRef", &template.package_ref);
    require_non_empty(issues, "$.jobTemplate.packageId", &template.package_id);
    require_non_empty(
        issues,
        "$.jobTemplate.packageVersion",
        &template.package_version,
    );
    require_non_empty(issues, "$.jobTemplate.task", &template.task);
    if !template.input_schema.is_object() {
        warnings.push(issue(
            "$.jobTemplate.inputSchema",
            "inputSchema should be a JSON Schema object",
        ));
    }
    validate_ref(
        "$.jobTemplate.packageRef".to_string(),
        &template.package_ref,
        issues,
        warnings,
    );
    if let Some(output_schema_ref) = &template.output_schema_ref {
        validate_ref(
            "$.jobTemplate.outputSchemaRef".to_string(),
            output_schema_ref,
            issues,
            warnings,
        );
    }
    if let Some(deadline_ms) = template.deadline_ms {
        if deadline_ms == 0 {
            issues.push(issue(
                "$.jobTemplate.deadlineMs",
                "deadlineMs must be greater than zero when set",
            ));
        }
    }
}

fn validate_items(
    job: &BatchJobV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if job.items.is_empty() {
        issues.push(issue("$.items", "Batch job must include at least one item"));
    }
    let mut seen = BTreeSet::new();
    for (index, item) in job.items.iter().enumerate() {
        let base = format!("$.items[{index}]");
        require_non_empty_owned(issues, format!("{base}.itemId"), &item.item_id);
        if !item.item_id.trim().is_empty() && !seen.insert(item.item_id.clone()) {
            issues.push(issue(
                format!("{base}.itemId"),
                "Batch item id must be unique",
            ));
        }
        if item.input.is_null()
            && item
                .input_ref
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
        {
            issues.push(issue(
                format!("{base}.input"),
                "Batch item must include inline input or inputRef",
            ));
        }
        if let Some(input_ref) = &item.input_ref {
            validate_ref(format!("{base}.inputRef"), input_ref, issues, warnings);
        }
        if !item.metadata.is_object() {
            warnings.push(issue(
                format!("{base}.metadata"),
                "Batch item metadata should be an object",
            ));
        }
    }
}

fn validate_batch_policy(
    job: &BatchJobV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if job.max_concurrency == 0 {
        issues.push(issue(
            "$.maxConcurrency",
            "maxConcurrency must be greater than zero",
        ));
    }
    if job.max_concurrency as usize > job.items.len().max(1) {
        warnings.push(issue(
            "$.maxConcurrency",
            "maxConcurrency exceeds item count; execution plan will clamp parallelism",
        ));
    }
    if job.checkpoint_policy.enabled && job.checkpoint_policy.every_items == 0 {
        issues.push(issue(
            "$.checkpointPolicy.everyItems",
            "Checkpoint interval must be greater than zero when checkpointing is enabled",
        ));
    }
    if let Some(storage_ref) = &job.checkpoint_policy.storage_ref {
        validate_ref(
            "$.checkpointPolicy.storageRef".to_string(),
            storage_ref,
            issues,
            warnings,
        );
    }
    if !job.checkpoint_policy.enabled
        && matches!(
            job.partial_result_policy,
            BatchPartialResultPolicy::OnCheckpoint
                | BatchPartialResultPolicy::OnFailureAndCheckpoint
        )
    {
        warnings.push(issue(
            "$.partialResultPolicy",
            "Checkpoint-based partial results require checkpointPolicy.enabled for durable recovery",
        ));
    }
    require_non_empty(issues, "$.settlementMethod", &job.settlement_method);
    if !(0.0..=1.0).contains(&job.validation_policy.sample_rate) {
        issues.push(issue(
            "$.validationPolicy.sampleRate",
            "Validation sampleRate must be between 0.0 and 1.0",
        ));
    }
    if job.validation_policy.required && job.validation_policy.sample_rate <= 0.0 {
        warnings.push(issue(
            "$.validationPolicy.sampleRate",
            "Validation is required but sampleRate is zero; provide validator refs or a sampling policy before production execution",
        ));
    }
    for (index, validator_ref) in job.validation_policy.validator_refs.iter().enumerate() {
        validate_ref(
            format!("$.validationPolicy.validatorRefs[{index}]"),
            validator_ref,
            issues,
            warnings,
        );
    }
}

fn batch_job_signing_value(job: &BatchJobV1) -> Value {
    let mut value = serde_json::to_value(job).expect("batch job should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("batchId");
        object.remove("signature");
    }
    value
}

fn item_input_hash_value(item: &BatchItemV1) -> Value {
    json!({
        "input": item.input,
        "inputRef": item.input_ref
    })
}

fn require_non_empty(issues: &mut Vec<ValidationIssue>, path: &'static str, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value is required"));
    }
}

fn require_non_empty_owned(issues: &mut Vec<ValidationIssue>, path: String, value: &str) {
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

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("batch object should serialize");
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
    fn creates_signed_batch_job_and_plan() {
        let job = batch_job();
        let verification = verify_batch_job(&job);
        let plan = batch_execution_plan(&job);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(
            job.signature.as_deref(),
            Some(expected_batch_job_signature(&job).as_str())
        );
        assert!(job.batch_id.starts_with("batch-"));
        assert_eq!(plan.api_surface, ApiSurface::OpenAiBatches);
        assert_eq!(plan.item_api_surface, ApiSurface::OpenAiEmbeddings);
        assert_eq!(plan.item_count, 2);
        assert_eq!(plan.parallelism, 2);
        assert_eq!(plan.estimated_checkpoints, 1);
        assert!(plan.partial_results_allowed);
        assert_eq!(plan.ordered_items.len(), 2);
    }

    #[test]
    fn identity_signed_batch_job_verifies_and_detects_tampering() {
        let mut job = batch_job();
        let identity = hivemind_identity::identity_from_seed("0xRequester", b"batch-seed").unwrap();

        let envelope = sign_batch_job_with_identity(&mut job, &identity).unwrap();
        let verification = verify_batch_job(&job);

        assert_eq!(envelope.signer, job.requester);
        assert!(verification.valid, "{verification:#?}");

        job.items[0].input = json!({ "text": "changed" });
        let tampered = verify_batch_job(&job);
        assert!(!tampered.valid);
        assert!(
            tampered.issues.iter().any(|issue| {
                issue.path == "$.batchId" || issue.path == "$.signature.payloadHash"
            })
        );
    }

    #[test]
    fn rejects_duplicate_item_ids_and_zero_concurrency() {
        let mut job = batch_job();
        job.items[1].item_id = job.items[0].item_id.clone();
        job.max_concurrency = 0;
        sign_batch_job(&mut job);

        let verification = verify_batch_job(&job);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.items[1].itemId")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.maxConcurrency")
        );
    }

    #[test]
    fn unsigned_batch_job_still_requires_canonical_id() {
        let mut job = batch_job();
        job.signature = None;
        job.items[0].input = json!({ "text": "changed" });

        let verification = verify_batch_job(&job);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.batchId")
        );
    }

    #[test]
    fn plan_carries_validation_and_tier_policies() {
        let mut job = batch_job();
        job.validation_policy.required = true;
        job.validation_policy.sample_rate = 0.25;
        job.validation_policy.integrity_tier = IntegrityTier::DeterministicReplay;
        job.job_template.privacy_tier = PrivacyTier::NoLog;
        sign_batch_job(&mut job);

        let plan = batch_execution_plan(&job);

        assert!(plan.valid, "{plan:#?}");
        assert!(plan.validation_required);
        assert_eq!(plan.validation_tier, IntegrityTier::DeterministicReplay);
        assert_eq!(plan.privacy_tier, PrivacyTier::NoLog);
    }

    #[test]
    fn batch_job_store_lists_and_gets_jobs() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("hivemind-batch-store-{unique}"));
        fs::create_dir_all(dir.join("nested")).unwrap();

        let mut job = batch_job();
        job.job_template.package_ref = "https://example.com/packages/embedding/latest".to_string();
        job.items[0].input_ref = Some("bzz://input-one".to_string());
        job.items[1].input_ref = Some("https://example.com/input/stable".to_string());
        job.validation_policy.required = true;
        job.validation_policy.sample_rate = 0.5;
        sign_batch_job(&mut job);

        fs::write(
            dir.join("nested").join("embedding.batch.json"),
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

        let summary = list_batch_jobs(&dir).unwrap();
        assert_eq!(summary.batch_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.invalid_count, 0);
        assert_eq!(summary.item_count, 2);
        assert_eq!(summary.partial_results_allowed_count, 1);
        assert_eq!(summary.validation_required_count, 1);
        assert_eq!(summary.mutable_ref_count, 2);
        assert!(summary.warning_count > 0);
        assert_eq!(summary.batches[0].batch_id, job.batch_id);
        assert!(summary.batches[0].signature_present);

        let lookup = get_batch_job(&dir, &job.batch_id).unwrap().unwrap();
        assert_eq!(lookup.batch.batch_id, job.batch_id);
        assert!(lookup.verification.valid, "{:#?}", lookup.verification);
        assert!(lookup.execution_plan.valid, "{:#?}", lookup.execution_plan);
        assert_eq!(lookup.execution_plan.item_count, 2);
        assert!(lookup.execution_plan.validation_required);
        assert!(get_batch_job(&dir, "missing").unwrap().is_none());

        let _ = fs::remove_dir_all(dir);
    }

    fn batch_job() -> BatchJobV1 {
        create_batch_job(BatchJobInitOptionsV1 {
            requester: "0xRequester".to_string(),
            package_ref: "bzz://embedding-package".to_string(),
            package_id: "hivemind/embedding".to_string(),
            package_version: "0.1.0".to_string(),
            task: "embedding".to_string(),
            api_surface: Some(ApiSurface::OpenAiEmbeddings),
            items: vec![
                json!({ "text": "first document" }),
                json!({ "text": "second document" }),
            ],
            max_concurrency: 2,
            checkpoint_every_items: Some(2),
            partial_result_policy: Some(BatchPartialResultPolicy::OnCheckpoint),
            settlement_method: Some("free-local-dev".to_string()),
            privacy_tier: Some(PrivacyTier::Standard),
            integrity_tier: Some(IntegrityTier::ReceiptOnly),
        })
    }
}
