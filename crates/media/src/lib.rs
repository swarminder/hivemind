use anyhow::Context;
use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    ApiSurface, DataRetentionRule, IntegrityTier, LoggingRule, Modality, PrivacyTier,
    StreamingEventType, ValidationIssue, canonicalize_json, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEV_MEDIA_JOB_SIGNATURE_PREFIX: &str = "dev-media-job-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MediaTask {
    ImageGeneration,
    ImageEdit,
    AudioTranscription,
    TextToSpeech,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MediaPackageSelectorV1 {
    #[serde(
        rename = "packageRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_ref: Option<String>,
    #[serde(rename = "packageId", default, skip_serializing_if = "Option::is_none")]
    pub package_id: Option<String>,
    #[serde(
        rename = "packageVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_version: Option<String>,
    #[serde(
        rename = "serviceRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub service_ref: Option<String>,
    #[serde(
        rename = "modelAlias",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub model_alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MediaInputV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(rename = "inputRef", default, skip_serializing_if = "Option::is_none")]
    pub input_ref: Option<String>,
    #[serde(rename = "maskRef", default, skip_serializing_if = "Option::is_none")]
    pub mask_ref: Option<String>,
    #[serde(default)]
    pub parameters: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MediaOutputPolicyV1 {
    #[serde(rename = "responseFormat")]
    pub response_format: String,
    #[serde(rename = "outputRef", default, skip_serializing_if = "Option::is_none")]
    pub output_ref: Option<String>,
    pub count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voice: Option<String>,
    #[serde(
        rename = "audioFormat",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub audio_format: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MediaPrivacyV1 {
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "dataRetentionRule")]
    pub data_retention_rule: DataRetentionRule,
    #[serde(rename = "loggingRule")]
    pub logging_rule: LoggingRule,
}

impl Default for MediaPrivacyV1 {
    fn default() -> Self {
        Self {
            privacy_tier: PrivacyTier::NoLog,
            data_retention_rule: DataRetentionRule::DeleteAfterJob,
            logging_rule: LoggingRule::NoPromptOrOutputLogs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MediaJobV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "mediaJobId")]
    pub media_job_id: String,
    pub requester: String,
    pub task: MediaTask,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    #[serde(rename = "packageSelector")]
    pub package_selector: MediaPackageSelectorV1,
    pub input: MediaInputV1,
    #[serde(rename = "outputPolicy")]
    pub output_policy: MediaOutputPolicyV1,
    pub privacy: MediaPrivacyV1,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "settlementMethod")]
    pub settlement_method: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MediaJobInitOptionsV1 {
    pub requester: String,
    pub task: MediaTask,
    #[serde(rename = "packageRef", default)]
    pub package_ref: Option<String>,
    #[serde(rename = "packageId", default)]
    pub package_id: Option<String>,
    #[serde(rename = "packageVersion", default)]
    pub package_version: Option<String>,
    #[serde(rename = "serviceRef", default)]
    pub service_ref: Option<String>,
    #[serde(rename = "modelAlias", default)]
    pub model_alias: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(rename = "inputRef", default)]
    pub input_ref: Option<String>,
    #[serde(rename = "maskRef", default)]
    pub mask_ref: Option<String>,
    #[serde(default)]
    pub parameters: Option<Value>,
    #[serde(rename = "responseFormat", default)]
    pub response_format: Option<String>,
    #[serde(rename = "outputRef", default)]
    pub output_ref: Option<String>,
    #[serde(default)]
    pub count: Option<u32>,
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub quality: Option<String>,
    #[serde(default)]
    pub style: Option<String>,
    #[serde(default)]
    pub voice: Option<String>,
    #[serde(rename = "audioFormat", default)]
    pub audio_format: Option<String>,
    #[serde(rename = "privacyTier", default)]
    pub privacy_tier: Option<PrivacyTier>,
    #[serde(rename = "integrityTier", default)]
    pub integrity_tier: Option<IntegrityTier>,
    #[serde(rename = "settlementMethod", default)]
    pub settlement_method: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MediaJobVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "mediaJobId")]
    pub media_job_id: String,
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
pub struct MediaExecutionPlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "mediaJobId")]
    pub media_job_id: String,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    pub task: MediaTask,
    #[serde(rename = "modalitiesIn")]
    pub modalities_in: Vec<Modality>,
    #[serde(rename = "modalitiesOut")]
    pub modalities_out: Vec<Modality>,
    #[serde(rename = "immutableRefs")]
    pub immutable_refs: Vec<String>,
    #[serde(rename = "mutableRefs")]
    pub mutable_refs: Vec<String>,
    #[serde(rename = "responseFormat")]
    pub response_format: String,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "settlementMethod")]
    pub settlement_method: String,
    #[serde(rename = "allowedEventTypes")]
    pub allowed_event_types: Vec<StreamingEventType>,
    #[serde(default)]
    pub metadata: Value,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MediaJobIndexEntryV1 {
    #[serde(rename = "mediaJobId")]
    pub media_job_id: String,
    pub requester: String,
    pub task: MediaTask,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    #[serde(rename = "modalitiesInCount")]
    pub modalities_in_count: usize,
    #[serde(rename = "modalitiesOutCount")]
    pub modalities_out_count: usize,
    #[serde(rename = "responseFormat")]
    pub response_format: String,
    #[serde(rename = "outputCount")]
    pub output_count: u32,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "allowedEventTypeCount")]
    pub allowed_event_type_count: usize,
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
pub struct MediaJobStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "jobCount")]
    pub job_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "imageJobCount")]
    pub image_job_count: usize,
    #[serde(rename = "audioJobCount")]
    pub audio_job_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub jobs: Vec<MediaJobIndexEntryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MediaJobLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "mediaJobId")]
    pub media_job_id: String,
    #[serde(rename = "jobPath")]
    pub job_path: String,
    pub job: MediaJobV1,
    pub verification: MediaJobVerificationV1,
    #[serde(rename = "executionPlan")]
    pub execution_plan: MediaExecutionPlanV1,
}

pub fn create_media_job(options: MediaJobInitOptionsV1) -> MediaJobV1 {
    let api_surface = match options.task {
        MediaTask::ImageGeneration | MediaTask::ImageEdit => ApiSurface::OpenAiImages,
        MediaTask::AudioTranscription | MediaTask::TextToSpeech => ApiSurface::OpenAiAudio,
    };
    let mut job = MediaJobV1 {
        schema_version: "swarm-ai.media-job.v1".to_string(),
        media_job_id: String::new(),
        requester: options.requester,
        task: options.task,
        api_surface,
        package_selector: MediaPackageSelectorV1 {
            package_ref: options.package_ref,
            package_id: options.package_id,
            package_version: options.package_version,
            service_ref: options.service_ref,
            model_alias: options.model_alias,
        },
        input: MediaInputV1 {
            prompt: options.prompt,
            text: options.text,
            input_ref: options.input_ref,
            mask_ref: options.mask_ref,
            parameters: options.parameters.unwrap_or_else(|| json!({})),
        },
        output_policy: MediaOutputPolicyV1 {
            response_format: options.response_format.unwrap_or_else(|| "ref".to_string()),
            output_ref: options.output_ref,
            count: options.count.unwrap_or(1).max(1),
            size: options.size,
            quality: options.quality,
            style: options.style,
            voice: options.voice,
            audio_format: options.audio_format,
        },
        privacy: MediaPrivacyV1 {
            privacy_tier: options.privacy_tier.unwrap_or(PrivacyTier::NoLog),
            ..MediaPrivacyV1::default()
        },
        integrity_tier: options.integrity_tier.unwrap_or(IntegrityTier::ReceiptOnly),
        settlement_method: options
            .settlement_method
            .unwrap_or_else(|| "free-local-dev".to_string()),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_media_job(&mut job);
    job
}

pub fn sign_media_job(job: &mut MediaJobV1) {
    job.signature = Some(expected_media_job_signature(job));
    job.media_job_id = canonical_media_job_id(job);
}

pub fn sign_media_job_with_identity(
    job: &mut MediaJobV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != job.requester {
        anyhow::bail!(
            "identity subject {} does not match media job requester {}",
            identity.subject,
            job.requester
        );
    }
    let envelope =
        hivemind_identity::sign_value(identity, "media-job", &media_job_signing_value(job))?;
    job.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    job.media_job_id = canonical_media_job_id(job);
    Ok(envelope)
}

pub fn expected_media_job_signature(job: &MediaJobV1) -> String {
    format!(
        "{DEV_MEDIA_JOB_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&media_job_signing_value(job)))
    )
}

pub fn canonical_media_job_id(job: &MediaJobV1) -> String {
    stable_id("media", &media_job_signing_value(job))
}

pub fn verify_media_job(job: &MediaJobV1) -> MediaJobVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_media_job_signature(job));
    let signature = job
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if job.schema_version != "swarm-ai.media-job.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.media-job.v1",
        ));
    }
    require_non_empty(&mut issues, "$.mediaJobId", &job.media_job_id);
    if !job.media_job_id.is_empty() && job.media_job_id != canonical_media_job_id(job) {
        issues.push(issue(
            "$.mediaJobId",
            "Media job id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.requester", &job.requester);
    validate_package_selector(&job.package_selector, &mut issues, &mut warnings);
    validate_task_input(job, &mut issues, &mut warnings);
    validate_output_policy(&job.output_policy, &mut issues, &mut warnings);
    require_non_empty(&mut issues, "$.settlementMethod", &job.settlement_method);
    validate_created_at(&job.created_at, "$.createdAt", &mut issues);
    verify_signature(
        signature,
        "media-job",
        &media_job_signing_value(job),
        &job.requester,
        &mut expected_signature,
        &mut issues,
        "Media job signature does not match canonical dev signature or Ed25519 requester identity envelope",
    );
    if signature.is_none() {
        warnings.push(issue(
            "$.signature",
            "Media job is unsigned; verify requester and mediaJobId through a trusted source",
        ));
    }

    MediaJobVerificationV1 {
        schema_version: "swarm-ai.media-job-verification.v1".to_string(),
        media_job_id: job.media_job_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn media_execution_plan(job: &MediaJobV1) -> MediaExecutionPlanV1 {
    let verification = verify_media_job(job);
    let mut immutable_refs = Vec::new();
    let mut mutable_refs = Vec::new();
    for (_, reference) in media_refs(job) {
        if looks_mutable_ref(&reference) {
            mutable_refs.push(reference);
        } else {
            immutable_refs.push(reference);
        }
    }
    dedup(&mut immutable_refs);
    dedup(&mut mutable_refs);

    MediaExecutionPlanV1 {
        schema_version: "swarm-ai.media-execution-plan.v1".to_string(),
        media_job_id: job.media_job_id.clone(),
        api_surface: job.api_surface.clone(),
        task: job.task.clone(),
        modalities_in: modalities_in_for_task(job),
        modalities_out: modalities_out_for_task(job),
        immutable_refs,
        mutable_refs,
        response_format: job.output_policy.response_format.clone(),
        privacy_tier: job.privacy.privacy_tier.clone(),
        integrity_tier: job.integrity_tier.clone(),
        settlement_method: job.settlement_method.clone(),
        allowed_event_types: allowed_event_types(&job.task),
        metadata: json!({
            "executionLayer": "browser-local-remote-or-miner-runner",
            "storageLayer": "Swarm/Bee stores media package refs, input refs, output refs, receipts, and audit records; image/audio execution is runner-side.",
            "compatibilityMode": "contract-only",
        }),
        valid: verification.valid,
        issues: verification.issues,
        warnings: verification.warnings,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn list_media_jobs(job_dir: &Path) -> anyhow::Result<MediaJobStoreSummaryV1> {
    let mut files = Vec::new();
    collect_media_job_files(job_dir, &mut files)?;
    files.sort();

    let mut jobs = Vec::new();
    let mut valid_count = 0;
    let mut image_job_count = 0;
    let mut audio_job_count = 0;
    let mut mutable_ref_count = 0;
    let mut warning_count = 0;

    for path in files {
        let Some(job) = read_media_job_file(&path)? else {
            continue;
        };
        let verification = verify_media_job(&job);
        let execution_plan = media_execution_plan(&job);
        if verification.valid {
            valid_count += 1;
        }
        match job.task {
            MediaTask::ImageGeneration | MediaTask::ImageEdit => image_job_count += 1,
            MediaTask::AudioTranscription | MediaTask::TextToSpeech => audio_job_count += 1,
        }
        mutable_ref_count += execution_plan.mutable_refs.len();
        warning_count += execution_plan.warnings.len();
        jobs.push(media_job_index_entry(
            &job,
            &verification,
            &execution_plan,
            path.display().to_string(),
        ));
    }

    jobs.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.media_job_id.cmp(&right.media_job_id))
            .then(left.job_path.cmp(&right.job_path))
    });

    Ok(MediaJobStoreSummaryV1 {
        schema_version: "swarm-ai.media-job-store-summary.v1".to_string(),
        root: job_dir.display().to_string(),
        job_count: jobs.len(),
        valid_count,
        invalid_count: jobs.len().saturating_sub(valid_count),
        image_job_count,
        audio_job_count,
        mutable_ref_count,
        warning_count,
        jobs,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn get_media_job(
    job_dir: &Path,
    media_job_id: &str,
) -> anyhow::Result<Option<MediaJobLookupV1>> {
    let media_job_id = media_job_id.trim();
    if media_job_id.is_empty() {
        anyhow::bail!("mediaJobId is required");
    }

    let mut files = Vec::new();
    collect_media_job_files(job_dir, &mut files)?;
    files.sort();

    for path in files {
        let Some(job) = read_media_job_file(&path)? else {
            continue;
        };
        if job.media_job_id == media_job_id {
            let verification = verify_media_job(&job);
            let execution_plan = media_execution_plan(&job);
            return Ok(Some(MediaJobLookupV1 {
                schema_version: "swarm-ai.media-job-lookup.v1".to_string(),
                media_job_id: job.media_job_id.clone(),
                job_path: path.display().to_string(),
                job,
                verification,
                execution_plan,
            }));
        }
    }

    Ok(None)
}

fn collect_media_job_files(job_dir: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
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
            collect_media_job_files(&path, files)?;
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

fn read_media_job_file(path: &Path) -> anyhow::Result<Option<MediaJobV1>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let Some(schema_version) = value.get("schemaVersion").and_then(Value::as_str) else {
        return Ok(None);
    };
    if schema_version != "swarm-ai.media-job.v1" {
        return Ok(None);
    }
    serde_json::from_value(value)
        .map(Some)
        .with_context(|| format!("failed to parse media job {}", path.display()))
}

fn media_job_index_entry(
    job: &MediaJobV1,
    verification: &MediaJobVerificationV1,
    execution_plan: &MediaExecutionPlanV1,
    job_path: String,
) -> MediaJobIndexEntryV1 {
    MediaJobIndexEntryV1 {
        media_job_id: job.media_job_id.clone(),
        requester: job.requester.clone(),
        task: job.task.clone(),
        api_surface: job.api_surface.clone(),
        modalities_in_count: execution_plan.modalities_in.len(),
        modalities_out_count: execution_plan.modalities_out.len(),
        response_format: job.output_policy.response_format.clone(),
        output_count: job.output_policy.count,
        privacy_tier: job.privacy.privacy_tier.clone(),
        integrity_tier: job.integrity_tier.clone(),
        allowed_event_type_count: execution_plan.allowed_event_types.len(),
        mutable_ref_count: execution_plan.mutable_refs.len(),
        warning_count: execution_plan.warnings.len(),
        valid: verification.valid,
        signature_present: job.signature.is_some(),
        created_at: job.created_at.clone(),
        job_path,
    }
}

fn validate_package_selector(
    selector: &MediaPackageSelectorV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if selector.package_ref.is_none()
        && selector.service_ref.is_none()
        && selector.package_id.is_none()
        && selector.model_alias.is_none()
    {
        issues.push(issue(
            "$.packageSelector",
            "Media job must include a packageRef, serviceRef, packageId, or modelAlias",
        ));
    }
    if let Some(package_ref) = &selector.package_ref {
        validate_ref(
            "$.packageSelector.packageRef".to_string(),
            package_ref,
            issues,
            warnings,
        );
    }
    if let Some(service_ref) = &selector.service_ref {
        validate_ref(
            "$.packageSelector.serviceRef".to_string(),
            service_ref,
            issues,
            warnings,
        );
    }
}

fn validate_task_input(
    job: &MediaJobV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    match job.task {
        MediaTask::ImageGeneration => {
            if empty_option(&job.input.prompt) {
                issues.push(issue(
                    "$.input.prompt",
                    "Image generation requires a prompt",
                ));
            }
        }
        MediaTask::ImageEdit => {
            if empty_option(&job.input.prompt) {
                issues.push(issue("$.input.prompt", "Image edit requires a prompt"));
            }
            if empty_option(&job.input.input_ref) {
                issues.push(issue("$.input.inputRef", "Image edit requires an inputRef"));
            }
        }
        MediaTask::AudioTranscription => {
            if empty_option(&job.input.input_ref) {
                issues.push(issue(
                    "$.input.inputRef",
                    "Audio transcription requires an inputRef",
                ));
            }
        }
        MediaTask::TextToSpeech => {
            if empty_option(&job.input.text) {
                issues.push(issue("$.input.text", "Text-to-speech requires text"));
            }
        }
    }
    for (path, reference) in media_refs(job) {
        validate_ref(path, &reference, issues, warnings);
    }
}

fn validate_output_policy(
    policy: &MediaOutputPolicyV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if policy.count == 0 || policy.count > 16 {
        issues.push(issue(
            "$.outputPolicy.count",
            "count must be between 1 and 16",
        ));
    }
    if policy.response_format.trim().is_empty() {
        issues.push(issue(
            "$.outputPolicy.responseFormat",
            "responseFormat is required",
        ));
    }
    if policy.output_ref.is_none()
        && matches!(policy.response_format.as_str(), "ref" | "audio_ref" | "url")
    {
        warnings.push(issue(
            "$.outputPolicy.outputRef",
            "Reference-style media responses should include an outputRef once execution runs",
        ));
    }
    if let Some(output_ref) = &policy.output_ref {
        validate_ref(
            "$.outputPolicy.outputRef".to_string(),
            output_ref,
            issues,
            warnings,
        );
    }
}

fn media_refs(job: &MediaJobV1) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    if let Some(package_ref) = &job.package_selector.package_ref {
        refs.push((
            "$.packageSelector.packageRef".to_string(),
            package_ref.clone(),
        ));
    }
    if let Some(service_ref) = &job.package_selector.service_ref {
        refs.push((
            "$.packageSelector.serviceRef".to_string(),
            service_ref.clone(),
        ));
    }
    if let Some(input_ref) = &job.input.input_ref {
        refs.push(("$.input.inputRef".to_string(), input_ref.clone()));
    }
    if let Some(mask_ref) = &job.input.mask_ref {
        refs.push(("$.input.maskRef".to_string(), mask_ref.clone()));
    }
    if let Some(output_ref) = &job.output_policy.output_ref {
        refs.push(("$.outputPolicy.outputRef".to_string(), output_ref.clone()));
    }
    refs
}

fn modalities_in_for_task(job: &MediaJobV1) -> Vec<Modality> {
    match job.task {
        MediaTask::ImageGeneration => vec![Modality::Text],
        MediaTask::ImageEdit => vec![Modality::Text, Modality::Image],
        MediaTask::AudioTranscription => vec![Modality::Audio],
        MediaTask::TextToSpeech => vec![Modality::Text],
    }
}

fn modalities_out_for_task(job: &MediaJobV1) -> Vec<Modality> {
    match job.task {
        MediaTask::ImageGeneration | MediaTask::ImageEdit => vec![Modality::Image],
        MediaTask::AudioTranscription => vec![Modality::Text],
        MediaTask::TextToSpeech => vec![Modality::Audio],
    }
}

fn allowed_event_types(task: &MediaTask) -> Vec<StreamingEventType> {
    let mut events = vec![
        StreamingEventType::Started,
        StreamingEventType::LogEvent,
        StreamingEventType::PartialReceipt,
        StreamingEventType::Completed,
        StreamingEventType::Error,
        StreamingEventType::Cancelled,
    ];
    match task {
        MediaTask::ImageGeneration | MediaTask::ImageEdit => {
            events.push(StreamingEventType::ImageProgress);
        }
        MediaTask::AudioTranscription => {
            events.push(StreamingEventType::TextDelta);
        }
        MediaTask::TextToSpeech => {
            events.push(StreamingEventType::AudioChunk);
        }
    }
    events
}

fn media_job_signing_value(job: &MediaJobV1) -> Value {
    let mut value = serde_json::to_value(job).expect("media job should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("mediaJobId");
        object.remove("signature");
    }
    value
}

fn empty_option(value: &Option<String>) -> bool {
    value
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .is_empty()
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
    let value = serde_json::to_value(value).expect("value should serialize for stable id");
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
    fn creates_signed_image_generation_job_and_plan() {
        let job = create_media_job(MediaJobInitOptionsV1 {
            requester: "local-dev".to_string(),
            task: MediaTask::ImageGeneration,
            package_ref: None,
            package_id: Some("hivemind/image-generator".to_string()),
            package_version: Some("0.1.0".to_string()),
            service_ref: None,
            model_alias: Some("hivemind/image".to_string()),
            prompt: Some("a tiny protocol workbench".to_string()),
            text: None,
            input_ref: None,
            mask_ref: None,
            parameters: Some(json!({ "seed": 7 })),
            response_format: Some("url".to_string()),
            output_ref: Some("local://media/output/image".to_string()),
            count: Some(2),
            size: Some("1024x1024".to_string()),
            quality: Some("standard".to_string()),
            style: Some("natural".to_string()),
            voice: None,
            audio_format: None,
            privacy_tier: Some(PrivacyTier::NoLog),
            integrity_tier: Some(IntegrityTier::ReceiptOnly),
            settlement_method: None,
        });
        let verification = verify_media_job(&job);
        let plan = media_execution_plan(&job);

        assert!(verification.valid);
        assert_eq!(job.media_job_id, canonical_media_job_id(&job));
        assert_eq!(plan.api_surface, ApiSurface::OpenAiImages);
        assert_eq!(plan.modalities_out, vec![Modality::Image]);
        assert!(plan.valid);
    }

    #[test]
    fn rejects_missing_audio_input_ref() {
        let mut job = create_media_job(MediaJobInitOptionsV1 {
            requester: "local-dev".to_string(),
            task: MediaTask::AudioTranscription,
            package_ref: None,
            package_id: Some("hivemind/transcribe".to_string()),
            package_version: None,
            service_ref: None,
            model_alias: Some("hivemind/audio".to_string()),
            prompt: None,
            text: None,
            input_ref: None,
            mask_ref: None,
            parameters: None,
            response_format: Some("text".to_string()),
            output_ref: None,
            count: Some(1),
            size: None,
            quality: None,
            style: None,
            voice: None,
            audio_format: None,
            privacy_tier: None,
            integrity_tier: None,
            settlement_method: None,
        });
        sign_media_job(&mut job);
        let verification = verify_media_job(&job);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.input.inputRef")
        );
    }

    #[test]
    fn identity_signed_media_job_verifies_and_detects_tampering() {
        let identity = hivemind_identity::identity_from_seed("local-dev", b"media-seed").unwrap();
        let mut job = create_media_job(MediaJobInitOptionsV1 {
            requester: "local-dev".to_string(),
            task: MediaTask::TextToSpeech,
            package_ref: Some("bzz://speech-package".to_string()),
            package_id: Some("hivemind/speech".to_string()),
            package_version: Some("0.1.0".to_string()),
            service_ref: None,
            model_alias: None,
            prompt: None,
            text: Some("hello".to_string()),
            input_ref: None,
            mask_ref: None,
            parameters: None,
            response_format: Some("audio_ref".to_string()),
            output_ref: Some("local://media/output/audio".to_string()),
            count: Some(1),
            size: None,
            quality: None,
            style: None,
            voice: Some("alloy".to_string()),
            audio_format: Some("mp3".to_string()),
            privacy_tier: None,
            integrity_tier: None,
            settlement_method: None,
        });
        sign_media_job_with_identity(&mut job, &identity).unwrap();
        let verification = verify_media_job(&job);

        assert!(verification.valid);
        job.input.text = Some("tampered".to_string());
        let verification = verify_media_job(&job);
        assert!(!verification.valid);
    }

    #[test]
    fn media_job_store_lists_and_gets_jobs() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("hivemind-media-store-{unique}"));
        fs::create_dir_all(dir.join("nested")).unwrap();

        let job = create_media_job(MediaJobInitOptionsV1 {
            requester: "local-dev".to_string(),
            task: MediaTask::ImageEdit,
            package_ref: Some("https://example.com/image/edit/latest".to_string()),
            package_id: Some("hivemind/image-edit".to_string()),
            package_version: Some("0.1.0".to_string()),
            service_ref: None,
            model_alias: None,
            prompt: Some("replace the background".to_string()),
            text: None,
            input_ref: Some("https://example.com/source/latest".to_string()),
            mask_ref: Some("bzz://mask".to_string()),
            parameters: Some(json!({ "seed": 11 })),
            response_format: Some("url".to_string()),
            output_ref: Some("local://media/output/image-edit".to_string()),
            count: Some(1),
            size: Some("1024x1024".to_string()),
            quality: Some("standard".to_string()),
            style: Some("natural".to_string()),
            voice: None,
            audio_format: None,
            privacy_tier: Some(PrivacyTier::NoLog),
            integrity_tier: Some(IntegrityTier::DeterministicReplay),
            settlement_method: None,
        });

        fs::write(
            dir.join("nested").join("image-edit.media.json"),
            serde_json::to_vec_pretty(&job).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("identity.json"),
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": "swarm-ai.identity.keypair.v1",
                "subject": "local-dev"
            }))
            .unwrap(),
        )
        .unwrap();

        let summary = list_media_jobs(&dir).unwrap();
        assert_eq!(summary.job_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.invalid_count, 0);
        assert_eq!(summary.image_job_count, 1);
        assert_eq!(summary.audio_job_count, 0);
        assert_eq!(summary.mutable_ref_count, 2);
        assert!(summary.warning_count > 0);
        assert_eq!(summary.jobs[0].media_job_id, job.media_job_id);
        assert!(summary.jobs[0].signature_present);

        let lookup = get_media_job(&dir, &job.media_job_id).unwrap().unwrap();
        assert_eq!(lookup.job.media_job_id, job.media_job_id);
        assert!(lookup.verification.valid, "{:#?}", lookup.verification);
        assert!(lookup.execution_plan.valid, "{:#?}", lookup.execution_plan);
        assert_eq!(lookup.execution_plan.mutable_refs.len(), 2);
        assert!(get_media_job(&dir, "missing").unwrap().is_none());

        let _ = fs::remove_dir_all(dir);
    }
}
