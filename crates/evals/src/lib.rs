use anyhow::Context;
use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    ApiSurface, IntegrityTier, PrivacyTier, StreamingEventType, ValidationIssue, canonicalize_json,
    hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const DEV_EVAL_MANIFEST_SIGNATURE_PREFIX: &str = "dev-eval-manifest-signature-v1";
const DEV_EVAL_RUN_SIGNATURE_PREFIX: &str = "dev-eval-run-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum EvalKind {
    Dataset,
    ModelGraded,
    HumanReview,
    Regression,
    Safety,
    Retrieval,
    AgentTooling,
    Rag,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvalManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evalId")]
    pub eval_id: String,
    pub name: String,
    pub owner: String,
    pub kind: EvalKind,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    #[serde(rename = "datasetRefs", default)]
    pub dataset_refs: Vec<String>,
    #[serde(rename = "scoringRuleRefs", default)]
    pub scoring_rule_refs: Vec<String>,
    #[serde(rename = "targetRefs", default)]
    pub target_refs: Vec<String>,
    #[serde(
        rename = "graderModelRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub grader_model_ref: Option<String>,
    #[serde(
        rename = "outputSchemaRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_schema_ref: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvalManifestInitOptionsV1 {
    pub name: String,
    pub owner: String,
    #[serde(default)]
    pub kind: Option<EvalKind>,
    #[serde(rename = "datasetRefs", default)]
    pub dataset_refs: Vec<String>,
    #[serde(rename = "scoringRuleRefs", default)]
    pub scoring_rule_refs: Vec<String>,
    #[serde(rename = "targetRefs", default)]
    pub target_refs: Vec<String>,
    #[serde(rename = "graderModelRef", default)]
    pub grader_model_ref: Option<String>,
    #[serde(rename = "outputSchemaRef", default)]
    pub output_schema_ref: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvalManifestVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evalId")]
    pub eval_id: String,
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
pub struct EvalRunV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evalRunId")]
    pub eval_run_id: String,
    #[serde(rename = "evalId")]
    pub eval_id: String,
    pub requester: String,
    #[serde(rename = "targetRef")]
    pub target_ref: String,
    #[serde(rename = "inputRefs", default)]
    pub input_refs: Vec<String>,
    #[serde(rename = "sampleCount")]
    pub sample_count: u32,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "settlementMethod")]
    pub settlement_method: String,
    #[serde(rename = "reportRef", default, skip_serializing_if = "Option::is_none")]
    pub report_ref: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvalRunInitOptionsV1 {
    #[serde(rename = "evalId")]
    pub eval_id: String,
    pub requester: String,
    #[serde(rename = "targetRef")]
    pub target_ref: String,
    #[serde(rename = "inputRefs", default)]
    pub input_refs: Vec<String>,
    #[serde(rename = "sampleCount", default)]
    pub sample_count: Option<u32>,
    #[serde(rename = "privacyTier", default)]
    pub privacy_tier: Option<PrivacyTier>,
    #[serde(rename = "integrityTier", default)]
    pub integrity_tier: Option<IntegrityTier>,
    #[serde(rename = "settlementMethod", default)]
    pub settlement_method: Option<String>,
    #[serde(rename = "reportRef", default)]
    pub report_ref: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvalRunVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evalRunId")]
    pub eval_run_id: String,
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
pub struct EvalRunPlanningRequestV1 {
    pub manifest: EvalManifestV1,
    pub run: EvalRunV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvalRunPlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "evalRunId")]
    pub eval_run_id: String,
    #[serde(rename = "evalId")]
    pub eval_id: String,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    pub kind: EvalKind,
    #[serde(rename = "targetRef")]
    pub target_ref: String,
    #[serde(rename = "datasetRefs")]
    pub dataset_refs: Vec<String>,
    #[serde(rename = "scoringRuleRefs")]
    pub scoring_rule_refs: Vec<String>,
    #[serde(rename = "inputRefs")]
    pub input_refs: Vec<String>,
    #[serde(rename = "immutableRefs")]
    pub immutable_refs: Vec<String>,
    #[serde(rename = "mutableRefs")]
    pub mutable_refs: Vec<String>,
    #[serde(rename = "sampleCount")]
    pub sample_count: u32,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "settlementMethod")]
    pub settlement_method: String,
    #[serde(rename = "reportRef", default, skip_serializing_if = "Option::is_none")]
    pub report_ref: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum EvalRecordType {
    Manifest,
    Run,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvalRecordSummaryV1 {
    #[serde(rename = "recordId")]
    pub record_id: String,
    #[serde(rename = "recordType")]
    pub record_type: EvalRecordType,
    #[serde(rename = "evalId")]
    pub eval_id: String,
    #[serde(rename = "evalRunId", default, skip_serializing_if = "Option::is_none")]
    pub eval_run_id: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<EvalKind>,
    #[serde(
        rename = "sampleCount",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sample_count: Option<u32>,
    #[serde(
        rename = "privacyTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub privacy_tier: Option<PrivacyTier>,
    #[serde(
        rename = "integrityTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub integrity_tier: Option<IntegrityTier>,
    #[serde(rename = "planAvailable")]
    pub plan_available: bool,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub valid: bool,
    #[serde(rename = "signaturePresent")]
    pub signature_present: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvalRecordStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "manifestCount")]
    pub manifest_count: usize,
    #[serde(rename = "runCount")]
    pub run_count: usize,
    #[serde(rename = "recordCount")]
    pub record_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "planAvailableCount")]
    pub plan_available_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub records: Vec<EvalRecordSummaryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EvalRecordLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "recordId")]
    pub record_id: String,
    #[serde(rename = "recordType")]
    pub record_type: EvalRecordType,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<EvalManifestV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<EvalRunV1>,
    #[serde(
        rename = "manifestVerification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub manifest_verification: Option<EvalManifestVerificationV1>,
    #[serde(
        rename = "runVerification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub run_verification: Option<EvalRunVerificationV1>,
    #[serde(rename = "runPlan", default, skip_serializing_if = "Option::is_none")]
    pub run_plan: Option<EvalRunPlanV1>,
}

pub fn create_eval_manifest(options: EvalManifestInitOptionsV1) -> EvalManifestV1 {
    let mut dataset_refs = options.dataset_refs;
    dedup(&mut dataset_refs);
    let mut scoring_rule_refs = options.scoring_rule_refs;
    dedup(&mut scoring_rule_refs);
    let mut target_refs = options.target_refs;
    dedup(&mut target_refs);
    let mut manifest = EvalManifestV1 {
        schema_version: "swarm-ai.eval-manifest.v1".to_string(),
        eval_id: String::new(),
        name: options.name,
        owner: options.owner,
        kind: options.kind.unwrap_or(EvalKind::Dataset),
        api_surface: ApiSurface::OpenAiEvals,
        dataset_refs,
        scoring_rule_refs,
        target_refs,
        grader_model_ref: trim_optional_string(options.grader_model_ref),
        output_schema_ref: trim_optional_string(options.output_schema_ref),
        metadata: options.metadata.unwrap_or_else(|| json!({})),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_eval_manifest(&mut manifest);
    manifest
}

pub fn sign_eval_manifest(manifest: &mut EvalManifestV1) {
    manifest.signature = Some(expected_eval_manifest_signature(manifest));
    manifest.eval_id = canonical_eval_manifest_id(manifest);
}

pub fn sign_eval_manifest_with_identity(
    manifest: &mut EvalManifestV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != manifest.owner {
        anyhow::bail!(
            "identity subject {} does not match eval owner {}",
            identity.subject,
            manifest.owner
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "eval-manifest",
        &eval_manifest_signing_value(manifest),
    )?;
    manifest.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    manifest.eval_id = canonical_eval_manifest_id(manifest);
    Ok(envelope)
}

pub fn expected_eval_manifest_signature(manifest: &EvalManifestV1) -> String {
    format!(
        "{DEV_EVAL_MANIFEST_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&eval_manifest_signing_value(manifest)))
    )
}

pub fn canonical_eval_manifest_id(manifest: &EvalManifestV1) -> String {
    stable_id("eval", &eval_manifest_signing_value(manifest))
}

pub fn verify_eval_manifest(manifest: &EvalManifestV1) -> EvalManifestVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_eval_manifest_signature(manifest));
    let signature = manifest
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if manifest.schema_version != "swarm-ai.eval-manifest.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.eval-manifest.v1",
        ));
    }
    require_non_empty(&mut issues, "$.evalId", &manifest.eval_id);
    if !manifest.eval_id.is_empty() && manifest.eval_id != canonical_eval_manifest_id(manifest) {
        issues.push(issue(
            "$.evalId",
            "Eval id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.name", &manifest.name);
    require_non_empty(&mut issues, "$.owner", &manifest.owner);
    if manifest.dataset_refs.is_empty() {
        issues.push(issue(
            "$.datasetRefs",
            "Eval manifest must include at least one dataset, data source, or input collection ref",
        ));
    }
    if manifest.scoring_rule_refs.is_empty()
        && manifest.grader_model_ref.is_none()
        && manifest.kind != EvalKind::HumanReview
    {
        issues.push(issue(
            "$.scoringRuleRefs",
            "Eval manifest must include scoring rules, a grader model, or human-review kind",
        ));
    }
    for (index, reference) in manifest.dataset_refs.iter().enumerate() {
        validate_ref(
            format!("$.datasetRefs[{index}]"),
            reference,
            &mut issues,
            &mut warnings,
        );
    }
    for (index, reference) in manifest.scoring_rule_refs.iter().enumerate() {
        validate_ref(
            format!("$.scoringRuleRefs[{index}]"),
            reference,
            &mut issues,
            &mut warnings,
        );
    }
    for (index, reference) in manifest.target_refs.iter().enumerate() {
        validate_ref(
            format!("$.targetRefs[{index}]"),
            reference,
            &mut issues,
            &mut warnings,
        );
    }
    if let Some(reference) = &manifest.grader_model_ref {
        validate_ref(
            "$.graderModelRef".to_string(),
            reference,
            &mut issues,
            &mut warnings,
        );
    }
    if let Some(reference) = &manifest.output_schema_ref {
        validate_ref(
            "$.outputSchemaRef".to_string(),
            reference,
            &mut issues,
            &mut warnings,
        );
    }
    validate_created_at(&manifest.created_at, "$.createdAt", &mut issues);
    verify_signature(
        signature,
        "eval-manifest",
        &eval_manifest_signing_value(manifest),
        &manifest.owner,
        &mut expected_signature,
        &mut issues,
        "Eval manifest signature does not match canonical dev signature or Ed25519 owner identity envelope",
    );
    if signature.is_none() {
        warnings.push(issue(
            "$.signature",
            "Eval manifest is unsigned; verify owner and evalId through a trusted source",
        ));
    }

    EvalManifestVerificationV1 {
        schema_version: "swarm-ai.eval-manifest-verification.v1".to_string(),
        eval_id: manifest.eval_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn create_eval_run(options: EvalRunInitOptionsV1) -> EvalRunV1 {
    let mut input_refs = options.input_refs;
    dedup(&mut input_refs);
    let sample_count = options
        .sample_count
        .unwrap_or_else(|| input_refs.len().max(1) as u32)
        .max(1);
    let mut run = EvalRunV1 {
        schema_version: "swarm-ai.eval-run.v1".to_string(),
        eval_run_id: String::new(),
        eval_id: options.eval_id,
        requester: options.requester,
        target_ref: options.target_ref,
        input_refs,
        sample_count,
        privacy_tier: options.privacy_tier.unwrap_or(PrivacyTier::NoLog),
        integrity_tier: options
            .integrity_tier
            .unwrap_or(IntegrityTier::ValidatorSpotCheck),
        settlement_method: options
            .settlement_method
            .unwrap_or_else(|| "free-local-dev".to_string()),
        report_ref: trim_optional_string(options.report_ref),
        metadata: options.metadata.unwrap_or_else(|| json!({})),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_eval_run(&mut run);
    run
}

pub fn sign_eval_run(run: &mut EvalRunV1) {
    run.signature = Some(expected_eval_run_signature(run));
    run.eval_run_id = canonical_eval_run_id(run);
}

pub fn sign_eval_run_with_identity(
    run: &mut EvalRunV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != run.requester {
        anyhow::bail!(
            "identity subject {} does not match eval run requester {}",
            identity.subject,
            run.requester
        );
    }
    let envelope =
        hivemind_identity::sign_value(identity, "eval-run", &eval_run_signing_value(run))?;
    run.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    run.eval_run_id = canonical_eval_run_id(run);
    Ok(envelope)
}

pub fn expected_eval_run_signature(run: &EvalRunV1) -> String {
    format!(
        "{DEV_EVAL_RUN_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&eval_run_signing_value(run)))
    )
}

pub fn canonical_eval_run_id(run: &EvalRunV1) -> String {
    stable_id("evalrun", &eval_run_signing_value(run))
}

pub fn verify_eval_run(run: &EvalRunV1) -> EvalRunVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_eval_run_signature(run));
    let signature = run
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if run.schema_version != "swarm-ai.eval-run.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.eval-run.v1",
        ));
    }
    require_non_empty(&mut issues, "$.evalRunId", &run.eval_run_id);
    if !run.eval_run_id.is_empty() && run.eval_run_id != canonical_eval_run_id(run) {
        issues.push(issue(
            "$.evalRunId",
            "Eval run id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.evalId", &run.eval_id);
    require_non_empty(&mut issues, "$.requester", &run.requester);
    require_non_empty(&mut issues, "$.targetRef", &run.target_ref);
    validate_ref(
        "$.targetRef".to_string(),
        &run.target_ref,
        &mut issues,
        &mut warnings,
    );
    if run.input_refs.is_empty() {
        warnings.push(issue(
            "$.inputRefs",
            "Eval run has no explicit input refs and will rely on manifest dataset refs",
        ));
    }
    for (index, reference) in run.input_refs.iter().enumerate() {
        validate_ref(
            format!("$.inputRefs[{index}]"),
            reference,
            &mut issues,
            &mut warnings,
        );
    }
    if run.sample_count == 0 {
        issues.push(issue("$.sampleCount", "sampleCount must be at least 1"));
    }
    if run.sample_count > 1_000_000 {
        issues.push(issue(
            "$.sampleCount",
            "sampleCount must be no greater than 1,000,000 for a single eval run contract",
        ));
    }
    require_non_empty(&mut issues, "$.settlementMethod", &run.settlement_method);
    if let Some(reference) = &run.report_ref {
        validate_ref(
            "$.reportRef".to_string(),
            reference,
            &mut issues,
            &mut warnings,
        );
    }
    validate_created_at(&run.created_at, "$.createdAt", &mut issues);
    verify_signature(
        signature,
        "eval-run",
        &eval_run_signing_value(run),
        &run.requester,
        &mut expected_signature,
        &mut issues,
        "Eval run signature does not match canonical dev signature or Ed25519 requester identity envelope",
    );
    if signature.is_none() {
        warnings.push(issue(
            "$.signature",
            "Eval run is unsigned; verify requester and evalRunId through a trusted source",
        ));
    }

    EvalRunVerificationV1 {
        schema_version: "swarm-ai.eval-run-verification.v1".to_string(),
        eval_run_id: run.eval_run_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn eval_run_plan(manifest: &EvalManifestV1, run: &EvalRunV1) -> EvalRunPlanV1 {
    let manifest_verification = verify_eval_manifest(manifest);
    let run_verification = verify_eval_run(run);
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    issues.extend(manifest_verification.issues);
    issues.extend(run_verification.issues);
    warnings.extend(manifest_verification.warnings);
    warnings.extend(run_verification.warnings);
    if manifest.eval_id != run.eval_id {
        issues.push(issue(
            "$.run.evalId",
            "Eval run evalId must match the eval manifest",
        ));
    }

    let mut refs = Vec::new();
    refs.push(run.target_ref.clone());
    refs.extend(manifest.dataset_refs.clone());
    refs.extend(manifest.scoring_rule_refs.clone());
    refs.extend(manifest.target_refs.clone());
    refs.extend(run.input_refs.clone());
    if let Some(reference) = &manifest.grader_model_ref {
        refs.push(reference.clone());
    }
    if let Some(reference) = &manifest.output_schema_ref {
        refs.push(reference.clone());
    }
    if let Some(reference) = &run.report_ref {
        refs.push(reference.clone());
    }
    let mut immutable_refs = Vec::new();
    let mut mutable_refs = Vec::new();
    for reference in refs {
        if looks_mutable_ref(&reference) {
            mutable_refs.push(reference);
        } else {
            immutable_refs.push(reference);
        }
    }
    dedup(&mut immutable_refs);
    dedup(&mut mutable_refs);

    let mut allowed_event_types = vec![
        StreamingEventType::Started,
        StreamingEventType::Heartbeat,
        StreamingEventType::LogEvent,
        StreamingEventType::PartialReceipt,
        StreamingEventType::Completed,
        StreamingEventType::Error,
        StreamingEventType::Cancelled,
    ];
    match manifest.kind {
        EvalKind::Retrieval | EvalKind::Rag => {
            allowed_event_types.push(StreamingEventType::RetrievalEvent)
        }
        EvalKind::Safety => allowed_event_types.push(StreamingEventType::SafetyEvent),
        _ => {}
    }

    EvalRunPlanV1 {
        schema_version: "swarm-ai.eval-run-plan.v1".to_string(),
        eval_run_id: run.eval_run_id.clone(),
        eval_id: manifest.eval_id.clone(),
        api_surface: ApiSurface::OpenAiEvals,
        kind: manifest.kind.clone(),
        target_ref: run.target_ref.clone(),
        dataset_refs: manifest.dataset_refs.clone(),
        scoring_rule_refs: manifest.scoring_rule_refs.clone(),
        input_refs: run.input_refs.clone(),
        immutable_refs,
        mutable_refs,
        sample_count: run.sample_count,
        privacy_tier: run.privacy_tier.clone(),
        integrity_tier: run.integrity_tier.clone(),
        settlement_method: run.settlement_method.clone(),
        report_ref: run.report_ref.clone(),
        allowed_event_types,
        metadata: json!({
            "executionLayer": "browser-local-remote-or-miner-evaluation-worker",
            "storageLayer": "Swarm/Bee stores eval manifests, datasets, scoring rules, run reports, receipts, and audit evidence; evaluation execution remains runner-side.",
            "reportingLayer": "EvaluationResult records from hivemind-benchmarks can be attached through reportRef after execution.",
            "compatibilityMode": "contract-only",
        }),
        valid: issues.is_empty(),
        issues,
        warnings,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn list_eval_records(eval_dir: &Path) -> anyhow::Result<EvalRecordStoreSummaryV1> {
    let documents = read_eval_record_documents(eval_dir)?;
    let manifests = eval_manifest_index(&documents);

    let mut records = Vec::new();
    let mut manifest_count = 0;
    let mut run_count = 0;
    let mut valid_count = 0;
    let mut plan_available_count = 0;
    let mut mutable_ref_count = 0;
    let mut warning_count = 0;

    for (path, document) in documents {
        let path_string = path.display().to_string();
        match document {
            EvalRecordDocument::Manifest(manifest) => {
                let verification = verify_eval_manifest(&manifest);
                let mutable_refs = mutable_eval_manifest_refs(&manifest);
                if verification.valid {
                    valid_count += 1;
                }
                manifest_count += 1;
                mutable_ref_count += mutable_refs.len();
                warning_count += verification.warnings.len();
                records.push(eval_manifest_index_entry(
                    &manifest,
                    &verification,
                    mutable_refs.len(),
                    path_string,
                ));
            }
            EvalRecordDocument::Run(run) => {
                let verification = verify_eval_run(&run);
                let manifest = manifests.get(&run.eval_id);
                let plan = manifest.map(|manifest| eval_run_plan(manifest, &run));
                let valid = plan
                    .as_ref()
                    .map(|plan| plan.valid)
                    .unwrap_or(verification.valid);
                if valid {
                    valid_count += 1;
                }
                if plan.is_some() {
                    plan_available_count += 1;
                }
                run_count += 1;
                mutable_ref_count += plan
                    .as_ref()
                    .map(|plan| plan.mutable_refs.len())
                    .unwrap_or_else(|| mutable_eval_run_refs(&run).len());
                warning_count += plan
                    .as_ref()
                    .map(|plan| plan.warnings.len())
                    .unwrap_or_else(|| verification.warnings.len());
                records.push(eval_run_index_entry(
                    &run,
                    manifest,
                    &verification,
                    plan.as_ref(),
                    path_string,
                ));
            }
        }
    }

    records.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.record_id.cmp(&right.record_id))
            .then(left.path.cmp(&right.path))
    });

    Ok(EvalRecordStoreSummaryV1 {
        schema_version: "swarm-ai.eval-record-store-summary.v1".to_string(),
        root: eval_dir.display().to_string(),
        manifest_count,
        run_count,
        record_count: records.len(),
        valid_count,
        invalid_count: records.len().saturating_sub(valid_count),
        plan_available_count,
        mutable_ref_count,
        warning_count,
        records,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn get_eval_record(
    eval_dir: &Path,
    record_id: &str,
) -> anyhow::Result<Option<EvalRecordLookupV1>> {
    let record_id = record_id.trim();
    if record_id.is_empty() {
        anyhow::bail!("recordId is required");
    }

    let documents = read_eval_record_documents(eval_dir)?;
    let manifests = eval_manifest_index(&documents);
    for (path, document) in documents {
        match document {
            EvalRecordDocument::Manifest(manifest) if manifest.eval_id == record_id => {
                let verification = verify_eval_manifest(&manifest);
                return Ok(Some(EvalRecordLookupV1 {
                    schema_version: "swarm-ai.eval-record-lookup.v1".to_string(),
                    record_id: manifest.eval_id.clone(),
                    record_type: EvalRecordType::Manifest,
                    path: path.display().to_string(),
                    manifest: Some(manifest),
                    run: None,
                    manifest_verification: Some(verification),
                    run_verification: None,
                    run_plan: None,
                }));
            }
            EvalRecordDocument::Run(run) if run.eval_run_id == record_id => {
                let verification = verify_eval_run(&run);
                let manifest = manifests.get(&run.eval_id).cloned();
                let plan = manifest
                    .as_ref()
                    .map(|manifest| eval_run_plan(manifest, &run));
                return Ok(Some(EvalRecordLookupV1 {
                    schema_version: "swarm-ai.eval-record-lookup.v1".to_string(),
                    record_id: run.eval_run_id.clone(),
                    record_type: EvalRecordType::Run,
                    path: path.display().to_string(),
                    manifest,
                    run: Some(run),
                    manifest_verification: None,
                    run_verification: Some(verification),
                    run_plan: plan,
                }));
            }
            _ => {}
        }
    }

    Ok(None)
}

#[derive(Debug, Clone)]
enum EvalRecordDocument {
    Manifest(EvalManifestV1),
    Run(EvalRunV1),
}

fn read_eval_record_documents(
    eval_dir: &Path,
) -> anyhow::Result<Vec<(PathBuf, EvalRecordDocument)>> {
    let mut files = Vec::new();
    collect_eval_record_files(eval_dir, &mut files)?;
    files.sort();

    let mut documents = Vec::new();
    for path in files {
        let Some(document) = read_eval_record_file(&path)? else {
            continue;
        };
        documents.push((path, document));
    }
    Ok(documents)
}

fn eval_manifest_index(
    documents: &[(PathBuf, EvalRecordDocument)],
) -> BTreeMap<String, EvalManifestV1> {
    documents
        .iter()
        .filter_map(|(_, document)| match document {
            EvalRecordDocument::Manifest(manifest) => {
                Some((manifest.eval_id.clone(), manifest.clone()))
            }
            EvalRecordDocument::Run(_) => None,
        })
        .collect()
}

fn collect_eval_record_files(eval_dir: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    if !eval_dir.exists() {
        return Ok(());
    }
    for entry in
        fs::read_dir(eval_dir).with_context(|| format!("failed to read {}", eval_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_eval_record_files(&path, files)?;
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

fn read_eval_record_file(path: &Path) -> anyhow::Result<Option<EvalRecordDocument>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let Some(schema_version) = value.get("schemaVersion").and_then(Value::as_str) else {
        return Ok(None);
    };
    match schema_version {
        "swarm-ai.eval-manifest.v1" => serde_json::from_value(value)
            .map(EvalRecordDocument::Manifest)
            .map(Some)
            .with_context(|| format!("failed to parse eval manifest {}", path.display())),
        "swarm-ai.eval-run.v1" => serde_json::from_value(value)
            .map(EvalRecordDocument::Run)
            .map(Some)
            .with_context(|| format!("failed to parse eval run {}", path.display())),
        _ => Ok(None),
    }
}

fn eval_manifest_index_entry(
    manifest: &EvalManifestV1,
    verification: &EvalManifestVerificationV1,
    mutable_ref_count: usize,
    path: String,
) -> EvalRecordSummaryV1 {
    EvalRecordSummaryV1 {
        record_id: manifest.eval_id.clone(),
        record_type: EvalRecordType::Manifest,
        eval_id: manifest.eval_id.clone(),
        eval_run_id: None,
        display_name: manifest.name.clone(),
        owner: manifest.owner.clone(),
        kind: Some(manifest.kind.clone()),
        sample_count: None,
        privacy_tier: None,
        integrity_tier: None,
        plan_available: false,
        mutable_ref_count,
        warning_count: verification.warnings.len(),
        valid: verification.valid,
        signature_present: manifest.signature.is_some(),
        created_at: manifest.created_at.clone(),
        path,
    }
}

fn eval_run_index_entry(
    run: &EvalRunV1,
    manifest: Option<&EvalManifestV1>,
    verification: &EvalRunVerificationV1,
    plan: Option<&EvalRunPlanV1>,
    path: String,
) -> EvalRecordSummaryV1 {
    EvalRecordSummaryV1 {
        record_id: run.eval_run_id.clone(),
        record_type: EvalRecordType::Run,
        eval_id: run.eval_id.clone(),
        eval_run_id: Some(run.eval_run_id.clone()),
        display_name: manifest
            .map(|manifest| format!("{} run", manifest.name))
            .unwrap_or_else(|| format!("Eval run {}", run.eval_run_id)),
        owner: run.requester.clone(),
        kind: manifest.map(|manifest| manifest.kind.clone()),
        sample_count: Some(run.sample_count),
        privacy_tier: Some(run.privacy_tier.clone()),
        integrity_tier: Some(run.integrity_tier.clone()),
        plan_available: plan.is_some(),
        mutable_ref_count: plan
            .map(|plan| plan.mutable_refs.len())
            .unwrap_or_else(|| mutable_eval_run_refs(run).len()),
        warning_count: plan
            .map(|plan| plan.warnings.len())
            .unwrap_or_else(|| verification.warnings.len()),
        valid: plan.map(|plan| plan.valid).unwrap_or(verification.valid),
        signature_present: run.signature.is_some(),
        created_at: run.created_at.clone(),
        path,
    }
}

fn mutable_eval_manifest_refs(manifest: &EvalManifestV1) -> Vec<String> {
    let mut refs = Vec::new();
    refs.extend(manifest.dataset_refs.clone());
    refs.extend(manifest.scoring_rule_refs.clone());
    refs.extend(manifest.target_refs.clone());
    if let Some(reference) = &manifest.grader_model_ref {
        refs.push(reference.clone());
    }
    if let Some(reference) = &manifest.output_schema_ref {
        refs.push(reference.clone());
    }
    mutable_refs(refs)
}

fn mutable_eval_run_refs(run: &EvalRunV1) -> Vec<String> {
    let mut refs = vec![run.target_ref.clone()];
    refs.extend(run.input_refs.clone());
    if let Some(reference) = &run.report_ref {
        refs.push(reference.clone());
    }
    mutable_refs(refs)
}

fn mutable_refs(refs: Vec<String>) -> Vec<String> {
    let mut refs: Vec<_> = refs
        .into_iter()
        .filter(|reference| looks_mutable_ref(reference))
        .collect();
    dedup(&mut refs);
    refs
}

fn eval_manifest_signing_value(manifest: &EvalManifestV1) -> Value {
    let mut value = serde_json::to_value(manifest).expect("eval manifest should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("evalId");
        object.remove("signature");
    }
    value
}

fn eval_run_signing_value(run: &EvalRunV1) -> Value {
    let mut value = serde_json::to_value(run).expect("eval run should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("evalRunId");
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

fn trim_optional_string(value: Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
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
    fn creates_signed_eval_manifest_run_and_plan() {
        let manifest = create_eval_manifest(EvalManifestInitOptionsV1 {
            name: "Regression smoke".to_string(),
            owner: "local-dev".to_string(),
            kind: Some(EvalKind::Regression),
            dataset_refs: vec!["local://datasets/regression-smoke".to_string()],
            scoring_rule_refs: vec!["local://scoring/exact-match".to_string()],
            target_refs: vec!["local://openai/models/hivemind/hello-chat".to_string()],
            grader_model_ref: None,
            output_schema_ref: None,
            metadata: Some(json!({ "suite": "smoke" })),
        });
        let run = create_eval_run(EvalRunInitOptionsV1 {
            eval_id: manifest.eval_id.clone(),
            requester: "local-dev".to_string(),
            target_ref: "local://openai/models/hivemind/hello-chat".to_string(),
            input_refs: vec!["local://datasets/regression-smoke".to_string()],
            sample_count: Some(10),
            privacy_tier: Some(PrivacyTier::NoLog),
            integrity_tier: Some(IntegrityTier::ValidatorSpotCheck),
            settlement_method: None,
            report_ref: Some("local://eval-reports/regression-smoke".to_string()),
            metadata: None,
        });
        let plan = eval_run_plan(&manifest, &run);

        assert!(verify_eval_manifest(&manifest).valid);
        assert!(verify_eval_run(&run).valid);
        assert!(plan.valid);
        assert_eq!(manifest.eval_id, canonical_eval_manifest_id(&manifest));
        assert_eq!(run.eval_run_id, canonical_eval_run_id(&run));
        assert_eq!(plan.api_surface, ApiSurface::OpenAiEvals);
        assert!(plan.immutable_refs.contains(&run.target_ref));
    }

    #[test]
    fn rejects_eval_run_without_target_and_samples() {
        let mut run = create_eval_run(EvalRunInitOptionsV1 {
            eval_id: "eval-1".to_string(),
            requester: "local-dev".to_string(),
            target_ref: String::new(),
            input_refs: Vec::new(),
            sample_count: Some(1),
            privacy_tier: None,
            integrity_tier: None,
            settlement_method: None,
            report_ref: None,
            metadata: None,
        });
        run.sample_count = 0;
        sign_eval_run(&mut run);
        let verification = verify_eval_run(&run);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.targetRef")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.sampleCount")
        );
    }

    #[test]
    fn identity_signed_eval_manifest_rejects_tamper() {
        let identity = hivemind_identity::generate_identity("local-dev").unwrap();
        let mut manifest = create_eval_manifest(EvalManifestInitOptionsV1 {
            name: "Safety eval".to_string(),
            owner: "local-dev".to_string(),
            kind: Some(EvalKind::Safety),
            dataset_refs: vec!["local://datasets/safety".to_string()],
            scoring_rule_refs: vec!["local://scoring/safety".to_string()],
            target_refs: Vec::new(),
            grader_model_ref: Some("local://openai/models/safety-grader".to_string()),
            output_schema_ref: None,
            metadata: None,
        });
        sign_eval_manifest_with_identity(&mut manifest, &identity).unwrap();
        assert!(verify_eval_manifest(&manifest).valid);

        manifest.name = "Tampered".to_string();
        let verification = verify_eval_manifest(&manifest);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path.starts_with("$.signature"))
        );
    }

    #[test]
    fn eval_record_store_lists_and_gets_manifests_and_runs() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "hivemind-eval-records-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(dir.join("runs")).unwrap();

        let manifest = create_eval_manifest(EvalManifestInitOptionsV1 {
            name: "RAG answer quality".to_string(),
            owner: "local-dev-researcher".to_string(),
            kind: Some(EvalKind::Rag),
            dataset_refs: vec!["https://example.com/datasets/rag/latest".to_string()],
            scoring_rule_refs: vec!["bzz://scoring-rag".to_string()],
            target_refs: vec!["https://example.com/models/rag/latest".to_string()],
            grader_model_ref: Some("https://example.com/models/grader/latest".to_string()),
            output_schema_ref: None,
            metadata: None,
        });
        let run = create_eval_run(EvalRunInitOptionsV1 {
            eval_id: manifest.eval_id.clone(),
            requester: "local-dev-runner".to_string(),
            target_ref: "https://example.com/models/rag/latest".to_string(),
            input_refs: vec!["bzz://eval-inputs".to_string()],
            sample_count: Some(25),
            privacy_tier: Some(PrivacyTier::NoLog),
            integrity_tier: Some(IntegrityTier::ValidatorSpotCheck),
            settlement_method: None,
            report_ref: Some("https://example.com/reports/rag/latest".to_string()),
            metadata: None,
        });

        fs::write(
            dir.join("rag.eval.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("runs").join("rag.run.json"),
            serde_json::to_vec_pretty(&run).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("runs").join("identity.json"),
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": "swarm-ai.identity-keypair.v1"
            }))
            .unwrap(),
        )
        .unwrap();

        let summary = list_eval_records(&dir).unwrap();

        assert_eq!(summary.manifest_count, 1);
        assert_eq!(summary.run_count, 1);
        assert_eq!(summary.record_count, 2);
        assert_eq!(summary.valid_count, 2);
        assert_eq!(summary.plan_available_count, 1);
        assert!(summary.mutable_ref_count >= 4);
        assert!(summary.warning_count >= 4);

        let manifest_lookup = get_eval_record(&dir, &manifest.eval_id).unwrap().unwrap();
        assert_eq!(manifest_lookup.record_type, EvalRecordType::Manifest);
        assert!(manifest_lookup.manifest.is_some());
        assert!(manifest_lookup.run.is_none());
        assert!(manifest_lookup.manifest_verification.unwrap().valid);
        assert!(manifest_lookup.run_plan.is_none());

        let run_lookup = get_eval_record(&dir, &run.eval_run_id).unwrap().unwrap();
        assert_eq!(run_lookup.record_type, EvalRecordType::Run);
        assert!(run_lookup.manifest.is_some());
        assert!(run_lookup.run.is_some());
        assert!(run_lookup.run_verification.unwrap().valid);
        assert!(run_lookup.run_plan.unwrap().valid);

        assert!(get_eval_record(&dir, "missing").unwrap().is_none());

        fs::remove_dir_all(dir).unwrap();
    }
}
