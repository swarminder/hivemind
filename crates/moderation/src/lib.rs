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

const DEV_MODERATION_POLICY_SIGNATURE_PREFIX: &str = "dev-moderation-policy-signature-v1";
const DEV_MODERATION_REQUEST_SIGNATURE_PREFIX: &str = "dev-moderation-request-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ModerationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ModerationAction {
    Allow,
    Review,
    Redact,
    Block,
    Escalate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationCategoryPolicyV1 {
    pub name: String,
    pub description: String,
    #[serde(rename = "defaultThreshold")]
    pub default_threshold: f64,
    pub severity: ModerationSeverity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationActionRuleV1 {
    pub category: String,
    #[serde(rename = "minScore")]
    pub min_score: f64,
    pub action: ModerationAction,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationAuditPolicyV1 {
    #[serde(rename = "storeSafetyEvents")]
    pub store_safety_events: bool,
    #[serde(rename = "storeInputHash")]
    pub store_input_hash: bool,
    #[serde(
        rename = "evidenceRetentionRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub evidence_retention_ref: Option<String>,
}

impl Default for ModerationAuditPolicyV1 {
    fn default() -> Self {
        Self {
            store_safety_events: true,
            store_input_hash: true,
            evidence_retention_ref: Some("local://moderation/audit/default".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationPolicyManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "policyId")]
    pub policy_id: String,
    pub name: String,
    pub publisher: String,
    pub description: String,
    pub categories: Vec<ModerationCategoryPolicyV1>,
    #[serde(rename = "actionRules")]
    pub action_rules: Vec<ModerationActionRuleV1>,
    #[serde(rename = "modelRefs", default)]
    pub model_refs: Vec<String>,
    #[serde(rename = "safetyPolicyRefs", default)]
    pub safety_policy_refs: Vec<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(rename = "auditPolicy")]
    pub audit_policy: ModerationAuditPolicyV1,
    #[serde(default)]
    pub metadata: Value,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationPolicyInitOptionsV1 {
    pub name: String,
    pub publisher: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "modelRefs", default)]
    pub model_refs: Vec<String>,
    #[serde(rename = "safetyPolicyRefs", default)]
    pub safety_policy_refs: Vec<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationPackageSelectorV1 {
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
pub struct ModerationPrivacyV1 {
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "dataRetentionRule")]
    pub data_retention_rule: DataRetentionRule,
    #[serde(rename = "loggingRule")]
    pub logging_rule: LoggingRule,
    #[serde(rename = "redactInputsInLogs")]
    pub redact_inputs_in_logs: bool,
}

impl Default for ModerationPrivacyV1 {
    fn default() -> Self {
        Self {
            privacy_tier: PrivacyTier::NoLog,
            data_retention_rule: DataRetentionRule::DeleteAfterJob,
            logging_rule: LoggingRule::NoPromptOrOutputLogs,
            redact_inputs_in_logs: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "moderationRequestId")]
    pub moderation_request_id: String,
    pub requester: String,
    #[serde(rename = "packageSelector")]
    pub package_selector: ModerationPackageSelectorV1,
    #[serde(rename = "policyRef")]
    pub policy_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
    #[serde(rename = "inputRef", default, skip_serializing_if = "Option::is_none")]
    pub input_ref: Option<String>,
    #[serde(rename = "inputHash")]
    pub input_hash: String,
    #[serde(default)]
    pub modalities: Vec<Modality>,
    #[serde(default)]
    pub categories: Vec<String>,
    pub privacy: ModerationPrivacyV1,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "traceRequired")]
    pub trace_required: bool,
    #[serde(rename = "settlementMethod")]
    pub settlement_method: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationRequestInitOptionsV1 {
    pub requester: String,
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
    #[serde(rename = "policyRef", default)]
    pub policy_ref: Option<String>,
    #[serde(default)]
    pub input: Option<Value>,
    #[serde(rename = "inputRef", default)]
    pub input_ref: Option<String>,
    #[serde(default)]
    pub modalities: Vec<Modality>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(rename = "privacyTier", default)]
    pub privacy_tier: Option<PrivacyTier>,
    #[serde(rename = "integrityTier", default)]
    pub integrity_tier: Option<IntegrityTier>,
    #[serde(rename = "traceRequired", default)]
    pub trace_required: Option<bool>,
    #[serde(rename = "settlementMethod", default)]
    pub settlement_method: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationPolicyVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "policyId")]
    pub policy_id: String,
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
pub struct ModerationRequestVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "moderationRequestId")]
    pub moderation_request_id: String,
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
pub struct ModerationCategoryThresholdV1 {
    pub category: String,
    pub threshold: f64,
    pub action: ModerationAction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationPlanRequestV1 {
    pub request: ModerationRequestV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<ModerationPolicyManifestV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationPlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "moderationRequestId")]
    pub moderation_request_id: String,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    #[serde(rename = "policyRef")]
    pub policy_ref: String,
    #[serde(rename = "inputRef", default, skip_serializing_if = "Option::is_none")]
    pub input_ref: Option<String>,
    #[serde(rename = "inputHash")]
    pub input_hash: String,
    pub modalities: Vec<Modality>,
    pub categories: Vec<String>,
    pub thresholds: Vec<ModerationCategoryThresholdV1>,
    #[serde(rename = "actionRules")]
    pub action_rules: Vec<ModerationActionRuleV1>,
    #[serde(rename = "immutableRefs")]
    pub immutable_refs: Vec<String>,
    #[serde(rename = "mutableRefs")]
    pub mutable_refs: Vec<String>,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "traceRequired")]
    pub trace_required: bool,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ModerationRecordType {
    Policy,
    Request,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationRecordSummaryV1 {
    #[serde(rename = "recordId")]
    pub record_id: String,
    #[serde(rename = "recordType")]
    pub record_type: ModerationRecordType,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub owner: String,
    #[serde(rename = "categoryCount")]
    pub category_count: usize,
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
    #[serde(
        rename = "traceRequired",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub trace_required: Option<bool>,
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
pub struct ModerationRecordStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "policyCount")]
    pub policy_count: usize,
    #[serde(rename = "requestCount")]
    pub request_count: usize,
    #[serde(rename = "recordCount")]
    pub record_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "traceRequiredCount")]
    pub trace_required_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub records: Vec<ModerationRecordSummaryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ModerationRecordLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "recordId")]
    pub record_id: String,
    #[serde(rename = "recordType")]
    pub record_type: ModerationRecordType,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<ModerationPolicyManifestV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<ModerationRequestV1>,
    #[serde(
        rename = "policyVerification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub policy_verification: Option<ModerationPolicyVerificationV1>,
    #[serde(
        rename = "requestVerification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_verification: Option<ModerationRequestVerificationV1>,
    #[serde(
        rename = "moderationPlan",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub moderation_plan: Option<ModerationPlanV1>,
}

pub fn create_moderation_policy(
    options: ModerationPolicyInitOptionsV1,
) -> ModerationPolicyManifestV1 {
    let mut model_refs = options.model_refs;
    dedup(&mut model_refs);
    let mut safety_policy_refs = options.safety_policy_refs;
    dedup(&mut safety_policy_refs);
    let mut evidence_refs = options.evidence_refs;
    dedup(&mut evidence_refs);

    let categories = default_categories();
    let action_rules = categories
        .iter()
        .map(|category| ModerationActionRuleV1 {
            category: category.name.clone(),
            min_score: category.default_threshold,
            action: action_for_severity(&category.severity),
            reason: format!("Default {} moderation policy", category.name),
        })
        .collect();

    let mut policy = ModerationPolicyManifestV1 {
        schema_version: "swarm-ai.moderation-policy.v1".to_string(),
        policy_id: String::new(),
        name: options.name,
        publisher: options.publisher,
        description: options.description.unwrap_or_else(|| {
            "Default signed moderation policy for decentralized safety classification".to_string()
        }),
        categories,
        action_rules,
        model_refs,
        safety_policy_refs,
        evidence_refs,
        audit_policy: ModerationAuditPolicyV1::default(),
        metadata: json!({}),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_moderation_policy(&mut policy);
    policy
}

pub fn sign_moderation_policy(policy: &mut ModerationPolicyManifestV1) {
    policy.signature = Some(expected_moderation_policy_signature(policy));
    policy.policy_id = canonical_moderation_policy_id(policy);
}

pub fn sign_moderation_policy_with_identity(
    policy: &mut ModerationPolicyManifestV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != policy.publisher {
        anyhow::bail!(
            "identity subject {} does not match moderation policy publisher {}",
            identity.subject,
            policy.publisher
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "moderation-policy",
        &moderation_policy_signing_value(policy),
    )?;
    policy.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    policy.policy_id = canonical_moderation_policy_id(policy);
    Ok(envelope)
}

pub fn expected_moderation_policy_signature(policy: &ModerationPolicyManifestV1) -> String {
    format!(
        "{DEV_MODERATION_POLICY_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&moderation_policy_signing_value(policy)))
    )
}

pub fn canonical_moderation_policy_id(policy: &ModerationPolicyManifestV1) -> String {
    stable_id(
        "moderation-policy",
        &moderation_policy_signing_value(policy),
    )
}

pub fn verify_moderation_policy(
    policy: &ModerationPolicyManifestV1,
) -> ModerationPolicyVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_moderation_policy_signature(policy));
    let signature = policy
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if policy.schema_version != "swarm-ai.moderation-policy.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.moderation-policy.v1",
        ));
    }
    require_non_empty(&mut issues, "$.policyId", &policy.policy_id);
    if !policy.policy_id.is_empty() && policy.policy_id != canonical_moderation_policy_id(policy) {
        issues.push(issue(
            "$.policyId",
            "Moderation policy id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.name", &policy.name);
    require_non_empty(&mut issues, "$.publisher", &policy.publisher);
    if policy.categories.is_empty() {
        issues.push(issue(
            "$.categories",
            "Moderation policy must declare at least one category",
        ));
    }
    validate_categories(&policy.categories, &mut issues);
    validate_action_rules(
        &policy.action_rules,
        &policy.categories,
        &mut issues,
        &mut warnings,
    );
    validate_audit_policy(&policy.audit_policy, &mut issues, &mut warnings);
    for (path, reference) in moderation_policy_refs(policy) {
        validate_ref(path, &reference, &mut issues, &mut warnings);
    }
    validate_created_at(&policy.created_at, "$.createdAt", &mut issues);
    verify_signature(
        signature,
        "moderation-policy",
        &moderation_policy_signing_value(policy),
        &policy.publisher,
        &mut expected_signature,
        &mut issues,
        "Moderation policy signature does not match canonical dev signature or Ed25519 publisher identity envelope",
    );
    if signature.is_none() {
        warnings.push(issue(
            "$.signature",
            "Moderation policy is unsigned; verify publisher and policyId through a trusted source",
        ));
    }

    ModerationPolicyVerificationV1 {
        schema_version: "swarm-ai.moderation-policy-verification.v1".to_string(),
        policy_id: policy.policy_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn create_moderation_request(options: ModerationRequestInitOptionsV1) -> ModerationRequestV1 {
    let mut modalities = if options.modalities.is_empty() {
        vec![Modality::Text]
    } else {
        options.modalities
    };
    dedup_modalities(&mut modalities);
    let mut categories = options.categories;
    if categories.is_empty() {
        categories = default_category_names();
    }
    dedup(&mut categories);
    let input_hash = input_hash(options.input.as_ref(), options.input_ref.as_deref());

    let mut request = ModerationRequestV1 {
        schema_version: "swarm-ai.moderation-request.v1".to_string(),
        moderation_request_id: String::new(),
        requester: options.requester,
        package_selector: ModerationPackageSelectorV1 {
            package_ref: options.package_ref,
            package_id: options.package_id,
            package_version: options.package_version,
            service_ref: options.service_ref,
            model_alias: options.model_alias,
        },
        policy_ref: options
            .policy_ref
            .unwrap_or_else(|| "local://moderation/policy/default".to_string()),
        input: options.input,
        input_ref: options.input_ref,
        input_hash,
        modalities,
        categories,
        privacy: ModerationPrivacyV1 {
            privacy_tier: options.privacy_tier.unwrap_or(PrivacyTier::NoLog),
            ..ModerationPrivacyV1::default()
        },
        integrity_tier: options.integrity_tier.unwrap_or(IntegrityTier::ReceiptOnly),
        trace_required: options.trace_required.unwrap_or(true),
        settlement_method: options
            .settlement_method
            .unwrap_or_else(|| "free-local-dev".to_string()),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_moderation_request(&mut request);
    request
}

pub fn sign_moderation_request(request: &mut ModerationRequestV1) {
    request.input_hash = input_hash(request.input.as_ref(), request.input_ref.as_deref());
    request.signature = Some(expected_moderation_request_signature(request));
    request.moderation_request_id = canonical_moderation_request_id(request);
}

pub fn sign_moderation_request_with_identity(
    request: &mut ModerationRequestV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != request.requester {
        anyhow::bail!(
            "identity subject {} does not match moderation requester {}",
            identity.subject,
            request.requester
        );
    }
    request.input_hash = input_hash(request.input.as_ref(), request.input_ref.as_deref());
    let envelope = hivemind_identity::sign_value(
        identity,
        "moderation-request",
        &moderation_request_signing_value(request),
    )?;
    request.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    request.moderation_request_id = canonical_moderation_request_id(request);
    Ok(envelope)
}

pub fn expected_moderation_request_signature(request: &ModerationRequestV1) -> String {
    format!(
        "{DEV_MODERATION_REQUEST_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&moderation_request_signing_value(
            request
        )))
    )
}

pub fn canonical_moderation_request_id(request: &ModerationRequestV1) -> String {
    stable_id(
        "moderation-request",
        &moderation_request_signing_value(request),
    )
}

pub fn verify_moderation_request(request: &ModerationRequestV1) -> ModerationRequestVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_moderation_request_signature(request));
    let signature = request
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if request.schema_version != "swarm-ai.moderation-request.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.moderation-request.v1",
        ));
    }
    require_non_empty(
        &mut issues,
        "$.moderationRequestId",
        &request.moderation_request_id,
    );
    if !request.moderation_request_id.is_empty()
        && request.moderation_request_id != canonical_moderation_request_id(request)
    {
        issues.push(issue(
            "$.moderationRequestId",
            "Moderation request id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.requester", &request.requester);
    validate_selector(&request.package_selector, &mut issues, &mut warnings);
    validate_ref(
        "$.policyRef".to_string(),
        &request.policy_ref,
        &mut issues,
        &mut warnings,
    );
    validate_request_input(request, &mut issues, &mut warnings);
    validate_modalities(&request.modalities, &mut issues, &mut warnings);
    validate_category_names(&request.categories, "$.categories", &mut issues);
    validate_created_at(&request.created_at, "$.createdAt", &mut issues);
    verify_signature(
        signature,
        "moderation-request",
        &moderation_request_signing_value(request),
        &request.requester,
        &mut expected_signature,
        &mut issues,
        "Moderation request signature does not match canonical dev signature or Ed25519 requester identity envelope",
    );
    if signature.is_none() {
        warnings.push(issue(
            "$.signature",
            "Moderation request is unsigned; verify requester and moderationRequestId through a trusted source",
        ));
    }

    ModerationRequestVerificationV1 {
        schema_version: "swarm-ai.moderation-request-verification.v1".to_string(),
        moderation_request_id: request.moderation_request_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn moderation_plan(request: &ModerationRequestV1) -> ModerationPlanV1 {
    moderation_plan_with_policy(request, None)
}

pub fn moderation_plan_with_policy(
    request: &ModerationRequestV1,
    policy: Option<&ModerationPolicyManifestV1>,
) -> ModerationPlanV1 {
    let request_verification = verify_moderation_request(request);
    let mut issues = request_verification.issues;
    let mut warnings = request_verification.warnings;
    let policy_verification = policy.map(verify_moderation_policy);
    if let Some(verification) = &policy_verification {
        for policy_issue in &verification.issues {
            issues.push(issue(
                format!("$.policy{}", policy_issue.path.trim_start_matches('$')),
                policy_issue.message.clone(),
            ));
        }
        for policy_warning in &verification.warnings {
            warnings.push(issue(
                format!("$.policy{}", policy_warning.path.trim_start_matches('$')),
                policy_warning.message.clone(),
            ));
        }
    }

    let categories = plan_categories(request, policy);
    let thresholds = plan_thresholds(&categories, policy);
    let action_rules = policy
        .map(|policy| policy.action_rules.clone())
        .unwrap_or_else(|| default_action_rules(&categories));
    let mut immutable_refs = Vec::new();
    let mut mutable_refs = Vec::new();
    for (_, reference) in moderation_plan_refs(request, policy) {
        if looks_mutable_ref(&reference) {
            mutable_refs.push(reference);
        } else {
            immutable_refs.push(reference);
        }
    }
    dedup(&mut immutable_refs);
    dedup(&mut mutable_refs);

    ModerationPlanV1 {
        schema_version: "swarm-ai.moderation-plan.v1".to_string(),
        moderation_request_id: request.moderation_request_id.clone(),
        api_surface: ApiSurface::Moderation,
        policy_ref: request.policy_ref.clone(),
        input_ref: request.input_ref.clone(),
        input_hash: request.input_hash.clone(),
        modalities: request.modalities.clone(),
        categories,
        thresholds,
        action_rules,
        immutable_refs,
        mutable_refs,
        privacy_tier: request.privacy.privacy_tier.clone(),
        integrity_tier: request.integrity_tier.clone(),
        trace_required: request.trace_required,
        settlement_method: request.settlement_method.clone(),
        allowed_event_types: vec![
            StreamingEventType::Started,
            StreamingEventType::SafetyEvent,
            StreamingEventType::PartialReceipt,
            StreamingEventType::Completed,
            StreamingEventType::Error,
        ],
        metadata: json!({
            "executionLayer": "browser-local-remote-or-miner-runner",
            "storageLayer": "Swarm/Bee stores moderation policy packages, input refs, evidence refs, receipts, and audit records; classification execution is runner-side.",
            "openAiCompatibility": {
                "endpoint": "/v1/moderations",
                "nativeObject": "ModerationRequestV1"
            },
            "policyVerification": policy_verification,
        }),
        valid: issues.is_empty(),
        issues,
        warnings,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn moderation_plan_from_request(request: &ModerationPlanRequestV1) -> ModerationPlanV1 {
    moderation_plan_with_policy(&request.request, request.policy.as_ref())
}

pub fn list_moderation_records(
    moderation_dir: &Path,
) -> anyhow::Result<ModerationRecordStoreSummaryV1> {
    let mut files = Vec::new();
    collect_moderation_record_files(moderation_dir, &mut files)?;
    files.sort();

    let mut records = Vec::new();
    let mut policy_count = 0;
    let mut request_count = 0;
    let mut valid_count = 0;
    let mut trace_required_count = 0;
    let mut mutable_ref_count = 0;
    let mut warning_count = 0;

    for path in files {
        let Some(document) = read_moderation_record_file(&path)? else {
            continue;
        };
        let path_string = path.display().to_string();
        match document {
            ModerationRecordDocument::Policy(policy) => {
                let verification = verify_moderation_policy(&policy);
                let mutable_refs = mutable_moderation_policy_refs(&policy);
                if verification.valid {
                    valid_count += 1;
                }
                policy_count += 1;
                mutable_ref_count += mutable_refs.len();
                warning_count += verification.warnings.len();
                records.push(moderation_policy_index_entry(
                    &policy,
                    &verification,
                    mutable_refs.len(),
                    path_string,
                ));
            }
            ModerationRecordDocument::Request(request) => {
                let verification = verify_moderation_request(&request);
                let plan = moderation_plan(&request);
                if plan.valid {
                    valid_count += 1;
                }
                if request.trace_required {
                    trace_required_count += 1;
                }
                request_count += 1;
                mutable_ref_count += plan.mutable_refs.len();
                warning_count += plan.warnings.len();
                records.push(moderation_request_index_entry(
                    &request,
                    &verification,
                    &plan,
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

    Ok(ModerationRecordStoreSummaryV1 {
        schema_version: "swarm-ai.moderation-record-store-summary.v1".to_string(),
        root: moderation_dir.display().to_string(),
        policy_count,
        request_count,
        record_count: records.len(),
        valid_count,
        invalid_count: records.len().saturating_sub(valid_count),
        trace_required_count,
        mutable_ref_count,
        warning_count,
        records,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn get_moderation_record(
    moderation_dir: &Path,
    record_id: &str,
) -> anyhow::Result<Option<ModerationRecordLookupV1>> {
    let record_id = record_id.trim();
    if record_id.is_empty() {
        anyhow::bail!("recordId is required");
    }

    let mut files = Vec::new();
    collect_moderation_record_files(moderation_dir, &mut files)?;
    files.sort();

    for path in files {
        let Some(document) = read_moderation_record_file(&path)? else {
            continue;
        };
        match document {
            ModerationRecordDocument::Policy(policy) if policy.policy_id == record_id => {
                let verification = verify_moderation_policy(&policy);
                return Ok(Some(ModerationRecordLookupV1 {
                    schema_version: "swarm-ai.moderation-record-lookup.v1".to_string(),
                    record_id: policy.policy_id.clone(),
                    record_type: ModerationRecordType::Policy,
                    path: path.display().to_string(),
                    policy: Some(policy),
                    request: None,
                    policy_verification: Some(verification),
                    request_verification: None,
                    moderation_plan: None,
                }));
            }
            ModerationRecordDocument::Request(request)
                if request.moderation_request_id == record_id =>
            {
                let verification = verify_moderation_request(&request);
                let plan = moderation_plan(&request);
                return Ok(Some(ModerationRecordLookupV1 {
                    schema_version: "swarm-ai.moderation-record-lookup.v1".to_string(),
                    record_id: request.moderation_request_id.clone(),
                    record_type: ModerationRecordType::Request,
                    path: path.display().to_string(),
                    policy: None,
                    request: Some(request),
                    policy_verification: None,
                    request_verification: Some(verification),
                    moderation_plan: Some(plan),
                }));
            }
            _ => {}
        }
    }

    Ok(None)
}

enum ModerationRecordDocument {
    Policy(ModerationPolicyManifestV1),
    Request(ModerationRequestV1),
}

fn collect_moderation_record_files(
    moderation_dir: &Path,
    files: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    if !moderation_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(moderation_dir)
        .with_context(|| format!("failed to read {}", moderation_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_moderation_record_files(&path, files)?;
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

fn read_moderation_record_file(path: &Path) -> anyhow::Result<Option<ModerationRecordDocument>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let Some(schema_version) = value.get("schemaVersion").and_then(Value::as_str) else {
        return Ok(None);
    };
    match schema_version {
        "swarm-ai.moderation-policy.v1" => serde_json::from_value(value)
            .map(ModerationRecordDocument::Policy)
            .map(Some)
            .with_context(|| format!("failed to parse moderation policy {}", path.display())),
        "swarm-ai.moderation-request.v1" => serde_json::from_value(value)
            .map(ModerationRecordDocument::Request)
            .map(Some)
            .with_context(|| format!("failed to parse moderation request {}", path.display())),
        _ => Ok(None),
    }
}

fn moderation_policy_index_entry(
    policy: &ModerationPolicyManifestV1,
    verification: &ModerationPolicyVerificationV1,
    mutable_ref_count: usize,
    path: String,
) -> ModerationRecordSummaryV1 {
    ModerationRecordSummaryV1 {
        record_id: policy.policy_id.clone(),
        record_type: ModerationRecordType::Policy,
        display_name: policy.name.clone(),
        owner: policy.publisher.clone(),
        category_count: policy.categories.len(),
        privacy_tier: None,
        integrity_tier: None,
        trace_required: None,
        mutable_ref_count,
        warning_count: verification.warnings.len(),
        valid: verification.valid,
        signature_present: policy.signature.is_some(),
        created_at: policy.created_at.clone(),
        path,
    }
}

fn moderation_request_index_entry(
    request: &ModerationRequestV1,
    verification: &ModerationRequestVerificationV1,
    plan: &ModerationPlanV1,
    path: String,
) -> ModerationRecordSummaryV1 {
    ModerationRecordSummaryV1 {
        record_id: request.moderation_request_id.clone(),
        record_type: ModerationRecordType::Request,
        display_name: format!("Moderation request {}", request.moderation_request_id),
        owner: request.requester.clone(),
        category_count: plan.categories.len(),
        privacy_tier: Some(request.privacy.privacy_tier.clone()),
        integrity_tier: Some(request.integrity_tier.clone()),
        trace_required: Some(request.trace_required),
        mutable_ref_count: plan.mutable_refs.len(),
        warning_count: plan.warnings.len(),
        valid: verification.valid && plan.valid,
        signature_present: request.signature.is_some(),
        created_at: request.created_at.clone(),
        path,
    }
}

fn mutable_moderation_policy_refs(policy: &ModerationPolicyManifestV1) -> Vec<String> {
    let mut refs: Vec<_> = moderation_policy_refs(policy)
        .into_iter()
        .filter_map(|(_, reference)| looks_mutable_ref(&reference).then_some(reference))
        .collect();
    if let Some(reference) = &policy.audit_policy.evidence_retention_ref {
        if looks_mutable_ref(reference) {
            refs.push(reference.clone());
        }
    }
    dedup(&mut refs);
    refs
}

fn default_categories() -> Vec<ModerationCategoryPolicyV1> {
    vec![
        category(
            "hate",
            "Hateful or abusive content toward protected groups",
            0.50,
            ModerationSeverity::High,
        ),
        category(
            "harassment",
            "Targeted harassment, bullying, or threats",
            0.50,
            ModerationSeverity::High,
        ),
        category(
            "self-harm",
            "Self-harm intent, ideation, or instructions",
            0.35,
            ModerationSeverity::Critical,
        ),
        category(
            "sexual",
            "Sexual content requiring policy handling",
            0.60,
            ModerationSeverity::Medium,
        ),
        category(
            "violence",
            "Violent content or violent instructions",
            0.55,
            ModerationSeverity::High,
        ),
        category(
            "illicit",
            "Illicit behavior, evasion, or abuse enablement",
            0.50,
            ModerationSeverity::High,
        ),
        category(
            "privacy",
            "Personal data exposure or privacy-sensitive content",
            0.45,
            ModerationSeverity::High,
        ),
        category(
            "spam",
            "Spam, scam, or deceptive bulk content",
            0.65,
            ModerationSeverity::Medium,
        ),
    ]
}

fn category(
    name: &'static str,
    description: &'static str,
    default_threshold: f64,
    severity: ModerationSeverity,
) -> ModerationCategoryPolicyV1 {
    ModerationCategoryPolicyV1 {
        name: name.to_string(),
        description: description.to_string(),
        default_threshold,
        severity,
    }
}

fn default_category_names() -> Vec<String> {
    default_categories()
        .into_iter()
        .map(|category| category.name)
        .collect()
}

fn default_action_rules(categories: &[String]) -> Vec<ModerationActionRuleV1> {
    categories
        .iter()
        .map(|category| ModerationActionRuleV1 {
            category: category.clone(),
            min_score: 0.50,
            action: ModerationAction::Review,
            reason: "Default review threshold without an attached policy manifest".to_string(),
        })
        .collect()
}

fn action_for_severity(severity: &ModerationSeverity) -> ModerationAction {
    match severity {
        ModerationSeverity::Low => ModerationAction::Allow,
        ModerationSeverity::Medium => ModerationAction::Review,
        ModerationSeverity::High => ModerationAction::Block,
        ModerationSeverity::Critical => ModerationAction::Escalate,
    }
}

fn plan_categories(
    request: &ModerationRequestV1,
    policy: Option<&ModerationPolicyManifestV1>,
) -> Vec<String> {
    let mut categories = if request.categories.is_empty() {
        policy
            .map(|policy| {
                policy
                    .categories
                    .iter()
                    .map(|category| category.name.clone())
                    .collect()
            })
            .unwrap_or_else(default_category_names)
    } else {
        request.categories.clone()
    };
    dedup(&mut categories);
    categories
}

fn plan_thresholds(
    categories: &[String],
    policy: Option<&ModerationPolicyManifestV1>,
) -> Vec<ModerationCategoryThresholdV1> {
    categories
        .iter()
        .map(|category| {
            let policy_category = policy.and_then(|policy| {
                policy
                    .categories
                    .iter()
                    .find(|policy_category| policy_category.name == *category)
            });
            ModerationCategoryThresholdV1 {
                category: category.clone(),
                threshold: policy_category
                    .map(|policy_category| policy_category.default_threshold)
                    .unwrap_or(0.50),
                action: policy_category
                    .map(|policy_category| action_for_severity(&policy_category.severity))
                    .unwrap_or(ModerationAction::Review),
            }
        })
        .collect()
}

fn validate_categories(
    categories: &[ModerationCategoryPolicyV1],
    issues: &mut Vec<ValidationIssue>,
) {
    let mut names = BTreeSet::new();
    for (index, category) in categories.iter().enumerate() {
        let path = format!("$.categories[{index}]");
        if category.name.trim().is_empty() {
            issues.push(issue(format!("{path}.name"), "Category name is required"));
        } else if !names.insert(category.name.clone()) {
            issues.push(issue(
                format!("{path}.name"),
                "Category names must be unique",
            ));
        }
        if category.description.trim().is_empty() {
            issues.push(issue(
                format!("{path}.description"),
                "Category description is required",
            ));
        }
        validate_score(
            category.default_threshold,
            format!("{path}.defaultThreshold"),
            issues,
        );
    }
}

fn validate_action_rules(
    rules: &[ModerationActionRuleV1],
    categories: &[ModerationCategoryPolicyV1],
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    let category_names: BTreeSet<_> = categories
        .iter()
        .map(|category| category.name.as_str())
        .collect();
    for (index, rule) in rules.iter().enumerate() {
        let path = format!("$.actionRules[{index}]");
        if rule.category.trim().is_empty() {
            issues.push(issue(
                format!("{path}.category"),
                "Rule category is required",
            ));
        } else if !category_names.contains(rule.category.as_str()) {
            warnings.push(issue(
                format!("{path}.category"),
                "Rule category is not declared in categories",
            ));
        }
        validate_score(rule.min_score, format!("{path}.minScore"), issues);
        if rule.reason.trim().is_empty() {
            warnings.push(issue(
                format!("{path}.reason"),
                "Action rules should explain why the action applies",
            ));
        }
    }
}

fn validate_audit_policy(
    policy: &ModerationAuditPolicyV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if !policy.store_input_hash && policy.evidence_retention_ref.is_none() {
        warnings.push(issue(
            "$.auditPolicy",
            "Moderation audit policy stores neither input hashes nor an evidence retention ref",
        ));
    }
    if let Some(reference) = &policy.evidence_retention_ref {
        validate_ref(
            "$.auditPolicy.evidenceRetentionRef".to_string(),
            reference,
            issues,
            warnings,
        );
    }
}

fn validate_selector(
    selector: &ModerationPackageSelectorV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    let has_selector = selector
        .package_ref
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        || selector
            .package_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || selector
            .service_ref
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || selector
            .model_alias
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
    if !has_selector {
        issues.push(issue(
            "$.packageSelector",
            "Moderation request must include a packageRef, serviceRef, packageId, or modelAlias",
        ));
    }
    if let Some(reference) = &selector.package_ref {
        validate_ref(
            "$.packageSelector.packageRef".to_string(),
            reference,
            issues,
            warnings,
        );
    }
    if let Some(reference) = &selector.service_ref {
        validate_ref(
            "$.packageSelector.serviceRef".to_string(),
            reference,
            issues,
            warnings,
        );
    }
}

fn validate_request_input(
    request: &ModerationRequestV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    let has_inline_input = request.input.as_ref().is_some_and(|input| !input.is_null());
    let has_input_ref = request
        .input_ref
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    if !has_inline_input && !has_input_ref {
        issues.push(issue(
            "$.input",
            "Moderation request must include inline input or inputRef",
        ));
    }
    if let Some(input_ref) = &request.input_ref {
        validate_ref("$.inputRef".to_string(), input_ref, issues, warnings);
    }
    if let Some(input) = &request.input {
        let bytes = serde_json::to_vec(input).unwrap_or_default().len();
        if bytes > 64 * 1024 {
            warnings.push(issue(
                "$.input",
                "Large moderation inputs should be stored through Swarm/Bee and referenced with inputRef",
            ));
        }
    }
    let expected_hash = input_hash(request.input.as_ref(), request.input_ref.as_deref());
    if request.input_hash != expected_hash {
        issues.push(issue(
            "$.inputHash",
            "inputHash does not match inline input/inputRef",
        ));
    }
}

fn validate_modalities(
    modalities: &[Modality],
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if modalities.is_empty() {
        issues.push(issue(
            "$.modalities",
            "Moderation request must declare at least one modality",
        ));
    }
    for (index, modality) in modalities.iter().enumerate() {
        if matches!(
            modality,
            Modality::TrainingData | Modality::EvaluationData | Modality::VectorSearch
        ) {
            warnings.push(issue(
                format!("$.modalities[{index}]"),
                "This modality is unusual for direct moderation; verify the request mapping",
            ));
        }
    }
}

fn validate_category_names(
    categories: &[String],
    path: &'static str,
    issues: &mut Vec<ValidationIssue>,
) {
    let mut names = BTreeSet::new();
    for (index, category) in categories.iter().enumerate() {
        if category.trim().is_empty() {
            issues.push(issue(
                format!("{path}[{index}]"),
                "Category name must not be empty",
            ));
        } else if !names.insert(category.clone()) {
            issues.push(issue(
                format!("{path}[{index}]"),
                "Category names must be unique",
            ));
        }
    }
}

fn validate_score(score: f64, path: String, issues: &mut Vec<ValidationIssue>) {
    if !(0.0..=1.0).contains(&score) {
        issues.push(issue(path, "Score threshold must be between 0.0 and 1.0"));
    }
}

fn moderation_policy_refs(policy: &ModerationPolicyManifestV1) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    for (index, reference) in policy.model_refs.iter().enumerate() {
        refs.push((format!("$.modelRefs[{index}]"), reference.clone()));
    }
    for (index, reference) in policy.safety_policy_refs.iter().enumerate() {
        refs.push((format!("$.safetyPolicyRefs[{index}]"), reference.clone()));
    }
    for (index, reference) in policy.evidence_refs.iter().enumerate() {
        refs.push((format!("$.evidenceRefs[{index}]"), reference.clone()));
    }
    refs
}

fn moderation_plan_refs(
    request: &ModerationRequestV1,
    policy: Option<&ModerationPolicyManifestV1>,
) -> Vec<(String, String)> {
    let mut refs = vec![("$.policyRef".to_string(), request.policy_ref.clone())];
    if let Some(input_ref) = &request.input_ref {
        refs.push(("$.inputRef".to_string(), input_ref.clone()));
    }
    if let Some(package_ref) = &request.package_selector.package_ref {
        refs.push((
            "$.packageSelector.packageRef".to_string(),
            package_ref.clone(),
        ));
    }
    if let Some(service_ref) = &request.package_selector.service_ref {
        refs.push((
            "$.packageSelector.serviceRef".to_string(),
            service_ref.clone(),
        ));
    }
    if let Some(policy) = policy {
        refs.extend(moderation_policy_refs(policy));
    }
    refs
}

fn input_hash(input: Option<&Value>, input_ref: Option<&str>) -> String {
    if let Some(input) = input {
        return hash_canonical_json(&canonicalize_json(input));
    }
    if let Some(input_ref) = input_ref {
        return hash_canonical_json(&canonicalize_json(&json!({ "inputRef": input_ref })));
    }
    hash_canonical_json(&canonicalize_json(&json!(null)))
}

fn moderation_policy_signing_value(policy: &ModerationPolicyManifestV1) -> Value {
    let mut value = serde_json::to_value(policy).expect("moderation policy should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("policyId");
        object.remove("signature");
    }
    value
}

fn moderation_request_signing_value(request: &ModerationRequestV1) -> Value {
    let mut value = serde_json::to_value(request).expect("moderation request should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("moderationRequestId");
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

fn dedup_modalities(values: &mut Vec<Modality>) {
    let mut seen = BTreeSet::new();
    values.retain(|value| {
        let key = serde_json::to_string(value).unwrap_or_default();
        seen.insert(key)
    });
}

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("moderation object should serialize");
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
    fn creates_signed_policy_request_and_plan() {
        let policy = moderation_policy();
        let request = moderation_request();
        let policy_verification = verify_moderation_policy(&policy);
        let request_verification = verify_moderation_request(&request);
        let plan = moderation_plan_with_policy(&request, Some(&policy));

        assert!(policy_verification.valid, "{policy_verification:#?}");
        assert!(request_verification.valid, "{request_verification:#?}");
        assert_eq!(
            policy.signature.as_deref(),
            Some(expected_moderation_policy_signature(&policy).as_str())
        );
        assert_eq!(
            request.signature.as_deref(),
            Some(expected_moderation_request_signature(&request).as_str())
        );
        assert!(policy.policy_id.starts_with("moderation-policy-"));
        assert!(
            request
                .moderation_request_id
                .starts_with("moderation-request-")
        );
        assert_eq!(plan.api_surface, ApiSurface::Moderation);
        assert!(plan.valid, "{plan:#?}");
        assert_eq!(plan.privacy_tier, PrivacyTier::NoLog);
        assert!(
            plan.allowed_event_types
                .contains(&StreamingEventType::SafetyEvent)
        );
        assert!(
            plan.immutable_refs
                .contains(&"bzz://moderation-policy".to_string())
        );
    }

    #[test]
    fn identity_signed_request_verifies_and_detects_tampering() {
        let mut request = moderation_request();
        let identity =
            hivemind_identity::identity_from_seed("0xRequester", b"moderation-seed").unwrap();

        let envelope = sign_moderation_request_with_identity(&mut request, &identity).unwrap();
        let verification = verify_moderation_request(&request);

        assert_eq!(envelope.signer, request.requester);
        assert!(verification.valid, "{verification:#?}");

        request.input = Some(json!("changed"));
        let tampered = verify_moderation_request(&request);
        assert!(!tampered.valid);
        assert!(tampered.issues.iter().any(|issue| {
            issue.path == "$.moderationRequestId"
                || issue.path == "$.inputHash"
                || issue.path == "$.signature.payloadHash"
        }));
    }

    #[test]
    fn rejects_missing_request_selector_and_input() {
        let mut request = moderation_request();
        request.package_selector = ModerationPackageSelectorV1 {
            package_ref: None,
            package_id: None,
            package_version: None,
            service_ref: None,
            model_alias: None,
        };
        request.input = None;
        request.input_ref = None;
        sign_moderation_request(&mut request);

        let verification = verify_moderation_request(&request);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.packageSelector")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.input")
        );
    }

    #[test]
    fn rejects_invalid_policy_thresholds() {
        let mut policy = moderation_policy();
        policy.categories[0].default_threshold = 1.5;
        sign_moderation_policy(&mut policy);

        let verification = verify_moderation_policy(&policy);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.categories[0].defaultThreshold")
        );
    }

    #[test]
    fn moderation_record_store_lists_and_gets_policies_and_requests() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "hivemind-moderation-records-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(dir.join("nested")).unwrap();

        let mut policy = moderation_policy();
        policy.model_refs = vec!["https://example.com/moderation/latest".to_string()];
        sign_moderation_policy(&mut policy);

        let mut request = moderation_request();
        request.package_selector.package_ref =
            Some("https://example.com/moderation/latest".to_string());
        request.policy_ref = "https://example.com/policies/moderation/latest".to_string();
        sign_moderation_request(&mut request);

        fs::write(
            dir.join("default.policy.json"),
            serde_json::to_vec_pretty(&policy).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("nested").join("classify.request.json"),
            serde_json::to_vec_pretty(&request).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("nested").join("identity.json"),
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": "swarm-ai.identity-keypair.v1"
            }))
            .unwrap(),
        )
        .unwrap();

        let summary = list_moderation_records(&dir).unwrap();

        assert_eq!(summary.policy_count, 1);
        assert_eq!(summary.request_count, 1);
        assert_eq!(summary.record_count, 2);
        assert_eq!(summary.valid_count, 2);
        assert_eq!(summary.trace_required_count, 1);
        assert!(summary.mutable_ref_count >= 3);
        assert!(summary.warning_count >= 3);
        assert!(summary.records.iter().any(|record| {
            record.record_id == policy.policy_id
                && record.record_type == ModerationRecordType::Policy
                && record.signature_present
        }));
        assert!(summary.records.iter().any(|record| {
            record.record_id == request.moderation_request_id
                && record.record_type == ModerationRecordType::Request
                && record.trace_required == Some(true)
        }));

        let policy_lookup = get_moderation_record(&dir, &policy.policy_id)
            .unwrap()
            .unwrap();
        assert_eq!(policy_lookup.record_type, ModerationRecordType::Policy);
        assert!(policy_lookup.policy.is_some());
        assert!(policy_lookup.request.is_none());
        assert!(policy_lookup.policy_verification.unwrap().valid);
        assert!(policy_lookup.moderation_plan.is_none());

        let request_lookup = get_moderation_record(&dir, &request.moderation_request_id)
            .unwrap()
            .unwrap();
        assert_eq!(request_lookup.record_type, ModerationRecordType::Request);
        assert!(request_lookup.request.is_some());
        assert!(request_lookup.request_verification.unwrap().valid);
        assert!(request_lookup.moderation_plan.unwrap().valid);

        assert!(get_moderation_record(&dir, "missing").unwrap().is_none());

        fs::remove_dir_all(dir).unwrap();
    }

    fn moderation_policy() -> ModerationPolicyManifestV1 {
        create_moderation_policy(ModerationPolicyInitOptionsV1 {
            name: "Default Moderation".to_string(),
            publisher: "0xPublisher".to_string(),
            description: Some("Policy for smoke tests".to_string()),
            model_refs: vec!["bzz://moderation-model".to_string()],
            safety_policy_refs: vec!["bzz://safety-policy".to_string()],
            evidence_refs: vec!["bzz://policy-evidence".to_string()],
        })
    }

    fn moderation_request() -> ModerationRequestV1 {
        create_moderation_request(ModerationRequestInitOptionsV1 {
            requester: "0xRequester".to_string(),
            package_ref: Some("bzz://moderation-model".to_string()),
            package_id: Some("hivemind/moderation".to_string()),
            package_version: Some("0.1.0".to_string()),
            service_ref: None,
            model_alias: None,
            policy_ref: Some("bzz://moderation-policy".to_string()),
            input: Some(json!("please classify this message")),
            input_ref: None,
            modalities: vec![Modality::Text],
            categories: vec!["hate".to_string(), "self-harm".to_string()],
            privacy_tier: Some(PrivacyTier::NoLog),
            integrity_tier: Some(IntegrityTier::ReceiptOnly),
            trace_required: Some(true),
            settlement_method: Some("free-local-dev".to_string()),
        })
    }
}
