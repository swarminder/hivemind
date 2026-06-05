use anyhow::Context;
use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    ApiSurface, DataRetentionRule, LoggingRule, Modality, PrivacyTier, StreamingEventType,
    ValidationIssue, canonicalize_json, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEV_REALTIME_SESSION_SIGNATURE_PREFIX: &str = "dev-realtime-session-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RealtimeTransport {
    Websocket,
    Webrtc,
    HttpStream,
    Local,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RealtimePackageSelectorV1 {
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
pub struct RealtimeToolRefV1 {
    #[serde(rename = "toolId", default, skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
    #[serde(rename = "toolRef")]
    pub tool_ref: String,
    #[serde(rename = "approvalRequired")]
    pub approval_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RealtimePrivacyV1 {
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "dataRetentionRule")]
    pub data_retention_rule: DataRetentionRule,
    #[serde(rename = "loggingRule")]
    pub logging_rule: LoggingRule,
    #[serde(rename = "ephemeralSession")]
    pub ephemeral_session: bool,
}

impl Default for RealtimePrivacyV1 {
    fn default() -> Self {
        Self {
            privacy_tier: PrivacyTier::NoLog,
            data_retention_rule: DataRetentionRule::DeleteAfterJob,
            logging_rule: LoggingRule::NoPromptOrOutputLogs,
            ephemeral_session: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RealtimeSessionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub requester: String,
    #[serde(rename = "packageSelector")]
    pub package_selector: RealtimePackageSelectorV1,
    #[serde(rename = "modalitiesIn")]
    pub modalities_in: Vec<Modality>,
    #[serde(rename = "modalitiesOut")]
    pub modalities_out: Vec<Modality>,
    pub transport: RealtimeTransport,
    #[serde(rename = "latencyTargetMs")]
    pub latency_target_ms: u32,
    #[serde(rename = "interruptionsAllowed")]
    pub interruptions_allowed: bool,
    #[serde(default)]
    pub tools: Vec<RealtimeToolRefV1>,
    pub privacy: RealtimePrivacyV1,
    #[serde(rename = "settlementMethod")]
    pub settlement_method: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RealtimeSessionInitOptionsV1 {
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
    #[serde(rename = "modalitiesIn", default)]
    pub modalities_in: Vec<Modality>,
    #[serde(rename = "modalitiesOut", default)]
    pub modalities_out: Vec<Modality>,
    #[serde(default)]
    pub transport: Option<RealtimeTransport>,
    #[serde(rename = "latencyTargetMs", default)]
    pub latency_target_ms: Option<u32>,
    #[serde(rename = "interruptionsAllowed", default)]
    pub interruptions_allowed: Option<bool>,
    #[serde(rename = "toolRefs", default)]
    pub tool_refs: Vec<String>,
    #[serde(rename = "privacyTier", default)]
    pub privacy_tier: Option<PrivacyTier>,
    #[serde(rename = "settlementMethod", default)]
    pub settlement_method: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RealtimeSessionVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
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
pub struct RealtimeConnectionPlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "apiSurface")]
    pub api_surface: ApiSurface,
    pub transport: RealtimeTransport,
    #[serde(rename = "connectionMode")]
    pub connection_mode: String,
    #[serde(rename = "connectionRef")]
    pub connection_ref: String,
    #[serde(rename = "latencyTargetMs")]
    pub latency_target_ms: u32,
    #[serde(rename = "interruptionsAllowed")]
    pub interruptions_allowed: bool,
    #[serde(rename = "modalitiesIn")]
    pub modalities_in: Vec<Modality>,
    #[serde(rename = "modalitiesOut")]
    pub modalities_out: Vec<Modality>,
    #[serde(rename = "toolRefs")]
    pub tool_refs: Vec<String>,
    #[serde(rename = "approvalRequired")]
    pub approval_required: bool,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
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
pub struct RealtimeSessionIndexEntryV1 {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub requester: String,
    pub transport: RealtimeTransport,
    #[serde(rename = "connectionMode")]
    pub connection_mode: String,
    #[serde(rename = "latencyTargetMs")]
    pub latency_target_ms: u32,
    #[serde(rename = "modalitiesInCount")]
    pub modalities_in_count: usize,
    #[serde(rename = "modalitiesOutCount")]
    pub modalities_out_count: usize,
    #[serde(rename = "toolCount")]
    pub tool_count: usize,
    #[serde(rename = "approvalRequired")]
    pub approval_required: bool,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "ephemeralSession")]
    pub ephemeral_session: bool,
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
    #[serde(rename = "sessionPath")]
    pub session_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RealtimeSessionStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "sessionCount")]
    pub session_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "approvalRequiredCount")]
    pub approval_required_count: usize,
    #[serde(rename = "ephemeralSessionCount")]
    pub ephemeral_session_count: usize,
    #[serde(rename = "lowLatencyCount")]
    pub low_latency_count: usize,
    #[serde(rename = "mutableRefCount")]
    pub mutable_ref_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub sessions: Vec<RealtimeSessionIndexEntryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RealtimeSessionLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "sessionPath")]
    pub session_path: String,
    pub session: RealtimeSessionV1,
    pub verification: RealtimeSessionVerificationV1,
    #[serde(rename = "connectionPlan")]
    pub connection_plan: RealtimeConnectionPlanV1,
}

pub fn create_realtime_session(options: RealtimeSessionInitOptionsV1) -> RealtimeSessionV1 {
    let mut modalities_in = if options.modalities_in.is_empty() {
        vec![Modality::Audio, Modality::Text]
    } else {
        options.modalities_in
    };
    dedup_modalities(&mut modalities_in);
    let mut modalities_out = if options.modalities_out.is_empty() {
        vec![Modality::Audio, Modality::Text]
    } else {
        options.modalities_out
    };
    dedup_modalities(&mut modalities_out);
    let mut tool_refs = options.tool_refs;
    dedup(&mut tool_refs);

    let mut session = RealtimeSessionV1 {
        schema_version: "swarm-ai.realtime-session.v1".to_string(),
        session_id: String::new(),
        requester: options.requester,
        package_selector: RealtimePackageSelectorV1 {
            package_ref: options.package_ref,
            package_id: options.package_id,
            package_version: options.package_version,
            service_ref: options.service_ref,
            model_alias: options.model_alias,
        },
        modalities_in,
        modalities_out,
        transport: options.transport.unwrap_or(RealtimeTransport::Websocket),
        latency_target_ms: options.latency_target_ms.unwrap_or(250),
        interruptions_allowed: options.interruptions_allowed.unwrap_or(true),
        tools: tool_refs
            .into_iter()
            .map(|tool_ref| RealtimeToolRefV1 {
                tool_id: None,
                tool_ref,
                approval_required: true,
            })
            .collect(),
        privacy: RealtimePrivacyV1 {
            privacy_tier: options.privacy_tier.unwrap_or(PrivacyTier::NoLog),
            ..RealtimePrivacyV1::default()
        },
        settlement_method: options
            .settlement_method
            .unwrap_or_else(|| "free-local-dev".to_string()),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_realtime_session(&mut session);
    session
}

pub fn sign_realtime_session(session: &mut RealtimeSessionV1) {
    session.signature = Some(expected_realtime_session_signature(session));
    session.session_id = canonical_realtime_session_id(session);
}

pub fn sign_realtime_session_with_identity(
    session: &mut RealtimeSessionV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != session.requester {
        anyhow::bail!(
            "identity subject {} does not match realtime session requester {}",
            identity.subject,
            session.requester
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "realtime-session",
        &realtime_session_signing_value(session),
    )?;
    session.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    session.session_id = canonical_realtime_session_id(session);
    Ok(envelope)
}

pub fn expected_realtime_session_signature(session: &RealtimeSessionV1) -> String {
    format!(
        "{DEV_REALTIME_SESSION_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&realtime_session_signing_value(session)))
    )
}

pub fn canonical_realtime_session_id(session: &RealtimeSessionV1) -> String {
    stable_id("realtime-session", &realtime_session_signing_value(session))
}

pub fn verify_realtime_session(session: &RealtimeSessionV1) -> RealtimeSessionVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_realtime_session_signature(session));
    let signature = session
        .signature
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if session.schema_version != "swarm-ai.realtime-session.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.realtime-session.v1",
        ));
    }
    require_non_empty(&mut issues, "$.sessionId", &session.session_id);
    if !session.session_id.is_empty()
        && session.session_id != canonical_realtime_session_id(session)
    {
        issues.push(issue(
            "$.sessionId",
            "Realtime session id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.requester", &session.requester);
    validate_package_selector(&session.package_selector, &mut issues, &mut warnings);
    validate_modalities(session, &mut issues, &mut warnings);
    validate_transport(session, &mut issues, &mut warnings);
    validate_tools(&session.tools, &mut issues, &mut warnings);
    require_non_empty(
        &mut issues,
        "$.settlementMethod",
        &session.settlement_method,
    );
    validate_created_at(&session.created_at, "$.createdAt", &mut issues);
    verify_signature(
        signature,
        "realtime-session",
        &realtime_session_signing_value(session),
        &session.requester,
        &mut expected_signature,
        &mut issues,
        "Realtime session signature does not match canonical dev signature or Ed25519 requester identity envelope",
    );
    if signature.is_none() {
        warnings.push(issue(
            "$.signature",
            "Realtime session is unsigned; verify requester and sessionId through a trusted source",
        ));
    }

    RealtimeSessionVerificationV1 {
        schema_version: "swarm-ai.realtime-session-verification.v1".to_string(),
        session_id: session.session_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn realtime_connection_plan(session: &RealtimeSessionV1) -> RealtimeConnectionPlanV1 {
    realtime_connection_plan_for_surface(session, ApiSurface::OpenAiRealtime)
}

pub fn realtime_connection_plan_for_surface(
    session: &RealtimeSessionV1,
    api_surface: ApiSurface,
) -> RealtimeConnectionPlanV1 {
    let verification = verify_realtime_session(session);
    let tool_refs: Vec<String> = session
        .tools
        .iter()
        .map(|tool| tool.tool_ref.clone())
        .collect();
    let approval_required = session.tools.iter().any(|tool| tool.approval_required);

    RealtimeConnectionPlanV1 {
        schema_version: "swarm-ai.realtime-connection-plan.v1".to_string(),
        session_id: session.session_id.clone(),
        api_surface,
        transport: session.transport.clone(),
        connection_mode: connection_mode(&session.transport).to_string(),
        connection_ref: connection_ref(session),
        latency_target_ms: session.latency_target_ms,
        interruptions_allowed: session.interruptions_allowed,
        modalities_in: session.modalities_in.clone(),
        modalities_out: session.modalities_out.clone(),
        tool_refs,
        approval_required,
        privacy_tier: session.privacy.privacy_tier.clone(),
        settlement_method: session.settlement_method.clone(),
        allowed_event_types: allowed_event_types(session),
        metadata: json!({
            "storageRole": "Swarm/Bee stores packages, tool manifests, receipts, and audit evidence; realtime transport is runner-side.",
            "ephemeralSession": session.privacy.ephemeral_session
        }),
        valid: verification.valid,
        issues: verification.issues,
        warnings: verification.warnings,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn list_realtime_sessions(session_dir: &Path) -> anyhow::Result<RealtimeSessionStoreSummaryV1> {
    let mut files = Vec::new();
    collect_realtime_session_files(session_dir, &mut files)?;
    files.sort();

    let mut sessions = Vec::new();
    let mut valid_count = 0;
    let mut approval_required_count = 0;
    let mut ephemeral_session_count = 0;
    let mut low_latency_count = 0;
    let mut mutable_ref_count = 0;
    let mut warning_count = 0;

    for path in files {
        let Some(session) = read_realtime_session_file(&path)? else {
            continue;
        };
        let verification = verify_realtime_session(&session);
        let connection_plan = realtime_connection_plan(&session);
        let mutable_refs = mutable_realtime_refs(&session);
        if verification.valid {
            valid_count += 1;
        }
        if connection_plan.approval_required {
            approval_required_count += 1;
        }
        if session.privacy.ephemeral_session {
            ephemeral_session_count += 1;
        }
        if session.latency_target_ms <= 250 {
            low_latency_count += 1;
        }
        mutable_ref_count += mutable_refs.len();
        warning_count += connection_plan.warnings.len();
        sessions.push(realtime_session_index_entry(
            &session,
            &verification,
            &connection_plan,
            mutable_refs.len(),
            path.display().to_string(),
        ));
    }

    sessions.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.session_id.cmp(&right.session_id))
            .then(left.session_path.cmp(&right.session_path))
    });

    Ok(RealtimeSessionStoreSummaryV1 {
        schema_version: "swarm-ai.realtime-session-store-summary.v1".to_string(),
        root: session_dir.display().to_string(),
        session_count: sessions.len(),
        valid_count,
        invalid_count: sessions.len().saturating_sub(valid_count),
        approval_required_count,
        ephemeral_session_count,
        low_latency_count,
        mutable_ref_count,
        warning_count,
        sessions,
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn get_realtime_session(
    session_dir: &Path,
    session_id: &str,
) -> anyhow::Result<Option<RealtimeSessionLookupV1>> {
    let session_id = session_id.trim();
    if session_id.is_empty() {
        anyhow::bail!("sessionId is required");
    }

    let mut files = Vec::new();
    collect_realtime_session_files(session_dir, &mut files)?;
    files.sort();

    for path in files {
        let Some(session) = read_realtime_session_file(&path)? else {
            continue;
        };
        if session.session_id == session_id {
            let verification = verify_realtime_session(&session);
            let connection_plan = realtime_connection_plan(&session);
            return Ok(Some(RealtimeSessionLookupV1 {
                schema_version: "swarm-ai.realtime-session-lookup.v1".to_string(),
                session_id: session.session_id.clone(),
                session_path: path.display().to_string(),
                session,
                verification,
                connection_plan,
            }));
        }
    }

    Ok(None)
}

fn collect_realtime_session_files(
    session_dir: &Path,
    files: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    if !session_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(session_dir)
        .with_context(|| format!("failed to read {}", session_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_realtime_session_files(&path, files)?;
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

fn read_realtime_session_file(path: &Path) -> anyhow::Result<Option<RealtimeSessionV1>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let Some(schema_version) = value.get("schemaVersion").and_then(Value::as_str) else {
        return Ok(None);
    };
    if schema_version != "swarm-ai.realtime-session.v1" {
        return Ok(None);
    }
    serde_json::from_value(value)
        .map(Some)
        .with_context(|| format!("failed to parse realtime session {}", path.display()))
}

fn realtime_session_index_entry(
    session: &RealtimeSessionV1,
    verification: &RealtimeSessionVerificationV1,
    connection_plan: &RealtimeConnectionPlanV1,
    mutable_ref_count: usize,
    session_path: String,
) -> RealtimeSessionIndexEntryV1 {
    RealtimeSessionIndexEntryV1 {
        session_id: session.session_id.clone(),
        requester: session.requester.clone(),
        transport: session.transport.clone(),
        connection_mode: connection_plan.connection_mode.clone(),
        latency_target_ms: session.latency_target_ms,
        modalities_in_count: session.modalities_in.len(),
        modalities_out_count: session.modalities_out.len(),
        tool_count: session.tools.len(),
        approval_required: connection_plan.approval_required,
        privacy_tier: session.privacy.privacy_tier.clone(),
        ephemeral_session: session.privacy.ephemeral_session,
        allowed_event_type_count: connection_plan.allowed_event_types.len(),
        mutable_ref_count,
        warning_count: connection_plan.warnings.len(),
        valid: verification.valid,
        signature_present: session.signature.is_some(),
        created_at: session.created_at.clone(),
        session_path,
    }
}

fn mutable_realtime_refs(session: &RealtimeSessionV1) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(package_ref) = &session.package_selector.package_ref {
        push_mutable_ref(&mut refs, package_ref);
    }
    if let Some(service_ref) = &session.package_selector.service_ref {
        push_mutable_ref(&mut refs, service_ref);
    }
    for tool in &session.tools {
        push_mutable_ref(&mut refs, &tool.tool_ref);
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

fn validate_package_selector(
    selector: &RealtimePackageSelectorV1,
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
            "Realtime session must include a packageRef, serviceRef, packageId, or modelAlias",
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
    if let Some(package_id) = &selector.package_id {
        if package_id.trim().is_empty() {
            issues.push(issue("$.packageSelector.packageId", "packageId is empty"));
        }
    }
}

fn validate_modalities(
    session: &RealtimeSessionV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if session.modalities_in.is_empty() {
        issues.push(issue(
            "$.modalitiesIn",
            "Realtime session must declare input modalities",
        ));
    }
    if session.modalities_out.is_empty() {
        issues.push(issue(
            "$.modalitiesOut",
            "Realtime session must declare output modalities",
        ));
    }
    let realtime_in = session
        .modalities_in
        .iter()
        .any(|modality| matches!(modality, Modality::Audio | Modality::Video | Modality::Chat));
    let realtime_out = session
        .modalities_out
        .iter()
        .any(|modality| matches!(modality, Modality::Audio | Modality::Video | Modality::Chat));
    if !realtime_in && !realtime_out {
        warnings.push(issue(
            "$.modalitiesIn",
            "Realtime sessions usually include audio, video, or chat modalities",
        ));
    }
}

fn validate_transport(
    session: &RealtimeSessionV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if session.latency_target_ms == 0 {
        issues.push(issue(
            "$.latencyTargetMs",
            "latencyTargetMs must be greater than zero",
        ));
    }
    if session.latency_target_ms > 5_000 {
        warnings.push(issue(
            "$.latencyTargetMs",
            "Realtime latency target is high; batch or streaming execution may fit better",
        ));
    }
    if session.transport == RealtimeTransport::HttpStream && session.interruptions_allowed {
        warnings.push(issue(
            "$.transport",
            "HTTP stream transport may not support low-latency interruption semantics",
        ));
    }
    if session.transport == RealtimeTransport::Webrtc
        && !session
            .modalities_in
            .iter()
            .chain(session.modalities_out.iter())
            .any(|modality| matches!(modality, Modality::Audio | Modality::Video))
    {
        warnings.push(issue(
            "$.transport",
            "WebRTC transport is usually most useful for audio or video sessions",
        ));
    }
}

fn validate_tools(
    tools: &[RealtimeToolRefV1],
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    let mut seen = BTreeSet::new();
    for (index, tool) in tools.iter().enumerate() {
        let base = format!("$.tools[{index}]");
        if tool.tool_ref.trim().is_empty() {
            issues.push(issue(format!("{base}.toolRef"), "toolRef is required"));
        } else {
            if !seen.insert(tool.tool_ref.clone()) {
                issues.push(issue(format!("{base}.toolRef"), "toolRef must be unique"));
            }
            validate_ref(format!("{base}.toolRef"), &tool.tool_ref, issues, warnings);
        }
    }
}

fn connection_mode(transport: &RealtimeTransport) -> &'static str {
    match transport {
        RealtimeTransport::Websocket => "bidirectional-stream",
        RealtimeTransport::Webrtc => "peer-realtime-media",
        RealtimeTransport::HttpStream => "server-event-stream",
        RealtimeTransport::Local => "local-loopback",
    }
}

fn connection_ref(session: &RealtimeSessionV1) -> String {
    match session.transport {
        RealtimeTransport::Websocket => {
            format!("local://realtime/{}/websocket", session.session_id)
        }
        RealtimeTransport::Webrtc => format!("local://realtime/{}/webrtc", session.session_id),
        RealtimeTransport::HttpStream => format!("local://realtime/{}/stream", session.session_id),
        RealtimeTransport::Local => format!("local://realtime/{}/local", session.session_id),
    }
}

fn allowed_event_types(session: &RealtimeSessionV1) -> Vec<StreamingEventType> {
    let mut events = vec![
        StreamingEventType::Started,
        StreamingEventType::Heartbeat,
        StreamingEventType::LogEvent,
        StreamingEventType::Completed,
        StreamingEventType::Error,
        StreamingEventType::Cancelled,
    ];
    if has_modality(&session.modalities_out, &Modality::Text)
        || has_modality(&session.modalities_out, &Modality::Chat)
    {
        events.push(StreamingEventType::TextDelta);
        events.push(StreamingEventType::TokenDelta);
    }
    if has_modality(&session.modalities_in, &Modality::Audio)
        || has_modality(&session.modalities_out, &Modality::Audio)
    {
        events.push(StreamingEventType::AudioChunk);
    }
    if !session.tools.is_empty() {
        events.push(StreamingEventType::ToolCallRequested);
        events.push(StreamingEventType::ToolCallResult);
    }
    if session.interruptions_allowed {
        events.push(StreamingEventType::SafetyEvent);
    }
    events
}

fn has_modality(values: &[Modality], modality: &Modality) -> bool {
    values.iter().any(|value| value == modality)
}

fn realtime_session_signing_value(session: &RealtimeSessionV1) -> Value {
    let mut value = serde_json::to_value(session).expect("realtime session should serialize");
    if let Value::Object(ref mut object) = value {
        object.remove("sessionId");
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
    let value = serde_json::to_value(value).expect("realtime object should serialize");
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
    fn creates_signed_realtime_session_and_connection_plan() {
        let session = realtime_session();
        let verification = verify_realtime_session(&session);
        let plan = realtime_connection_plan(&session);

        assert!(verification.valid, "{verification:#?}");
        assert_eq!(
            session.signature.as_deref(),
            Some(expected_realtime_session_signature(&session).as_str())
        );
        assert!(session.session_id.starts_with("realtime-session-"));
        assert_eq!(plan.api_surface, ApiSurface::OpenAiRealtime);
        assert_eq!(plan.transport, RealtimeTransport::Websocket);
        assert_eq!(plan.connection_mode, "bidirectional-stream");
        assert!(plan.approval_required);
        assert!(
            plan.allowed_event_types
                .contains(&StreamingEventType::AudioChunk)
        );
        assert!(
            plan.allowed_event_types
                .contains(&StreamingEventType::ToolCallRequested)
        );
    }

    #[test]
    fn connection_plan_can_use_provider_specific_api_surface() {
        let session = realtime_session();
        let plan = realtime_connection_plan_for_surface(&session, ApiSurface::GeminiLive);

        assert_eq!(plan.api_surface, ApiSurface::GeminiLive);
        assert_eq!(plan.session_id, session.session_id);
        assert!(plan.valid);
    }

    #[test]
    fn identity_signed_realtime_session_verifies_and_detects_tampering() {
        let mut session = realtime_session();
        let identity =
            hivemind_identity::identity_from_seed("0xRequester", b"realtime-seed").unwrap();

        let envelope = sign_realtime_session_with_identity(&mut session, &identity).unwrap();
        let verification = verify_realtime_session(&session);

        assert_eq!(envelope.signer, session.requester);
        assert!(verification.valid, "{verification:#?}");

        session.latency_target_ms = 999;
        let tampered = verify_realtime_session(&session);
        assert!(!tampered.valid);
        assert!(tampered.issues.iter().any(|issue| {
            issue.path == "$.sessionId" || issue.path == "$.signature.payloadHash"
        }));
    }

    #[test]
    fn rejects_missing_selector_and_zero_latency() {
        let mut session = realtime_session();
        session.package_selector = RealtimePackageSelectorV1 {
            package_ref: None,
            package_id: None,
            package_version: None,
            service_ref: None,
            model_alias: None,
        };
        session.latency_target_ms = 0;
        sign_realtime_session(&mut session);

        let verification = verify_realtime_session(&session);

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
                .any(|issue| issue.path == "$.latencyTargetMs")
        );
    }

    #[test]
    fn unsigned_realtime_session_still_requires_canonical_id() {
        let mut session = realtime_session();
        session.signature = None;
        session.settlement_method = "changed".to_string();

        let verification = verify_realtime_session(&session);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.sessionId")
        );
    }

    #[test]
    fn plan_warns_for_http_stream_interruptions_and_high_latency() {
        let mut session = realtime_session();
        session.transport = RealtimeTransport::HttpStream;
        session.latency_target_ms = 6_000;
        sign_realtime_session(&mut session);

        let plan = realtime_connection_plan(&session);

        assert!(plan.valid, "{plan:#?}");
        assert_eq!(plan.connection_mode, "server-event-stream");
        assert!(
            plan.warnings
                .iter()
                .any(|issue| issue.path == "$.transport")
        );
        assert!(
            plan.warnings
                .iter()
                .any(|issue| issue.path == "$.latencyTargetMs")
        );
    }

    #[test]
    fn realtime_session_store_lists_and_gets_sessions() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("hivemind-realtime-store-{unique}"));
        fs::create_dir_all(dir.join("nested")).unwrap();

        let mut session = realtime_session();
        session.package_selector.package_ref =
            Some("https://example.com/realtime/latest".to_string());
        session.tools[0].tool_ref = "https://example.com/tools/repo-search/latest".to_string();
        sign_realtime_session(&mut session);

        fs::write(
            dir.join("nested").join("voice.session.json"),
            serde_json::to_vec_pretty(&session).unwrap(),
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

        let summary = list_realtime_sessions(&dir).unwrap();
        assert_eq!(summary.session_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.invalid_count, 0);
        assert_eq!(summary.approval_required_count, 1);
        assert_eq!(summary.ephemeral_session_count, 1);
        assert_eq!(summary.low_latency_count, 1);
        assert_eq!(summary.mutable_ref_count, 2);
        assert!(summary.warning_count > 0);
        assert_eq!(summary.sessions[0].session_id, session.session_id);
        assert!(summary.sessions[0].signature_present);

        let lookup = get_realtime_session(&dir, &session.session_id)
            .unwrap()
            .unwrap();
        assert_eq!(lookup.session.session_id, session.session_id);
        assert!(lookup.verification.valid, "{:#?}", lookup.verification);
        assert!(
            lookup.connection_plan.valid,
            "{:#?}",
            lookup.connection_plan
        );
        assert!(lookup.connection_plan.approval_required);
        assert_eq!(lookup.connection_plan.tool_refs.len(), 1);
        assert!(get_realtime_session(&dir, "missing").unwrap().is_none());

        let _ = fs::remove_dir_all(dir);
    }

    fn realtime_session() -> RealtimeSessionV1 {
        create_realtime_session(RealtimeSessionInitOptionsV1 {
            requester: "0xRequester".to_string(),
            package_ref: Some("bzz://realtime-session-package".to_string()),
            package_id: Some("hivemind/realtime-agent".to_string()),
            package_version: Some("0.1.0".to_string()),
            service_ref: None,
            model_alias: None,
            modalities_in: vec![Modality::Audio, Modality::Text],
            modalities_out: vec![Modality::Audio, Modality::Text],
            transport: Some(RealtimeTransport::Websocket),
            latency_target_ms: Some(200),
            interruptions_allowed: Some(true),
            tool_refs: vec!["bzz://tool".to_string()],
            privacy_tier: Some(PrivacyTier::NoLog),
            settlement_method: Some("free-local-dev".to_string()),
        })
    }
}
