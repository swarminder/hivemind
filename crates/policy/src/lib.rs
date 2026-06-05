pub use hivemind_core::{
    PolicyDecision, PolicyDecisionV1, evaluate_package_policy, policy_execution_block_reason,
};

use anyhow::Context;
use hivemind_core::{
    IntegrityTier, PackageManifestV1, PermissionRequest, PrivacyTier, TrustPolicyV1,
    TrustPolicyVerificationV1, hash_canonical_json, policy::RiskLevel,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const TRUST_POLICY_SCHEMA_VERSION: &str = "swarm-ai.trust-policy.v1";
pub const PERMISSION_MANIFEST_V2_SCHEMA_VERSION: &str = "hivemind.permission_manifest.v2";
pub const RISK_INSPECTION_REPORT_SCHEMA_VERSION: &str = "hivemind.risk_inspection_report.v1";
pub const CONSENT_RECORD_SCHEMA_VERSION: &str = "hivemind.consent_record.v1";
pub const TOOL_PERMISSION_GRANT_SCHEMA_VERSION: &str = "hivemind.tool_permission_grant.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CodeExecutionMode {
    None,
    Sandboxed,
    UnsandboxedRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionCategory {
    Network,
    Storage,
    UserDevice,
    Wallet,
    LocalRuntime,
    Runner,
    Evidence,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionSeverity {
    Low,
    Medium,
    High,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PermissionDefinitionV1 {
    pub name: String,
    pub category: PermissionCategory,
    pub severity: PermissionSeverity,
    #[serde(rename = "defaultAction")]
    pub default_action: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PermissionManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub permissions: Vec<PermissionRequest>,
    #[serde(rename = "riskLevel")]
    pub risk_level: RiskLevel,
    #[serde(rename = "codeExecution")]
    pub code_execution: CodeExecutionMode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PermissionSummaryV1 {
    pub name: String,
    #[serde(default)]
    pub purpose: Option<String>,
    pub required: bool,
    pub category: PermissionCategory,
    pub severity: PermissionSeverity,
    #[serde(rename = "defaultAction")]
    pub default_action: String,
    #[serde(rename = "consentRequired")]
    pub consent_required: bool,
    #[serde(rename = "defaultDenied")]
    pub default_denied: bool,
    #[serde(rename = "sandboxRequired")]
    pub sandbox_required: bool,
    #[serde(default)]
    pub limits: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PermissionManifestV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "manifestId")]
    pub manifest_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef", default)]
    pub package_ref: Option<String>,
    #[serde(rename = "runnerId", default)]
    pub runner_id: Option<String>,
    #[serde(rename = "declaredPermissionNames")]
    pub declared_permission_names: Vec<String>,
    #[serde(rename = "permissionSummaries")]
    pub permission_summaries: Vec<PermissionSummaryV1>,
    #[serde(rename = "riskLevel")]
    pub risk_level: RiskLevel,
    #[serde(rename = "codeExecution")]
    pub code_execution: CodeExecutionMode,
    #[serde(rename = "consentRequired")]
    pub consent_required: Vec<String>,
    #[serde(rename = "defaultDenied")]
    pub default_denied: Vec<String>,
    #[serde(rename = "sandboxRequirements")]
    pub sandbox_requirements: Vec<SandboxRequirementV1>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SandboxRequirementV1 {
    pub environment: String,
    pub requirement: String,
    pub enforced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ConsentDecisionV1 {
    Granted,
    Denied,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ConsentRecordV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "consentId")]
    pub consent_id: String,
    #[serde(rename = "policyDecisionId")]
    pub policy_decision_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "runnerId", default)]
    pub runner_id: Option<String>,
    #[serde(rename = "grantedBy")]
    pub granted_by: String,
    pub decision: ConsentDecisionV1,
    pub permissions: Vec<String>,
    pub reason: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt", default)]
    pub expires_at: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolPermissionGrantV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "grantId")]
    pub grant_id: String,
    #[serde(rename = "toolRef")]
    pub tool_ref: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "grantedTo")]
    pub granted_to: String,
    pub permissions: Vec<String>,
    #[serde(default)]
    pub scope: Value,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt", default)]
    pub expires_at: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RiskInspectionReportV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "reportId")]
    pub report_id: String,
    #[serde(rename = "permissionManifest")]
    pub permission_manifest: PermissionManifestV2,
    #[serde(rename = "policyDecision")]
    pub policy_decision: PolicyDecisionV1,
    #[serde(rename = "permissionCatalog")]
    pub permission_catalog: Vec<PermissionDefinitionV1>,
    #[serde(rename = "sandboxRequirements")]
    pub sandbox_requirements: Vec<SandboxRequirementV1>,
    #[serde(rename = "consentRequired")]
    pub consent_required: Vec<String>,
    #[serde(rename = "defaultDenied")]
    pub default_denied: Vec<String>,
    #[serde(rename = "toolPermissionGrantsRequired")]
    pub tool_permission_grants_required: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyInspectionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "permissionManifest")]
    pub permission_manifest: PermissionManifestV1,
    #[serde(rename = "policyDecision")]
    pub policy_decision: PolicyDecisionV1,
    #[serde(rename = "permissionCatalog")]
    pub permission_catalog: Vec<PermissionDefinitionV1>,
    #[serde(rename = "sandboxRequirements")]
    pub sandbox_requirements: Vec<SandboxRequirementV1>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TrustPolicyRecordSummaryV1 {
    #[serde(rename = "policyId")]
    pub policy_id: String,
    pub owner: String,
    #[serde(rename = "privacyTiers")]
    pub privacy_tiers: Vec<PrivacyTier>,
    #[serde(rename = "verificationTiers")]
    pub verification_tiers: Vec<IntegrityTier>,
    #[serde(rename = "allowOpenMiners")]
    pub allow_open_miners: bool,
    #[serde(rename = "allowConsumerGpu")]
    pub allow_consumer_gpu: bool,
    #[serde(rename = "requireReceipt")]
    pub require_receipt: bool,
    #[serde(rename = "requireValidation")]
    pub require_validation: bool,
    #[serde(rename = "signaturePresent")]
    pub signature_present: bool,
    pub valid: bool,
    #[serde(rename = "issueCount")]
    pub issue_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TrustPolicyStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "policyCount")]
    pub policy_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "signaturePresentCount")]
    pub signature_present_count: usize,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub records: Vec<TrustPolicyRecordSummaryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TrustPolicyLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "policyId")]
    pub policy_id: String,
    pub path: String,
    #[serde(rename = "trustPolicy")]
    pub trust_policy: TrustPolicyV1,
    pub verification: TrustPolicyVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TrustPolicyWriteResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "policyId")]
    pub policy_id: String,
    pub path: String,
    pub verification: TrustPolicyVerificationV1,
}

pub fn permission_manifest_from_package(manifest: &PackageManifestV1) -> PermissionManifestV1 {
    let code_execution = code_execution_mode(manifest);
    let risk_level = risk_level_for_permissions(&manifest.permissions, &code_execution);
    PermissionManifestV1 {
        schema_version: "swarm-ai.permissions.v1".to_string(),
        package_id: manifest.package_id.clone(),
        permissions: manifest.permissions.clone(),
        risk_level,
        code_execution,
    }
}

pub fn permission_manifest_v2_from_package(
    manifest: &PackageManifestV1,
    package_ref: impl Into<Option<String>>,
    runner_id: Option<String>,
) -> PermissionManifestV2 {
    let package_ref = package_ref.into();
    let permission_manifest = permission_manifest_from_package(manifest);
    let policy_decision = evaluate_package_policy(
        manifest,
        package_ref
            .clone()
            .unwrap_or_else(|| format!("local://manifest/{}", manifest.package_id)),
        runner_id.clone(),
    );
    let sandbox_requirements =
        sandbox_requirements(&permission_manifest, &policy_decision.restrictions);
    let permission_summaries =
        permission_summaries(&permission_manifest.permissions, &sandbox_requirements);
    let consent_required = permission_summaries
        .iter()
        .filter(|permission| permission.consent_required)
        .map(|permission| permission.name.clone())
        .collect::<Vec<_>>();
    let default_denied = permission_summaries
        .iter()
        .filter(|permission| permission.default_denied)
        .map(|permission| permission.name.clone())
        .collect::<Vec<_>>();
    let declared_permission_names = permission_manifest
        .permissions
        .iter()
        .map(|permission| permission.name.clone())
        .collect::<Vec<_>>();
    let warnings = permission_manifest_v2_warnings(
        &permission_manifest,
        &policy_decision,
        &sandbox_requirements,
    );

    let mut projected = PermissionManifestV2 {
        schema_version: PERMISSION_MANIFEST_V2_SCHEMA_VERSION.to_string(),
        object_kind: "permission_manifest".to_string(),
        manifest_id: String::new(),
        package_id: permission_manifest.package_id,
        package_ref,
        runner_id,
        declared_permission_names,
        permission_summaries,
        risk_level: permission_manifest.risk_level,
        code_execution: permission_manifest.code_execution,
        consent_required,
        default_denied,
        sandbox_requirements,
        warnings,
    };
    projected.manifest_id = canonical_permission_manifest_v2_id(&projected);
    projected
}

pub fn inspect_package_policy_v2(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
    runner_id: Option<String>,
) -> RiskInspectionReportV1 {
    let package_ref = package_ref.into();
    let permission_manifest =
        permission_manifest_v2_from_package(manifest, Some(package_ref.clone()), runner_id.clone());
    let policy_decision = evaluate_package_policy(manifest, package_ref, runner_id);
    let permission_catalog = permission_manifest
        .declared_permission_names
        .iter()
        .map(|name| permission_definition(name))
        .collect::<Vec<_>>();
    let tool_permission_grants_required = permission_manifest
        .permission_summaries
        .iter()
        .filter(|permission| {
            permission.name.starts_with("tool.")
                || permission.name.contains(".tool")
                || permission.name == "local.shell"
                || permission.name == "local.docker"
        })
        .map(|permission| permission.name.clone())
        .collect::<Vec<_>>();
    let mut report = RiskInspectionReportV1 {
        schema_version: RISK_INSPECTION_REPORT_SCHEMA_VERSION.to_string(),
        object_kind: "risk_inspection_report".to_string(),
        report_id: String::new(),
        sandbox_requirements: permission_manifest.sandbox_requirements.clone(),
        consent_required: permission_manifest.consent_required.clone(),
        default_denied: permission_manifest.default_denied.clone(),
        warnings: permission_manifest.warnings.clone(),
        permission_manifest,
        policy_decision,
        permission_catalog,
        tool_permission_grants_required,
    };
    report.report_id = canonical_risk_inspection_report_id(&report);
    report
}

pub fn inspect_package_policy(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
    runner_id: Option<String>,
) -> PolicyInspectionV1 {
    let permission_manifest = permission_manifest_from_package(manifest);
    let policy_decision = evaluate_package_policy(manifest, package_ref, runner_id);
    let permission_catalog = permission_manifest
        .permissions
        .iter()
        .map(|permission| permission_definition(&permission.name))
        .collect::<Vec<_>>();
    let sandbox_requirements =
        sandbox_requirements(&permission_manifest, &policy_decision.restrictions);
    let warnings = inspection_warnings(&permission_manifest, &policy_decision);

    PolicyInspectionV1 {
        schema_version: "swarm-ai.policy-inspection.v1".to_string(),
        permission_manifest,
        policy_decision,
        permission_catalog,
        sandbox_requirements,
        warnings,
    }
}

pub fn consent_record_from_policy_decision(
    policy_decision: &PolicyDecisionV1,
    granted_by: impl Into<String>,
    permissions: Vec<String>,
    decision: ConsentDecisionV1,
    reason: impl Into<String>,
    created_at: impl Into<String>,
    expires_at: Option<String>,
) -> ConsentRecordV1 {
    let mut record = ConsentRecordV1 {
        schema_version: CONSENT_RECORD_SCHEMA_VERSION.to_string(),
        object_kind: "consent_record".to_string(),
        consent_id: String::new(),
        policy_decision_id: canonical_policy_decision_id(policy_decision),
        package_id: policy_decision.package_id.clone(),
        package_ref: policy_decision.package_ref.clone(),
        runner_id: policy_decision.runner_id.clone(),
        granted_by: granted_by.into(),
        decision,
        permissions,
        reason: reason.into(),
        created_at: created_at.into(),
        expires_at,
        evidence_refs: Vec::new(),
        signature: None,
    };
    record.consent_id = canonical_consent_record_id(&record);
    record
}

pub fn tool_permission_grant(
    tool_ref: impl Into<String>,
    package_id: impl Into<String>,
    granted_to: impl Into<String>,
    permissions: Vec<String>,
    scope: Value,
    created_at: impl Into<String>,
    expires_at: Option<String>,
) -> ToolPermissionGrantV1 {
    let mut grant = ToolPermissionGrantV1 {
        schema_version: TOOL_PERMISSION_GRANT_SCHEMA_VERSION.to_string(),
        object_kind: "tool_permission_grant".to_string(),
        grant_id: String::new(),
        tool_ref: tool_ref.into(),
        package_id: package_id.into(),
        granted_to: granted_to.into(),
        permissions,
        scope,
        created_at: created_at.into(),
        expires_at,
        evidence_refs: Vec::new(),
        signature: None,
    };
    grant.grant_id = canonical_tool_permission_grant_id(&grant);
    grant
}

pub fn write_trust_policy_record(
    trust_dir: &Path,
    policy: &TrustPolicyV1,
) -> anyhow::Result<TrustPolicyWriteResultV1> {
    let verification = hivemind_core::verify_trust_policy(policy);
    if !verification.valid {
        anyhow::bail!(
            "trust policy {} is invalid: {}",
            display_policy_id(&policy.policy_id),
            trust_policy_issue_summary(&verification)
        );
    }

    fs::create_dir_all(trust_dir)
        .with_context(|| format!("failed to create {}", trust_dir.display()))?;
    let path = trust_policy_path(trust_dir, &policy.policy_id);
    fs::write(&path, serde_json::to_vec_pretty(policy)?)
        .with_context(|| format!("failed to write {}", path.display()))?;

    Ok(TrustPolicyWriteResultV1 {
        schema_version: "swarm-ai.trust-policy-write-result.v1".to_string(),
        policy_id: policy.policy_id.clone(),
        path: path.display().to_string(),
        verification,
    })
}

pub fn list_trust_policy_records(trust_dir: &Path) -> anyhow::Result<TrustPolicyStoreSummaryV1> {
    let mut records = Vec::new();
    for path in collect_json_files(trust_dir)? {
        let Some(policy) = read_trust_policy_document(&path)? else {
            continue;
        };
        records.push(trust_policy_record_summary(
            &policy,
            path.display().to_string(),
        ));
    }

    records.sort_by(|left, right| {
        left.owner
            .cmp(&right.owner)
            .then(left.policy_id.cmp(&right.policy_id))
            .then(left.path.cmp(&right.path))
    });
    let valid_count = records.iter().filter(|record| record.valid).count();
    let signature_present_count = records
        .iter()
        .filter(|record| record.signature_present)
        .count();
    let warning_count = records.iter().map(|record| record.warning_count).sum();

    Ok(TrustPolicyStoreSummaryV1 {
        schema_version: "swarm-ai.trust-policy-store-summary.v1".to_string(),
        root: trust_dir.display().to_string(),
        policy_count: records.len(),
        valid_count,
        invalid_count: records.len().saturating_sub(valid_count),
        signature_present_count,
        warning_count,
        records,
    })
}

pub fn get_trust_policy_record(
    trust_dir: &Path,
    policy_id: &str,
) -> anyhow::Result<Option<TrustPolicyLookupV1>> {
    let policy_id = policy_id.trim();
    if policy_id.is_empty() {
        anyhow::bail!("policyId is required");
    }

    let direct_path = trust_policy_path(trust_dir, policy_id);
    if direct_path.exists() {
        if let Some(policy) = read_trust_policy_document(&direct_path)? {
            if policy.policy_id == policy_id {
                return Ok(Some(trust_policy_lookup(policy, direct_path)));
            }
        }
    }

    for path in collect_json_files(trust_dir)? {
        if path == direct_path {
            continue;
        }
        let Some(policy) = read_trust_policy_document(&path)? else {
            continue;
        };
        if policy.policy_id == policy_id {
            return Ok(Some(trust_policy_lookup(policy, path)));
        }
    }
    Ok(None)
}

pub fn permission_catalog() -> Vec<PermissionDefinitionV1> {
    [
        "network.http",
        "network.websocket",
        "swarm.read",
        "swarm.write",
        "user.files.read",
        "user.files.write",
        "microphone.read",
        "camera.read",
        "clipboard.read",
        "clipboard.write",
        "wallet.connect",
        "wallet.sign",
        "local.shell",
        "local.docker",
        "runner.gpu",
        "receipt.public-evidence",
        "private-cache.write",
    ]
    .into_iter()
    .map(permission_definition)
    .collect()
}

pub fn permission_definition(name: &str) -> PermissionDefinitionV1 {
    let (category, severity, default_action, description) = match name {
        "network.http" => (
            PermissionCategory::Network,
            PermissionSeverity::Medium,
            "ask-user-or-allowlist",
            "HTTP calls to declared hosts.",
        ),
        "network.websocket" => (
            PermissionCategory::Network,
            PermissionSeverity::Medium,
            "ask-user-or-allowlist",
            "WebSocket connections to declared hosts.",
        ),
        "swarm.read" => (
            PermissionCategory::Storage,
            PermissionSeverity::Low,
            "allow",
            "Read public Swarm data.",
        ),
        "swarm.write" => (
            PermissionCategory::Storage,
            PermissionSeverity::Medium,
            "ask-user",
            "Write data to Swarm.",
        ),
        "user.files.read" => (
            PermissionCategory::UserDevice,
            PermissionSeverity::Medium,
            "ask-user",
            "Read user-selected local files.",
        ),
        "user.files.write" => (
            PermissionCategory::UserDevice,
            PermissionSeverity::Medium,
            "ask-user",
            "Write user-approved local files.",
        ),
        "microphone.read" => (
            PermissionCategory::UserDevice,
            PermissionSeverity::Medium,
            "ask-user",
            "Read microphone input.",
        ),
        "camera.read" => (
            PermissionCategory::UserDevice,
            PermissionSeverity::Medium,
            "ask-user",
            "Read camera input.",
        ),
        "clipboard.read" => (
            PermissionCategory::UserDevice,
            PermissionSeverity::Medium,
            "ask-user",
            "Read clipboard contents.",
        ),
        "clipboard.write" => (
            PermissionCategory::UserDevice,
            PermissionSeverity::Medium,
            "ask-user",
            "Write clipboard contents.",
        ),
        "wallet.connect" => (
            PermissionCategory::Wallet,
            PermissionSeverity::Medium,
            "ask-user",
            "Connect to a wallet account.",
        ),
        "wallet.sign" => (
            PermissionCategory::Wallet,
            PermissionSeverity::Blocked,
            "deny-by-default",
            "Request wallet signatures.",
        ),
        "local.shell" => (
            PermissionCategory::LocalRuntime,
            PermissionSeverity::Blocked,
            "deny-by-default",
            "Run local shell commands.",
        ),
        "local.docker" => (
            PermissionCategory::LocalRuntime,
            PermissionSeverity::Blocked,
            "deny-by-default",
            "Run local containers.",
        ),
        "runner.gpu" => (
            PermissionCategory::Runner,
            PermissionSeverity::Low,
            "allow-if-runner-supports",
            "Use runner GPU resources.",
        ),
        "receipt.public-evidence" => (
            PermissionCategory::Evidence,
            PermissionSeverity::Medium,
            "ask-user",
            "Publish public execution evidence.",
        ),
        "private-cache.write" => (
            PermissionCategory::Storage,
            PermissionSeverity::Low,
            "allow-with-quota",
            "Write private package cache data.",
        ),
        _ => (
            PermissionCategory::Unknown,
            PermissionSeverity::Medium,
            "review-required",
            "Unknown permission name.",
        ),
    };

    PermissionDefinitionV1 {
        name: name.to_string(),
        category,
        severity,
        default_action: default_action.to_string(),
        description: description.to_string(),
    }
}

fn trust_policy_record_summary(policy: &TrustPolicyV1, path: String) -> TrustPolicyRecordSummaryV1 {
    let verification = hivemind_core::verify_trust_policy(policy);
    TrustPolicyRecordSummaryV1 {
        policy_id: policy.policy_id.clone(),
        owner: policy.owner.clone(),
        privacy_tiers: policy.allowed_privacy_tiers.clone(),
        verification_tiers: policy.allowed_verification_tiers.clone(),
        allow_open_miners: policy.allow_open_miners,
        allow_consumer_gpu: policy.allow_consumer_gpu,
        require_receipt: policy.require_receipt,
        require_validation: policy.require_validation,
        signature_present: policy.signature.is_some(),
        valid: verification.valid,
        issue_count: verification.issues.len(),
        warning_count: verification.warnings.len(),
        path,
    }
}

fn trust_policy_lookup(policy: TrustPolicyV1, path: PathBuf) -> TrustPolicyLookupV1 {
    let verification = hivemind_core::verify_trust_policy(&policy);
    TrustPolicyLookupV1 {
        schema_version: "swarm-ai.trust-policy-lookup.v1".to_string(),
        policy_id: policy.policy_id.clone(),
        path: path.display().to_string(),
        trust_policy: policy,
        verification,
    }
}

fn read_trust_policy_document(path: &Path) -> anyhow::Result<Option<TrustPolicyV1>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse JSON from {}", path.display()))?;
    if value.get("schemaVersion").and_then(Value::as_str) != Some(TRUST_POLICY_SCHEMA_VERSION) {
        return Ok(None);
    }
    let policy = serde_json::from_value(value)
        .with_context(|| format!("failed to parse TrustPolicyV1 from {}", path.display()))?;
    Ok(Some(policy))
}

fn collect_json_files(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if root.exists() {
        collect_json_files_into(root, &mut files)?;
    }
    files.sort();
    Ok(files)
}

fn collect_json_files_into(dir: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_json_files_into(&path, files)?;
        } else if file_type.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            files.push(path);
        }
    }
    Ok(())
}

fn trust_policy_path(trust_dir: &Path, policy_id: &str) -> PathBuf {
    trust_dir.join(format!(
        "{}.trust-policy.json",
        safe_file_component(policy_id)
    ))
}

fn safe_file_component(value: &str) -> String {
    let safe = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    if safe.is_empty() {
        "trust-policy".to_string()
    } else {
        safe
    }
}

fn display_policy_id(policy_id: &str) -> &str {
    if policy_id.trim().is_empty() {
        "<missing>"
    } else {
        policy_id
    }
}

fn trust_policy_issue_summary(verification: &TrustPolicyVerificationV1) -> String {
    if verification.issues.is_empty() {
        return "unknown validation failure".to_string();
    }
    verification
        .issues
        .iter()
        .map(|issue| format!("{}: {}", issue.path, issue.message))
        .collect::<Vec<_>>()
        .join("; ")
}

fn code_execution_mode(manifest: &PackageManifestV1) -> CodeExecutionMode {
    if manifest
        .permissions
        .iter()
        .any(|permission| matches!(permission.name.as_str(), "local.shell" | "local.docker"))
    {
        return CodeExecutionMode::UnsandboxedRequired;
    }

    if manifest.artifact_groups.iter().any(|group| {
        matches!(
            group.engine.as_str(),
            "python" | "node" | "wasmtime" | "llama.cpp" | "onnxruntime"
        ) || matches!(
            group.format.as_str(),
            "python" | "wasm" | "container" | "binary"
        )
    }) {
        CodeExecutionMode::Sandboxed
    } else {
        CodeExecutionMode::None
    }
}

fn risk_level_for_permissions(
    permissions: &[PermissionRequest],
    code_execution: &CodeExecutionMode,
) -> RiskLevel {
    if *code_execution == CodeExecutionMode::UnsandboxedRequired
        || permissions.iter().any(|permission| {
            matches!(
                permission.name.as_str(),
                "local.shell" | "local.docker" | "wallet.sign"
            )
        })
    {
        return RiskLevel::Blocked;
    }

    if permissions.iter().any(|permission| {
        matches!(
            permission.name.as_str(),
            "network.http"
                | "network.websocket"
                | "user.files.read"
                | "user.files.write"
                | "microphone.read"
                | "camera.read"
                | "wallet.connect"
                | "clipboard.read"
                | "clipboard.write"
                | "receipt.public-evidence"
                | "swarm.write"
        )
    }) {
        return RiskLevel::Medium;
    }

    match code_execution {
        CodeExecutionMode::Sandboxed => RiskLevel::Medium,
        CodeExecutionMode::None => RiskLevel::Low,
        CodeExecutionMode::UnsandboxedRequired => RiskLevel::Blocked,
    }
}

fn permission_summaries(
    permissions: &[PermissionRequest],
    sandbox_requirements: &[SandboxRequirementV1],
) -> Vec<PermissionSummaryV1> {
    permissions
        .iter()
        .map(|permission| {
            let definition = permission_definition(&permission.name);
            PermissionSummaryV1 {
                name: permission.name.clone(),
                purpose: permission.purpose.clone(),
                required: permission.required,
                category: definition.category,
                severity: definition.severity,
                default_action: definition.default_action,
                consent_required: permission_requires_consent(&permission.name),
                default_denied: permission_default_denied(&permission.name),
                sandbox_required: sandbox_requirements
                    .iter()
                    .any(|requirement| requirement_applies_to_permission(requirement, permission)),
                limits: permission.limits.clone(),
            }
        })
        .collect()
}

fn permission_requires_consent(name: &str) -> bool {
    matches!(
        name,
        "network.http"
            | "network.websocket"
            | "swarm.write"
            | "user.files.read"
            | "user.files.write"
            | "microphone.read"
            | "camera.read"
            | "wallet.connect"
            | "wallet.sign"
            | "clipboard.read"
            | "clipboard.write"
            | "receipt.public-evidence"
    )
}

fn permission_default_denied(name: &str) -> bool {
    matches!(name, "local.shell" | "local.docker" | "wallet.sign")
}

fn requirement_applies_to_permission(
    requirement: &SandboxRequirementV1,
    permission: &PermissionRequest,
) -> bool {
    let text = format!("{} {}", requirement.environment, requirement.requirement);
    match permission.name.as_str() {
        "network.http" | "network.websocket" => text.contains("network"),
        "user.files.read" | "user.files.write" => text.contains("file"),
        "wallet.connect" | "wallet.sign" => text.contains("wallet"),
        "local.shell" | "local.docker" => {
            text.contains("process") || text.contains("sandbox") || text.contains("local")
        }
        _ => requirement.environment == "all",
    }
}

fn sandbox_requirements(
    manifest: &PermissionManifestV1,
    restrictions: &Value,
) -> Vec<SandboxRequirementV1> {
    let mut requirements = vec![
        requirement("browser", "run package code in worker/wasm sandbox", true),
        requirement(
            "local",
            "deny undeclared filesystem and process access",
            true,
        ),
        requirement(
            "remote",
            "isolate each job from runner host credentials",
            true,
        ),
    ];

    for permission in &manifest.permissions {
        match permission.name.as_str() {
            "network.http" | "network.websocket" => requirements.push(requirement(
                "all",
                "enforce declared network host allowlist",
                has_allowed_hosts(&permission.limits),
            )),
            "user.files.read" | "user.files.write" => requirements.push(requirement(
                "browser-local",
                "restrict file access to explicit user-selected files",
                permission
                    .limits
                    .get("userSelectedOnly")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            )),
            "wallet.connect" | "wallet.sign" => requirements.push(requirement(
                "browser",
                "require per-call wallet consent",
                true,
            )),
            "local.shell" | "local.docker" => requirements.push(requirement(
                "local",
                "block unsandboxed process execution outside developer mode",
                false,
            )),
            _ => {}
        }
    }

    if restrictions
        .get("unknownRequiredPermissions")
        .and_then(Value::as_str)
        .is_some()
    {
        requirements.push(requirement(
            "all",
            "block unknown required permissions until reviewed",
            true,
        ));
    }

    requirements
}

fn permission_manifest_v2_warnings(
    permission_manifest: &PermissionManifestV1,
    policy_decision: &PolicyDecisionV1,
    sandbox_requirements: &[SandboxRequirementV1],
) -> Vec<String> {
    let mut warnings = inspection_warnings(permission_manifest, policy_decision);
    for permission in &permission_manifest.permissions {
        match permission.name.as_str() {
            "network.http" | "network.websocket" if !has_allowed_hosts(&permission.limits) => {
                warnings.push(format!(
                    "Permission {} does not declare allowedHosts; runtime must block outbound network until an allowlist is supplied",
                    permission.name
                ));
            }
            "wallet.connect" | "wallet.sign" => {
                warnings.push(format!(
                    "Permission {} requires explicit per-call wallet consent",
                    permission.name
                ));
            }
            "local.shell" | "local.docker" => {
                warnings.push(format!(
                    "Permission {} requires a tool grant and is denied outside developer-reviewed sandboxes",
                    permission.name
                ));
            }
            _ => {}
        }
    }
    if sandbox_requirements
        .iter()
        .any(|requirement| !requirement.enforced)
    {
        warnings.push(
            "One or more sandbox requirements are not enforceable by the current local policy"
                .to_string(),
        );
    }
    warnings
}

fn inspection_warnings(
    permission_manifest: &PermissionManifestV1,
    policy_decision: &PolicyDecisionV1,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if permission_manifest.permissions.is_empty() {
        warnings.push("Package declares no elevated permissions".to_string());
    }
    if permission_manifest.code_execution == CodeExecutionMode::Sandboxed {
        warnings.push("Package includes executable artifacts and requires sandboxing".to_string());
    }
    if policy_decision.decision == PolicyDecision::Deny {
        warnings.push("Default policy denies this package until reviewed".to_string());
    }
    warnings
}

fn canonical_permission_manifest_v2_id(manifest: &PermissionManifestV2) -> String {
    let mut value =
        serde_json::to_value(manifest).expect("permission manifest v2 should serialize");
    value["manifestId"] = Value::String(String::new());
    format!("permission-manifest-v2:{}", hash_canonical_json(&value))
}

fn canonical_risk_inspection_report_id(report: &RiskInspectionReportV1) -> String {
    let mut value = serde_json::to_value(report).expect("risk inspection report should serialize");
    value["reportId"] = Value::String(String::new());
    format!("risk-inspection-report:{}", hash_canonical_json(&value))
}

pub fn canonical_policy_decision_id(policy_decision: &PolicyDecisionV1) -> String {
    let value = serde_json::to_value(policy_decision).expect("policy decision should serialize");
    format!("policy-decision:{}", hash_canonical_json(&value))
}

pub fn canonical_consent_record_id(record: &ConsentRecordV1) -> String {
    let mut value = serde_json::to_value(record).expect("consent record should serialize");
    value["consentId"] = Value::String(String::new());
    format!("consent-record:{}", hash_canonical_json(&value))
}

pub fn canonical_tool_permission_grant_id(grant: &ToolPermissionGrantV1) -> String {
    let mut value = serde_json::to_value(grant).expect("tool permission grant should serialize");
    value["grantId"] = Value::String(String::new());
    format!("tool-permission-grant:{}", hash_canonical_json(&value))
}

fn has_allowed_hosts(limits: &Value) -> bool {
    limits
        .get("allowedHosts")
        .and_then(Value::as_array)
        .is_some_and(|hosts| !hosts.is_empty())
}

fn requirement(
    environment: impl Into<String>,
    requirement: impl Into<String>,
    enforced: bool,
) -> SandboxRequirementV1 {
    SandboxRequirementV1 {
        environment: environment.into(),
        requirement: requirement.into(),
        enforced,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ArtifactGroup, ArtifactMinimum, LicenseInfo, LicenseType, PackageKind, Publisher,
    };
    use serde_json::{Value, json};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn no_permissions_are_low_risk() {
        let manifest = package(Vec::new());

        let inspection = inspect_package_policy(&manifest, "bzz://pkg", Some("runner".to_string()));

        assert_eq!(inspection.permission_manifest.risk_level, RiskLevel::Low);
        assert_eq!(inspection.policy_decision.decision, PolicyDecision::Allow);
    }

    #[test]
    fn shell_permission_is_blocked() {
        let manifest = package(vec![PermissionRequest {
            name: "local.shell".to_string(),
            purpose: Some("run scripts".to_string()),
            required: true,
            limits: json!({}),
        }]);

        let inspection = inspect_package_policy(&manifest, "bzz://pkg", Some("runner".to_string()));

        assert_eq!(
            inspection.permission_manifest.risk_level,
            RiskLevel::Blocked
        );
        assert_eq!(inspection.policy_decision.decision, PolicyDecision::Deny);
    }

    #[test]
    fn swarm_write_requires_explicit_approval() {
        let manifest = package(vec![PermissionRequest {
            name: "swarm.write".to_string(),
            purpose: Some("publish generated files".to_string()),
            required: false,
            limits: json!({}),
        }]);

        let inspection = inspect_package_policy(&manifest, "bzz://pkg", Some("runner".to_string()));

        assert_eq!(inspection.policy_decision.decision, PolicyDecision::AskUser);
        assert!(
            policy_execution_block_reason(&inspection.policy_decision)
                .unwrap()
                .contains("explicit user approval")
        );
    }

    #[test]
    fn private_cache_write_requires_runtime_restrictions() {
        let manifest = package(vec![PermissionRequest {
            name: "private-cache.write".to_string(),
            purpose: Some("cache encrypted package data".to_string()),
            required: false,
            limits: json!({}),
        }]);

        let inspection = inspect_package_policy(&manifest, "bzz://pkg", Some("runner".to_string()));

        assert_eq!(
            inspection.policy_decision.decision,
            PolicyDecision::AllowWithRestrictions
        );
        assert_eq!(
            inspection
                .policy_decision
                .restrictions
                .get("cache")
                .and_then(Value::as_str),
            Some("runner-controlled-quota")
        );
    }

    #[test]
    fn permission_manifest_v2_marks_wallet_consent_and_default_denial() {
        let manifest = package(vec![
            PermissionRequest {
                name: "wallet.connect".to_string(),
                purpose: Some("read account".to_string()),
                required: true,
                limits: json!({}),
            },
            PermissionRequest {
                name: "wallet.sign".to_string(),
                purpose: Some("sign settlement".to_string()),
                required: true,
                limits: json!({}),
            },
        ]);

        let report = inspect_package_policy_v2(
            &manifest,
            "bzz://wallet-package",
            Some("browser-runner".to_string()),
        );

        assert_eq!(report.schema_version, RISK_INSPECTION_REPORT_SCHEMA_VERSION);
        assert!(report.report_id.starts_with("risk-inspection-report:"));
        assert!(
            report
                .consent_required
                .contains(&"wallet.connect".to_string())
        );
        assert!(report.consent_required.contains(&"wallet.sign".to_string()));
        assert!(report.default_denied.contains(&"wallet.sign".to_string()));
        assert_eq!(report.policy_decision.decision, PolicyDecision::Deny);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("per-call wallet consent"))
        );
    }

    #[test]
    fn permission_manifest_v2_warns_for_network_without_allowlist() {
        let manifest = package(vec![PermissionRequest {
            name: "network.http".to_string(),
            purpose: Some("call remote tool".to_string()),
            required: true,
            limits: json!({}),
        }]);

        let report = inspect_package_policy_v2(&manifest, "bzz://agent", None);

        assert!(
            report
                .consent_required
                .contains(&"network.http".to_string())
        );
        assert_eq!(report.policy_decision.decision, PolicyDecision::AskUser);
        assert!(report.sandbox_requirements.iter().any(|requirement| {
            requirement
                .requirement
                .contains("declared network host allowlist")
                && !requirement.enforced
        }));
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("does not declare allowedHosts"))
        );
    }

    #[test]
    fn shell_permission_requires_tool_grant_and_unenforced_sandbox() {
        let manifest = package(vec![PermissionRequest {
            name: "local.shell".to_string(),
            purpose: Some("run repo tests".to_string()),
            required: true,
            limits: json!({}),
        }]);

        let report = inspect_package_policy_v2(&manifest, "bzz://tool-agent", None);

        assert_eq!(report.permission_manifest.risk_level, RiskLevel::Blocked);
        assert!(report.default_denied.contains(&"local.shell".to_string()));
        assert!(
            report
                .tool_permission_grants_required
                .contains(&"local.shell".to_string())
        );
        assert!(
            report
                .sandbox_requirements
                .iter()
                .any(|requirement| !requirement.enforced)
        );
    }

    #[test]
    fn consent_and_tool_grant_ids_are_stable() {
        let manifest = package(vec![PermissionRequest {
            name: "swarm.write".to_string(),
            purpose: Some("publish result".to_string()),
            required: false,
            limits: json!({}),
        }]);
        let decision =
            evaluate_package_policy(&manifest, "bzz://pkg", Some("browser-runner".to_string()));

        let consent = consent_record_from_policy_decision(
            &decision,
            "0xUser",
            vec!["swarm.write".to_string()],
            ConsentDecisionV1::Granted,
            "approved publish",
            "2026-06-05T00:00:00Z",
            None,
        );
        let same_consent = consent_record_from_policy_decision(
            &decision,
            "0xUser",
            vec!["swarm.write".to_string()],
            ConsentDecisionV1::Granted,
            "approved publish",
            "2026-06-05T00:00:00Z",
            None,
        );
        assert_eq!(consent.consent_id, same_consent.consent_id);
        assert_eq!(
            consent.policy_decision_id,
            canonical_policy_decision_id(&decision)
        );

        let grant = tool_permission_grant(
            "bzz://repo-search-tool",
            "hivemind/policy-test",
            "workflow-runner",
            vec!["user.files.read".to_string()],
            json!({ "paths": ["docs/"] }),
            "2026-06-05T00:00:00Z",
            None,
        );
        assert_eq!(grant.grant_id, canonical_tool_permission_grant_id(&grant));
    }

    #[test]
    fn trust_policy_store_writes_lists_and_looks_up_signed_policy() {
        let root = temp_dir("trust-policy-store");
        let mut policy = TrustPolicyV1::local_only("policy-store-test");
        hivemind_core::sign_trust_policy(&mut policy).unwrap();

        let write = write_trust_policy_record(&root, &policy).unwrap();
        assert!(Path::new(&write.path).exists());
        assert!(write.verification.valid);

        let summary = list_trust_policy_records(&root).unwrap();
        assert_eq!(summary.policy_count, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.signature_present_count, 1);
        assert_eq!(summary.records[0].policy_id, policy.policy_id);

        let lookup = get_trust_policy_record(&root, &policy.policy_id)
            .unwrap()
            .unwrap();
        assert_eq!(lookup.trust_policy.policy_id, policy.policy_id);
        assert!(lookup.verification.valid);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn trust_policy_store_rejects_invalid_writes_but_lists_invalid_files() {
        let root = temp_dir("trust-policy-invalid");
        let mut policy = TrustPolicyV1::local_only("policy-store-test");
        policy.policy_id = "wrong-policy-id".to_string();

        let error = write_trust_policy_record(&root, &policy).unwrap_err();
        assert!(error.to_string().contains("invalid"));

        fs::create_dir_all(root.join("manual")).unwrap();
        fs::write(
            root.join("manual").join("invalid.json"),
            serde_json::to_vec_pretty(&policy).unwrap(),
        )
        .unwrap();
        fs::write(
            root.join("not-a-policy.json"),
            br#"{"schemaVersion":"other.schema.v1"}"#,
        )
        .unwrap();

        let summary = list_trust_policy_records(&root).unwrap();
        assert_eq!(summary.policy_count, 1);
        assert_eq!(summary.valid_count, 0);
        assert_eq!(summary.invalid_count, 1);
        assert_eq!(summary.records[0].issue_count, 1);

        let lookup = get_trust_policy_record(&root, "wrong-policy-id")
            .unwrap()
            .unwrap();
        assert!(!lookup.verification.valid);

        let _ = fs::remove_dir_all(root);
    }

    fn package(permissions: Vec<PermissionRequest>) -> PackageManifestV1 {
        PackageManifestV1 {
            schema_version: "swarm-ai.package.v1".to_string(),
            package_id: "hivemind/policy-test".to_string(),
            kind: PackageKind::Model,
            name: "Policy Test".to_string(),
            version: "0.1.0".to_string(),
            publisher: Publisher {
                address: "0x0".to_string(),
                display_name: "Policy".to_string(),
                publisher_profile_ref: None,
            },
            capabilities: vec!["embedding".to_string()],
            artifact_groups: vec![ArtifactGroup {
                id: "local".to_string(),
                target: "local-mock".to_string(),
                engine: "rust-mock".to_string(),
                format: "json".to_string(),
                paths: vec!["model/config.json".to_string()],
                total_bytes: 1,
                sha256: "0".repeat(64),
                minimum: ArtifactMinimum {
                    memory_mb: Some(1),
                    webgpu: Some(false),
                    disk_mb: None,
                },
            }],
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            permissions,
            license: LicenseInfo {
                license_type: LicenseType::Open,
                name: Some("Apache-2.0".to_string()),
                url: None,
            },
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hivemind-policy-{name}-{nanos}"))
    }
}
