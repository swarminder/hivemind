use chrono::{DateTime, Utc};
pub use hivemind_core::{
    ACCESS_EVALUATION_RESULT_SCHEMA_VERSION, ACCESS_GRANT_V3_SCHEMA_VERSION,
    ACCESS_POLICY_V2_SCHEMA_VERSION, ACCESS_POLICY_V2_VERIFICATION_SCHEMA_VERSION,
    ASSET_ACCESS_RULE_SCHEMA_VERSION, ASSET_ACCESS_RULE_V2_SCHEMA_VERSION, AccessControlMode,
    AccessControlV1, AccessDecision, AccessEvaluationResultV1, AccessEvaluationV1,
    AccessGrantRevocationV1, AccessGrantV1, AccessGrantV2, AccessGrantV3, AccessMethod,
    AccessPaymentRequirementV1, AccessPolicyV1, AccessPolicyV1Context, AccessPolicyV2,
    AccessPolicyV2VerificationV1, AccessPolicyVerificationV1, AccessPrivacyRequirementV1,
    AccessProofV1, AccessRequestV1, AccessRevocationListV1, AccessRightV1, AccessScopeV1,
    AccessSubjectTypeV1, AccessSubjectV1, AccessVerificationRequirementV1, AssetAccessRuleV1,
    AssetAccessRuleV2, LICENSE_POLICY_V2_SCHEMA_VERSION, LicensePolicyV1, LicensePolicyV2,
    PAID_ACCESS_QUOTE_SCHEMA_VERSION, PaidAccessQuoteV1, access_evaluation_result,
    access_grant_v3_from_v2, access_policy_v2_from_license_policy,
    access_policy_v2_from_license_policy_v2, access_policy_v2_from_license_policy_with_context,
    asset_access_rule_v2_from_v1, asset_access_rules_v2_from_access_policy,
    canonical_access_policy_v2_id, canonical_asset_access_rule_v2_id,
    expected_access_policy_v2_signature, license_policy_v2_from_license_policy,
    license_policy_v2_from_manifest, paid_access_quote, paid_access_quote_with_listing_ref,
    sign_access_policy_v2, verify_access_policy_v2,
};
use hivemind_core::{
    PackageManifestV1, ValidationIssue, canonicalize_json, hash_canonical_json,
    license_policy_from_manifest,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEV_GRANT_SIGNATURE_PREFIX: &str = "dev-signature-v1";
const DEV_GRANT_V2_SIGNATURE_PREFIX: &str = "dev-access-grant-v2-signature-v1";
const DEV_GRANT_V3_SIGNATURE_PREFIX: &str = "dev-access-grant-v3-signature-v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantV2VerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "grantId")]
    pub grant_id: String,
    #[serde(rename = "expectedGrantId")]
    pub expected_grant_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantV3VerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "grantId")]
    pub grant_id: String,
    #[serde(rename = "expectedGrantId")]
    pub expected_grant_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantRevocationVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "expectedSignature")]
    pub expected_signature: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessRevocationListVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "revokedGrantIds")]
    pub revoked_grant_ids: Vec<String>,
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantIndexEntryV1 {
    #[serde(rename = "grantId")]
    pub grant_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub grantee: String,
    #[serde(rename = "runnerId", default)]
    pub runner_id: Option<String>,
    #[serde(rename = "allowedUses")]
    pub allowed_uses: Vec<String>,
    #[serde(rename = "expiresAt", default)]
    pub expires_at: Option<String>,
    #[serde(rename = "accessMethod")]
    pub access_method: AccessMethod,
    pub issuer: String,
    #[serde(rename = "grantPath")]
    pub grant_path: String,
    pub verification: AccessGrantVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "grantCount")]
    pub grant_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub grants: Vec<AccessGrantIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "grantId")]
    pub grant_id: String,
    #[serde(rename = "grantPath")]
    pub grant_path: String,
    pub grant: AccessGrantV1,
    pub verification: AccessGrantVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantRevocationIndexEntryV1 {
    #[serde(rename = "revocationId")]
    pub revocation_id: String,
    #[serde(rename = "grantId")]
    pub grant_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub grantee: String,
    #[serde(rename = "revokedBy")]
    pub revoked_by: String,
    pub reason: String,
    #[serde(rename = "revokedAt")]
    pub revoked_at: String,
    #[serde(rename = "revocationPath")]
    pub revocation_path: String,
    pub verification: AccessGrantRevocationVerificationV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantRevocationStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "revocationCount")]
    pub revocation_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    pub revocations: Vec<AccessGrantRevocationIndexEntryV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantRevocationLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "revocationId")]
    pub revocation_id: String,
    #[serde(rename = "revocationPath")]
    pub revocation_path: String,
    pub revocation: AccessGrantRevocationV1,
    pub verification: AccessGrantRevocationVerificationV1,
}

pub fn access_request(
    request_id: impl Into<String>,
    package_id: impl Into<String>,
    package_ref: impl Into<String>,
    requester: impl Into<String>,
    requested_use: impl Into<String>,
    runner_id: Option<String>,
    proofs: Vec<AccessProofV1>,
) -> AccessRequestV1 {
    AccessRequestV1 {
        schema_version: "swarm-ai.access-request.v1".to_string(),
        request_id: request_id.into(),
        package_id: package_id.into(),
        package_ref: package_ref.into(),
        requester: requester.into(),
        requested_use: requested_use.into(),
        runner_id,
        proofs,
    }
}

pub fn open_access_grant(
    package_id: impl Into<String>,
    package_ref: impl Into<String>,
    grantee: impl Into<String>,
) -> AccessGrantV1 {
    let mut grant = AccessGrantV1 {
        schema_version: "swarm-ai.access-grant.v1".to_string(),
        grant_id: "dev-open-access".to_string(),
        package_id: package_id.into(),
        package_ref: package_ref.into(),
        grantee: grantee.into(),
        runner_id: None,
        allowed_uses: vec![
            "personal".to_string(),
            "commercial".to_string(),
            "research".to_string(),
            "runner-service".to_string(),
            "validation".to_string(),
        ],
        expires_at: None,
        access_method: AccessMethod::Open,
        encrypted_access_ref: None,
        issuer: "local-dev".to_string(),
        signature: String::new(),
    };
    sign_access_grant(&mut grant);
    grant
}

pub fn dev_access_grant(
    policy: &LicensePolicyV1,
    grantee: impl Into<String>,
    requested_use: impl Into<String>,
    runner_id: Option<String>,
    expires_at: Option<String>,
) -> AccessGrantV1 {
    dev_access_grant_issued_by(
        policy,
        grantee,
        requested_use,
        runner_id,
        expires_at,
        "local-dev",
    )
}

pub fn dev_access_grant_issued_by(
    policy: &LicensePolicyV1,
    grantee: impl Into<String>,
    requested_use: impl Into<String>,
    runner_id: Option<String>,
    expires_at: Option<String>,
    issuer: impl Into<String>,
) -> AccessGrantV1 {
    let requested_use = requested_use.into();
    let mut grant = AccessGrantV1 {
        schema_version: "swarm-ai.access-grant.v1".to_string(),
        grant_id: format!(
            "dev-grant-{}-{}",
            safe_id_component(&policy.package_id),
            requested_use
        ),
        package_id: policy.package_id.clone(),
        package_ref: policy.package_ref.clone(),
        grantee: grantee.into(),
        runner_id,
        allowed_uses: vec![requested_use],
        expires_at,
        access_method: match policy.access_control.mode {
            hivemind_core::AccessControlMode::None => AccessMethod::Open,
            hivemind_core::AccessControlMode::Act => AccessMethod::Act,
            hivemind_core::AccessControlMode::EncryptedRef => AccessMethod::EncryptedReference,
            hivemind_core::AccessControlMode::ExternalLicenseServer => AccessMethod::External,
        },
        encrypted_access_ref: None,
        issuer: issuer.into(),
        signature: String::new(),
    };
    sign_access_grant(&mut grant);
    grant
}

pub fn sign_access_grant(grant: &mut AccessGrantV1) {
    grant.signature = expected_access_grant_signature(grant);
}

pub fn sign_access_grant_with_identity(
    grant: &mut AccessGrantV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != grant.issuer {
        anyhow::bail!(
            "identity subject {} does not match access grant issuer {}",
            identity.subject,
            grant.issuer
        );
    }
    let envelope =
        hivemind_identity::sign_value(identity, "access-grant", &grant_signing_value(grant))?;
    grant.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    Ok(envelope)
}

pub fn expected_access_grant_signature(grant: &AccessGrantV1) -> String {
    dev_signature("access-grant", &grant.issuer, &grant_signing_value(grant))
}

pub fn verify_access_grant(grant: &AccessGrantV1) -> AccessGrantVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if grant.schema_version != "swarm-ai.access-grant.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.access-grant.v1",
        ));
    }
    if grant.grant_id.trim().is_empty() {
        issues.push(issue("$.grantId", "Access grant id is required"));
    }
    if grant.package_id.trim().is_empty() || !grant.package_id.contains('/') {
        issues.push(issue(
            "$.packageId",
            "Package id must use publisher/name form",
        ));
    }
    if !grant.package_ref.starts_with("bzz://") {
        issues.push(issue(
            "$.packageRef",
            "Access grant packageRef must be bzz://",
        ));
    }
    if grant.grantee.trim().is_empty() {
        issues.push(issue("$.grantee", "Access grant grantee is required"));
    }
    if grant.allowed_uses.is_empty() {
        issues.push(issue(
            "$.allowedUses",
            "Access grant must allow at least one use",
        ));
    }
    if grant.issuer.trim().is_empty() {
        issues.push(issue("$.issuer", "Access grant issuer is required"));
    }
    let mut expected_signature = expected_access_grant_signature(grant);
    if grant
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &grant.signature,
            "access-grant",
            &grant_signing_value(grant),
            Some(&grant.issuer),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if grant.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Access grant signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production wallet signing",
        ));
    }
    AccessGrantVerificationV1 {
        schema_version: "swarm-ai.access-grant-verification.v1".to_string(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339(),
    }
}

pub fn dev_access_grant_v2(
    issuer: impl Into<String>,
    grantee: impl Into<String>,
    scopes: Vec<AccessScopeV1>,
    subjects: Vec<AccessSubjectV1>,
    allowed_uses: Vec<String>,
    expires_at: Option<String>,
) -> serde_json::Result<AccessGrantV2> {
    let mut grant = AccessGrantV2 {
        schema_version: "hivemind.access-grant.v2".to_string(),
        grant_id: "access-grant-pending".to_string(),
        issuer: issuer.into(),
        grantee: grantee.into(),
        scopes,
        subjects,
        allowed_uses,
        constraints: json!({}),
        issued_at: Utc::now().to_rfc3339(),
        expires_at,
        runner_id: None,
        revocation_list_ref: None,
        payment_ref: None,
        settlement_ref: None,
        evidence_refs: Vec::new(),
        signatures: Vec::new(),
    };
    sign_access_grant_v2(&mut grant)?;
    Ok(grant)
}

pub fn canonical_access_grant_v2_id(grant: &AccessGrantV2) -> serde_json::Result<String> {
    Ok(format!(
        "access-grant-{}",
        &hash_canonical_json(&canonicalize_json(&access_grant_v2_signing_value(grant)?))[..24]
    ))
}

pub fn expected_access_grant_v2_signature(grant: &AccessGrantV2) -> serde_json::Result<String> {
    let value = json!({
        "label": "access-grant-v2",
        "issuer": grant.issuer,
        "payload": access_grant_v2_signing_value(grant)?,
    });
    Ok(format!(
        "{DEV_GRANT_V2_SIGNATURE_PREFIX}:{}",
        &hash_canonical_json(&canonicalize_json(&value))[..32]
    ))
}

pub fn sign_access_grant_v2(grant: &mut AccessGrantV2) -> serde_json::Result<String> {
    grant.grant_id = canonical_access_grant_v2_id(grant)?;
    let signature = expected_access_grant_v2_signature(grant)?;
    grant
        .signatures
        .retain(|value| !value.starts_with(DEV_GRANT_V2_SIGNATURE_PREFIX));
    grant.signatures.push(signature.clone());
    Ok(signature)
}

pub fn verify_access_grant_v2(grant: &AccessGrantV2) -> AccessGrantV2VerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_grant_id =
        canonical_access_grant_v2_id(grant).unwrap_or_else(|_| "access-grant-invalid".to_string());
    let expected_signature = expected_access_grant_v2_signature(grant)
        .unwrap_or_else(|_| format!("{DEV_GRANT_V2_SIGNATURE_PREFIX}:invalid"));

    if grant.schema_version != "hivemind.access-grant.v2" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.access-grant.v2",
        ));
    }
    if grant.grant_id.trim().is_empty() {
        issues.push(issue("$.grantId", "Access grant id is required"));
    } else if grant.grant_id != expected_grant_id {
        issues.push(issue(
            "$.grantId",
            "Access grant id does not match canonical grant content",
        ));
    }
    if grant.issuer.trim().is_empty() {
        issues.push(issue("$.issuer", "Access grant issuer is required"));
    }
    if grant.grantee.trim().is_empty() {
        issues.push(issue("$.grantee", "Access grant grantee is required"));
    }
    validate_access_scopes(&grant.scopes, &grant.subjects, &mut issues);
    validate_access_subjects(&grant.subjects, &mut issues, &mut warnings);
    validate_access_grant_timestamps(grant, &mut issues);
    validate_access_grant_refs(grant, &mut warnings);
    if !grant.constraints.is_null() && !grant.constraints.is_object() {
        warnings.push(issue(
            "$.constraints",
            "Access grant constraints should be an object when present",
        ));
    }
    verify_access_grant_v2_signatures(
        &grant.signatures,
        &expected_signature,
        &mut issues,
        &mut warnings,
    );

    AccessGrantV2VerificationV1 {
        schema_version: "hivemind.access-grant-verification.v2".to_string(),
        grant_id: grant.grant_id.clone(),
        expected_grant_id,
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339(),
    }
}

pub fn dev_access_grant_v3(
    issuer: impl Into<String>,
    grantee: impl Into<String>,
    scopes: Vec<AccessScopeV1>,
    subjects: Vec<AccessSubjectV1>,
    asset_rules: Vec<AssetAccessRuleV2>,
    allowed_uses: Vec<String>,
    privacy_tier: Option<hivemind_core::PrivacyTier>,
    expires_at: Option<String>,
) -> serde_json::Result<AccessGrantV3> {
    let grant_v2 = AccessGrantV2 {
        schema_version: "hivemind.access-grant.v2".to_string(),
        grant_id: "access-grant-pending".to_string(),
        issuer: issuer.into(),
        grantee: grantee.into(),
        scopes,
        subjects,
        allowed_uses,
        constraints: json!({}),
        issued_at: Utc::now().to_rfc3339(),
        expires_at,
        runner_id: None,
        revocation_list_ref: None,
        payment_ref: None,
        settlement_ref: None,
        evidence_refs: Vec::new(),
        signatures: Vec::new(),
    };
    let mut grant = access_grant_v3_from_v2(&grant_v2, asset_rules, privacy_tier, Vec::new());
    sign_access_grant_v3(&mut grant)?;
    Ok(grant)
}

pub fn canonical_access_grant_v3_id(grant: &AccessGrantV3) -> serde_json::Result<String> {
    Ok(format!(
        "access-grant-v3-{}",
        &hash_canonical_json(&canonicalize_json(&access_grant_v3_signing_value(grant)?))[..24]
    ))
}

pub fn expected_access_grant_v3_signature(grant: &AccessGrantV3) -> serde_json::Result<String> {
    let value = json!({
        "label": "access-grant-v3",
        "issuer": grant.issuer,
        "payload": access_grant_v3_signing_value(grant)?,
    });
    Ok(format!(
        "{DEV_GRANT_V3_SIGNATURE_PREFIX}:{}",
        &hash_canonical_json(&canonicalize_json(&value))[..32]
    ))
}

pub fn sign_access_grant_v3(grant: &mut AccessGrantV3) -> serde_json::Result<String> {
    grant.grant_id = canonical_access_grant_v3_id(grant)?;
    let signature = expected_access_grant_v3_signature(grant)?;
    grant
        .signatures
        .retain(|value| !value.starts_with(DEV_GRANT_V3_SIGNATURE_PREFIX));
    grant.signatures.push(signature.clone());
    Ok(signature)
}

pub fn verify_access_grant_v3(grant: &AccessGrantV3) -> AccessGrantV3VerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_grant_id = canonical_access_grant_v3_id(grant)
        .unwrap_or_else(|_| "access-grant-v3-invalid".to_string());
    let expected_signature = expected_access_grant_v3_signature(grant)
        .unwrap_or_else(|_| format!("{DEV_GRANT_V3_SIGNATURE_PREFIX}:invalid"));

    if grant.schema_version != ACCESS_GRANT_V3_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {ACCESS_GRANT_V3_SCHEMA_VERSION}"),
        ));
    }
    if grant.object_kind != "access_grant" {
        issues.push(issue(
            "$.objectKind",
            "Expected objectKind to be access_grant",
        ));
    }
    if grant.grant_id.trim().is_empty() {
        issues.push(issue("$.grantId", "Access grant id is required"));
    } else if grant.grant_id != expected_grant_id {
        issues.push(issue(
            "$.grantId",
            "Access grant v3 id does not match canonical grant content",
        ));
    }
    if grant.issuer.trim().is_empty() {
        issues.push(issue("$.issuer", "Access grant issuer is required"));
    }
    if grant.grantee.trim().is_empty() {
        issues.push(issue("$.grantee", "Access grant grantee is required"));
    }
    validate_access_scopes(&grant.scopes, &grant.subjects, &mut issues);
    validate_access_subjects(&grant.subjects, &mut issues, &mut warnings);
    validate_access_grant_v3_timestamps(grant, &mut issues);
    validate_access_grant_v3_refs(grant, &mut warnings);
    validate_asset_rules_v3(grant, &mut issues, &mut warnings);
    if grant
        .asset_rules
        .iter()
        .any(|rule| rule.payment_requirement.required)
        && grant.payment_ref.is_none()
        && grant.payment_evidence_refs.is_empty()
    {
        warnings.push(issue(
            "$.paymentEvidenceRefs",
            "Paid asset grant should include paymentRef or paymentEvidenceRefs",
        ));
    }
    if grant
        .asset_rules
        .iter()
        .any(|rule| rule.privacy_requirement.runner_grant_required)
        && grant.privacy_tier.is_none()
    {
        warnings.push(issue(
            "$.privacyTier",
            "Protected asset grant should declare the privacy tier it authorizes",
        ));
    }
    verify_access_grant_v3_signatures(
        &grant.signatures,
        &expected_signature,
        &mut issues,
        &mut warnings,
    );

    AccessGrantV3VerificationV1 {
        schema_version: "hivemind.access-grant-verification.v3".to_string(),
        grant_id: grant.grant_id.clone(),
        expected_grant_id,
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339(),
    }
}

pub fn read_access_grant(path: &Path) -> anyhow::Result<AccessGrantV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse access grant JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_access_grant(grants_dir: &Path, grant: &AccessGrantV1) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(grants_dir)?;
    let path = grants_dir.join(format!("{}.json", safe_id_component(&grant.grant_id)));
    fs::write(&path, serde_json::to_vec_pretty(grant)?)?;
    Ok(path)
}

pub fn get_access_grant(
    grants_dir: &Path,
    grant_id: &str,
) -> anyhow::Result<Option<AccessGrantLookupV1>> {
    let direct_path = grants_dir.join(format!("{}.json", safe_id_component(grant_id)));
    if direct_path.exists() {
        let grant = read_access_grant(&direct_path)?;
        if grant.grant_id == grant_id {
            return Ok(Some(access_grant_lookup(grant, direct_path)));
        }
    }

    if !grants_dir.exists() {
        return Ok(None);
    }

    for entry in fs::read_dir(grants_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let grant = read_access_grant(&path)?;
            if grant.grant_id == grant_id {
                return Ok(Some(access_grant_lookup(grant, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_access_grants(grants_dir: &Path) -> anyhow::Result<AccessGrantStoreSummaryV1> {
    let mut grants = Vec::new();
    if grants_dir.exists() {
        for entry in fs::read_dir(grants_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let grant = read_access_grant(&path)?;
                grants.push(access_grant_index_entry(&grant, path.display().to_string()));
            }
        }
    }
    grants.sort_by(|left, right| {
        left.package_ref
            .cmp(&right.package_ref)
            .then(left.grantee.cmp(&right.grantee))
            .then(left.grant_id.cmp(&right.grant_id))
    });
    let valid_count = grants
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    Ok(AccessGrantStoreSummaryV1 {
        schema_version: "swarm-ai.access-grant-store-summary.v1".to_string(),
        root: grants_dir.display().to_string(),
        grant_count: grants.len(),
        valid_count,
        invalid_count: grants.len().saturating_sub(valid_count),
        grants,
    })
}

pub fn revoke_access_grant(
    grant: &AccessGrantV1,
    revoked_by: impl Into<String>,
    reason: impl Into<String>,
) -> AccessGrantRevocationV1 {
    let revoked_by = revoked_by.into();
    let reason = reason.into();
    let revoked_at = Utc::now().to_rfc3339();
    let revocation_seed = json!({
        "grantId": grant.grant_id,
        "packageId": grant.package_id,
        "packageRef": grant.package_ref,
        "grantee": grant.grantee,
        "revokedBy": revoked_by,
        "reason": reason,
        "revokedAt": revoked_at,
    });
    let mut revocation = AccessGrantRevocationV1 {
        schema_version: "swarm-ai.access-grant-revocation.v1".to_string(),
        revocation_id: format!(
            "revocation-{}",
            hash_canonical_json(&canonicalize_json(&revocation_seed))
        ),
        grant_id: grant.grant_id.clone(),
        package_id: grant.package_id.clone(),
        package_ref: grant.package_ref.clone(),
        grantee: grant.grantee.clone(),
        revoked_by,
        reason,
        revoked_at,
        signature: String::new(),
    };
    sign_access_grant_revocation(&mut revocation);
    revocation
}

pub fn access_revocation_list(revocations: Vec<AccessGrantRevocationV1>) -> AccessRevocationListV1 {
    AccessRevocationListV1 {
        schema_version: "swarm-ai.access-revocation-list.v1".to_string(),
        generated_at: Utc::now().to_rfc3339(),
        revocations,
    }
}

pub fn sign_access_grant_revocation(revocation: &mut AccessGrantRevocationV1) {
    revocation.signature = expected_access_grant_revocation_signature(revocation);
}

pub fn sign_access_grant_revocation_with_identity(
    revocation: &mut AccessGrantRevocationV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != revocation.revoked_by {
        anyhow::bail!(
            "identity subject {} does not match access revocation authority {}",
            identity.subject,
            revocation.revoked_by
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "access-grant-revocation",
        &revocation_signing_value(revocation),
    )?;
    revocation.signature = hivemind_identity::encode_signature_envelope(&envelope)?;
    Ok(envelope)
}

pub fn expected_access_grant_revocation_signature(revocation: &AccessGrantRevocationV1) -> String {
    dev_signature(
        "access-grant-revocation",
        &revocation.revoked_by,
        &revocation_signing_value(revocation),
    )
}

pub fn verify_access_grant_revocation(
    revocation: &AccessGrantRevocationV1,
    grant: Option<&AccessGrantV1>,
) -> AccessGrantRevocationVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if revocation.schema_version != "swarm-ai.access-grant-revocation.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.access-grant-revocation.v1",
        ));
    }
    if revocation.revocation_id.trim().is_empty() {
        issues.push(issue("$.revocationId", "Access revocation id is required"));
    }
    if revocation.grant_id.trim().is_empty() {
        issues.push(issue("$.grantId", "Access revocation grant id is required"));
    }
    if revocation.package_id.trim().is_empty() || !revocation.package_id.contains('/') {
        issues.push(issue(
            "$.packageId",
            "Access revocation package id must use publisher/name form",
        ));
    }
    if !revocation.package_ref.starts_with("bzz://") {
        issues.push(issue(
            "$.packageRef",
            "Access revocation packageRef must be bzz://",
        ));
    }
    if revocation.grantee.trim().is_empty() {
        issues.push(issue("$.grantee", "Access revocation grantee is required"));
    }
    if revocation.revoked_by.trim().is_empty() {
        issues.push(issue(
            "$.revokedBy",
            "Access revocation authority is required",
        ));
    }
    if revocation.reason.trim().is_empty() {
        issues.push(issue("$.reason", "Access revocation reason is required"));
    }
    if DateTime::parse_from_rfc3339(&revocation.revoked_at).is_err() {
        issues.push(issue(
            "$.revokedAt",
            "Access revocation revokedAt is not RFC3339",
        ));
    }
    let mut expected_signature = expected_access_grant_revocation_signature(revocation);
    if revocation
        .signature
        .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
    {
        let verification = hivemind_identity::verify_value_signature_string(
            &revocation.signature,
            "access-grant-revocation",
            &revocation_signing_value(revocation),
            Some(&revocation.revoked_by),
        );
        expected_signature = format!("ed25519-payload-hash:{}", verification.payload_hash);
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(&signature_issue.path),
                signature_issue.message,
            ));
        }
    } else if revocation.signature != expected_signature {
        issues.push(issue(
            "$.signature",
            "Access revocation signature does not match canonical dev signature or Ed25519 identity envelope",
        ));
    } else {
        warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production wallet signing",
        ));
    }

    if let Some(grant) = grant {
        if revocation.grant_id != grant.grant_id {
            issues.push(issue(
                "$.grantId",
                "Access revocation grantId does not match grant",
            ));
        }
        if revocation.package_id != grant.package_id {
            issues.push(issue(
                "$.packageId",
                "Access revocation packageId does not match grant",
            ));
        }
        if revocation.package_ref != grant.package_ref {
            issues.push(issue(
                "$.packageRef",
                "Access revocation packageRef does not match grant",
            ));
        }
        if revocation.grantee != grant.grantee {
            issues.push(issue(
                "$.grantee",
                "Access revocation grantee does not match grant",
            ));
        }
    }

    AccessGrantRevocationVerificationV1 {
        schema_version: "swarm-ai.access-grant-revocation-verification.v1".to_string(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339(),
    }
}

pub fn read_access_grant_revocation(path: &Path) -> anyhow::Result<AccessGrantRevocationV1> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse access grant revocation JSON from {}: {error}",
            path.display()
        )
    })
}

pub fn write_access_grant_revocation(
    revocations_dir: &Path,
    revocation: &AccessGrantRevocationV1,
) -> anyhow::Result<PathBuf> {
    fs::create_dir_all(revocations_dir)?;
    let path = revocations_dir.join(format!(
        "{}.json",
        safe_id_component(&revocation.revocation_id)
    ));
    fs::write(&path, serde_json::to_vec_pretty(revocation)?)?;
    Ok(path)
}

pub fn get_access_grant_revocation(
    revocations_dir: &Path,
    revocation_id: &str,
) -> anyhow::Result<Option<AccessGrantRevocationLookupV1>> {
    let direct_path = revocations_dir.join(format!("{}.json", safe_id_component(revocation_id)));
    if direct_path.exists() {
        let revocation = read_access_grant_revocation(&direct_path)?;
        if revocation.revocation_id == revocation_id {
            return Ok(Some(access_grant_revocation_lookup(
                revocation,
                direct_path,
            )));
        }
    }

    if !revocations_dir.exists() {
        return Ok(None);
    }

    for entry in fs::read_dir(revocations_dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("json")
        {
            let revocation = read_access_grant_revocation(&path)?;
            if revocation.revocation_id == revocation_id {
                return Ok(Some(access_grant_revocation_lookup(revocation, path)));
            }
        }
    }
    Ok(None)
}

pub fn list_access_grant_revocations(
    revocations_dir: &Path,
) -> anyhow::Result<AccessGrantRevocationStoreSummaryV1> {
    let mut revocations = Vec::new();
    if revocations_dir.exists() {
        for entry in fs::read_dir(revocations_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file()
                && path.extension().and_then(|extension| extension.to_str()) == Some("json")
            {
                let revocation = read_access_grant_revocation(&path)?;
                revocations.push(access_grant_revocation_index_entry(
                    &revocation,
                    path.display().to_string(),
                ));
            }
        }
    }
    revocations.sort_by(|left, right| {
        left.package_ref
            .cmp(&right.package_ref)
            .then(left.revoked_at.cmp(&right.revoked_at))
            .then(left.revocation_id.cmp(&right.revocation_id))
    });
    let valid_count = revocations
        .iter()
        .filter(|entry| entry.verification.valid)
        .count();
    Ok(AccessGrantRevocationStoreSummaryV1 {
        schema_version: "swarm-ai.access-grant-revocation-store-summary.v1".to_string(),
        root: revocations_dir.display().to_string(),
        revocation_count: revocations.len(),
        valid_count,
        invalid_count: revocations.len().saturating_sub(valid_count),
        revocations,
    })
}

pub fn verify_access_revocation_list(
    revocation_list: &AccessRevocationListV1,
) -> AccessRevocationListVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    if revocation_list.schema_version != "swarm-ai.access-revocation-list.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.access-revocation-list.v1",
        ));
    }
    if DateTime::parse_from_rfc3339(&revocation_list.generated_at).is_err() {
        issues.push(issue(
            "$.generatedAt",
            "Access revocation list generatedAt is not RFC3339",
        ));
    }

    let mut seen_grants = BTreeSet::new();
    let mut revoked_grant_ids = Vec::new();
    for (index, revocation) in revocation_list.revocations.iter().enumerate() {
        let verification = verify_access_grant_revocation(revocation, None);
        if !verification.valid {
            for validation_issue in verification.issues {
                issues.push(issue(
                    format!(
                        "$.revocations[{index}]{}",
                        validation_issue.path.trim_start_matches('$')
                    ),
                    validation_issue.message,
                ));
            }
        }
        warnings.extend(verification.warnings);
        if !seen_grants.insert(revocation.grant_id.clone()) {
            issues.push(issue(
                format!("$.revocations[{index}].grantId"),
                "Access revocation list contains duplicate grantId",
            ));
        }
        revoked_grant_ids.push(revocation.grant_id.clone());
    }

    AccessRevocationListVerificationV1 {
        schema_version: "swarm-ai.access-revocation-list-verification.v1".to_string(),
        valid: issues.is_empty(),
        issues,
        warnings,
        revoked_grant_ids,
        verified_at: Utc::now().to_rfc3339(),
    }
}

pub fn grant_revocation<'a>(
    grant: &AccessGrantV1,
    revocation_list: Option<&'a AccessRevocationListV1>,
) -> Option<&'a AccessGrantRevocationV1> {
    let revocation_list = revocation_list?;
    revocation_list
        .revocations
        .iter()
        .find(|revocation| revocation_matches_grant(revocation, grant))
}

pub fn evaluate_execution_access(
    manifest: &PackageManifestV1,
    package_ref: &str,
    request_id: &str,
    requester: &str,
    requested_use: &str,
    runner_id: Option<&str>,
    grant: Option<&AccessGrantV1>,
) -> AccessEvaluationV1 {
    evaluate_execution_access_with_revocations(
        manifest,
        package_ref,
        request_id,
        requester,
        requested_use,
        runner_id,
        grant,
        None,
    )
}

pub fn evaluate_execution_access_with_revocations(
    manifest: &PackageManifestV1,
    package_ref: &str,
    request_id: &str,
    requester: &str,
    requested_use: &str,
    runner_id: Option<&str>,
    grant: Option<&AccessGrantV1>,
    revocation_list: Option<&AccessRevocationListV1>,
) -> AccessEvaluationV1 {
    let policy = license_policy_from_manifest(manifest, package_ref);
    let request = access_request(
        request_id,
        manifest.package_id.clone(),
        package_ref.to_string(),
        requester.to_string(),
        requested_use.to_string(),
        runner_id.map(str::to_string),
        Vec::new(),
    );
    evaluate_access_request_with_revocations(&policy, &request, grant, revocation_list, Utc::now())
}

pub fn evaluate_access_request(
    policy: &LicensePolicyV1,
    request: &AccessRequestV1,
    grant: Option<&AccessGrantV1>,
    now: DateTime<Utc>,
) -> AccessEvaluationV1 {
    evaluate_access_request_with_revocations(policy, request, grant, None, now)
}

pub fn evaluate_access_request_with_revocations(
    policy: &LicensePolicyV1,
    request: &AccessRequestV1,
    grant: Option<&AccessGrantV1>,
    revocation_list: Option<&AccessRevocationListV1>,
    now: DateTime<Utc>,
) -> AccessEvaluationV1 {
    let mut reasons = Vec::new();

    if policy.package_id != request.package_id {
        return evaluation(
            policy,
            AccessDecision::Denied,
            vec!["Access request packageId does not match license policy".to_string()],
            None,
        );
    }

    if policy.package_ref != request.package_ref {
        return evaluation(
            policy,
            AccessDecision::Denied,
            vec!["Access request packageRef does not match license policy".to_string()],
            None,
        );
    }

    if policy
        .restricted_uses
        .iter()
        .any(|item| item == &request.requested_use)
    {
        return evaluation(
            policy,
            AccessDecision::Denied,
            vec![format!("Use {} is restricted", request.requested_use)],
            None,
        );
    }

    if !policy
        .allowed_uses
        .iter()
        .any(|item| item == &request.requested_use)
    {
        return evaluation(
            policy,
            AccessDecision::Denied,
            vec![format!(
                "Use {} is not allowed by the package license",
                request.requested_use
            )],
            None,
        );
    }

    if !policy.requires_access_grant {
        return evaluation(
            policy,
            AccessDecision::Granted,
            vec!["Open license does not require an access grant".to_string()],
            grant.map(|grant| grant.grant_id.clone()),
        );
    }

    let Some(grant) = grant else {
        reasons.push("License requires an access grant".to_string());
        if request
            .proofs
            .iter()
            .any(|proof| proof.proof_type == "payment" || proof.proof_type == "subscription")
        {
            reasons.push("Payment proof must be exchanged for an access grant".to_string());
        }
        return evaluation(policy, AccessDecision::PaymentRequired, reasons, None);
    };

    let denied = validate_grant(policy, request, grant, revocation_list, now);
    if !denied.is_empty() {
        return evaluation(
            policy,
            AccessDecision::Denied,
            denied,
            Some(grant.grant_id.clone()),
        );
    }

    evaluation(
        policy,
        AccessDecision::Granted,
        vec![format!(
            "Access grant {} authorizes execution",
            grant.grant_id
        )],
        Some(grant.grant_id.clone()),
    )
}

fn validate_grant(
    policy: &LicensePolicyV1,
    request: &AccessRequestV1,
    grant: &AccessGrantV1,
    revocation_list: Option<&AccessRevocationListV1>,
    now: DateTime<Utc>,
) -> Vec<String> {
    let mut reasons = Vec::new();

    if grant.package_id != policy.package_id {
        reasons.push("Grant packageId does not match license policy".to_string());
    }
    if grant.package_ref != policy.package_ref {
        reasons.push("Grant packageRef does not match license policy".to_string());
    }
    if grant.grantee != request.requester && grant.grantee != "*" {
        reasons.push("Grant grantee does not match requester".to_string());
    }
    if let Some(grant_runner) = grant.runner_id.as_deref() {
        if Some(grant_runner) != request.runner_id.as_deref() {
            reasons.push("Grant runnerId does not authorize this runner".to_string());
        }
    }
    if !grant
        .allowed_uses
        .iter()
        .any(|item| item == &request.requested_use)
    {
        reasons.push("Grant does not allow the requested use".to_string());
    }
    let verification = verify_access_grant(grant);
    if !verification.valid {
        reasons.push(format!(
            "Grant signature verification failed: {}",
            verification
                .issues
                .iter()
                .map(|issue| issue.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    if let Some(revocation) = grant_revocation(grant, revocation_list) {
        let verification = verify_access_grant_revocation(revocation, Some(grant));
        if verification.valid {
            reasons.push(format!(
                "Grant {} was revoked by {} at {}: {}",
                grant.grant_id, revocation.revoked_by, revocation.revoked_at, revocation.reason
            ));
        } else {
            reasons.push(format!(
                "Grant revocation verification failed: {}",
                verification
                    .issues
                    .iter()
                    .map(|issue| issue.message.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
    }
    if let Some(expires_at) = grant.expires_at.as_deref() {
        match DateTime::parse_from_rfc3339(expires_at) {
            Ok(expires_at) if expires_at.with_timezone(&Utc) <= now => {
                reasons.push("Grant is expired".to_string());
            }
            Ok(_) => {}
            Err(_) => reasons.push("Grant expiresAt is not RFC3339".to_string()),
        }
    }

    reasons
}

fn evaluation(
    policy: &LicensePolicyV1,
    decision: AccessDecision,
    reasons: Vec<String>,
    grant_id: Option<String>,
) -> AccessEvaluationV1 {
    AccessEvaluationV1 {
        schema_version: "swarm-ai.access-evaluation.v1".to_string(),
        package_id: policy.package_id.clone(),
        package_ref: policy.package_ref.clone(),
        decision,
        reasons,
        license_policy: policy.clone(),
        grant_id,
    }
}

fn access_grant_v2_signing_value(grant: &AccessGrantV2) -> serde_json::Result<Value> {
    let mut value = serde_json::to_value(grant)?;
    if let Value::Object(object) = &mut value {
        object.remove("grantId");
        object.remove("signatures");
    }
    Ok(value)
}

fn access_grant_v3_signing_value(grant: &AccessGrantV3) -> serde_json::Result<Value> {
    let mut value = serde_json::to_value(grant)?;
    if let Value::Object(object) = &mut value {
        object.remove("grantId");
        object.remove("signatures");
    }
    Ok(value)
}

fn validate_access_scopes(
    scopes: &[AccessScopeV1],
    subjects: &[AccessSubjectV1],
    issues: &mut Vec<ValidationIssue>,
) {
    if scopes.is_empty() {
        issues.push(issue(
            "$.scopes",
            "Access grant must include at least one asset-level scope",
        ));
        return;
    }

    let mut seen = BTreeSet::new();
    for (index, scope) in scopes.iter().enumerate() {
        if !seen.insert(*scope) {
            issues.push(issue(
                format!("$.scopes[{index}]"),
                "Access grant contains a duplicate scope",
            ));
        }
        if !subjects
            .iter()
            .any(|subject| scope_matches_subject(*scope, subject.subject_type))
        {
            issues.push(issue(
                format!("$.scopes[{index}]"),
                "Access grant scope has no compatible subject",
            ));
        }
    }
}

fn validate_access_subjects(
    subjects: &[AccessSubjectV1],
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if subjects.is_empty() {
        issues.push(issue(
            "$.subjects",
            "Access grant must scope at least one asset, package, service, namespace, feed, receipt, trace, vector store, dataset, or tool",
        ));
        return;
    }

    let mut seen_subjects = BTreeSet::new();
    for (index, subject) in subjects.iter().enumerate() {
        let subject_path = format!("$.subjects[{index}]");
        if subject.subject_id.trim().is_empty() {
            issues.push(issue(
                format!("{subject_path}.subjectId"),
                "Access subject id is required",
            ));
        } else if !seen_subjects.insert((subject.subject_type, subject.subject_id.clone())) {
            issues.push(issue(
                format!("{subject_path}.subjectId"),
                "Access grant contains a duplicate subject",
            ));
        }
        if subject.refs.is_empty() && subject.content_hash.is_none() && subject.namespace.is_none()
        {
            warnings.push(issue(
                subject_path.clone(),
                "Access subject should include at least one concrete ref, contentHash, or namespace",
            ));
        }
        for (ref_index, reference) in subject.refs.iter().enumerate() {
            if reference.trim().is_empty() {
                issues.push(issue(
                    format!("{subject_path}.refs[{ref_index}]"),
                    "Access subject ref must not be empty",
                ));
            } else if !looks_like_access_reference(reference) {
                warnings.push(issue(
                    format!("{subject_path}.refs[{ref_index}]"),
                    "Access subject ref is not a recognized Swarm, local, web, IPFS, or hash reference",
                ));
            }
        }
        if let Some(content_hash) = &subject.content_hash
            && !looks_like_hash_ref(content_hash)
        {
            warnings.push(issue(
                format!("{subject_path}.contentHash"),
                "Access subject contentHash is not sha256-like",
            ));
        }
        if let Some(namespace) = &subject.namespace
            && namespace.trim().is_empty()
        {
            issues.push(issue(
                format!("{subject_path}.namespace"),
                "Access subject namespace must not be empty",
            ));
        }
        if matches!(subject.subject_type, AccessSubjectTypeV1::Namespace)
            && subject.namespace.is_none()
        {
            warnings.push(issue(
                format!("{subject_path}.namespace"),
                "Namespace subjects should include the concrete namespace value",
            ));
        }
    }
}

fn validate_access_grant_timestamps(grant: &AccessGrantV2, issues: &mut Vec<ValidationIssue>) {
    if DateTime::parse_from_rfc3339(&grant.issued_at).is_err() {
        issues.push(issue("$.issuedAt", "Access grant issuedAt must be RFC3339"));
    }
    if let Some(expires_at) = &grant.expires_at {
        match DateTime::parse_from_rfc3339(expires_at) {
            Ok(expires_at) if expires_at.with_timezone(&Utc) <= Utc::now() => {
                issues.push(issue("$.expiresAt", "Access grant is expired"));
            }
            Ok(_) => {}
            Err(_) => issues.push(issue(
                "$.expiresAt",
                "Access grant expiresAt must be RFC3339",
            )),
        }
    }
}

fn validate_access_grant_refs(grant: &AccessGrantV2, warnings: &mut Vec<ValidationIssue>) {
    for (index, reference) in grant.evidence_refs.iter().enumerate() {
        if !looks_like_access_reference(reference) {
            warnings.push(issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence ref is not a recognized Swarm, local, web, IPFS, or hash reference",
            ));
        }
    }
    for (path, reference) in [
        ("$.revocationListRef", grant.revocation_list_ref.as_deref()),
        ("$.paymentRef", grant.payment_ref.as_deref()),
        ("$.settlementRef", grant.settlement_ref.as_deref()),
    ] {
        if let Some(reference) = reference
            && !looks_like_access_reference(reference)
        {
            warnings.push(issue(
                path,
                "Reference is not a recognized Swarm, local, web, IPFS, or hash reference",
            ));
        }
    }
}

fn validate_access_grant_v3_timestamps(grant: &AccessGrantV3, issues: &mut Vec<ValidationIssue>) {
    if DateTime::parse_from_rfc3339(&grant.issued_at).is_err() {
        issues.push(issue("$.issuedAt", "Access grant issuedAt must be RFC3339"));
    }
    if let Some(expires_at) = &grant.expires_at {
        match DateTime::parse_from_rfc3339(expires_at) {
            Ok(expires_at) if expires_at.with_timezone(&Utc) <= Utc::now() => {
                issues.push(issue("$.expiresAt", "Access grant is expired"));
            }
            Ok(_) => {}
            Err(_) => issues.push(issue(
                "$.expiresAt",
                "Access grant expiresAt must be RFC3339",
            )),
        }
    }
}

fn validate_access_grant_v3_refs(grant: &AccessGrantV3, warnings: &mut Vec<ValidationIssue>) {
    for (index, reference) in grant.evidence_refs.iter().enumerate() {
        if !looks_like_access_reference(reference) {
            warnings.push(issue(
                format!("$.evidenceRefs[{index}]"),
                "Evidence ref is not a recognized Swarm, local, web, IPFS, or hash reference",
            ));
        }
    }
    for (index, reference) in grant.payment_evidence_refs.iter().enumerate() {
        if !looks_like_access_reference(reference) {
            warnings.push(issue(
                format!("$.paymentEvidenceRefs[{index}]"),
                "Payment evidence ref is not a recognized Swarm, local, web, IPFS, or hash reference",
            ));
        }
    }
    for (index, reference) in grant.revocation_hint_refs.iter().enumerate() {
        if !looks_like_access_reference(reference) {
            warnings.push(issue(
                format!("$.revocationHintRefs[{index}]"),
                "Revocation hint ref is not a recognized Swarm, local, web, IPFS, or hash reference",
            ));
        }
    }
    for (path, reference) in [
        ("$.revocationListRef", grant.revocation_list_ref.as_deref()),
        ("$.paymentRef", grant.payment_ref.as_deref()),
        ("$.settlementRef", grant.settlement_ref.as_deref()),
    ] {
        if let Some(reference) = reference
            && !looks_like_access_reference(reference)
        {
            warnings.push(issue(
                path,
                "Reference is not a recognized Swarm, local, web, IPFS, or hash reference",
            ));
        }
    }
}

fn validate_asset_rules_v3(
    grant: &AccessGrantV3,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if grant.asset_rules.is_empty() {
        warnings.push(issue(
            "$.assetRules",
            "AccessGrantV3 should carry the asset-level rules it authorizes when possible",
        ));
        return;
    }
    for (index, rule) in grant.asset_rules.iter().enumerate() {
        let path = format!("$.assetRules[{index}]");
        if rule.schema_version != ASSET_ACCESS_RULE_V2_SCHEMA_VERSION {
            issues.push(issue(
                format!("{path}.schemaVersion"),
                format!("Expected schemaVersion to be {ASSET_ACCESS_RULE_V2_SCHEMA_VERSION}"),
            ));
        }
        if rule.object_kind != "asset_access_rule" {
            issues.push(issue(
                format!("{path}.objectKind"),
                "Expected objectKind to be asset_access_rule",
            ));
        }
        if rule.rule_id != canonical_asset_access_rule_v2_id(rule) {
            issues.push(issue(
                format!("{path}.ruleId"),
                "Asset access rule v2 id does not match canonical rule content",
            ));
        }
        if rule.subject.subject_id.trim().is_empty() {
            issues.push(issue(
                format!("{path}.subject.subjectId"),
                "Asset access rule subject id is required",
            ));
        }
        if rule.allowed_scopes.is_empty() {
            warnings.push(issue(
                format!("{path}.allowedScopes"),
                "Asset access rule v2 should declare compatible grant scopes",
            ));
        }
        if rule.encrypted && !rule.grant_required {
            issues.push(issue(
                format!("{path}.grantRequired"),
                "Encrypted asset rules must require an access grant",
            ));
        }
        if !grant
            .subjects
            .iter()
            .any(|subject| subject.subject_id == rule.subject.subject_id)
        {
            warnings.push(issue(
                format!("{path}.subject"),
                "Grant subjects do not include this asset rule subject id",
            ));
        }
    }
}

fn verify_access_grant_v2_signatures(
    signatures: &[String],
    expected_signature: &str,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if signatures.is_empty() {
        warnings.push(issue(
            "$.signatures",
            "Access grant is unsigned development data",
        ));
        return;
    }
    let mut matched = false;
    let mut saw_local_dev = false;
    for (index, signature) in signatures.iter().enumerate() {
        let path = format!("$.signatures[{index}]");
        if signature.trim().is_empty() {
            issues.push(issue(path, "Signature must not be empty"));
        } else if signature == expected_signature {
            matched = true;
            saw_local_dev = true;
        } else if signature.starts_with(DEV_GRANT_V2_SIGNATURE_PREFIX) {
            saw_local_dev = true;
            issues.push(issue(
                path,
                "Access grant V2 signature does not match canonical content",
            ));
        } else {
            warnings.push(issue(
                path,
                "Access grant includes a non-local signature that was not verified here",
            ));
        }
    }
    if matched {
        warnings.push(issue(
            "$.signatures",
            "Signature is deterministic local-dev signing, not production identity signing",
        ));
    } else if !saw_local_dev {
        warnings.push(issue(
            "$.signatures",
            "Access grant does not include a locally verifiable development signature",
        ));
    }
}

fn verify_access_grant_v3_signatures(
    signatures: &[String],
    expected_signature: &str,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if signatures.is_empty() {
        warnings.push(issue(
            "$.signatures",
            "Access grant v3 is unsigned development data",
        ));
        return;
    }
    if signatures
        .iter()
        .any(|signature| signature == expected_signature)
    {
        warnings.push(issue(
            "$.signatures",
            "Access grant v3 uses deterministic local-dev signing, not production identity signing",
        ));
        return;
    }
    if signatures
        .iter()
        .any(|signature| signature.starts_with(DEV_GRANT_V3_SIGNATURE_PREFIX))
    {
        issues.push(issue(
            "$.signatures",
            "Access grant v3 signature does not match canonical dev signature",
        ));
    } else {
        warnings.push(issue(
            "$.signatures",
            "Access grant v3 has signatures, but none are recognized by local verifier",
        ));
    }
}

fn scope_matches_subject(scope: AccessScopeV1, subject_type: AccessSubjectTypeV1) -> bool {
    match scope {
        AccessScopeV1::ReadAsset => matches!(
            subject_type,
            AccessSubjectTypeV1::Asset
                | AccessSubjectTypeV1::Dataset
                | AccessSubjectTypeV1::VectorStore
                | AccessSubjectTypeV1::Tool
                | AccessSubjectTypeV1::Receipt
                | AccessSubjectTypeV1::Trace
        ),
        AccessScopeV1::ExecutePackage | AccessScopeV1::ValidatePackage => {
            subject_type == AccessSubjectTypeV1::Package
        }
        AccessScopeV1::RunService => subject_type == AccessSubjectTypeV1::Service,
        AccessScopeV1::PublishToNamespace => subject_type == AccessSubjectTypeV1::Namespace,
        AccessScopeV1::UpdateFeed => subject_type == AccessSubjectTypeV1::Feed,
        AccessScopeV1::ViewReceipt => subject_type == AccessSubjectTypeV1::Receipt,
        AccessScopeV1::ViewTrace => subject_type == AccessSubjectTypeV1::Trace,
        AccessScopeV1::UseVectorStore => subject_type == AccessSubjectTypeV1::VectorStore,
        AccessScopeV1::UseDataset => subject_type == AccessSubjectTypeV1::Dataset,
        AccessScopeV1::UseTool => subject_type == AccessSubjectTypeV1::Tool,
        AccessScopeV1::ResellOrDelegate => true,
    }
}

fn looks_like_access_reference(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("bzz://")
        || value.starts_with("local://")
        || value.starts_with("ipfs://")
        || value.starts_with("http://")
        || value.starts_with("https://")
        || looks_like_hash_ref(value)
}

fn looks_like_hash_ref(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("sha256:")
        || value.starts_with("sha256://")
        || (value.len() == 64 && value.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()))
}

fn grant_signing_value(grant: &AccessGrantV1) -> Value {
    json!({
        "schemaVersion": grant.schema_version,
        "grantId": grant.grant_id,
        "packageId": grant.package_id,
        "packageRef": grant.package_ref,
        "grantee": grant.grantee,
        "runnerId": grant.runner_id,
        "allowedUses": grant.allowed_uses,
        "expiresAt": grant.expires_at,
        "accessMethod": grant.access_method,
        "encryptedAccessRef": grant.encrypted_access_ref,
        "issuer": grant.issuer,
    })
}

fn revocation_signing_value(revocation: &AccessGrantRevocationV1) -> Value {
    json!({
        "schemaVersion": revocation.schema_version,
        "revocationId": revocation.revocation_id,
        "grantId": revocation.grant_id,
        "packageId": revocation.package_id,
        "packageRef": revocation.package_ref,
        "grantee": revocation.grantee,
        "revokedBy": revocation.revoked_by,
        "reason": revocation.reason,
        "revokedAt": revocation.revoked_at,
    })
}

fn revocation_matches_grant(revocation: &AccessGrantRevocationV1, grant: &AccessGrantV1) -> bool {
    revocation.grant_id == grant.grant_id
        && revocation.package_id == grant.package_id
        && revocation.package_ref == grant.package_ref
        && revocation.grantee == grant.grantee
}

fn dev_signature(label: &str, issuer: &str, payload: &Value) -> String {
    let value = json!({
        "label": label,
        "issuer": issuer,
        "payload": payload,
    });
    format!(
        "{DEV_GRANT_SIGNATURE_PREFIX}:{label}:{}",
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

fn access_grant_index_entry(grant: &AccessGrantV1, grant_path: String) -> AccessGrantIndexEntryV1 {
    let verification = verify_access_grant(grant);
    AccessGrantIndexEntryV1 {
        grant_id: grant.grant_id.clone(),
        package_id: grant.package_id.clone(),
        package_ref: grant.package_ref.clone(),
        grantee: grant.grantee.clone(),
        runner_id: grant.runner_id.clone(),
        allowed_uses: grant.allowed_uses.clone(),
        expires_at: grant.expires_at.clone(),
        access_method: grant.access_method.clone(),
        issuer: grant.issuer.clone(),
        grant_path,
        verification,
    }
}

fn access_grant_lookup(grant: AccessGrantV1, path: PathBuf) -> AccessGrantLookupV1 {
    let verification = verify_access_grant(&grant);
    AccessGrantLookupV1 {
        schema_version: "swarm-ai.access-grant-lookup.v1".to_string(),
        grant_id: grant.grant_id.clone(),
        grant_path: path.display().to_string(),
        grant,
        verification,
    }
}

fn access_grant_revocation_index_entry(
    revocation: &AccessGrantRevocationV1,
    revocation_path: String,
) -> AccessGrantRevocationIndexEntryV1 {
    let verification = verify_access_grant_revocation(revocation, None);
    AccessGrantRevocationIndexEntryV1 {
        revocation_id: revocation.revocation_id.clone(),
        grant_id: revocation.grant_id.clone(),
        package_id: revocation.package_id.clone(),
        package_ref: revocation.package_ref.clone(),
        grantee: revocation.grantee.clone(),
        revoked_by: revocation.revoked_by.clone(),
        reason: revocation.reason.clone(),
        revoked_at: revocation.revoked_at.clone(),
        revocation_path,
        verification,
    }
}

fn access_grant_revocation_lookup(
    revocation: AccessGrantRevocationV1,
    path: PathBuf,
) -> AccessGrantRevocationLookupV1 {
    let verification = verify_access_grant_revocation(&revocation, None);
    AccessGrantRevocationLookupV1 {
        schema_version: "swarm-ai.access-grant-revocation-lookup.v1".to_string(),
        revocation_id: revocation.revocation_id.clone(),
        revocation_path: path.display().to_string(),
        revocation,
        verification,
    }
}

fn safe_id_component(value: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ArtifactGroup, ArtifactMinimum, LicenseInfo, LicenseType, PackageKind, PrivacyTier,
        Publisher,
    };
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn open_license_grants_without_explicit_grant() {
        let manifest = manifest(LicenseType::Open);
        let evaluation = evaluate_execution_access(
            &manifest,
            "bzz://pkg",
            "req-1",
            "0xUser",
            "runner-service",
            Some("local"),
            None,
        );

        assert_eq!(evaluation.decision, AccessDecision::Granted);
    }

    #[test]
    fn commercial_license_requires_valid_grant() {
        let manifest = manifest(LicenseType::Commercial);
        let policy = license_policy_from_manifest(&manifest, "bzz://pkg");
        let request = access_request(
            "req-1",
            manifest.package_id.clone(),
            "bzz://pkg",
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            Vec::new(),
        );
        let missing = evaluate_access_request(&policy, &request, None, Utc::now());
        assert_eq!(missing.decision, AccessDecision::PaymentRequired);

        let grant = dev_access_grant(
            &policy,
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            None,
        );
        assert!(verify_access_grant(&grant).valid);

        let granted = evaluate_access_request(&policy, &request, Some(&grant), Utc::now());
        assert_eq!(granted.decision, AccessDecision::Granted);
        assert_eq!(granted.grant_id, Some(grant.grant_id));
    }

    #[test]
    fn identity_signed_grant_authorizes_access() {
        let manifest = manifest(LicenseType::Commercial);
        let policy = license_policy_from_manifest(&manifest, "bzz://pkg");
        let request = access_request(
            "req-1",
            manifest.package_id.clone(),
            "bzz://pkg",
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            Vec::new(),
        );
        let identity = hivemind_identity::identity_from_seed("0xIssuer", b"issuer-seed").unwrap();
        let mut grant = dev_access_grant_issued_by(
            &policy,
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            None,
            identity.subject.clone(),
        );

        let envelope = sign_access_grant_with_identity(&mut grant, &identity).unwrap();
        let verification = verify_access_grant(&grant);
        let granted = evaluate_access_request(&policy, &request, Some(&grant), Utc::now());

        assert_eq!(envelope.signer, grant.issuer);
        assert!(
            grant
                .signature
                .starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX)
        );
        assert!(verification.valid, "{:?}", verification.issues);
        assert!(
            verification
                .expected_signature
                .starts_with("ed25519-payload-hash:")
        );
        assert!(verification.warnings.is_empty());
        assert_eq!(granted.decision, AccessDecision::Granted);
    }

    #[test]
    fn tampered_grant_is_denied() {
        let manifest = manifest(LicenseType::Commercial);
        let policy = license_policy_from_manifest(&manifest, "bzz://pkg");
        let request = access_request(
            "req-1",
            manifest.package_id.clone(),
            "bzz://pkg",
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            Vec::new(),
        );
        let mut grant = dev_access_grant(
            &policy,
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            None,
        );
        grant.allowed_uses = vec!["validation".to_string()];

        let verification = verify_access_grant(&grant);
        let denied = evaluate_access_request(&policy, &request, Some(&grant), Utc::now());

        assert!(!verification.valid);
        assert_eq!(denied.decision, AccessDecision::Denied);
        assert!(
            denied
                .reasons
                .iter()
                .any(|reason| reason.contains("signature verification failed"))
        );
    }

    #[test]
    fn access_grant_v2_signs_asset_scoped_dataset_grants_and_detects_tampering() {
        let subject = AccessSubjectV1 {
            subject_id: "dataset/customer-support-v1".to_string(),
            subject_type: AccessSubjectTypeV1::Dataset,
            refs: vec!["bzz://dataset-customer-support".to_string()],
            asset_class: Some("dataset".to_string()),
            content_hash: Some(format!("sha256:{}", "a".repeat(64))),
            namespace: None,
        };
        let mut grant = dev_access_grant_v2(
            "did:hivemind:publisher",
            "did:hivemind:research-team",
            vec![AccessScopeV1::ReadAsset, AccessScopeV1::UseDataset],
            vec![subject],
            vec!["research".to_string(), "evaluation".to_string()],
            None,
        )
        .unwrap();

        let verification = verify_access_grant_v2(&grant);

        assert_eq!(grant.schema_version, "hivemind.access-grant.v2");
        assert!(grant.grant_id.starts_with("access-grant-"));
        assert_eq!(verification.expected_grant_id, grant.grant_id);
        assert_eq!(verification.expected_signature, grant.signatures[0]);
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signatures")
        );

        grant.subjects[0].refs = vec!["bzz://different-dataset".to_string()];
        let tampered = verify_access_grant_v2(&grant);

        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path == "$.grantId" || issue.path.starts_with("$.signatures"))
        );
    }

    #[test]
    fn access_grant_v2_rejects_scope_subject_mismatch_and_expired_grants() {
        let subject = AccessSubjectV1 {
            subject_id: "namespace/team-lab".to_string(),
            subject_type: AccessSubjectTypeV1::Namespace,
            refs: Vec::new(),
            asset_class: None,
            content_hash: None,
            namespace: Some("team-lab".to_string()),
        };
        let grant = dev_access_grant_v2(
            "did:hivemind:publisher",
            "did:hivemind:delegate",
            vec![AccessScopeV1::UseDataset],
            vec![subject],
            vec!["research".to_string()],
            Some("2000-01-01T00:00:00Z".to_string()),
        )
        .unwrap();

        let verification = verify_access_grant_v2(&grant);

        assert!(!verification.valid);
        assert!(verification.issues.iter().any(
            |issue| issue.path == "$.scopes[0]" && issue.message.contains("compatible subject")
        ));
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.expiresAt")
        );
    }

    #[test]
    fn access_grant_v3_projects_asset_rules_payment_evidence_and_detects_tampering() {
        let subject = AccessSubjectV1 {
            subject_id: "dataset/customer-support-v1".to_string(),
            subject_type: AccessSubjectTypeV1::Dataset,
            refs: vec!["bzz://dataset-customer-support".to_string()],
            asset_class: Some("dataset".to_string()),
            content_hash: Some(format!("sha256:{}", "c".repeat(64))),
            namespace: None,
        };
        let mut rule = AssetAccessRuleV2 {
            schema_version: ASSET_ACCESS_RULE_V2_SCHEMA_VERSION.to_string(),
            object_kind: "asset_access_rule".to_string(),
            rule_id: String::new(),
            subject: subject.clone(),
            rights: vec![AccessRightV1::ViewMetadata, AccessRightV1::DecryptArtifacts],
            allowed_scopes: vec![AccessScopeV1::ReadAsset, AccessScopeV1::UseDataset],
            access_method: AccessMethod::EncryptedReference,
            grant_required: true,
            public_metadata: true,
            encrypted: true,
            policy_ref: Some("local://access-policy-v2/policy-1".to_string()),
            license_ref: Some("bzz://license".to_string()),
            decryption_ref: Some(
                "local://access/decryption/dataset-customer-support-v1".to_string(),
            ),
            revocation_list_ref: Some("bzz://revocations".to_string()),
            settlement_ref: Some("bzz://settlement".to_string()),
            payment_requirement: AccessPaymentRequirementV1 {
                required: true,
                asset: Some("xDAI".to_string()),
                amount: Some(3.0),
                settlement_ref: Some("bzz://settlement".to_string()),
                subscription_ref: None,
            },
            privacy_requirement: AccessPrivacyRequirementV1 {
                allowed_privacy_tiers: vec![PrivacyTier::LocalOnly, PrivacyTier::TeeConfidential],
                runner_grant_required: true,
                secret_refs_required: true,
            },
            verification_requirement: AccessVerificationRequirementV1 {
                allowed_verification_tiers: vec![hivemind_core::IntegrityTier::ReceiptOnly],
                require_receipt: true,
                require_validation: false,
            },
            evidence_refs: vec!["bzz://access-evidence".to_string()],
        };
        rule.rule_id = canonical_asset_access_rule_v2_id(&rule);
        let grant_v2 = dev_access_grant_v2(
            "did:hivemind:publisher",
            "did:hivemind:research-team",
            vec![AccessScopeV1::ReadAsset, AccessScopeV1::UseDataset],
            vec![subject],
            vec!["research".to_string()],
            None,
        )
        .unwrap();
        let mut grant = access_grant_v3_from_v2(
            &grant_v2,
            vec![rule],
            Some(PrivacyTier::TeeConfidential),
            vec!["bzz://payment-authorization".to_string()],
        );
        grant.payment_ref = Some("bzz://payment-authorization".to_string());
        sign_access_grant_v3(&mut grant).unwrap();

        let verification = verify_access_grant_v3(&grant);
        assert_eq!(grant.schema_version, ACCESS_GRANT_V3_SCHEMA_VERSION);
        assert!(grant.grant_id.starts_with("access-grant-v3-"));
        assert_eq!(verification.expected_grant_id, grant.grant_id);
        assert_eq!(verification.expected_signature, grant.signatures[0]);
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signatures")
        );

        grant.asset_rules[0].encrypted = false;
        let tampered = verify_access_grant_v3(&grant);
        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path == "$.grantId" || issue.path.starts_with("$.signatures"))
        );
    }

    #[test]
    fn access_grant_v3_warns_when_paid_rule_lacks_payment_evidence() {
        let subject = AccessSubjectV1 {
            subject_id: "asset/private-model".to_string(),
            subject_type: AccessSubjectTypeV1::Asset,
            refs: vec!["bzz://private-model".to_string()],
            asset_class: Some("model".to_string()),
            content_hash: Some(format!("sha256:{}", "d".repeat(64))),
            namespace: None,
        };
        let mut grant = dev_access_grant_v3(
            "did:hivemind:publisher",
            "did:hivemind:buyer",
            vec![AccessScopeV1::ReadAsset],
            vec![subject.clone()],
            vec![AssetAccessRuleV2 {
                schema_version: ASSET_ACCESS_RULE_V2_SCHEMA_VERSION.to_string(),
                object_kind: "asset_access_rule".to_string(),
                rule_id: "pending".to_string(),
                subject,
                rights: vec![AccessRightV1::DecryptArtifacts],
                allowed_scopes: vec![AccessScopeV1::ReadAsset],
                access_method: AccessMethod::EncryptedReference,
                grant_required: true,
                public_metadata: true,
                encrypted: true,
                policy_ref: None,
                license_ref: None,
                decryption_ref: None,
                revocation_list_ref: None,
                settlement_ref: None,
                payment_requirement: AccessPaymentRequirementV1 {
                    required: true,
                    asset: Some("xDAI".to_string()),
                    amount: Some(1.0),
                    settlement_ref: None,
                    subscription_ref: None,
                },
                privacy_requirement: AccessPrivacyRequirementV1 {
                    allowed_privacy_tiers: vec![PrivacyTier::LocalOnly],
                    runner_grant_required: true,
                    secret_refs_required: true,
                },
                verification_requirement: AccessVerificationRequirementV1 {
                    allowed_verification_tiers: vec![hivemind_core::IntegrityTier::ReceiptOnly],
                    require_receipt: true,
                    require_validation: false,
                },
                evidence_refs: Vec::new(),
            }],
            vec!["commercial".to_string()],
            Some(PrivacyTier::LocalOnly),
            None,
        )
        .unwrap();
        grant.asset_rules[0].rule_id = canonical_asset_access_rule_v2_id(&grant.asset_rules[0]);
        sign_access_grant_v3(&mut grant).unwrap();

        let verification = verify_access_grant_v3(&grant);
        assert!(verification.valid, "{verification:#?}");
        assert!(verification.warnings.iter().any(|warning| {
            warning.path == "$.paymentEvidenceRefs"
                && warning
                    .message
                    .contains("paymentRef or paymentEvidenceRefs")
        }));
    }

    #[test]
    fn tampered_identity_signed_grant_is_denied() {
        let manifest = manifest(LicenseType::Commercial);
        let policy = license_policy_from_manifest(&manifest, "bzz://pkg");
        let request = access_request(
            "req-1",
            manifest.package_id.clone(),
            "bzz://pkg",
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            Vec::new(),
        );
        let identity = hivemind_identity::identity_from_seed("0xIssuer", b"issuer-seed").unwrap();
        let mut grant = dev_access_grant_issued_by(
            &policy,
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            None,
            identity.subject.clone(),
        );
        sign_access_grant_with_identity(&mut grant, &identity).unwrap();
        grant.allowed_uses = vec!["validation".to_string()];

        let verification = verify_access_grant(&grant);
        let denied = evaluate_access_request(&policy, &request, Some(&grant), Utc::now());

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signature.payloadHash")
        );
        assert_eq!(denied.decision, AccessDecision::Denied);
    }

    #[test]
    fn revoked_grant_is_denied() {
        let manifest = manifest(LicenseType::Commercial);
        let policy = license_policy_from_manifest(&manifest, "bzz://pkg");
        let request = access_request(
            "req-1",
            manifest.package_id.clone(),
            "bzz://pkg",
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            Vec::new(),
        );
        let grant = dev_access_grant(
            &policy,
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            None,
        );
        let revocation = revoke_access_grant(&grant, "local-dev", "subscription entitlement ended");
        let revocation_list = access_revocation_list(vec![revocation.clone()]);

        assert!(verify_access_grant_revocation(&revocation, Some(&grant)).valid);
        assert!(verify_access_revocation_list(&revocation_list).valid);

        let denied = evaluate_access_request_with_revocations(
            &policy,
            &request,
            Some(&grant),
            Some(&revocation_list),
            Utc::now(),
        );

        assert_eq!(denied.decision, AccessDecision::Denied);
        assert!(
            denied
                .reasons
                .iter()
                .any(|reason| reason.contains("was revoked"))
        );
    }

    #[test]
    fn access_stores_list_and_get_grants_and_revocations() {
        let grants_dir = unique_temp_dir("hivemind-access-grant-store-test");
        let revocations_dir = unique_temp_dir("hivemind-access-revocation-store-test");
        let manifest = manifest(LicenseType::Commercial);
        let policy = license_policy_from_manifest(&manifest, "bzz://pkg");
        let grant = dev_access_grant(
            &policy,
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            None,
        );
        let revocation = revoke_access_grant(&grant, "local-dev", "subscription entitlement ended");

        let grant_path = write_access_grant(&grants_dir, &grant).unwrap();
        let revocation_path = write_access_grant_revocation(&revocations_dir, &revocation).unwrap();
        let grant_summary = list_access_grants(&grants_dir).unwrap();
        let revocation_summary = list_access_grant_revocations(&revocations_dir).unwrap();
        let grant_lookup = get_access_grant(&grants_dir, &grant.grant_id)
            .unwrap()
            .unwrap();
        let revocation_lookup =
            get_access_grant_revocation(&revocations_dir, &revocation.revocation_id)
                .unwrap()
                .unwrap();
        let missing_grant = get_access_grant(&grants_dir, "missing-grant").unwrap();
        let missing_revocation =
            get_access_grant_revocation(&revocations_dir, "missing-revocation").unwrap();

        assert_eq!(grant_summary.grant_count, 1);
        assert_eq!(grant_summary.valid_count, 1);
        assert_eq!(grant_summary.grants[0].grant_id, grant.grant_id);
        assert_eq!(
            grant_summary.grants[0].grant_path,
            grant_path.display().to_string()
        );
        assert_eq!(grant_lookup.grant.grant_id, grant.grant_id);
        assert!(grant_lookup.verification.valid);
        assert!(missing_grant.is_none());

        assert_eq!(revocation_summary.revocation_count, 1);
        assert_eq!(revocation_summary.valid_count, 1);
        assert_eq!(
            revocation_summary.revocations[0].revocation_id,
            revocation.revocation_id
        );
        assert_eq!(
            revocation_summary.revocations[0].revocation_path,
            revocation_path.display().to_string()
        );
        assert_eq!(
            revocation_lookup.revocation.revocation_id,
            revocation.revocation_id
        );
        assert!(revocation_lookup.verification.valid);
        assert!(missing_revocation.is_none());

        let _ = fs::remove_dir_all(grants_dir);
        let _ = fs::remove_dir_all(revocations_dir);
    }

    #[test]
    fn identity_signed_revocation_is_valid_and_denies_access() {
        let manifest = manifest(LicenseType::Commercial);
        let policy = license_policy_from_manifest(&manifest, "bzz://pkg");
        let request = access_request(
            "req-1",
            manifest.package_id.clone(),
            "bzz://pkg",
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            Vec::new(),
        );
        let identity = hivemind_identity::identity_from_seed("0xIssuer", b"issuer-seed").unwrap();
        let mut grant = dev_access_grant_issued_by(
            &policy,
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            None,
            identity.subject.clone(),
        );
        sign_access_grant_with_identity(&mut grant, &identity).unwrap();
        let mut revocation =
            revoke_access_grant(&grant, identity.subject.clone(), "subscription ended");
        let envelope =
            sign_access_grant_revocation_with_identity(&mut revocation, &identity).unwrap();
        let revocation_list = access_revocation_list(vec![revocation.clone()]);

        let verification = verify_access_grant_revocation(&revocation, Some(&grant));
        let list_verification = verify_access_revocation_list(&revocation_list);
        let denied = evaluate_access_request_with_revocations(
            &policy,
            &request,
            Some(&grant),
            Some(&revocation_list),
            Utc::now(),
        );

        assert_eq!(envelope.signer, revocation.revoked_by);
        assert!(verification.valid, "{:?}", verification.issues);
        assert!(verification.warnings.is_empty());
        assert!(list_verification.valid, "{:?}", list_verification.issues);
        assert_eq!(denied.decision, AccessDecision::Denied);
    }

    #[test]
    fn tampered_revocation_is_invalid() {
        let manifest = manifest(LicenseType::Commercial);
        let policy = license_policy_from_manifest(&manifest, "bzz://pkg");
        let grant = dev_access_grant(
            &policy,
            "0xUser",
            "runner-service",
            Some("local".to_string()),
            None,
        );
        let mut revocation =
            revoke_access_grant(&grant, "local-dev", "subscription entitlement ended");
        revocation.reason = "different reason".to_string();

        let verification = verify_access_grant_revocation(&revocation, Some(&grant));

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.message.contains("signature"))
        );
    }

    fn manifest(license_type: LicenseType) -> PackageManifestV1 {
        PackageManifestV1 {
            schema_version: "swarm-ai.package.v1".to_string(),
            package_id: "hivemind/test".to_string(),
            kind: PackageKind::Model,
            name: "Test".to_string(),
            version: "0.1.0".to_string(),
            publisher: Publisher {
                address: "0x0000000000000000000000000000000000000000".to_string(),
                display_name: "Hivemind".to_string(),
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
            permissions: Vec::new(),
            license: LicenseInfo {
                license_type,
                name: Some("Example".to_string()),
                url: None,
            },
        }
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nanos}"))
    }
}
