use crate::canonical::{canonicalize_json, hash_canonical_json};
use crate::manifest::{LicenseType, PackageManifestV1};
use crate::trust::{IntegrityTier, PrivacyTier};
use crate::validation::ValidationIssue;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEV_ACCESS_POLICY_SIGNATURE_PREFIX: &str = "dev-access-policy-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AccessDecision {
    Granted,
    Denied,
    PaymentRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AccessControlMode {
    None,
    EncryptedRef,
    Act,
    ExternalLicenseServer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum AccessMethod {
    None,
    Act,
    EncryptedReference,
    External,
    Open,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessControlV1 {
    pub mode: AccessControlMode,
    #[serde(rename = "actRef", default)]
    pub act_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LicensePolicyV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "licenseType")]
    pub license_type: LicenseType,
    #[serde(rename = "allowedUses")]
    pub allowed_uses: Vec<String>,
    #[serde(rename = "restrictedUses")]
    pub restricted_uses: Vec<String>,
    #[serde(rename = "requiresAccessGrant")]
    pub requires_access_grant: bool,
    #[serde(rename = "termsRef", default)]
    pub terms_ref: Option<String>,
    #[serde(rename = "accessControl")]
    pub access_control: AccessControlV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessRightV1 {
    ViewMetadata,
    DownloadPublicArtifacts,
    DecryptArtifacts,
    ExecuteLocally,
    ExecuteRemotely,
    HostService,
    ValidatePackage,
    FineTune,
    Redistribute,
    CommercialUse,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessPaymentRequirementV1 {
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<f64>,
    #[serde(
        rename = "settlementRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub settlement_ref: Option<String>,
    #[serde(
        rename = "subscriptionRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub subscription_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessPrivacyRequirementV1 {
    #[serde(rename = "allowedPrivacyTiers")]
    pub allowed_privacy_tiers: Vec<PrivacyTier>,
    #[serde(rename = "runnerGrantRequired")]
    pub runner_grant_required: bool,
    #[serde(rename = "secretRefsRequired")]
    pub secret_refs_required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessVerificationRequirementV1 {
    #[serde(rename = "allowedVerificationTiers")]
    pub allowed_verification_tiers: Vec<IntegrityTier>,
    #[serde(rename = "requireReceipt")]
    pub require_receipt: bool,
    #[serde(rename = "requireValidation")]
    pub require_validation: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct AccessPolicyV1Context {
    #[serde(
        rename = "serviceRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub service_ref: Option<String>,
    #[serde(rename = "allowedUsers", default)]
    pub allowed_users: Vec<String>,
    #[serde(rename = "allowedRunners", default)]
    pub allowed_runners: Vec<String>,
    #[serde(rename = "allowedOrganizations", default)]
    pub allowed_organizations: Vec<String>,
    #[serde(
        rename = "revocationListRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revocation_list_ref: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub sign: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessPolicyV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "policyId")]
    pub policy_id: String,
    #[serde(
        rename = "packageRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_ref: Option<String>,
    #[serde(
        rename = "serviceRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub service_ref: Option<String>,
    #[serde(rename = "licenseType")]
    pub license_type: LicenseType,
    #[serde(rename = "allowedUsers")]
    pub allowed_users: Vec<String>,
    #[serde(rename = "allowedRunners")]
    pub allowed_runners: Vec<String>,
    #[serde(rename = "allowedOrganizations")]
    pub allowed_organizations: Vec<String>,
    pub rights: Vec<AccessRightV1>,
    #[serde(rename = "paymentRequirement")]
    pub payment_requirement: AccessPaymentRequirementV1,
    #[serde(rename = "privacyRequirement")]
    pub privacy_requirement: AccessPrivacyRequirementV1,
    #[serde(rename = "verificationRequirement")]
    pub verification_requirement: AccessVerificationRequirementV1,
    #[serde(
        rename = "licenseRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub license_ref: Option<String>,
    #[serde(
        rename = "revocationListRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revocation_list_ref: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessPolicyVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "policyId")]
    pub policy_id: String,
    #[serde(rename = "expectedPolicyId")]
    pub expected_policy_id: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(
        rename = "expectedSignature",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expected_signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AccessProofV1 {
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub requester: String,
    #[serde(rename = "requestedUse")]
    pub requested_use: String,
    #[serde(rename = "runnerId", default)]
    pub runner_id: Option<String>,
    #[serde(default)]
    pub proofs: Vec<AccessProofV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
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
    #[serde(rename = "encryptedAccessRef", default)]
    pub encrypted_access_ref: Option<String>,
    pub issuer: String,
    pub signature: String,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AccessScopeV1 {
    ReadAsset,
    ExecutePackage,
    RunService,
    PublishToNamespace,
    UpdateFeed,
    ValidatePackage,
    ViewReceipt,
    ViewTrace,
    UseVectorStore,
    UseDataset,
    UseTool,
    ResellOrDelegate,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AccessSubjectTypeV1 {
    Asset,
    Package,
    Service,
    Namespace,
    Feed,
    Receipt,
    Trace,
    VectorStore,
    Dataset,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessSubjectV1 {
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: AccessSubjectTypeV1,
    #[serde(default)]
    pub refs: Vec<String>,
    #[serde(
        rename = "assetClass",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub asset_class: Option<String>,
    #[serde(
        rename = "contentHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "grantId")]
    pub grant_id: String,
    pub issuer: String,
    pub grantee: String,
    pub scopes: Vec<AccessScopeV1>,
    pub subjects: Vec<AccessSubjectV1>,
    #[serde(rename = "allowedUses", default)]
    pub allowed_uses: Vec<String>,
    #[serde(default)]
    pub constraints: Value,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "runnerId", default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<String>,
    #[serde(
        rename = "revocationListRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revocation_list_ref: Option<String>,
    #[serde(
        rename = "paymentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub payment_ref: Option<String>,
    #[serde(
        rename = "settlementRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub settlement_ref: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGrantRevocationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
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
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessRevocationListV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    pub revocations: Vec<AccessGrantRevocationV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessEvaluationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub decision: AccessDecision,
    pub reasons: Vec<String>,
    #[serde(rename = "licensePolicy")]
    pub license_policy: LicensePolicyV1,
    #[serde(rename = "grantId", default)]
    pub grant_id: Option<String>,
}

pub fn license_requires_access_grant(license_type: &LicenseType) -> bool {
    !matches!(license_type, LicenseType::Open)
}

pub fn default_allowed_uses(license_type: &LicenseType) -> Vec<String> {
    let uses: &[&str] = match license_type {
        LicenseType::Open => &[
            "personal",
            "commercial",
            "research",
            "runner-service",
            "validation",
        ],
        LicenseType::Commercial => &["commercial", "runner-service", "validation"],
        LicenseType::Private => &["runner-service", "validation"],
        LicenseType::TokenGated | LicenseType::Subscription => {
            &["personal", "runner-service", "validation"]
        }
        LicenseType::Custom => &["personal", "commercial", "runner-service", "validation"],
    };
    uses.iter().copied().map(str::to_string).collect()
}

pub fn default_access_control_mode(license_type: &LicenseType) -> AccessControlMode {
    if license_requires_access_grant(license_type) {
        AccessControlMode::EncryptedRef
    } else {
        AccessControlMode::None
    }
}

pub fn license_policy_from_manifest(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
) -> LicensePolicyV1 {
    let license_type = manifest.license.license_type.clone();
    LicensePolicyV1 {
        schema_version: "swarm-ai.license-policy.v1".to_string(),
        package_id: manifest.package_id.clone(),
        package_ref: package_ref.into(),
        license_type: license_type.clone(),
        allowed_uses: default_allowed_uses(&license_type),
        restricted_uses: vec![
            "training-competitor-model".to_string(),
            "redistribution".to_string(),
        ],
        requires_access_grant: license_requires_access_grant(&license_type),
        terms_ref: manifest.license.url.clone(),
        access_control: AccessControlV1 {
            mode: default_access_control_mode(&license_type),
            act_ref: None,
        },
    }
}

pub fn access_policy_from_license_policy(policy: &LicensePolicyV1) -> AccessPolicyV1 {
    access_policy_from_license_policy_with_context(policy, AccessPolicyV1Context::default())
}

pub fn access_policy_from_license_policy_with_context(
    policy: &LicensePolicyV1,
    context: AccessPolicyV1Context,
) -> AccessPolicyV1 {
    let mut access_policy = AccessPolicyV1 {
        schema_version: "hivemind.access_policy.v1".to_string(),
        policy_id: String::new(),
        package_ref: Some(policy.package_ref.clone()),
        service_ref: context.service_ref,
        license_type: policy.license_type.clone(),
        allowed_users: context.allowed_users,
        allowed_runners: context.allowed_runners,
        allowed_organizations: context.allowed_organizations,
        rights: access_rights_for_license_policy(policy),
        payment_requirement: payment_requirement_for_license_policy(policy),
        privacy_requirement: privacy_requirement_for_license_policy(policy),
        verification_requirement: verification_requirement_for_license_policy(policy),
        license_ref: Some(format!("local://license-policy/{}", policy.package_id)),
        revocation_list_ref: context.revocation_list_ref,
        expires_at: context.expires_at,
        signature: None,
    };
    access_policy.policy_id = canonical_access_policy_id(&access_policy)
        .unwrap_or_else(|_| "access-policy-invalid".to_string());
    if context.sign {
        let _ = sign_access_policy(&mut access_policy);
    }
    access_policy
}

pub fn canonical_access_policy_id(policy: &AccessPolicyV1) -> serde_json::Result<String> {
    Ok(format!(
        "access-policy-{}",
        &hash_canonical_json(&canonicalize_json(&access_policy_signing_value(policy)?))[..24]
    ))
}

pub fn expected_access_policy_signature(policy: &AccessPolicyV1) -> serde_json::Result<String> {
    Ok(format!(
        "{DEV_ACCESS_POLICY_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&access_policy_signing_value(policy)?))
    ))
}

pub fn sign_access_policy(policy: &mut AccessPolicyV1) -> serde_json::Result<String> {
    policy.policy_id = canonical_access_policy_id(policy)?;
    let signature = expected_access_policy_signature(policy)?;
    policy.signature = Some(signature.clone());
    Ok(signature)
}

pub fn verify_access_policy(policy: &AccessPolicyV1) -> AccessPolicyVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_policy_id =
        canonical_access_policy_id(policy).unwrap_or_else(|_| "access-policy-invalid".to_string());
    let expected_signature = expected_access_policy_signature(policy).ok();

    if policy.schema_version != "hivemind.access_policy.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be hivemind.access_policy.v1",
        ));
    }
    if policy.policy_id.trim().is_empty() {
        issues.push(issue("$.policyId", "Access policy id is required"));
    } else if policy.policy_id != expected_policy_id {
        issues.push(issue(
            "$.policyId",
            "Access policy id does not match canonical policy content",
        ));
    }
    if policy.package_ref.is_none() && policy.service_ref.is_none() {
        issues.push(issue(
            "$.packageRef",
            "Access policy must reference a packageRef or serviceRef",
        ));
    }
    if let Some(package_ref) = &policy.package_ref
        && !package_ref.starts_with("bzz://")
        && !package_ref.starts_with("local://")
    {
        issues.push(issue(
            "$.packageRef",
            "Access policy packageRef must be bzz:// or local://",
        ));
    }
    if policy.rights.is_empty() {
        issues.push(issue(
            "$.rights",
            "Access policy must grant at least one possible right",
        ));
    }
    if policy.payment_requirement.required
        && policy
            .payment_requirement
            .asset
            .as_deref()
            .unwrap_or("")
            .is_empty()
    {
        warnings.push(issue(
            "$.paymentRequirement.asset",
            "Payment is required but no concrete asset is declared yet",
        ));
    }
    if policy.privacy_requirement.allowed_privacy_tiers.is_empty() {
        issues.push(issue(
            "$.privacyRequirement.allowedPrivacyTiers",
            "At least one privacy tier must be allowed",
        ));
    }
    if policy
        .verification_requirement
        .allowed_verification_tiers
        .is_empty()
    {
        issues.push(issue(
            "$.verificationRequirement.allowedVerificationTiers",
            "At least one verification tier must be allowed",
        ));
    }
    match (&policy.signature, &expected_signature) {
        (Some(signature), Some(expected)) if signature == expected => warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production identity signing",
        )),
        (Some(_), Some(_)) => issues.push(issue(
            "$.signature",
            "Access policy signature does not match canonical dev signature",
        )),
        (None, _) => warnings.push(issue(
            "$.signature",
            "Access policy is unsigned development data",
        )),
        _ => {}
    }

    AccessPolicyVerificationV1 {
        schema_version: "hivemind.access_policy_verification.v1".to_string(),
        policy_id: policy.policy_id.clone(),
        expected_policy_id,
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
    }
}

fn access_rights_for_license_policy(policy: &LicensePolicyV1) -> Vec<AccessRightV1> {
    let mut rights = vec![
        AccessRightV1::ViewMetadata,
        AccessRightV1::DownloadPublicArtifacts,
        AccessRightV1::ExecuteLocally,
        AccessRightV1::ValidatePackage,
    ];
    if policy.requires_access_grant || policy.access_control.mode != AccessControlMode::None {
        rights.push(AccessRightV1::DecryptArtifacts);
    }
    if policy
        .allowed_uses
        .iter()
        .any(|allowed| allowed == "runner-service")
    {
        rights.push(AccessRightV1::ExecuteRemotely);
        rights.push(AccessRightV1::HostService);
    }
    if policy
        .allowed_uses
        .iter()
        .any(|allowed| allowed == "commercial")
    {
        rights.push(AccessRightV1::CommercialUse);
    }
    if policy
        .allowed_uses
        .iter()
        .any(|allowed| allowed == "fine-tune")
    {
        rights.push(AccessRightV1::FineTune);
    }
    if !policy
        .restricted_uses
        .iter()
        .any(|restricted| restricted == "redistribution")
        && policy.license_type == LicenseType::Open
    {
        rights.push(AccessRightV1::Redistribute);
    }
    rights.sort_by_key(|right| format!("{right:?}"));
    rights.dedup();
    rights
}

fn payment_requirement_for_license_policy(policy: &LicensePolicyV1) -> AccessPaymentRequirementV1 {
    AccessPaymentRequirementV1 {
        required: matches!(
            policy.license_type,
            LicenseType::Commercial | LicenseType::TokenGated | LicenseType::Subscription
        ),
        asset: None,
        amount: None,
        settlement_ref: None,
        subscription_ref: None,
    }
}

fn privacy_requirement_for_license_policy(policy: &LicensePolicyV1) -> AccessPrivacyRequirementV1 {
    let protected = policy.requires_access_grant || policy.license_type == LicenseType::Private;
    AccessPrivacyRequirementV1 {
        allowed_privacy_tiers: if protected {
            vec![PrivacyTier::LocalOnly, PrivacyTier::TeeConfidential]
        } else {
            vec![
                PrivacyTier::Standard,
                PrivacyTier::NoLog,
                PrivacyTier::RedactedInput,
                PrivacyTier::LocalOnly,
            ]
        },
        runner_grant_required: protected,
        secret_refs_required: policy.access_control.mode != AccessControlMode::None,
    }
}

fn verification_requirement_for_license_policy(
    policy: &LicensePolicyV1,
) -> AccessVerificationRequirementV1 {
    let protected = policy.requires_access_grant || policy.license_type == LicenseType::Private;
    AccessVerificationRequirementV1 {
        allowed_verification_tiers: if protected {
            vec![
                IntegrityTier::ReceiptOnly,
                IntegrityTier::ValidatorSpotCheck,
                IntegrityTier::TeeAttested,
            ]
        } else {
            vec![
                IntegrityTier::ReceiptOnly,
                IntegrityTier::ValidatorSpotCheck,
            ]
        },
        require_receipt: true,
        require_validation: false,
    }
}

fn access_policy_signing_value(policy: &AccessPolicyV1) -> serde_json::Result<Value> {
    let mut value = serde_json::to_value(policy)?;
    if let Value::Object(object) = &mut value {
        object.remove("policyId");
        object.remove("signature");
    }
    Ok(value)
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
    use crate::manifest::{LicenseInfo, PackageKind, Publisher};
    use serde_json::json;

    #[test]
    fn access_policy_projection_for_open_license_is_public_and_unsigned() {
        let manifest = test_manifest(LicenseType::Open);
        let license_policy = license_policy_from_manifest(&manifest, "bzz://open-package");

        let access_policy = access_policy_from_license_policy(&license_policy);
        let verification = verify_access_policy(&access_policy);

        assert_eq!(access_policy.schema_version, "hivemind.access_policy.v1");
        assert_eq!(
            verification.schema_version,
            "hivemind.access_policy_verification.v1"
        );
        assert!(access_policy.policy_id.starts_with("access-policy-"));
        assert_eq!(
            access_policy.package_ref.as_deref(),
            Some("bzz://open-package")
        );
        assert_eq!(access_policy.license_type, LicenseType::Open);
        assert!(
            access_policy
                .rights
                .contains(&AccessRightV1::DownloadPublicArtifacts)
        );
        assert!(
            access_policy
                .rights
                .contains(&AccessRightV1::ExecuteRemotely)
        );
        assert!(!access_policy.payment_requirement.required);
        assert!(
            access_policy
                .privacy_requirement
                .allowed_privacy_tiers
                .contains(&PrivacyTier::Standard)
        );
        assert!(!access_policy.privacy_requirement.runner_grant_required);
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signature")
        );
    }

    #[test]
    fn signed_access_policy_for_private_license_requires_grants_and_confidential_execution() {
        let manifest = test_manifest(LicenseType::Private);
        let license_policy = license_policy_from_manifest(&manifest, "bzz://private-package");

        let access_policy = access_policy_from_license_policy_with_context(
            &license_policy,
            AccessPolicyV1Context {
                allowed_users: vec!["enterprise-user".to_string()],
                allowed_runners: vec!["confidential-runner".to_string()],
                revocation_list_ref: Some("bzz://revocations".to_string()),
                sign: true,
                ..Default::default()
            },
        );
        let verification = verify_access_policy(&access_policy);

        assert_eq!(
            access_policy.allowed_runners,
            vec!["confidential-runner".to_string()]
        );
        assert_eq!(access_policy.license_type, LicenseType::Private);
        assert!(
            access_policy
                .rights
                .contains(&AccessRightV1::DecryptArtifacts)
        );
        assert!(access_policy.privacy_requirement.runner_grant_required);
        assert!(access_policy.privacy_requirement.secret_refs_required);
        assert!(
            access_policy
                .privacy_requirement
                .allowed_privacy_tiers
                .contains(&PrivacyTier::TeeConfidential)
        );
        assert!(
            access_policy
                .verification_requirement
                .allowed_verification_tiers
                .contains(&IntegrityTier::TeeAttested)
        );
        assert!(access_policy.signature.is_some());
        assert!(verification.valid, "{verification:#?}");
    }

    fn test_manifest(license_type: LicenseType) -> PackageManifestV1 {
        PackageManifestV1 {
            schema_version: "swarm-ai.package.v1".to_string(),
            package_id: "hivemind/test".to_string(),
            kind: PackageKind::Model,
            name: "Test".to_string(),
            version: "0.1.0".to_string(),
            publisher: Publisher {
                address: "0x0".to_string(),
                display_name: "Hivemind Labs".to_string(),
                publisher_profile_ref: None,
            },
            capabilities: vec!["embedding".to_string()],
            artifact_groups: Vec::new(),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            permissions: Vec::new(),
            license: LicenseInfo {
                license_type,
                name: None,
                url: Some("bzz://license-terms".to_string()),
            },
        }
    }
}
