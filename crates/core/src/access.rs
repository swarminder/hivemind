use crate::canonical::{canonicalize_json, hash_canonical_json};
use crate::manifest::{LicenseType, PackageManifestV1};
use crate::trust::{IntegrityTier, PrivacyTier};
use crate::validation::ValidationIssue;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEV_ACCESS_POLICY_SIGNATURE_PREFIX: &str = "dev-access-policy-signature-v1";
const DEV_ACCESS_POLICY_V2_SIGNATURE_PREFIX: &str = "dev-access-policy-v2-signature-v1";

pub const LICENSE_POLICY_V2_SCHEMA_VERSION: &str = "hivemind.license_policy.v2";
pub const ACCESS_POLICY_V2_SCHEMA_VERSION: &str = "hivemind.access_policy.v2";
pub const ACCESS_POLICY_V2_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.access_policy_verification.v2";
pub const ASSET_ACCESS_RULE_SCHEMA_VERSION: &str = "hivemind.asset_access_rule.v1";
pub const ASSET_ACCESS_RULE_V2_SCHEMA_VERSION: &str = "hivemind.asset_access_rule.v2";
pub const PAID_ACCESS_QUOTE_SCHEMA_VERSION: &str = "hivemind.paid_access_quote.v1";
pub const ACCESS_EVALUATION_RESULT_SCHEMA_VERSION: &str = "hivemind.access_evaluation_result.v1";
pub const ACCESS_GRANT_V3_SCHEMA_VERSION: &str = "hivemind.access-grant.v3";

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
pub struct AssetAccessRuleV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub subject: AccessSubjectV1,
    pub rights: Vec<AccessRightV1>,
    #[serde(rename = "accessMethod")]
    pub access_method: AccessMethod,
    #[serde(rename = "grantRequired")]
    pub grant_required: bool,
    #[serde(rename = "publicMetadata")]
    pub public_metadata: bool,
    pub encrypted: bool,
    #[serde(rename = "paymentRequirement")]
    pub payment_requirement: AccessPaymentRequirementV1,
    #[serde(rename = "privacyRequirement")]
    pub privacy_requirement: AccessPrivacyRequirementV1,
    #[serde(rename = "verificationRequirement")]
    pub verification_requirement: AccessVerificationRequirementV1,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AssetAccessRuleV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub subject: AccessSubjectV1,
    pub rights: Vec<AccessRightV1>,
    #[serde(rename = "allowedScopes")]
    pub allowed_scopes: Vec<AccessScopeV1>,
    #[serde(rename = "accessMethod")]
    pub access_method: AccessMethod,
    #[serde(rename = "grantRequired")]
    pub grant_required: bool,
    #[serde(rename = "publicMetadata")]
    pub public_metadata: bool,
    pub encrypted: bool,
    #[serde(rename = "policyRef", default, skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
    #[serde(
        rename = "licenseRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub license_ref: Option<String>,
    #[serde(
        rename = "decryptionRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub decryption_ref: Option<String>,
    #[serde(
        rename = "revocationListRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revocation_list_ref: Option<String>,
    #[serde(
        rename = "settlementRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub settlement_ref: Option<String>,
    #[serde(rename = "paymentRequirement")]
    pub payment_requirement: AccessPaymentRequirementV1,
    #[serde(rename = "privacyRequirement")]
    pub privacy_requirement: AccessPrivacyRequirementV1,
    #[serde(rename = "verificationRequirement")]
    pub verification_requirement: AccessVerificationRequirementV1,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LicensePolicyV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "policyId")]
    pub policy_id: String,
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
    pub rights: Vec<AccessRightV1>,
    #[serde(rename = "requiresAccessGrant")]
    pub requires_access_grant: bool,
    #[serde(rename = "termsRef", default)]
    pub terms_ref: Option<String>,
    #[serde(rename = "accessControl")]
    pub access_control: AccessControlV1,
    #[serde(rename = "assetRules")]
    pub asset_rules: Vec<AssetAccessRuleV1>,
    #[serde(rename = "paymentRequirement")]
    pub payment_requirement: AccessPaymentRequirementV1,
    #[serde(rename = "privacyRequirement")]
    pub privacy_requirement: AccessPrivacyRequirementV1,
    #[serde(rename = "verificationRequirement")]
    pub verification_requirement: AccessVerificationRequirementV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessPolicyV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
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
    #[serde(rename = "assetRules")]
    pub asset_rules: Vec<AssetAccessRuleV1>,
    #[serde(rename = "grantScopes")]
    pub grant_scopes: Vec<AccessScopeV1>,
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
    #[serde(
        rename = "settlementRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub settlement_ref: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessPolicyV2VerificationV1 {
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PaidAccessQuoteV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "quoteId")]
    pub quote_id: String,
    #[serde(rename = "policyId")]
    pub policy_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub requester: String,
    #[serde(rename = "requestedUse")]
    pub requested_use: String,
    #[serde(rename = "assetRef", default, skip_serializing_if = "Option::is_none")]
    pub asset_ref: Option<String>,
    pub amount: f64,
    pub currency: String,
    #[serde(rename = "paymentMethod")]
    pub payment_method: String,
    #[serde(
        rename = "settlementRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub settlement_ref: Option<String>,
    #[serde(
        rename = "listingRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub listing_ref: Option<String>,
    #[serde(rename = "grantScopes")]
    pub grant_scopes: Vec<AccessScopeV1>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessEvaluationResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "resultId")]
    pub result_id: String,
    #[serde(rename = "policyId")]
    pub policy_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "assetRef", default, skip_serializing_if = "Option::is_none")]
    pub asset_ref: Option<String>,
    pub requester: String,
    pub action: AccessScopeV1,
    pub decision: AccessDecision,
    pub allowed: bool,
    pub reasons: Vec<String>,
    #[serde(rename = "grantId", default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
    #[serde(
        rename = "paidAccessQuote",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub paid_access_quote: Option<PaidAccessQuoteV1>,
    #[serde(
        rename = "evaluatedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub evaluated_at: Option<String>,
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
pub struct AccessGrantV3 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "grantId")]
    pub grant_id: String,
    pub issuer: String,
    pub grantee: String,
    pub scopes: Vec<AccessScopeV1>,
    pub subjects: Vec<AccessSubjectV1>,
    #[serde(rename = "assetRules", default)]
    pub asset_rules: Vec<AssetAccessRuleV2>,
    #[serde(rename = "allowedUses", default)]
    pub allowed_uses: Vec<String>,
    #[serde(
        rename = "privacyTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub privacy_tier: Option<PrivacyTier>,
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
    #[serde(rename = "revocationHintRefs", default)]
    pub revocation_hint_refs: Vec<String>,
    #[serde(
        rename = "paymentRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub payment_ref: Option<String>,
    #[serde(rename = "paymentEvidenceRefs", default)]
    pub payment_evidence_refs: Vec<String>,
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

pub fn license_policy_v2_from_manifest(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
) -> LicensePolicyV2 {
    let policy = license_policy_from_manifest(manifest, package_ref);
    let asset_rules = asset_access_rules_from_manifest(manifest, &policy);
    license_policy_v2_from_license_policy_with_rules(&policy, asset_rules)
}

pub fn license_policy_v2_from_license_policy(policy: &LicensePolicyV1) -> LicensePolicyV2 {
    license_policy_v2_from_license_policy_with_rules(
        policy,
        vec![package_access_rule_for_license_policy(policy)],
    )
}

pub fn access_policy_v2_from_license_policy(policy: &LicensePolicyV1) -> AccessPolicyV2 {
    let policy_v2 = license_policy_v2_from_license_policy(policy);
    access_policy_v2_from_license_policy_v2(&policy_v2, AccessPolicyV1Context::default())
}

pub fn access_policy_v2_from_license_policy_with_context(
    policy: &LicensePolicyV1,
    context: AccessPolicyV1Context,
) -> AccessPolicyV2 {
    let policy_v2 = license_policy_v2_from_license_policy(policy);
    access_policy_v2_from_license_policy_v2(&policy_v2, context)
}

pub fn access_policy_v2_from_license_policy_v2(
    policy: &LicensePolicyV2,
    context: AccessPolicyV1Context,
) -> AccessPolicyV2 {
    let mut access_policy = AccessPolicyV2 {
        schema_version: ACCESS_POLICY_V2_SCHEMA_VERSION.to_string(),
        object_kind: "access_policy".to_string(),
        policy_id: String::new(),
        package_ref: Some(policy.package_ref.clone()),
        service_ref: context.service_ref,
        license_type: policy.license_type.clone(),
        allowed_users: context.allowed_users,
        allowed_runners: context.allowed_runners,
        allowed_organizations: context.allowed_organizations,
        rights: policy.rights.clone(),
        asset_rules: policy.asset_rules.clone(),
        grant_scopes: grant_scopes_for_access_rights(&policy.rights),
        payment_requirement: policy.payment_requirement.clone(),
        privacy_requirement: policy.privacy_requirement.clone(),
        verification_requirement: policy.verification_requirement.clone(),
        license_ref: Some(format!("local://license-policy-v2/{}", policy.policy_id)),
        revocation_list_ref: context.revocation_list_ref,
        settlement_ref: policy.payment_requirement.settlement_ref.clone(),
        expires_at: context.expires_at,
        evidence_refs: Vec::new(),
        signature: None,
    };
    access_policy.policy_id = canonical_access_policy_v2_id(&access_policy)
        .unwrap_or_else(|_| "access-policy-v2-invalid".to_string());
    if context.sign {
        let _ = sign_access_policy_v2(&mut access_policy);
    }
    access_policy
}

pub fn canonical_access_policy_v2_id(policy: &AccessPolicyV2) -> serde_json::Result<String> {
    Ok(format!(
        "access-policy-v2-{}",
        &hash_canonical_json(&canonicalize_json(&access_policy_v2_signing_value(policy)?))[..24]
    ))
}

pub fn expected_access_policy_v2_signature(policy: &AccessPolicyV2) -> serde_json::Result<String> {
    Ok(format!(
        "{DEV_ACCESS_POLICY_V2_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&access_policy_v2_signing_value(policy)?))
    ))
}

pub fn sign_access_policy_v2(policy: &mut AccessPolicyV2) -> serde_json::Result<String> {
    policy.policy_id = canonical_access_policy_v2_id(policy)?;
    let signature = expected_access_policy_v2_signature(policy)?;
    policy.signature = Some(signature.clone());
    Ok(signature)
}

pub fn verify_access_policy_v2(policy: &AccessPolicyV2) -> AccessPolicyV2VerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_policy_id = canonical_access_policy_v2_id(policy)
        .unwrap_or_else(|_| "access-policy-v2-invalid".to_string());
    let expected_signature = expected_access_policy_v2_signature(policy).ok();

    if policy.schema_version != ACCESS_POLICY_V2_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {ACCESS_POLICY_V2_SCHEMA_VERSION}"),
        ));
    }
    if policy.object_kind != "access_policy" {
        issues.push(issue(
            "$.objectKind",
            "Expected objectKind to be access_policy",
        ));
    }
    if policy.policy_id.trim().is_empty() {
        issues.push(issue("$.policyId", "Access policy id is required"));
    } else if policy.policy_id != expected_policy_id {
        issues.push(issue(
            "$.policyId",
            "Access policy id does not match canonical v2 policy content",
        ));
    }
    if policy.package_ref.is_none() && policy.service_ref.is_none() {
        issues.push(issue(
            "$.packageRef",
            "Access policy v2 must reference a packageRef or serviceRef",
        ));
    }
    if policy.rights.is_empty() {
        issues.push(issue(
            "$.rights",
            "Access policy v2 must grant at least one possible right",
        ));
    }
    if policy.asset_rules.is_empty() {
        issues.push(issue(
            "$.assetRules",
            "Access policy v2 must include asset-level access rules",
        ));
    }
    for (index, rule) in policy.asset_rules.iter().enumerate() {
        validate_asset_access_rule(rule, index, &mut issues, &mut warnings);
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
            "Payment is required but no concrete asset/currency is declared yet",
        ));
    }
    if policy.grant_scopes.is_empty()
        && policy
            .asset_rules
            .iter()
            .any(|rule| rule.grant_required || rule.encrypted)
    {
        issues.push(issue(
            "$.grantScopes",
            "Protected access policy v2 must advertise at least one grant scope",
        ));
    }
    match (&policy.signature, &expected_signature) {
        (Some(signature), Some(expected)) if signature == expected => warnings.push(issue(
            "$.signature",
            "Signature is deterministic local-dev signing, not production identity signing",
        )),
        (Some(_), Some(_)) => issues.push(issue(
            "$.signature",
            "Access policy v2 signature does not match canonical dev signature",
        )),
        (None, _) => warnings.push(issue(
            "$.signature",
            "Access policy v2 is unsigned development data",
        )),
        _ => {}
    }

    AccessPolicyV2VerificationV1 {
        schema_version: ACCESS_POLICY_V2_VERIFICATION_SCHEMA_VERSION.to_string(),
        policy_id: policy.policy_id.clone(),
        expected_policy_id,
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
    }
}

pub fn paid_access_quote(
    policy: &AccessPolicyV2,
    requester: impl Into<String>,
    requested_use: impl Into<String>,
    asset_ref: Option<String>,
    amount: Option<f64>,
    currency: Option<String>,
    expires_at: Option<String>,
) -> PaidAccessQuoteV1 {
    paid_access_quote_with_listing_ref(
        policy,
        requester,
        requested_use,
        asset_ref,
        amount,
        currency,
        expires_at,
        None,
        Vec::new(),
    )
}

pub fn paid_access_quote_with_listing_ref(
    policy: &AccessPolicyV2,
    requester: impl Into<String>,
    requested_use: impl Into<String>,
    asset_ref: Option<String>,
    amount: Option<f64>,
    currency: Option<String>,
    expires_at: Option<String>,
    listing_ref: Option<String>,
    evidence_refs: Vec<String>,
) -> PaidAccessQuoteV1 {
    let mut quote_evidence_refs = policy.evidence_refs.clone();
    quote_evidence_refs.extend(evidence_refs);
    quote_evidence_refs.sort();
    quote_evidence_refs.dedup();
    let mut quote = PaidAccessQuoteV1 {
        schema_version: PAID_ACCESS_QUOTE_SCHEMA_VERSION.to_string(),
        quote_id: String::new(),
        policy_id: policy.policy_id.clone(),
        package_ref: policy.package_ref.clone().unwrap_or_default(),
        requester: requester.into(),
        requested_use: requested_use.into(),
        asset_ref,
        amount: amount.or(policy.payment_requirement.amount).unwrap_or(
            if policy.payment_requirement.required {
                1.0
            } else {
                0.0
            },
        ),
        currency: currency
            .or_else(|| policy.payment_requirement.asset.clone())
            .unwrap_or_else(|| "xDAI".to_string()),
        payment_method: "local-dev-payment-authorization".to_string(),
        settlement_ref: policy
            .settlement_ref
            .clone()
            .or_else(|| policy.payment_requirement.settlement_ref.clone()),
        listing_ref,
        grant_scopes: policy.grant_scopes.clone(),
        expires_at,
        evidence_refs: quote_evidence_refs,
    };
    quote.quote_id = canonical_paid_access_quote_id(&quote);
    quote
}

pub fn access_evaluation_result(
    policy: &AccessPolicyV2,
    evaluation: &AccessEvaluationV1,
    requester: impl Into<String>,
    action: AccessScopeV1,
    asset_ref: Option<String>,
    paid_access_quote: Option<PaidAccessQuoteV1>,
    evaluated_at: Option<String>,
) -> AccessEvaluationResultV1 {
    let mut result = AccessEvaluationResultV1 {
        schema_version: ACCESS_EVALUATION_RESULT_SCHEMA_VERSION.to_string(),
        result_id: String::new(),
        policy_id: policy.policy_id.clone(),
        package_ref: policy
            .package_ref
            .clone()
            .unwrap_or_else(|| evaluation.package_ref.clone()),
        asset_ref,
        requester: requester.into(),
        action,
        decision: evaluation.decision.clone(),
        allowed: evaluation.decision == AccessDecision::Granted,
        reasons: evaluation.reasons.clone(),
        grant_id: evaluation.grant_id.clone(),
        paid_access_quote,
        evaluated_at,
    };
    result.result_id = canonical_access_evaluation_result_id(&result);
    result
}

pub fn asset_access_rule_v2_from_v1(
    rule: &AssetAccessRuleV1,
    policy_ref: Option<String>,
    license_ref: Option<String>,
    revocation_list_ref: Option<String>,
    settlement_ref: Option<String>,
) -> AssetAccessRuleV2 {
    let mut rule_v2 = AssetAccessRuleV2 {
        schema_version: ASSET_ACCESS_RULE_V2_SCHEMA_VERSION.to_string(),
        object_kind: "asset_access_rule".to_string(),
        rule_id: String::new(),
        subject: rule.subject.clone(),
        rights: rule.rights.clone(),
        allowed_scopes: grant_scopes_for_access_rights(&rule.rights),
        access_method: rule.access_method.clone(),
        grant_required: rule.grant_required,
        public_metadata: rule.public_metadata,
        encrypted: rule.encrypted,
        policy_ref,
        license_ref,
        decryption_ref: if rule.encrypted {
            rule.subject.refs.first().map(|reference| {
                format!("local://access/decryption/{}", reference_id_tail(reference))
            })
        } else {
            None
        },
        revocation_list_ref,
        settlement_ref: settlement_ref.or_else(|| rule.payment_requirement.settlement_ref.clone()),
        payment_requirement: rule.payment_requirement.clone(),
        privacy_requirement: rule.privacy_requirement.clone(),
        verification_requirement: rule.verification_requirement.clone(),
        evidence_refs: rule.evidence_refs.clone(),
    };
    rule_v2.rule_id = canonical_asset_access_rule_v2_id(&rule_v2);
    rule_v2
}

pub fn asset_access_rules_v2_from_access_policy(policy: &AccessPolicyV2) -> Vec<AssetAccessRuleV2> {
    policy
        .asset_rules
        .iter()
        .map(|rule| {
            asset_access_rule_v2_from_v1(
                rule,
                Some(format!("local://access-policy-v2/{}", policy.policy_id)),
                policy.license_ref.clone(),
                policy.revocation_list_ref.clone(),
                policy.settlement_ref.clone(),
            )
        })
        .collect()
}

pub fn access_grant_v3_from_v2(
    grant: &AccessGrantV2,
    asset_rules: Vec<AssetAccessRuleV2>,
    privacy_tier: Option<PrivacyTier>,
    payment_evidence_refs: Vec<String>,
) -> AccessGrantV3 {
    let mut evidence_refs = grant.evidence_refs.clone();
    evidence_refs.extend(payment_evidence_refs.iter().cloned());
    evidence_refs.sort();
    evidence_refs.dedup();
    AccessGrantV3 {
        schema_version: ACCESS_GRANT_V3_SCHEMA_VERSION.to_string(),
        object_kind: "access_grant".to_string(),
        grant_id: grant
            .grant_id
            .clone()
            .replace("access-grant-", "access-grant-v3-"),
        issuer: grant.issuer.clone(),
        grantee: grant.grantee.clone(),
        scopes: grant.scopes.clone(),
        subjects: grant.subjects.clone(),
        asset_rules,
        allowed_uses: grant.allowed_uses.clone(),
        privacy_tier,
        constraints: grant.constraints.clone(),
        issued_at: grant.issued_at.clone(),
        expires_at: grant.expires_at.clone(),
        runner_id: grant.runner_id.clone(),
        revocation_list_ref: grant.revocation_list_ref.clone(),
        revocation_hint_refs: grant
            .revocation_list_ref
            .clone()
            .into_iter()
            .collect::<Vec<_>>(),
        payment_ref: grant.payment_ref.clone(),
        payment_evidence_refs,
        settlement_ref: grant.settlement_ref.clone(),
        evidence_refs,
        signatures: Vec::new(),
    }
}

pub fn canonical_asset_access_rule_v2_id(rule: &AssetAccessRuleV2) -> String {
    let mut value = serde_json::to_value(rule).expect("asset access rule v2 should serialize");
    if let Value::Object(object) = &mut value {
        object.remove("ruleId");
    }
    format!(
        "asset-access-rule-v2-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
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

fn license_policy_v2_from_license_policy_with_rules(
    policy: &LicensePolicyV1,
    asset_rules: Vec<AssetAccessRuleV1>,
) -> LicensePolicyV2 {
    let rights = access_rights_for_license_policy(policy);
    let payment_requirement = payment_requirement_for_license_policy(policy);
    let privacy_requirement = privacy_requirement_for_license_policy(policy);
    let verification_requirement = verification_requirement_for_license_policy(policy);
    let mut policy_v2 = LicensePolicyV2 {
        schema_version: LICENSE_POLICY_V2_SCHEMA_VERSION.to_string(),
        object_kind: "license_policy".to_string(),
        policy_id: String::new(),
        package_id: policy.package_id.clone(),
        package_ref: policy.package_ref.clone(),
        license_type: policy.license_type.clone(),
        allowed_uses: policy.allowed_uses.clone(),
        restricted_uses: policy.restricted_uses.clone(),
        rights,
        requires_access_grant: policy.requires_access_grant,
        terms_ref: policy.terms_ref.clone(),
        access_control: policy.access_control.clone(),
        asset_rules,
        payment_requirement,
        privacy_requirement,
        verification_requirement,
    };
    policy_v2.policy_id = canonical_license_policy_v2_id(&policy_v2);
    policy_v2
}

fn asset_access_rules_from_manifest(
    manifest: &PackageManifestV1,
    policy: &LicensePolicyV1,
) -> Vec<AssetAccessRuleV1> {
    if manifest.artifact_groups.is_empty() {
        return vec![package_access_rule_for_license_policy(policy)];
    }
    manifest
        .artifact_groups
        .iter()
        .map(|artifact| {
            let subject = AccessSubjectV1 {
                subject_id: artifact.id.clone(),
                subject_type: AccessSubjectTypeV1::Asset,
                refs: artifact
                    .paths
                    .iter()
                    .map(|path| format!("package://{}/{}", manifest.package_id, path))
                    .collect(),
                asset_class: Some(artifact.format.clone()),
                content_hash: Some(format!("sha256:{}", artifact.sha256)),
                namespace: None,
            };
            asset_access_rule_for_subject(policy, subject)
        })
        .collect()
}

fn package_access_rule_for_license_policy(policy: &LicensePolicyV1) -> AssetAccessRuleV1 {
    let subject = AccessSubjectV1 {
        subject_id: policy.package_id.clone(),
        subject_type: AccessSubjectTypeV1::Package,
        refs: vec![policy.package_ref.clone()],
        asset_class: Some("package".to_string()),
        content_hash: None,
        namespace: None,
    };
    asset_access_rule_for_subject(policy, subject)
}

fn asset_access_rule_for_subject(
    policy: &LicensePolicyV1,
    subject: AccessSubjectV1,
) -> AssetAccessRuleV1 {
    let grant_required =
        policy.requires_access_grant || policy.access_control.mode != AccessControlMode::None;
    let mut rights = vec![AccessRightV1::ViewMetadata];
    if grant_required {
        rights.push(AccessRightV1::DecryptArtifacts);
    } else {
        rights.push(AccessRightV1::DownloadPublicArtifacts);
    }
    rights.extend(access_rights_for_license_policy(policy));
    rights.sort_by_key(|right| format!("{right:?}"));
    rights.dedup();
    let mut rule = AssetAccessRuleV1 {
        schema_version: ASSET_ACCESS_RULE_SCHEMA_VERSION.to_string(),
        rule_id: String::new(),
        subject,
        rights,
        access_method: match policy.access_control.mode {
            AccessControlMode::None => AccessMethod::Open,
            AccessControlMode::Act => AccessMethod::Act,
            AccessControlMode::EncryptedRef => AccessMethod::EncryptedReference,
            AccessControlMode::ExternalLicenseServer => AccessMethod::External,
        },
        grant_required,
        public_metadata: true,
        encrypted: grant_required,
        payment_requirement: payment_requirement_for_license_policy(policy),
        privacy_requirement: privacy_requirement_for_license_policy(policy),
        verification_requirement: verification_requirement_for_license_policy(policy),
        evidence_refs: Vec::new(),
    };
    rule.rule_id = canonical_asset_access_rule_id(&rule);
    rule
}

fn grant_scopes_for_access_rights(rights: &[AccessRightV1]) -> Vec<AccessScopeV1> {
    let mut scopes = Vec::new();
    for right in rights {
        match right {
            AccessRightV1::ViewMetadata | AccessRightV1::DownloadPublicArtifacts => {
                scopes.push(AccessScopeV1::ReadAsset)
            }
            AccessRightV1::DecryptArtifacts => scopes.push(AccessScopeV1::ReadAsset),
            AccessRightV1::ExecuteLocally | AccessRightV1::ExecuteRemotely => {
                scopes.push(AccessScopeV1::ExecutePackage)
            }
            AccessRightV1::HostService => scopes.push(AccessScopeV1::RunService),
            AccessRightV1::ValidatePackage => scopes.push(AccessScopeV1::ValidatePackage),
            AccessRightV1::FineTune => scopes.push(AccessScopeV1::UseDataset),
            AccessRightV1::Redistribute | AccessRightV1::CommercialUse => {
                scopes.push(AccessScopeV1::ResellOrDelegate)
            }
        }
    }
    scopes.sort();
    scopes.dedup();
    scopes
}

fn validate_asset_access_rule(
    rule: &AssetAccessRuleV1,
    index: usize,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    let path = format!("$.assetRules[{index}]");
    if rule.schema_version != ASSET_ACCESS_RULE_SCHEMA_VERSION {
        issues.push(issue(
            format!("{path}.schemaVersion"),
            format!("Expected schemaVersion to be {ASSET_ACCESS_RULE_SCHEMA_VERSION}"),
        ));
    }
    if rule.rule_id.trim().is_empty() {
        issues.push(issue(format!("{path}.ruleId"), "Rule id is required"));
    } else if rule.rule_id != canonical_asset_access_rule_id(rule) {
        issues.push(issue(
            format!("{path}.ruleId"),
            "Asset access rule id does not match canonical rule content",
        ));
    }
    if rule.subject.subject_id.trim().is_empty() {
        issues.push(issue(
            format!("{path}.subject.subjectId"),
            "Asset access rule subject id is required",
        ));
    }
    if rule.rights.is_empty() {
        issues.push(issue(
            format!("{path}.rights"),
            "Asset access rule must grant at least one right",
        ));
    }
    if rule.encrypted && !rule.grant_required {
        issues.push(issue(
            format!("{path}.grantRequired"),
            "Encrypted asset rules must require an access grant",
        ));
    }
    if rule.payment_requirement.required && !rule.grant_required {
        warnings.push(issue(
            format!("{path}.paymentRequirement"),
            "Paid access rules should normally require an access grant",
        ));
    }
    if !rule.public_metadata && rule.subject.subject_type == AccessSubjectTypeV1::Package {
        warnings.push(issue(
            format!("{path}.publicMetadata"),
            "Package-level rules should keep metadata public when possible",
        ));
    }
}

fn canonical_license_policy_v2_id(policy: &LicensePolicyV2) -> String {
    let mut value = serde_json::to_value(policy).expect("license policy v2 should serialize");
    if let Value::Object(object) = &mut value {
        object.remove("policyId");
    }
    format!(
        "license-policy-v2-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

fn canonical_asset_access_rule_id(rule: &AssetAccessRuleV1) -> String {
    let mut value = serde_json::to_value(rule).expect("asset access rule should serialize");
    if let Value::Object(object) = &mut value {
        object.remove("ruleId");
    }
    format!(
        "asset-access-rule-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

fn canonical_paid_access_quote_id(quote: &PaidAccessQuoteV1) -> String {
    let mut value = serde_json::to_value(quote).expect("paid access quote should serialize");
    if let Value::Object(object) = &mut value {
        object.remove("quoteId");
    }
    format!(
        "paid-access-quote-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

fn canonical_access_evaluation_result_id(result: &AccessEvaluationResultV1) -> String {
    let mut value =
        serde_json::to_value(result).expect("access evaluation result should serialize");
    if let Value::Object(object) = &mut value {
        object.remove("resultId");
    }
    format!(
        "access-evaluation-result-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

fn reference_id_tail(reference: &str) -> String {
    reference
        .rsplit(['/', ':'])
        .find(|part| !part.trim().is_empty())
        .unwrap_or("asset")
        .to_string()
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

fn access_policy_v2_signing_value(policy: &AccessPolicyV2) -> serde_json::Result<Value> {
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
    use crate::manifest::{ArtifactGroup, ArtifactMinimum, LicenseInfo, PackageKind, Publisher};
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

    #[test]
    fn license_policy_v2_projects_artifact_rules_for_private_assets() {
        let mut manifest = test_manifest(LicenseType::Private);
        manifest.artifact_groups = vec![ArtifactGroup {
            id: "weights".to_string(),
            target: "gpu".to_string(),
            engine: "vllm".to_string(),
            format: "safetensors".to_string(),
            paths: vec!["model.safetensors".to_string()],
            total_bytes: 1024,
            sha256: "a".repeat(64),
            minimum: ArtifactMinimum {
                memory_mb: Some(8192),
                webgpu: Some(false),
                disk_mb: Some(2048),
            },
        }];

        let license_policy = license_policy_v2_from_manifest(&manifest, "bzz://private-package");
        let access_policy = access_policy_v2_from_license_policy_v2(
            &license_policy,
            AccessPolicyV1Context {
                allowed_users: vec!["enterprise-user".to_string()],
                sign: true,
                ..Default::default()
            },
        );
        let verification = verify_access_policy_v2(&access_policy);

        assert_eq!(
            license_policy.schema_version,
            LICENSE_POLICY_V2_SCHEMA_VERSION
        );
        assert_eq!(license_policy.object_kind, "license_policy");
        assert_eq!(license_policy.asset_rules.len(), 1);
        let rule = &license_policy.asset_rules[0];
        let expected_hash = format!("sha256:{}", "a".repeat(64));
        assert_eq!(rule.subject.subject_type, AccessSubjectTypeV1::Asset);
        assert_eq!(
            rule.subject.content_hash.as_deref(),
            Some(expected_hash.as_str())
        );
        assert!(rule.public_metadata);
        assert!(rule.encrypted);
        assert!(rule.grant_required);
        assert!(rule.rights.contains(&AccessRightV1::DecryptArtifacts));
        assert!(
            access_policy
                .grant_scopes
                .contains(&AccessScopeV1::ReadAsset)
        );
        assert!(access_policy.signature.is_some());
        assert!(verification.valid, "{verification:#?}");
    }

    #[test]
    fn asset_access_rule_v2_projects_policy_links_and_scope_hints() {
        let mut manifest = test_manifest(LicenseType::Private);
        manifest.artifact_groups = vec![ArtifactGroup {
            id: "weights".to_string(),
            target: "gpu".to_string(),
            engine: "vllm".to_string(),
            format: "safetensors".to_string(),
            paths: vec!["model.safetensors".to_string()],
            total_bytes: 1024,
            sha256: "b".repeat(64),
            minimum: ArtifactMinimum {
                memory_mb: Some(8192),
                webgpu: Some(false),
                disk_mb: Some(2048),
            },
        }];

        let license_policy = license_policy_v2_from_manifest(&manifest, "bzz://private-package");
        let access_policy = access_policy_v2_from_license_policy_v2(
            &license_policy,
            AccessPolicyV1Context {
                revocation_list_ref: Some("bzz://revocations".to_string()),
                sign: true,
                ..Default::default()
            },
        );
        let rules = asset_access_rules_v2_from_access_policy(&access_policy);

        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.schema_version, ASSET_ACCESS_RULE_V2_SCHEMA_VERSION);
        assert_eq!(rule.object_kind, "asset_access_rule");
        assert!(rule.rule_id.starts_with("asset-access-rule-v2-"));
        assert_eq!(rule.rule_id, canonical_asset_access_rule_v2_id(rule));
        assert!(rule.allowed_scopes.contains(&AccessScopeV1::ReadAsset));
        assert!(rule.encrypted);
        assert!(rule.grant_required);
        let expected_policy_ref = format!("local://access-policy-v2/{}", access_policy.policy_id);
        assert_eq!(
            rule.policy_ref.as_deref(),
            Some(expected_policy_ref.as_str())
        );
        assert_eq!(
            rule.revocation_list_ref.as_deref(),
            Some("bzz://revocations")
        );
        assert!(rule.decryption_ref.is_some());
    }

    #[test]
    fn paid_access_quote_and_evaluation_result_are_canonical() {
        let manifest = test_manifest(LicenseType::Commercial);
        let license_policy = license_policy_from_manifest(&manifest, "bzz://paid-package");
        let access_policy = access_policy_v2_from_license_policy(&license_policy);

        let quote = paid_access_quote(
            &access_policy,
            "buyer",
            "commercial",
            Some("package://hivemind/test/model.safetensors".to_string()),
            Some(2.5),
            Some("xDAI".to_string()),
            Some("2026-12-31T00:00:00Z".to_string()),
        );
        let evaluation = AccessEvaluationV1 {
            schema_version: "swarm-ai.access-evaluation.v1".to_string(),
            package_id: license_policy.package_id.clone(),
            package_ref: license_policy.package_ref.clone(),
            decision: AccessDecision::PaymentRequired,
            reasons: vec!["paid access requires payment authorization".to_string()],
            license_policy,
            grant_id: None,
        };
        let result = access_evaluation_result(
            &access_policy,
            &evaluation,
            "buyer",
            AccessScopeV1::ReadAsset,
            quote.asset_ref.clone(),
            Some(quote.clone()),
            Some("2026-06-05T00:00:00Z".to_string()),
        );

        assert_eq!(quote.schema_version, PAID_ACCESS_QUOTE_SCHEMA_VERSION);
        assert!(quote.quote_id.starts_with("paid-access-quote-"));
        assert_eq!(quote.amount, 2.5);
        assert!(quote.grant_scopes.contains(&AccessScopeV1::ReadAsset));
        assert_eq!(
            result.schema_version,
            ACCESS_EVALUATION_RESULT_SCHEMA_VERSION
        );
        assert!(result.result_id.starts_with("access-evaluation-result-"));
        assert_eq!(result.decision, AccessDecision::PaymentRequired);
        assert!(!result.allowed);
        assert_eq!(
            result.paid_access_quote.as_ref().unwrap().quote_id,
            quote.quote_id
        );
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
