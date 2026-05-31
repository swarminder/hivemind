use crate::manifest::{LicenseType, PackageManifestV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
