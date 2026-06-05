use anyhow::Context;
use chrono::{DateTime, SecondsFormat, Utc};
use hivemind_core::{ValidationIssue, canonicalize_json, hash_canonical_json};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use schemars::JsonSchema;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEV_GOVERNANCE_POLICY_SIGNATURE_PREFIX: &str = "dev-governance-policy-signature-v1";
const DEV_SCHEMA_RELEASE_SIGNATURE_PREFIX: &str = "dev-schema-release-signature-v1";
const DEV_SECURITY_ADVISORY_SIGNATURE_PREFIX: &str = "dev-security-advisory-signature-v1";
const DEV_COMPONENT_READINESS_SIGNATURE_PREFIX: &str = "dev-component-readiness-signature-v1";
pub const COMPONENT_READINESS_SCHEMA_VERSION: &str = "hivemind.component_readiness.v1";
pub const COMPONENT_READINESS_INIT_OPTIONS_SCHEMA_VERSION: &str =
    "hivemind.component_readiness_init_options.v1";
pub const COMPONENT_READINESS_VERIFICATION_SCHEMA_VERSION: &str =
    "hivemind.component_readiness_verification.v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum GovernanceScope {
    ProtocolSchemas,
    CompatibilityCertification,
    RegistryCuration,
    ValidatorEligibility,
    MarketplaceRules,
    MinerOnboarding,
    SecurityResponse,
    EconomicPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum GovernanceRuleStatus {
    Draft,
    Active,
    Deprecated,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SchemaCompatibilityStatus {
    Experimental,
    Development,
    ProductionApproved,
    Deprecated,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentReadinessLevelV1 {
    Mock,
    Local,
    Gateway,
    Testnet,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SecuritySeverity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityAdvisoryStatus {
    Draft,
    Published,
    Mitigated,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityAdvisoryCategory {
    PackageVulnerability,
    MaliciousPackage,
    RunnerAbuse,
    MinerFraud,
    CompromisedKey,
    HiddenBenchmarkLeakage,
    EmergencyAccessRevocation,
    SandboxEscape,
    ConfidentialAttestationFailure,
    DisputeEscalation,
    SecurityResponse,
    RegistryCuration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GovernanceDeprecationPolicyV1 {
    #[serde(rename = "deprecatedAfterDays")]
    pub deprecated_after_days: u32,
    #[serde(rename = "removalAfterDays")]
    pub removal_after_days: u32,
    #[serde(rename = "migrationRequired")]
    pub migration_required: bool,
}

impl Default for GovernanceDeprecationPolicyV1 {
    fn default() -> Self {
        Self {
            deprecated_after_days: 180,
            removal_after_days: 365,
            migration_required: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GovernanceRoleV1 {
    pub role: String,
    #[serde(default)]
    pub responsibilities: Vec<String>,
    #[serde(rename = "authorityRefs", default)]
    pub authority_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GovernanceRuleRefV1 {
    pub scope: GovernanceScope,
    #[serde(rename = "ruleRef")]
    pub rule_ref: String,
    pub description: String,
    pub status: GovernanceRuleStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GovernancePolicyManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "policyId")]
    pub policy_id: String,
    pub title: String,
    pub steward: String,
    pub scopes: Vec<GovernanceScope>,
    pub roles: Vec<GovernanceRoleV1>,
    pub rules: Vec<GovernanceRuleRefV1>,
    #[serde(rename = "compatibilityTestRefs", default)]
    pub compatibility_test_refs: Vec<String>,
    #[serde(rename = "approvedSchemaVersions", default)]
    pub approved_schema_versions: Vec<String>,
    #[serde(rename = "deprecationPolicy")]
    pub deprecation_policy: GovernanceDeprecationPolicyV1,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(
        rename = "effectiveAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub effective_at: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GovernancePolicyInitOptionsV1 {
    pub title: String,
    pub steward: String,
    #[serde(default)]
    pub scopes: Vec<GovernanceScope>,
    #[serde(rename = "approvedSchemaVersions", default)]
    pub approved_schema_versions: Vec<String>,
    #[serde(rename = "compatibilityTestRefs", default)]
    pub compatibility_test_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GovernancePolicyVerificationV1 {
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
pub struct SchemaReleaseV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "releaseId")]
    pub release_id: String,
    #[serde(rename = "objectType")]
    pub object_type: String,
    #[serde(rename = "releasedSchemaVersion")]
    pub released_schema_version: String,
    #[serde(rename = "interfaceVersion")]
    pub interface_version: String,
    pub status: SchemaCompatibilityStatus,
    #[serde(rename = "breakingChange")]
    pub breaking_change: bool,
    #[serde(rename = "compatibleWith", default)]
    pub compatible_with: Vec<String>,
    #[serde(
        rename = "migrationGuideRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub migration_guide_ref: Option<String>,
    #[serde(rename = "compatibilityTestRefs", default)]
    pub compatibility_test_refs: Vec<String>,
    #[serde(rename = "approvedBy", default)]
    pub approved_by: Vec<String>,
    #[serde(
        rename = "deprecationPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deprecation_policy: Option<GovernanceDeprecationPolicyV1>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SchemaReleaseInitOptionsV1 {
    #[serde(rename = "objectType")]
    pub object_type: String,
    #[serde(rename = "releasedSchemaVersion")]
    pub released_schema_version: String,
    #[serde(rename = "interfaceVersion")]
    pub interface_version: String,
    pub status: SchemaCompatibilityStatus,
    #[serde(rename = "breakingChange", default)]
    pub breaking_change: bool,
    #[serde(rename = "compatibleWith", default)]
    pub compatible_with: Vec<String>,
    #[serde(rename = "compatibilityTestRefs", default)]
    pub compatibility_test_refs: Vec<String>,
    #[serde(rename = "approvedBy", default)]
    pub approved_by: Vec<String>,
    #[serde(rename = "migrationGuideRef", default)]
    pub migration_guide_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SchemaReleaseVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "releaseId")]
    pub release_id: String,
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
pub struct SecurityAdvisoryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "advisoryId")]
    pub advisory_id: String,
    pub title: String,
    pub reporter: String,
    pub severity: SecuritySeverity,
    pub status: SecurityAdvisoryStatus,
    pub categories: Vec<SecurityAdvisoryCategory>,
    #[serde(rename = "affectedRefs", default)]
    pub affected_refs: Vec<String>,
    pub summary: String,
    pub impact: String,
    #[serde(rename = "mitigationRefs", default)]
    pub mitigation_refs: Vec<String>,
    #[serde(rename = "recommendedActions", default)]
    pub recommended_actions: Vec<String>,
    #[serde(rename = "disclosedAt")]
    pub disclosed_at: String,
    #[serde(
        rename = "resolvedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resolved_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SecurityAdvisoryInitOptionsV1 {
    pub title: String,
    pub reporter: String,
    pub severity: SecuritySeverity,
    #[serde(default)]
    pub categories: Vec<SecurityAdvisoryCategory>,
    #[serde(rename = "affectedRefs", default)]
    pub affected_refs: Vec<String>,
    pub summary: String,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SecurityAdvisoryVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "advisoryId")]
    pub advisory_id: String,
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
pub struct SecurityResponsePlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "advisoryId")]
    pub advisory_id: String,
    pub severity: SecuritySeverity,
    #[serde(rename = "requiresEmergencyAction")]
    pub requires_emergency_action: bool,
    #[serde(rename = "affectedRefs", default)]
    pub affected_refs: Vec<String>,
    pub actions: Vec<String>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ComponentReadinessV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "readinessId")]
    pub readiness_id: String,
    #[serde(rename = "componentName")]
    pub component_name: String,
    #[serde(rename = "componentType")]
    pub component_type: String,
    pub owner: String,
    pub status: ComponentReadinessLevelV1,
    #[serde(
        rename = "implementationRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub implementation_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "schemaRefs", default)]
    pub schema_refs: Vec<String>,
    #[serde(rename = "apiSurfaces", default)]
    pub api_surfaces: Vec<String>,
    #[serde(rename = "supportedEnvironments", default)]
    pub supported_environments: Vec<String>,
    #[serde(rename = "compatibilityCertificationRefs", default)]
    pub compatibility_certification_refs: Vec<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blockers: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ComponentReadinessInitOptionsV1 {
    #[serde(
        rename = "schemaVersion",
        default = "component_readiness_init_options_schema_version"
    )]
    pub schema_version: String,
    #[serde(rename = "componentName")]
    pub component_name: String,
    #[serde(rename = "componentType")]
    pub component_type: String,
    pub owner: String,
    pub status: ComponentReadinessLevelV1,
    #[serde(
        rename = "implementationRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub implementation_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "schemaRefs", default)]
    pub schema_refs: Vec<String>,
    #[serde(rename = "apiSurfaces", default)]
    pub api_surfaces: Vec<String>,
    #[serde(rename = "supportedEnvironments", default)]
    pub supported_environments: Vec<String>,
    #[serde(rename = "compatibilityCertificationRefs", default)]
    pub compatibility_certification_refs: Vec<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub blockers: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ComponentReadinessVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "readinessId")]
    pub readiness_id: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum GovernanceRecordType {
    Policy,
    SchemaRelease,
    SecurityAdvisory,
    ComponentReadiness,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GovernanceRecordSummaryV1 {
    #[serde(rename = "recordId")]
    pub record_id: String,
    #[serde(rename = "recordType")]
    pub record_type: GovernanceRecordType,
    pub title: String,
    #[serde(rename = "primaryActor")]
    pub primary_actor: String,
    pub status: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "signaturePresent")]
    pub signature_present: bool,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GovernanceStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "policyCount")]
    pub policy_count: usize,
    #[serde(rename = "schemaReleaseCount")]
    pub schema_release_count: usize,
    #[serde(rename = "securityAdvisoryCount")]
    pub security_advisory_count: usize,
    #[serde(rename = "componentReadinessCount")]
    pub component_readiness_count: usize,
    #[serde(rename = "productionReadyComponentCount")]
    pub production_ready_component_count: usize,
    #[serde(rename = "blockedComponentCount")]
    pub blocked_component_count: usize,
    #[serde(rename = "criticalAdvisoryCount")]
    pub critical_advisory_count: usize,
    #[serde(rename = "emergencyActionCount")]
    pub emergency_action_count: usize,
    #[serde(rename = "recordCount")]
    pub record_count: usize,
    pub records: Vec<GovernanceRecordSummaryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GovernanceRecordLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "recordId")]
    pub record_id: String,
    #[serde(
        rename = "recordType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub record_type: Option<GovernanceRecordType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<GovernancePolicyManifestV1>,
    #[serde(
        rename = "schemaRelease",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub schema_release: Option<SchemaReleaseV1>,
    #[serde(
        rename = "securityAdvisory",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub security_advisory: Option<SecurityAdvisoryV1>,
    #[serde(
        rename = "componentReadiness",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub component_readiness: Option<ComponentReadinessV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

pub fn create_governance_policy(
    options: GovernancePolicyInitOptionsV1,
) -> GovernancePolicyManifestV1 {
    let scopes = if options.scopes.is_empty() {
        vec![
            GovernanceScope::ProtocolSchemas,
            GovernanceScope::CompatibilityCertification,
            GovernanceScope::RegistryCuration,
            GovernanceScope::ValidatorEligibility,
            GovernanceScope::MarketplaceRules,
            GovernanceScope::MinerOnboarding,
            GovernanceScope::SecurityResponse,
        ]
    } else {
        sorted_unique(options.scopes)
    };
    let mut approved_schema_versions = options.approved_schema_versions;
    approved_schema_versions.sort();
    approved_schema_versions.dedup();
    let mut compatibility_test_refs = options.compatibility_test_refs;
    compatibility_test_refs.sort();
    compatibility_test_refs.dedup();

    let mut policy = GovernancePolicyManifestV1 {
        schema_version: "swarm-ai.governance-policy.v1".to_string(),
        policy_id: String::new(),
        title: options.title,
        steward: options.steward,
        scopes: scopes.clone(),
        roles: default_roles(),
        rules: default_rule_refs(&scopes),
        compatibility_test_refs,
        approved_schema_versions,
        deprecation_policy: GovernanceDeprecationPolicyV1::default(),
        created_at: timestamp(),
        effective_at: None,
        expires_at: None,
        metadata: json!({}),
        signature: None,
    };
    sign_governance_policy(&mut policy);
    policy
}

pub fn create_schema_release(options: SchemaReleaseInitOptionsV1) -> SchemaReleaseV1 {
    let mut compatible_with = options.compatible_with;
    compatible_with.sort();
    compatible_with.dedup();
    let mut compatibility_test_refs = options.compatibility_test_refs;
    compatibility_test_refs.sort();
    compatibility_test_refs.dedup();
    let mut approved_by = options.approved_by;
    approved_by.sort();
    approved_by.dedup();

    let mut release = SchemaReleaseV1 {
        schema_version: "swarm-ai.schema-release.v1".to_string(),
        release_id: String::new(),
        object_type: options.object_type,
        released_schema_version: options.released_schema_version,
        interface_version: options.interface_version,
        status: options.status,
        breaking_change: options.breaking_change,
        compatible_with,
        migration_guide_ref: options.migration_guide_ref,
        compatibility_test_refs,
        approved_by,
        deprecation_policy: None,
        created_at: timestamp(),
        signature: None,
    };
    sign_schema_release(&mut release);
    release
}

pub fn create_security_advisory(options: SecurityAdvisoryInitOptionsV1) -> SecurityAdvisoryV1 {
    let categories = if options.categories.is_empty() {
        vec![SecurityAdvisoryCategory::SecurityResponse]
    } else {
        sorted_unique(options.categories)
    };
    let mut affected_refs = options.affected_refs;
    affected_refs.sort();
    affected_refs.dedup();

    let mut advisory = SecurityAdvisoryV1 {
        schema_version: "swarm-ai.security-advisory.v1".to_string(),
        advisory_id: String::new(),
        title: options.title,
        reporter: options.reporter,
        severity: options.severity,
        status: SecurityAdvisoryStatus::Published,
        categories,
        affected_refs,
        summary: options.summary,
        impact: options.impact,
        mitigation_refs: Vec::new(),
        recommended_actions: Vec::new(),
        disclosed_at: timestamp(),
        resolved_at: None,
        signature: None,
    };
    advisory.recommended_actions = default_security_actions(&advisory);
    sign_security_advisory(&mut advisory);
    advisory
}

pub fn create_component_readiness(
    options: ComponentReadinessInitOptionsV1,
) -> ComponentReadinessV1 {
    let mut schema_refs = options.schema_refs;
    schema_refs.sort();
    schema_refs.dedup();
    let mut api_surfaces = options.api_surfaces;
    api_surfaces.sort();
    api_surfaces.dedup();
    let mut supported_environments = options.supported_environments;
    supported_environments.sort();
    supported_environments.dedup();
    let mut compatibility_certification_refs = options.compatibility_certification_refs;
    compatibility_certification_refs.sort();
    compatibility_certification_refs.dedup();
    let mut evidence_refs = options.evidence_refs;
    evidence_refs.sort();
    evidence_refs.dedup();
    let mut blockers = options.blockers;
    blockers.sort();
    blockers.dedup();
    let mut limitations = options.limitations;
    limitations.sort();
    limitations.dedup();

    let mut readiness = ComponentReadinessV1 {
        schema_version: COMPONENT_READINESS_SCHEMA_VERSION.to_string(),
        readiness_id: String::new(),
        component_name: options.component_name,
        component_type: options.component_type,
        owner: options.owner,
        status: options.status,
        implementation_ref: options.implementation_ref,
        version: options.version,
        schema_refs,
        api_surfaces,
        supported_environments,
        compatibility_certification_refs,
        evidence_refs,
        blockers,
        limitations,
        updated_at: timestamp(),
        expires_at: options.expires_at,
        metadata: options.metadata,
        signature: None,
    };
    sign_component_readiness(&mut readiness);
    readiness
}

pub fn sign_governance_policy(policy: &mut GovernancePolicyManifestV1) {
    policy.signature = Some(expected_governance_policy_signature(policy));
    policy.policy_id = canonical_governance_policy_id(policy);
}

pub fn sign_schema_release(release: &mut SchemaReleaseV1) {
    release.signature = Some(expected_schema_release_signature(release));
    release.release_id = canonical_schema_release_id(release);
}

pub fn sign_security_advisory(advisory: &mut SecurityAdvisoryV1) {
    advisory.signature = Some(expected_security_advisory_signature(advisory));
    advisory.advisory_id = canonical_security_advisory_id(advisory);
}

pub fn sign_component_readiness(readiness: &mut ComponentReadinessV1) {
    readiness.signature = Some(expected_component_readiness_signature(readiness));
    readiness.readiness_id = canonical_component_readiness_id(readiness);
}

pub fn sign_governance_policy_with_identity(
    policy: &mut GovernancePolicyManifestV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != policy.steward {
        anyhow::bail!(
            "identity subject {} does not match governance policy steward {}",
            identity.subject,
            policy.steward
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "governance-policy",
        &policy_signing_value(policy),
    )?;
    policy.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    policy.policy_id = canonical_governance_policy_id(policy);
    Ok(envelope)
}

pub fn sign_schema_release_with_identity(
    release: &mut SchemaReleaseV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if !release
        .approved_by
        .iter()
        .any(|signer| signer == &identity.subject)
    {
        anyhow::bail!(
            "identity subject {} is not listed in schema release approvedBy",
            identity.subject
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "schema-release",
        &schema_release_signing_value(release),
    )?;
    release.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    release.release_id = canonical_schema_release_id(release);
    Ok(envelope)
}

pub fn sign_security_advisory_with_identity(
    advisory: &mut SecurityAdvisoryV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != advisory.reporter {
        anyhow::bail!(
            "identity subject {} does not match security advisory reporter {}",
            identity.subject,
            advisory.reporter
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "security-advisory",
        &security_advisory_signing_value(advisory),
    )?;
    advisory.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    advisory.advisory_id = canonical_security_advisory_id(advisory);
    Ok(envelope)
}

pub fn sign_component_readiness_with_identity(
    readiness: &mut ComponentReadinessV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != readiness.owner {
        anyhow::bail!(
            "identity subject {} does not match component readiness owner {}",
            identity.subject,
            readiness.owner
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "component-readiness",
        &component_readiness_signing_value(readiness),
    )?;
    readiness.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    readiness.readiness_id = canonical_component_readiness_id(readiness);
    Ok(envelope)
}

pub fn expected_governance_policy_signature(policy: &GovernancePolicyManifestV1) -> String {
    dev_signature(
        DEV_GOVERNANCE_POLICY_SIGNATURE_PREFIX,
        &policy_signing_value(policy),
    )
}

pub fn expected_schema_release_signature(release: &SchemaReleaseV1) -> String {
    dev_signature(
        DEV_SCHEMA_RELEASE_SIGNATURE_PREFIX,
        &schema_release_signing_value(release),
    )
}

pub fn expected_security_advisory_signature(advisory: &SecurityAdvisoryV1) -> String {
    dev_signature(
        DEV_SECURITY_ADVISORY_SIGNATURE_PREFIX,
        &security_advisory_signing_value(advisory),
    )
}

pub fn expected_component_readiness_signature(readiness: &ComponentReadinessV1) -> String {
    dev_signature(
        DEV_COMPONENT_READINESS_SIGNATURE_PREFIX,
        &component_readiness_signing_value(readiness),
    )
}

pub fn canonical_governance_policy_id(policy: &GovernancePolicyManifestV1) -> String {
    stable_id("governance-policy", &policy_signing_value(policy))
}

pub fn canonical_schema_release_id(release: &SchemaReleaseV1) -> String {
    stable_id("schema-release", &schema_release_signing_value(release))
}

pub fn canonical_security_advisory_id(advisory: &SecurityAdvisoryV1) -> String {
    stable_id(
        "security-advisory",
        &security_advisory_signing_value(advisory),
    )
}

pub fn canonical_component_readiness_id(readiness: &ComponentReadinessV1) -> String {
    stable_id(
        "component-readiness",
        &component_readiness_signing_value(readiness),
    )
}

pub fn verify_governance_policy(
    policy: &GovernancePolicyManifestV1,
) -> GovernancePolicyVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_governance_policy_signature(policy));

    if policy.schema_version != "swarm-ai.governance-policy.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.governance-policy.v1",
        ));
    }
    require_non_empty(&mut issues, "$.policyId", &policy.policy_id);
    if !policy.policy_id.is_empty() && policy.policy_id != canonical_governance_policy_id(policy) {
        issues.push(issue(
            "$.policyId",
            "Governance policy id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.title", &policy.title);
    require_non_empty(&mut issues, "$.steward", &policy.steward);
    if policy.scopes.is_empty() {
        issues.push(issue(
            "$.scopes",
            "Governance policy must declare at least one scope",
        ));
    }
    if policy.roles.is_empty() {
        warnings.push(issue(
            "$.roles",
            "Governance policy has no operational roles",
        ));
    }
    for (index, role) in policy.roles.iter().enumerate() {
        let base = format!("$.roles[{index}]");
        require_non_empty(&mut issues, format!("{base}.role"), &role.role);
        if role.responsibilities.is_empty() {
            warnings.push(issue(
                format!("{base}.responsibilities"),
                "Role has no declared responsibilities",
            ));
        }
    }
    if policy.rules.is_empty() {
        issues.push(issue(
            "$.rules",
            "Governance policy must reference at least one rule",
        ));
    }
    for (index, rule) in policy.rules.iter().enumerate() {
        let base = format!("$.rules[{index}]");
        require_non_empty(&mut issues, format!("{base}.ruleRef"), &rule.rule_ref);
        require_non_empty(
            &mut issues,
            format!("{base}.description"),
            &rule.description,
        );
        validate_ref(&mut warnings, format!("{base}.ruleRef"), &rule.rule_ref);
    }
    if policy.compatibility_test_refs.is_empty() {
        warnings.push(issue(
            "$.compatibilityTestRefs",
            "Policy does not point at compatibility certification tests",
        ));
    }
    if policy.approved_schema_versions.is_empty() {
        warnings.push(issue(
            "$.approvedSchemaVersions",
            "Policy does not name approved schema versions",
        ));
    }
    validate_deprecation_policy(
        &mut issues,
        "$.deprecationPolicy",
        &policy.deprecation_policy,
    );
    validate_optional_timestamps(
        &mut issues,
        &mut warnings,
        &policy.created_at,
        policy.effective_at.as_deref(),
        policy.expires_at.as_deref(),
    );
    verify_signature(
        &mut issues,
        &mut warnings,
        &mut expected_signature,
        "$.signature",
        "governance-policy",
        &policy_signing_value(policy),
        policy.signature.as_deref(),
        SignatureExpectation::ExactSigner(&policy.steward),
        "Governance policy signature does not match canonical dev signature or Ed25519 steward identity envelope",
        DEV_GOVERNANCE_POLICY_SIGNATURE_PREFIX,
    );

    GovernancePolicyVerificationV1 {
        schema_version: "swarm-ai.governance-policy-verification.v1".to_string(),
        policy_id: policy.policy_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: timestamp(),
    }
}

pub fn verify_schema_release(release: &SchemaReleaseV1) -> SchemaReleaseVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_schema_release_signature(release));

    if release.schema_version != "swarm-ai.schema-release.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.schema-release.v1",
        ));
    }
    require_non_empty(&mut issues, "$.releaseId", &release.release_id);
    if !release.release_id.is_empty() && release.release_id != canonical_schema_release_id(release)
    {
        issues.push(issue(
            "$.releaseId",
            "Schema release id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.objectType", &release.object_type);
    require_non_empty(
        &mut issues,
        "$.releasedSchemaVersion",
        &release.released_schema_version,
    );
    if !release.released_schema_version.contains(".v") {
        warnings.push(issue(
            "$.releasedSchemaVersion",
            "Schema version should include an explicit .vN suffix",
        ));
    }
    if Version::parse(&release.interface_version).is_err() {
        issues.push(issue(
            "$.interfaceVersion",
            "interfaceVersion must be semantic versioning",
        ));
    }
    if release.breaking_change && release.migration_guide_ref.is_none() {
        issues.push(issue(
            "$.migrationGuideRef",
            "Breaking schema releases must include a migration guide reference",
        ));
    }
    if matches!(
        release.status,
        SchemaCompatibilityStatus::ProductionApproved | SchemaCompatibilityStatus::Deprecated
    ) && release.approved_by.is_empty()
    {
        issues.push(issue(
            "$.approvedBy",
            "Production or deprecated schema releases must list approvers",
        ));
    }
    if matches!(
        release.status,
        SchemaCompatibilityStatus::ProductionApproved
    ) && release.compatibility_test_refs.is_empty()
    {
        issues.push(issue(
            "$.compatibilityTestRefs",
            "Production schema releases must reference compatibility tests",
        ));
    }
    if matches!(release.status, SchemaCompatibilityStatus::Deprecated)
        && release.deprecation_policy.is_none()
    {
        warnings.push(issue(
            "$.deprecationPolicy",
            "Deprecated schema release should include deprecation timing",
        ));
    }
    for (index, reference) in release.compatibility_test_refs.iter().enumerate() {
        validate_ref(
            &mut warnings,
            format!("$.compatibilityTestRefs[{index}]"),
            reference,
        );
    }
    if let Some(policy) = &release.deprecation_policy {
        validate_deprecation_policy(&mut issues, "$.deprecationPolicy", policy);
    }
    validate_required_timestamp(&mut issues, "$.createdAt", &release.created_at);
    verify_signature(
        &mut issues,
        &mut warnings,
        &mut expected_signature,
        "$.signature",
        "schema-release",
        &schema_release_signing_value(release),
        release.signature.as_deref(),
        SignatureExpectation::OneOf(&release.approved_by),
        "Schema release signature does not match canonical dev signature or Ed25519 approver identity envelope",
        DEV_SCHEMA_RELEASE_SIGNATURE_PREFIX,
    );

    SchemaReleaseVerificationV1 {
        schema_version: "swarm-ai.schema-release-verification.v1".to_string(),
        release_id: release.release_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: timestamp(),
    }
}

pub fn verify_security_advisory(advisory: &SecurityAdvisoryV1) -> SecurityAdvisoryVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_security_advisory_signature(advisory));

    if advisory.schema_version != "swarm-ai.security-advisory.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.security-advisory.v1",
        ));
    }
    require_non_empty(&mut issues, "$.advisoryId", &advisory.advisory_id);
    if !advisory.advisory_id.is_empty()
        && advisory.advisory_id != canonical_security_advisory_id(advisory)
    {
        issues.push(issue(
            "$.advisoryId",
            "Security advisory id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.title", &advisory.title);
    require_non_empty(&mut issues, "$.reporter", &advisory.reporter);
    require_non_empty(&mut issues, "$.summary", &advisory.summary);
    require_non_empty(&mut issues, "$.impact", &advisory.impact);
    if advisory.categories.is_empty() {
        issues.push(issue(
            "$.categories",
            "Security advisory must include at least one category",
        ));
    }
    if advisory.affected_refs.is_empty() {
        warnings.push(issue(
            "$.affectedRefs",
            "Advisory does not name affected packages, runners, miners, keys, or schemas",
        ));
    }
    for (index, reference) in advisory.affected_refs.iter().enumerate() {
        validate_ref(&mut warnings, format!("$.affectedRefs[{index}]"), reference);
    }
    if matches!(
        advisory.severity,
        SecuritySeverity::High | SecuritySeverity::Critical
    ) && advisory.recommended_actions.is_empty()
    {
        issues.push(issue(
            "$.recommendedActions",
            "High and critical advisories must include recommended actions",
        ));
    }
    if matches!(advisory.status, SecurityAdvisoryStatus::Mitigated)
        && advisory.resolved_at.is_none()
    {
        issues.push(issue(
            "$.resolvedAt",
            "Mitigated advisories must include resolvedAt",
        ));
    }
    validate_required_timestamp(&mut issues, "$.disclosedAt", &advisory.disclosed_at);
    if let Some(resolved_at) = &advisory.resolved_at {
        validate_required_timestamp(&mut issues, "$.resolvedAt", resolved_at);
    }
    verify_signature(
        &mut issues,
        &mut warnings,
        &mut expected_signature,
        "$.signature",
        "security-advisory",
        &security_advisory_signing_value(advisory),
        advisory.signature.as_deref(),
        SignatureExpectation::ExactSigner(&advisory.reporter),
        "Security advisory signature does not match canonical dev signature or Ed25519 reporter identity envelope",
        DEV_SECURITY_ADVISORY_SIGNATURE_PREFIX,
    );

    SecurityAdvisoryVerificationV1 {
        schema_version: "swarm-ai.security-advisory-verification.v1".to_string(),
        advisory_id: advisory.advisory_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: timestamp(),
    }
}

pub fn verify_component_readiness(
    readiness: &ComponentReadinessV1,
) -> ComponentReadinessVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_component_readiness_signature(readiness));

    if readiness.schema_version != COMPONENT_READINESS_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!("Expected schemaVersion to be {COMPONENT_READINESS_SCHEMA_VERSION}"),
        ));
    }
    require_non_empty(&mut issues, "$.readinessId", &readiness.readiness_id);
    if !readiness.readiness_id.is_empty()
        && readiness.readiness_id != canonical_component_readiness_id(readiness)
    {
        issues.push(issue(
            "$.readinessId",
            "Component readiness id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.componentName", &readiness.component_name);
    require_non_empty(&mut issues, "$.componentType", &readiness.component_type);
    require_non_empty(&mut issues, "$.owner", &readiness.owner);
    validate_required_timestamp(&mut issues, "$.updatedAt", &readiness.updated_at);
    if let Some(expires_at) = readiness.expires_at.as_deref() {
        let updated_at = parse_timestamp(&mut issues, "$.updatedAt", &readiness.updated_at);
        let expires_at = parse_timestamp(&mut issues, "$.expiresAt", expires_at);
        if let (Some(updated_at), Some(expires_at)) = (updated_at, expires_at) {
            if expires_at <= updated_at {
                issues.push(issue(
                    "$.expiresAt",
                    "expiresAt must be later than updatedAt",
                ));
            }
        }
    }
    if let Some(reference) = readiness.implementation_ref.as_deref() {
        validate_ref(&mut warnings, "$.implementationRef", reference);
    }
    for (index, reference) in readiness.schema_refs.iter().enumerate() {
        validate_ref(&mut warnings, format!("$.schemaRefs[{index}]"), reference);
    }
    for (index, reference) in readiness
        .compatibility_certification_refs
        .iter()
        .enumerate()
    {
        validate_ref(
            &mut warnings,
            format!("$.compatibilityCertificationRefs[{index}]"),
            reference,
        );
    }
    for (index, reference) in readiness.evidence_refs.iter().enumerate() {
        validate_ref(&mut warnings, format!("$.evidenceRefs[{index}]"), reference);
    }
    for (index, surface) in readiness.api_surfaces.iter().enumerate() {
        require_non_empty(&mut issues, format!("$.apiSurfaces[{index}]"), surface);
    }
    for (index, environment) in readiness.supported_environments.iter().enumerate() {
        require_non_empty(
            &mut issues,
            format!("$.supportedEnvironments[{index}]"),
            environment,
        );
    }
    for (index, blocker) in readiness.blockers.iter().enumerate() {
        require_non_empty(&mut issues, format!("$.blockers[{index}]"), blocker);
    }
    for (index, limitation) in readiness.limitations.iter().enumerate() {
        require_non_empty(&mut issues, format!("$.limitations[{index}]"), limitation);
    }

    match readiness.status {
        ComponentReadinessLevelV1::Production => {
            if readiness.compatibility_certification_refs.is_empty() {
                issues.push(issue(
                    "$.compatibilityCertificationRefs",
                    "Production readiness requires at least one compatibility certification ref",
                ));
            }
            if readiness.evidence_refs.is_empty() {
                issues.push(issue(
                    "$.evidenceRefs",
                    "Production readiness requires audit, validation, benchmark, or release evidence refs",
                ));
            }
            if !readiness.blockers.is_empty() {
                issues.push(issue(
                    "$.blockers",
                    "Production readiness cannot be claimed while blockers are present",
                ));
            }
        }
        ComponentReadinessLevelV1::Testnet => {
            if readiness.compatibility_certification_refs.is_empty() {
                warnings.push(issue(
                    "$.compatibilityCertificationRefs",
                    "Testnet readiness should point at compatibility certification evidence",
                ));
            }
        }
        ComponentReadinessLevelV1::Mock => {
            if readiness.limitations.is_empty() {
                warnings.push(issue(
                    "$.limitations",
                    "Mock readiness should declare what behavior is simulated",
                ));
            }
        }
        ComponentReadinessLevelV1::Local | ComponentReadinessLevelV1::Gateway => {
            if readiness.evidence_refs.is_empty() {
                warnings.push(issue(
                    "$.evidenceRefs",
                    "Local and gateway readiness records should point at test or audit evidence",
                ));
            }
        }
    }

    verify_signature(
        &mut issues,
        &mut warnings,
        &mut expected_signature,
        "$.signature",
        "component-readiness",
        &component_readiness_signing_value(readiness),
        readiness.signature.as_deref(),
        SignatureExpectation::ExactSigner(&readiness.owner),
        "Component readiness signature does not match canonical dev signature or Ed25519 owner identity envelope",
        DEV_COMPONENT_READINESS_SIGNATURE_PREFIX,
    );

    ComponentReadinessVerificationV1 {
        schema_version: COMPONENT_READINESS_VERIFICATION_SCHEMA_VERSION.to_string(),
        readiness_id: readiness.readiness_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: timestamp(),
    }
}

pub fn security_response_plan(advisory: &SecurityAdvisoryV1) -> SecurityResponsePlanV1 {
    let verification = verify_security_advisory(advisory);
    let mut actions = advisory.recommended_actions.clone();
    actions.extend(default_security_actions(advisory));
    actions.sort();
    actions.dedup();
    let requires_emergency_action = matches!(
        advisory.severity,
        SecuritySeverity::High | SecuritySeverity::Critical
    ) || advisory.categories.iter().any(|category| {
        matches!(
            category,
            SecurityAdvisoryCategory::CompromisedKey
                | SecurityAdvisoryCategory::EmergencyAccessRevocation
                | SecurityAdvisoryCategory::SandboxEscape
                | SecurityAdvisoryCategory::ConfidentialAttestationFailure
        )
    });

    SecurityResponsePlanV1 {
        schema_version: "swarm-ai.security-response-plan.v1".to_string(),
        advisory_id: advisory.advisory_id.clone(),
        severity: advisory.severity.clone(),
        requires_emergency_action,
        affected_refs: advisory.affected_refs.clone(),
        actions,
        warnings: verification.warnings,
        generated_at: timestamp(),
    }
}

pub fn list_governance_records(governance_dir: &Path) -> anyhow::Result<GovernanceStoreSummaryV1> {
    let mut files = Vec::new();
    collect_governance_json_files(governance_dir, &mut files)?;
    files.sort();
    let mut records = Vec::new();
    let mut policy_count = 0;
    let mut schema_release_count = 0;
    let mut security_advisory_count = 0;
    let mut component_readiness_count = 0;
    let mut production_ready_component_count = 0;
    let mut blocked_component_count = 0;
    let mut critical_advisory_count = 0;
    let mut emergency_action_count = 0;

    for path in files {
        let Some(document) = read_governance_record_file(&path)? else {
            continue;
        };
        match &document {
            GovernanceRecordDocument::Policy(_) => policy_count += 1,
            GovernanceRecordDocument::SchemaRelease(_) => schema_release_count += 1,
            GovernanceRecordDocument::SecurityAdvisory(advisory) => {
                security_advisory_count += 1;
                if matches!(advisory.severity, SecuritySeverity::Critical) {
                    critical_advisory_count += 1;
                }
                if security_response_plan(advisory).requires_emergency_action {
                    emergency_action_count += 1;
                }
            }
            GovernanceRecordDocument::ComponentReadiness(readiness) => {
                component_readiness_count += 1;
                if matches!(readiness.status, ComponentReadinessLevelV1::Production)
                    && verify_component_readiness(readiness).valid
                {
                    production_ready_component_count += 1;
                }
                if !readiness.blockers.is_empty() {
                    blocked_component_count += 1;
                }
            }
        }
        records.push(governance_record_summary(
            &document,
            path.display().to_string(),
        ));
    }
    records.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.record_id.cmp(&right.record_id))
            .then(left.path.cmp(&right.path))
    });

    Ok(GovernanceStoreSummaryV1 {
        schema_version: "swarm-ai.governance-store-summary.v1".to_string(),
        root: governance_dir.display().to_string(),
        policy_count,
        schema_release_count,
        security_advisory_count,
        component_readiness_count,
        production_ready_component_count,
        blocked_component_count,
        critical_advisory_count,
        emergency_action_count,
        record_count: records.len(),
        records,
        generated_at: timestamp(),
    })
}

pub fn get_governance_record(
    governance_dir: &Path,
    record_id: &str,
) -> anyhow::Result<Option<GovernanceRecordLookupV1>> {
    let record_id = record_id.trim();
    if record_id.is_empty() {
        anyhow::bail!("recordId is required");
    }
    let mut files = Vec::new();
    collect_governance_json_files(governance_dir, &mut files)?;
    files.sort();

    for path in files {
        let Some(document) = read_governance_record_file(&path)? else {
            continue;
        };
        if governance_record_id(&document) == record_id {
            return Ok(Some(governance_record_lookup(
                document,
                path.display().to_string(),
            )));
        }
    }

    Ok(None)
}

#[derive(Debug, Clone, PartialEq)]
enum GovernanceRecordDocument {
    Policy(GovernancePolicyManifestV1),
    SchemaRelease(SchemaReleaseV1),
    SecurityAdvisory(SecurityAdvisoryV1),
    ComponentReadiness(ComponentReadinessV1),
}

fn collect_governance_json_files(
    governance_dir: &Path,
    files: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    if !governance_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(governance_dir)
        .with_context(|| format!("failed to read {}", governance_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_governance_json_files(&path, files)?;
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

fn read_governance_record_file(path: &Path) -> anyhow::Result<Option<GovernanceRecordDocument>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let Some(schema_version) = value.get("schemaVersion").and_then(Value::as_str) else {
        return Ok(None);
    };
    match schema_version {
        "swarm-ai.governance-policy.v1" => Ok(Some(GovernanceRecordDocument::Policy(
            serde_json::from_value(value)
                .with_context(|| format!("failed to parse governance policy {}", path.display()))?,
        ))),
        "swarm-ai.schema-release.v1" => Ok(Some(GovernanceRecordDocument::SchemaRelease(
            serde_json::from_value(value)
                .with_context(|| format!("failed to parse schema release {}", path.display()))?,
        ))),
        "swarm-ai.security-advisory.v1" => Ok(Some(GovernanceRecordDocument::SecurityAdvisory(
            serde_json::from_value(value)
                .with_context(|| format!("failed to parse security advisory {}", path.display()))?,
        ))),
        COMPONENT_READINESS_SCHEMA_VERSION => {
            Ok(Some(GovernanceRecordDocument::ComponentReadiness(
                serde_json::from_value(value).with_context(|| {
                    format!("failed to parse component readiness {}", path.display())
                })?,
            )))
        }
        _ => Ok(None),
    }
}

fn governance_record_summary(
    document: &GovernanceRecordDocument,
    path: String,
) -> GovernanceRecordSummaryV1 {
    match document {
        GovernanceRecordDocument::Policy(policy) => GovernanceRecordSummaryV1 {
            record_id: policy.policy_id.clone(),
            record_type: GovernanceRecordType::Policy,
            title: policy.title.clone(),
            primary_actor: policy.steward.clone(),
            status: governance_policy_status(policy).to_string(),
            created_at: policy.created_at.clone(),
            signature_present: policy.signature.is_some(),
            path,
        },
        GovernanceRecordDocument::SchemaRelease(release) => GovernanceRecordSummaryV1 {
            record_id: release.release_id.clone(),
            record_type: GovernanceRecordType::SchemaRelease,
            title: format!(
                "{} {}",
                release.object_type, release.released_schema_version
            ),
            primary_actor: if release.approved_by.is_empty() {
                "unapproved".to_string()
            } else {
                release.approved_by.join(",")
            },
            status: schema_compatibility_status_label(&release.status).to_string(),
            created_at: release.created_at.clone(),
            signature_present: release.signature.is_some(),
            path,
        },
        GovernanceRecordDocument::SecurityAdvisory(advisory) => GovernanceRecordSummaryV1 {
            record_id: advisory.advisory_id.clone(),
            record_type: GovernanceRecordType::SecurityAdvisory,
            title: advisory.title.clone(),
            primary_actor: advisory.reporter.clone(),
            status: security_advisory_status_label(&advisory.status).to_string(),
            created_at: advisory.disclosed_at.clone(),
            signature_present: advisory.signature.is_some(),
            path,
        },
        GovernanceRecordDocument::ComponentReadiness(readiness) => GovernanceRecordSummaryV1 {
            record_id: readiness.readiness_id.clone(),
            record_type: GovernanceRecordType::ComponentReadiness,
            title: format!("{} {}", readiness.component_type, readiness.component_name),
            primary_actor: readiness.owner.clone(),
            status: component_readiness_level_label(&readiness.status).to_string(),
            created_at: readiness.updated_at.clone(),
            signature_present: readiness.signature.is_some(),
            path,
        },
    }
}

fn governance_record_lookup(
    document: GovernanceRecordDocument,
    path: String,
) -> GovernanceRecordLookupV1 {
    match document {
        GovernanceRecordDocument::Policy(policy) => GovernanceRecordLookupV1 {
            schema_version: "swarm-ai.governance-record-lookup.v1".to_string(),
            record_id: policy.policy_id.clone(),
            record_type: Some(GovernanceRecordType::Policy),
            policy: Some(policy),
            schema_release: None,
            security_advisory: None,
            component_readiness: None,
            path: Some(path),
        },
        GovernanceRecordDocument::SchemaRelease(release) => GovernanceRecordLookupV1 {
            schema_version: "swarm-ai.governance-record-lookup.v1".to_string(),
            record_id: release.release_id.clone(),
            record_type: Some(GovernanceRecordType::SchemaRelease),
            policy: None,
            schema_release: Some(release),
            security_advisory: None,
            component_readiness: None,
            path: Some(path),
        },
        GovernanceRecordDocument::SecurityAdvisory(advisory) => GovernanceRecordLookupV1 {
            schema_version: "swarm-ai.governance-record-lookup.v1".to_string(),
            record_id: advisory.advisory_id.clone(),
            record_type: Some(GovernanceRecordType::SecurityAdvisory),
            policy: None,
            schema_release: None,
            security_advisory: Some(advisory),
            component_readiness: None,
            path: Some(path),
        },
        GovernanceRecordDocument::ComponentReadiness(readiness) => GovernanceRecordLookupV1 {
            schema_version: "swarm-ai.governance-record-lookup.v1".to_string(),
            record_id: readiness.readiness_id.clone(),
            record_type: Some(GovernanceRecordType::ComponentReadiness),
            policy: None,
            schema_release: None,
            security_advisory: None,
            component_readiness: Some(readiness),
            path: Some(path),
        },
    }
}

fn governance_record_id(document: &GovernanceRecordDocument) -> &str {
    match document {
        GovernanceRecordDocument::Policy(policy) => &policy.policy_id,
        GovernanceRecordDocument::SchemaRelease(release) => &release.release_id,
        GovernanceRecordDocument::SecurityAdvisory(advisory) => &advisory.advisory_id,
        GovernanceRecordDocument::ComponentReadiness(readiness) => &readiness.readiness_id,
    }
}

fn governance_policy_status(policy: &GovernancePolicyManifestV1) -> &'static str {
    if policy
        .rules
        .iter()
        .all(|rule| matches!(rule.status, GovernanceRuleStatus::Draft))
    {
        "draft"
    } else if policy
        .rules
        .iter()
        .any(|rule| matches!(rule.status, GovernanceRuleStatus::Active))
    {
        "active"
    } else if policy
        .rules
        .iter()
        .all(|rule| matches!(rule.status, GovernanceRuleStatus::Retired))
    {
        "retired"
    } else if policy
        .rules
        .iter()
        .any(|rule| matches!(rule.status, GovernanceRuleStatus::Deprecated))
    {
        "deprecated"
    } else {
        "mixed"
    }
}

fn schema_compatibility_status_label(status: &SchemaCompatibilityStatus) -> &'static str {
    match status {
        SchemaCompatibilityStatus::Experimental => "experimental",
        SchemaCompatibilityStatus::Development => "development",
        SchemaCompatibilityStatus::ProductionApproved => "production-approved",
        SchemaCompatibilityStatus::Deprecated => "deprecated",
        SchemaCompatibilityStatus::Retired => "retired",
    }
}

fn security_advisory_status_label(status: &SecurityAdvisoryStatus) -> &'static str {
    match status {
        SecurityAdvisoryStatus::Draft => "draft",
        SecurityAdvisoryStatus::Published => "published",
        SecurityAdvisoryStatus::Mitigated => "mitigated",
        SecurityAdvisoryStatus::Revoked => "revoked",
    }
}

fn component_readiness_level_label(status: &ComponentReadinessLevelV1) -> &'static str {
    match status {
        ComponentReadinessLevelV1::Mock => "mock",
        ComponentReadinessLevelV1::Local => "local",
        ComponentReadinessLevelV1::Gateway => "gateway",
        ComponentReadinessLevelV1::Testnet => "testnet",
        ComponentReadinessLevelV1::Production => "production",
    }
}

fn policy_signing_value(policy: &GovernancePolicyManifestV1) -> Value {
    signing_value(policy, &["policyId", "signature"])
}

fn schema_release_signing_value(release: &SchemaReleaseV1) -> Value {
    signing_value(release, &["releaseId", "signature"])
}

fn security_advisory_signing_value(advisory: &SecurityAdvisoryV1) -> Value {
    signing_value(advisory, &["advisoryId", "signature"])
}

fn component_readiness_signing_value(readiness: &ComponentReadinessV1) -> Value {
    signing_value(readiness, &["readinessId", "signature"])
}

fn component_readiness_init_options_schema_version() -> String {
    COMPONENT_READINESS_INIT_OPTIONS_SCHEMA_VERSION.to_string()
}

fn signing_value<T: Serialize>(value: &T, removed_keys: &[&str]) -> Value {
    let mut value = serde_json::to_value(value).expect("governance object should serialize");
    if let Value::Object(ref mut object) = value {
        for key in removed_keys {
            object.remove(*key);
        }
    }
    value
}

fn default_roles() -> Vec<GovernanceRoleV1> {
    vec![
        GovernanceRoleV1 {
            role: "protocol-maintainer".to_string(),
            responsibilities: vec![
                "Maintain schema versions, SDK compatibility, and migration notes".to_string(),
            ],
            authority_refs: vec!["local://governance/protocol-maintainers".to_string()],
        },
        GovernanceRoleV1 {
            role: "security-responder".to_string(),
            responsibilities: vec![
                "Review advisories, emergency delisting, key compromise, and sandbox escape reports"
                    .to_string(),
            ],
            authority_refs: vec!["local://governance/security-response".to_string()],
        },
        GovernanceRoleV1 {
            role: "registry-operator".to_string(),
            responsibilities: vec![
                "Mirror packages, validations, advisories, deprecation records, and curation status"
                    .to_string(),
            ],
            authority_refs: vec!["local://governance/registry-operators".to_string()],
        },
    ]
}

fn default_rule_refs(scopes: &[GovernanceScope]) -> Vec<GovernanceRuleRefV1> {
    scopes
        .iter()
        .map(|scope| GovernanceRuleRefV1 {
            scope: scope.clone(),
            rule_ref: format!("local://governance/rules/{scope:?}").to_ascii_lowercase(),
            description: default_rule_description(scope),
            status: GovernanceRuleStatus::Active,
        })
        .collect()
}

fn default_rule_description(scope: &GovernanceScope) -> String {
    match scope {
        GovernanceScope::ProtocolSchemas => {
            "Breaking interface changes require new schemaVersion and migration guidance"
        }
        GovernanceScope::CompatibilityCertification => {
            "Production components must pass the published compatibility suite"
        }
        GovernanceScope::RegistryCuration => {
            "Curated registries must expose warnings, deprecations, and delisting evidence"
        }
        GovernanceScope::ValidatorEligibility => {
            "High-stakes validation requires trusted validator identity and audit evidence"
        }
        GovernanceScope::MarketplaceRules => {
            "Settlement, dispute, refund, and rejection records must preserve signed evidence"
        }
        GovernanceScope::MinerOnboarding => {
            "Open miners require hardware offers, heartbeats, benchmark evidence, and trust tiers"
        }
        GovernanceScope::SecurityResponse => {
            "Critical security reports require signed advisories and emergency response actions"
        }
        GovernanceScope::EconomicPolicy => {
            "Fees, staking, slashing, and rewards must be represented by auditable policy refs"
        }
    }
    .to_string()
}

fn default_security_actions(advisory: &SecurityAdvisoryV1) -> Vec<String> {
    let mut actions = Vec::new();
    if matches!(
        advisory.severity,
        SecuritySeverity::High | SecuritySeverity::Critical
    ) {
        actions.push("publish signed advisory to registry mirrors".to_string());
        actions.push("notify runner, miner, validator, and marketplace operators".to_string());
    }
    for category in &advisory.categories {
        match category {
            SecurityAdvisoryCategory::PackageVulnerability
            | SecurityAdvisoryCategory::MaliciousPackage => {
                actions.push(
                    "mark affected packages as warned or delisted in curated registries"
                        .to_string(),
                );
                actions.push("require publishers to issue patched package refs".to_string());
            }
            SecurityAdvisoryCategory::RunnerAbuse => {
                actions.push(
                    "suspend affected runner offers until receipt evidence is reviewed".to_string(),
                );
            }
            SecurityAdvisoryCategory::MinerFraud => {
                actions.push(
                    "require fresh miner benchmark and heartbeat evidence before relisting"
                        .to_string(),
                );
            }
            SecurityAdvisoryCategory::CompromisedKey => {
                actions.push(
                    "publish key revocation and reject new signatures from compromised keys"
                        .to_string(),
                );
            }
            SecurityAdvisoryCategory::HiddenBenchmarkLeakage => {
                actions.push(
                    "rotate hidden validation suites and invalidate affected reputation evidence"
                        .to_string(),
                );
            }
            SecurityAdvisoryCategory::EmergencyAccessRevocation => {
                actions.push(
                    "apply emergency access revocation lists before execution or settlement"
                        .to_string(),
                );
            }
            SecurityAdvisoryCategory::SandboxEscape => {
                actions.push(
                    "disable affected runner targets until sandbox fixes pass compatibility tests"
                        .to_string(),
                );
            }
            SecurityAdvisoryCategory::ConfidentialAttestationFailure => {
                actions.push(
                    "remove confidential privacy tier claims until attestation evidence is renewed"
                        .to_string(),
                );
            }
            SecurityAdvisoryCategory::DisputeEscalation => {
                actions.push(
                    "link advisory to dispute evidence and settlement resolution records"
                        .to_string(),
                );
            }
            SecurityAdvisoryCategory::SecurityResponse => {
                actions.push(
                    "assign security responder and preserve a signed incident trail".to_string(),
                );
            }
            SecurityAdvisoryCategory::RegistryCuration => {
                actions.push(
                    "publish registry curation rationale and affected package refs".to_string(),
                );
            }
        }
    }
    actions
}

fn validate_deprecation_policy(
    issues: &mut Vec<ValidationIssue>,
    base: &str,
    policy: &GovernanceDeprecationPolicyV1,
) {
    if policy.deprecated_after_days == 0 {
        issues.push(issue(
            format!("{base}.deprecatedAfterDays"),
            "Deprecation period must be greater than zero days",
        ));
    }
    if policy.removal_after_days < policy.deprecated_after_days {
        issues.push(issue(
            format!("{base}.removalAfterDays"),
            "Removal period must be greater than or equal to deprecation period",
        ));
    }
}

fn validate_optional_timestamps(
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
    created_at: &str,
    effective_at: Option<&str>,
    expires_at: Option<&str>,
) {
    let created = parse_timestamp(issues, "$.createdAt", created_at);
    let effective = effective_at.and_then(|value| parse_timestamp(issues, "$.effectiveAt", value));
    let expires = expires_at.and_then(|value| parse_timestamp(issues, "$.expiresAt", value));
    if let (Some(created), Some(effective)) = (created, effective) {
        if effective < created {
            warnings.push(issue(
                "$.effectiveAt",
                "effectiveAt is earlier than createdAt",
            ));
        }
    }
    if let (Some(created), Some(expires)) = (created, expires) {
        if expires <= created {
            issues.push(issue(
                "$.expiresAt",
                "expiresAt must be later than createdAt",
            ));
        }
    }
}

fn validate_required_timestamp(
    issues: &mut Vec<ValidationIssue>,
    path: impl Into<String>,
    value: &str,
) {
    parse_timestamp(issues, path, value);
}

fn parse_timestamp(
    issues: &mut Vec<ValidationIssue>,
    path: impl Into<String>,
    value: &str,
) -> Option<DateTime<chrono::FixedOffset>> {
    let path = path.into();
    match DateTime::parse_from_rfc3339(value) {
        Ok(timestamp) => Some(timestamp),
        Err(_) => {
            issues.push(issue(path, "Timestamp must be RFC3339"));
            None
        }
    }
}

fn validate_ref(warnings: &mut Vec<ValidationIssue>, path: impl Into<String>, reference: &str) {
    if reference.trim().is_empty() {
        warnings.push(issue(path, "Reference is empty"));
    } else if !looks_like_ref(reference) {
        warnings.push(issue(
            path,
            "Reference is not a recognized bzz://, local://, ipfs://, sha256://, https://, or urn: reference",
        ));
    }
}

fn looks_like_ref(reference: &str) -> bool {
    reference.starts_with("bzz://")
        || reference.starts_with("local://")
        || reference.starts_with("ipfs://")
        || reference.starts_with("sha256://")
        || reference.starts_with("https://")
        || reference.starts_with("urn:")
}

#[derive(Clone, Copy)]
enum SignatureExpectation<'a> {
    ExactSigner(&'a str),
    OneOf(&'a [String]),
}

fn verify_signature(
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
    expected_signature: &mut Option<String>,
    path: &'static str,
    label: &'static str,
    payload: &Value,
    signature: Option<&str>,
    expectation: SignatureExpectation<'_>,
    dev_mismatch_message: &'static str,
    dev_prefix: &'static str,
) {
    let signature = signature.map(str::trim).filter(|value| !value.is_empty());
    let Some(signature) = signature else {
        warnings.push(issue(
            path,
            "Object is unsigned; use only for development or trusted local review",
        ));
        return;
    };

    if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
        let expected_signer = match expectation {
            SignatureExpectation::ExactSigner(signer) => Some(signer),
            SignatureExpectation::OneOf(_) => None,
        };
        let verification = hivemind_identity::verify_value_signature_string(
            signature,
            label,
            payload,
            expected_signer,
        );
        *expected_signature = Some(format!(
            "ed25519-payload-hash:{}",
            verification.payload_hash
        ));
        let signer = verification.signer.clone();
        for signature_issue in verification.issues {
            issues.push(issue(
                signature_issue_path(path, &signature_issue.path),
                signature_issue.message,
            ));
        }
        if let (SignatureExpectation::OneOf(allowed), Some(signer)) = (expectation, signer) {
            if !allowed.is_empty() && !allowed.iter().any(|allowed| allowed == &signer) {
                issues.push(issue(
                    format!("{path}.signer"),
                    "Signature signer is not listed in approvedBy",
                ));
            }
        }
    } else if !signature.starts_with(dev_prefix) || Some(signature) != expected_signature.as_deref()
    {
        issues.push(issue(path, dev_mismatch_message));
    }
}

fn dev_signature(prefix: &str, payload: &Value) -> String {
    format!(
        "{prefix}:{}",
        hash_canonical_json(&canonicalize_json(payload))
    )
}

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("governance object should serialize");
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

fn require_non_empty(issues: &mut Vec<ValidationIssue>, path: impl Into<String>, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value is required"));
    }
}

fn sorted_unique<T>(values: Vec<T>) -> Vec<T>
where
    T: Ord,
{
    BTreeSet::from_iter(values).into_iter().collect()
}

fn signature_issue_path(base: &str, path: &str) -> String {
    if path == "$" {
        return base.to_string();
    }
    if let Some(rest) = path.strip_prefix("$.") {
        return format!("{base}.{rest}");
    }
    format!("{base}.{path}")
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::JOB_ORDER_SCHEMA_VERSION;

    #[test]
    fn creates_signed_governance_policy_with_default_operational_roles() {
        let policy = create_governance_policy(GovernancePolicyInitOptionsV1 {
            title: "Early production governance".to_string(),
            steward: "core-maintainers".to_string(),
            scopes: Vec::new(),
            approved_schema_versions: vec!["swarm-ai.package.v1".to_string()],
            compatibility_test_refs: vec!["bzz://compat-suite".to_string()],
        });

        let verification = verify_governance_policy(&policy);

        assert!(verification.valid, "{verification:#?}");
        assert!(policy.policy_id.starts_with("governance-policy-"));
        assert!(policy.scopes.contains(&GovernanceScope::MinerOnboarding));
        assert!(
            policy
                .roles
                .iter()
                .any(|role| role.role == "security-responder")
        );
        assert_eq!(
            policy.signature.as_deref(),
            Some(expected_governance_policy_signature(&policy).as_str())
        );
    }

    #[test]
    fn identity_signed_schema_release_verifies_and_detects_tampering() {
        let mut release = create_schema_release(SchemaReleaseInitOptionsV1 {
            object_type: "JobOrderV1".to_string(),
            released_schema_version: JOB_ORDER_SCHEMA_VERSION.to_string(),
            interface_version: "0.2.0".to_string(),
            status: SchemaCompatibilityStatus::ProductionApproved,
            breaking_change: false,
            compatible_with: vec![JOB_ORDER_SCHEMA_VERSION.to_string()],
            compatibility_test_refs: vec!["bzz://compat/job-order".to_string()],
            approved_by: vec!["core-maintainers".to_string()],
            migration_guide_ref: None,
        });
        let identity =
            hivemind_identity::identity_from_seed("core-maintainers", b"governance-seed").unwrap();

        let envelope = sign_schema_release_with_identity(&mut release, &identity).unwrap();
        let verification = verify_schema_release(&release);

        assert_eq!(envelope.signer, "core-maintainers");
        assert!(verification.valid, "{verification:#?}");
        assert!(
            verification
                .expected_signature
                .as_deref()
                .unwrap()
                .starts_with("ed25519-payload-hash:")
        );

        release.object_type = "ChangedObject".to_string();
        let tampered = verify_schema_release(&release);
        assert!(!tampered.valid);
        assert!(tampered.issues.iter().any(|issue| {
            issue.path == "$.releaseId" || issue.path == "$.signature.payloadHash"
        }));
    }

    #[test]
    fn production_schema_release_requires_tests_and_approvers() {
        let mut release = create_schema_release(SchemaReleaseInitOptionsV1 {
            object_type: "RunnerCapabilityV2".to_string(),
            released_schema_version: "swarm-ai.runner-capability.v2".to_string(),
            interface_version: "0.2.0".to_string(),
            status: SchemaCompatibilityStatus::ProductionApproved,
            breaking_change: false,
            compatible_with: Vec::new(),
            compatibility_test_refs: Vec::new(),
            approved_by: Vec::new(),
            migration_guide_ref: None,
        });
        sign_schema_release(&mut release);

        let verification = verify_schema_release(&release);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.approvedBy")
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.compatibilityTestRefs")
        );
    }

    #[test]
    fn security_advisory_plan_flags_emergency_actions() {
        let advisory = create_security_advisory(SecurityAdvisoryInitOptionsV1 {
            title: "Sandbox escape in native runner".to_string(),
            reporter: "security-team".to_string(),
            severity: SecuritySeverity::Critical,
            categories: vec![SecurityAdvisoryCategory::SandboxEscape],
            affected_refs: vec!["bzz://runner/native".to_string()],
            summary: "Native runner sandbox isolation can be bypassed".to_string(),
            impact: "Affected packages may access host resources".to_string(),
        });

        let verification = verify_security_advisory(&advisory);
        let plan = security_response_plan(&advisory);

        assert!(verification.valid, "{verification:#?}");
        assert!(plan.requires_emergency_action);
        assert!(plan.actions.iter().any(|action| action.contains("sandbox")));
    }

    #[test]
    fn identity_signed_advisory_requires_reporter_identity() {
        let mut advisory = create_security_advisory(SecurityAdvisoryInitOptionsV1 {
            title: "Compromised publisher key".to_string(),
            reporter: "security-team".to_string(),
            severity: SecuritySeverity::High,
            categories: vec![SecurityAdvisoryCategory::CompromisedKey],
            affected_refs: vec!["urn:key:publisher".to_string()],
            summary: "Publisher key was reported as compromised".to_string(),
            impact: "New package signatures from the key should be rejected".to_string(),
        });
        let identity =
            hivemind_identity::identity_from_seed("security-team", b"security-seed").unwrap();

        sign_security_advisory_with_identity(&mut advisory, &identity).unwrap();
        let verification = verify_security_advisory(&advisory);

        assert!(verification.valid, "{verification:#?}");
        advisory.impact = "changed after signing".to_string();
        let tampered = verify_security_advisory(&advisory);
        assert!(!tampered.valid);
    }

    #[test]
    fn component_readiness_requires_production_evidence_and_verifies_identity() {
        let mut readiness = create_component_readiness(ComponentReadinessInitOptionsV1 {
            schema_version: COMPONENT_READINESS_INIT_OPTIONS_SCHEMA_VERSION.to_string(),
            component_name: "hivemind-router".to_string(),
            component_type: "crate".to_string(),
            owner: "core-maintainers".to_string(),
            status: ComponentReadinessLevelV1::Production,
            implementation_ref: Some("local://crates/router".to_string()),
            version: Some("0.1.0".to_string()),
            schema_refs: vec!["urn:schema:hivemind.route_planner_request.v1".to_string()],
            api_surfaces: vec!["native-route-planning".to_string()],
            supported_environments: vec!["local-dev".to_string()],
            compatibility_certification_refs: Vec::new(),
            evidence_refs: Vec::new(),
            blockers: Vec::new(),
            limitations: Vec::new(),
            expires_at: None,
            metadata: json!({}),
        });

        let missing_evidence = verify_component_readiness(&readiness);
        assert!(!missing_evidence.valid);
        assert!(missing_evidence.issues.iter().any(|issue| {
            issue.path == "$.compatibilityCertificationRefs" || issue.path == "$.evidenceRefs"
        }));

        readiness
            .compatibility_certification_refs
            .push("local://compat/router".to_string());
        readiness
            .evidence_refs
            .push("local://tests/router-workspace".to_string());
        sign_component_readiness(&mut readiness);
        let identity =
            hivemind_identity::identity_from_seed("core-maintainers", b"readiness-seed").unwrap();
        let envelope = sign_component_readiness_with_identity(&mut readiness, &identity).unwrap();
        let verification = verify_component_readiness(&readiness);

        assert_eq!(envelope.signer, "core-maintainers");
        assert!(verification.valid, "{verification:#?}");

        readiness
            .blockers
            .push("missing production sandbox".to_string());
        sign_component_readiness(&mut readiness);
        let blocked = verify_component_readiness(&readiness);
        assert!(!blocked.valid);
        assert!(
            blocked
                .issues
                .iter()
                .any(|issue| issue.path == "$.blockers")
        );
    }

    #[test]
    fn governance_store_lists_and_looks_up_supported_records() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("hivemind-governance-store-{unique}"));
        fs::create_dir_all(dir.join("nested")).unwrap();

        let policy = create_governance_policy(GovernancePolicyInitOptionsV1 {
            title: "Production protocol governance".to_string(),
            steward: "core-maintainers".to_string(),
            scopes: vec![GovernanceScope::ProtocolSchemas],
            approved_schema_versions: vec!["swarm-ai.package.v1".to_string()],
            compatibility_test_refs: vec!["bzz://compat/package".to_string()],
        });
        let release = create_schema_release(SchemaReleaseInitOptionsV1 {
            object_type: "JobOrderV1".to_string(),
            released_schema_version: JOB_ORDER_SCHEMA_VERSION.to_string(),
            interface_version: "0.2.0".to_string(),
            status: SchemaCompatibilityStatus::ProductionApproved,
            breaking_change: false,
            compatible_with: vec![JOB_ORDER_SCHEMA_VERSION.to_string()],
            compatibility_test_refs: vec!["bzz://compat/job-order".to_string()],
            approved_by: vec!["core-maintainers".to_string()],
            migration_guide_ref: None,
        });
        let advisory = create_security_advisory(SecurityAdvisoryInitOptionsV1 {
            title: "Sandbox escape in native runner".to_string(),
            reporter: "security-team".to_string(),
            severity: SecuritySeverity::Critical,
            categories: vec![SecurityAdvisoryCategory::SandboxEscape],
            affected_refs: vec!["bzz://runner/native".to_string()],
            summary: "Native runner sandbox isolation can be bypassed".to_string(),
            impact: "Affected packages may access host resources".to_string(),
        });
        let readiness = create_component_readiness(ComponentReadinessInitOptionsV1 {
            schema_version: COMPONENT_READINESS_INIT_OPTIONS_SCHEMA_VERSION.to_string(),
            component_name: "hivemind-server".to_string(),
            component_type: "crate".to_string(),
            owner: "core-maintainers".to_string(),
            status: ComponentReadinessLevelV1::Production,
            implementation_ref: Some("local://crates/server".to_string()),
            version: Some("0.1.0".to_string()),
            schema_refs: vec!["urn:schema:hivemind.operational_metric_snapshot.v1".to_string()],
            api_surfaces: vec!["http-api".to_string()],
            supported_environments: vec!["local-dev".to_string()],
            compatibility_certification_refs: vec!["local://compat/server".to_string()],
            evidence_refs: vec!["local://tests/workspace".to_string()],
            blockers: Vec::new(),
            limitations: vec!["local development storage only".to_string()],
            expires_at: None,
            metadata: json!({}),
        });

        fs::write(
            dir.join("policy.json"),
            serde_json::to_vec_pretty(&policy).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("nested").join("release.json"),
            serde_json::to_vec_pretty(&release).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("advisory.json"),
            serde_json::to_vec_pretty(&advisory).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("readiness.json"),
            serde_json::to_vec_pretty(&readiness).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("identity.json"),
            serde_json::to_vec_pretty(&json!({
                "schemaVersion": "swarm-ai.identity.keypair.v1",
                "subject": "core-maintainers"
            }))
            .unwrap(),
        )
        .unwrap();

        let summary = list_governance_records(&dir).unwrap();
        assert_eq!(summary.record_count, 4);
        assert_eq!(summary.policy_count, 1);
        assert_eq!(summary.schema_release_count, 1);
        assert_eq!(summary.security_advisory_count, 1);
        assert_eq!(summary.component_readiness_count, 1);
        assert_eq!(summary.production_ready_component_count, 1);
        assert_eq!(summary.blocked_component_count, 0);
        assert_eq!(summary.critical_advisory_count, 1);
        assert_eq!(summary.emergency_action_count, 1);
        assert!(
            summary
                .records
                .iter()
                .all(|record| record.signature_present)
        );

        let lookup = get_governance_record(&dir, &policy.policy_id)
            .unwrap()
            .unwrap();
        assert_eq!(lookup.record_type, Some(GovernanceRecordType::Policy));
        assert_eq!(lookup.policy.unwrap().policy_id, policy.policy_id);
        assert!(lookup.schema_release.is_none());
        assert!(lookup.security_advisory.is_none());
        assert!(lookup.component_readiness.is_none());
        let readiness_lookup = get_governance_record(&dir, &readiness.readiness_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            readiness_lookup.record_type,
            Some(GovernanceRecordType::ComponentReadiness)
        );
        assert_eq!(
            readiness_lookup.component_readiness.unwrap().readiness_id,
            readiness.readiness_id
        );
        assert!(get_governance_record(&dir, "missing").unwrap().is_none());

        let _ = fs::remove_dir_all(dir);
    }
}
