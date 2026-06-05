use crate::canonical::{canonicalize_json, hash_canonical_json};
use crate::validation::ValidationIssue;
use chrono::{SecondsFormat, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

pub const PRIVACY_TIER_PROFILE_SCHEMA_VERSION: &str = "hivemind.privacy_tier_profile.v1";
pub const PRIVACY_TIER_CATALOG_SCHEMA_VERSION: &str = "hivemind.privacy_tier_catalog.v1";
pub const PRIVACY_REQUIREMENT_ASSESSMENT_REQUEST_SCHEMA_VERSION: &str =
    "hivemind.privacy_requirement_assessment_request.v1";
pub const PRIVACY_REQUIREMENT_ASSESSMENT_SCHEMA_VERSION: &str =
    "hivemind.privacy_requirement_assessment.v1";

const DEV_TRUST_POLICY_SIGNATURE_PREFIX: &str = "dev-trust-policy-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PrivacyTier {
    Public,
    Standard,
    StandardRemote,
    NoLog,
    NoLogRemote,
    RedactedInput,
    LocalOnly,
    BrowserOnly,
    EncryptedStorage,
    TeeConfidential,
    FheEncrypted,
    FheEncryptedInference,
    SplitTrustRedundant,
    ZkVerifiedInference,
    MpcExperimental,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityTier {
    ReceiptOnly,
    ValidatorSpotCheck,
    RedundantExecution,
    DeterministicReplay,
    TeeAttested,
    ZkProofWhenSupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DataRetentionRule {
    StandardRunnerPolicy,
    NoRetention,
    DeleteAfterJob,
    RetainAuditHashesOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum LoggingRule {
    StandardOperationalLogs,
    NoPromptOrOutputLogs,
    HashOnlyAuditLogs,
    NoLogs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ToolPermissionRule {
    DenyAll,
    PackageManifestOnly,
    ExplicitAllowList,
    UserApprovedPerJob,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PrivacyExecutionLocationV1 {
    PublicMetadata,
    Browser,
    LocalDevice,
    RemoteRunner,
    AiMiner,
    ConfidentialRunner,
    MultiParty,
    EncryptedStorage,
    Validator,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PrivacyDataMovementRuleV1 {
    PublicDataOnly,
    PlaintextMayReachRemoteRunner,
    NoPlaintextLeavesDevice,
    NoPlaintextLeavesBrowser,
    EncryptedAtRestOnly,
    PlaintextOnlyInsideAttestedTee,
    SplitAcrossIndependentRunners,
    CiphertextOnly,
    ProofOnly,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PrivacyTierProfileV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    pub tier: PrivacyTier,
    #[serde(rename = "tierName")]
    pub tier_name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub summary: String,
    #[serde(rename = "protects")]
    pub protects: Vec<String>,
    pub limitations: Vec<String>,
    #[serde(rename = "allowedExecution")]
    pub allowed_execution: Vec<PrivacyExecutionLocationV1>,
    #[serde(rename = "dataMovement")]
    pub data_movement: PrivacyDataMovementRuleV1,
    #[serde(rename = "requiresUserConsent")]
    pub requires_user_consent: bool,
    #[serde(rename = "requiresAccessGrant")]
    pub requires_access_grant: bool,
    #[serde(rename = "requiresEncryption")]
    pub requires_encryption: bool,
    #[serde(rename = "requiresKeyReleasePolicy")]
    pub requires_key_release_policy: bool,
    #[serde(rename = "requiresAttestation")]
    pub requires_attestation: bool,
    #[serde(rename = "requiresProof")]
    pub requires_proof: bool,
    #[serde(rename = "compatibleIntegrityTiers")]
    pub compatible_integrity_tiers: Vec<IntegrityTier>,
    #[serde(rename = "receiptPolicy")]
    pub receipt_policy: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PrivacyTierCatalogV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    pub profiles: Vec<PrivacyTierProfileV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PrivacyRequirementAssessmentRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestedTier")]
    pub requested_tier: PrivacyTier,
    #[serde(rename = "offeredTier")]
    pub offered_tier: PrivacyTier,
    #[serde(rename = "runnerLocation")]
    pub runner_location: PrivacyExecutionLocationV1,
    #[serde(
        rename = "integrityTier",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub integrity_tier: Option<IntegrityTier>,
    #[serde(rename = "hasUserConsent", default)]
    pub has_user_consent: bool,
    #[serde(rename = "hasAccessGrant", default)]
    pub has_access_grant: bool,
    #[serde(rename = "hasEncryptedAssetDescriptor", default)]
    pub has_encrypted_asset_descriptor: bool,
    #[serde(rename = "hasKeyReleasePolicy", default)]
    pub has_key_release_policy: bool,
    #[serde(rename = "hasRedactionPlan", default)]
    pub has_redaction_plan: bool,
    #[serde(rename = "hasAttestation", default)]
    pub has_attestation: bool,
    #[serde(rename = "allowsRemotePlaintext", default)]
    pub allows_remote_plaintext: bool,
    #[serde(rename = "proofRefs", default)]
    pub proof_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PrivacyRequirementAssessmentV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "requestedTier")]
    pub requested_tier: PrivacyTier,
    #[serde(rename = "offeredTier")]
    pub offered_tier: PrivacyTier,
    #[serde(rename = "runnerLocation")]
    pub runner_location: PrivacyExecutionLocationV1,
    pub satisfied: bool,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "requiredEvidence")]
    pub required_evidence: Vec<String>,
    pub limitations: Vec<String>,
    #[serde(rename = "assessedAt")]
    pub assessed_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TrustPolicyPriceLimitV1 {
    pub amount: f64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TrustPolicyV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "policyId")]
    pub policy_id: String,
    pub owner: String,
    #[serde(rename = "allowedPrivacyTiers")]
    pub allowed_privacy_tiers: Vec<PrivacyTier>,
    #[serde(rename = "allowedVerificationTiers")]
    pub allowed_verification_tiers: Vec<IntegrityTier>,
    #[serde(rename = "allowedRunners", default)]
    pub allowed_runners: Vec<String>,
    #[serde(rename = "blockedRunners", default)]
    pub blocked_runners: Vec<String>,
    #[serde(rename = "allowedPublishers", default)]
    pub allowed_publishers: Vec<String>,
    #[serde(rename = "allowOpenMiners")]
    pub allow_open_miners: bool,
    #[serde(rename = "allowConsumerGpu")]
    pub allow_consumer_gpu: bool,
    #[serde(rename = "requireReceipt")]
    pub require_receipt: bool,
    #[serde(rename = "requireValidation")]
    pub require_validation: bool,
    #[serde(rename = "maxPrice", default, skip_serializing_if = "Option::is_none")]
    pub max_price: Option<TrustPolicyPriceLimitV1>,
    #[serde(
        rename = "maxLatencyMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_latency_ms: Option<u64>,
    #[serde(rename = "regionHints", default)]
    pub region_hints: Vec<String>,
    #[serde(rename = "dataRetentionRule")]
    pub data_retention_rule: DataRetentionRule,
    #[serde(rename = "loggingRule")]
    pub logging_rule: LoggingRule,
    #[serde(rename = "toolPermissionRule")]
    pub tool_permission_rule: ToolPermissionRule,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TrustPolicyVerificationV1 {
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
    #[serde(rename = "verifiedAt")]
    pub verified_at: String,
}

pub fn privacy_tier_catalog() -> PrivacyTierCatalogV1 {
    PrivacyTierCatalogV1 {
        schema_version: PRIVACY_TIER_CATALOG_SCHEMA_VERSION.to_string(),
        object_kind: "privacy_tier_catalog".to_string(),
        profiles: privacy_tier_profiles(),
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn privacy_tier_profiles() -> Vec<PrivacyTierProfileV1> {
    privacy_tier_preference_order()
        .into_iter()
        .map(|tier| privacy_tier_profile(&tier))
        .collect()
}

pub fn privacy_tier_profile(tier: &PrivacyTier) -> PrivacyTierProfileV1 {
    match tier {
        PrivacyTier::Public => profile(
            PrivacyTier::Public,
            "public",
            vec![],
            "Public data that can be indexed, routed, and audited without private payload handling.",
            vec!["public metadata", "public inputs", "public outputs"],
            vec![
                "Does not protect prompts, files, outputs, identity, or usage patterns.",
                "Only use for data that is intentionally public.",
            ],
            vec![
                PrivacyExecutionLocationV1::PublicMetadata,
                PrivacyExecutionLocationV1::Browser,
                PrivacyExecutionLocationV1::LocalDevice,
                PrivacyExecutionLocationV1::RemoteRunner,
                PrivacyExecutionLocationV1::AiMiner,
                PrivacyExecutionLocationV1::Validator,
            ],
            PrivacyDataMovementRuleV1::PublicDataOnly,
            false,
            false,
            false,
            false,
            false,
            false,
            vec![IntegrityTier::ReceiptOnly],
            "public receipts may include input and output references",
        ),
        PrivacyTier::Standard | PrivacyTier::StandardRemote => profile(
            tier.clone(),
            tier_wire_name(tier),
            legacy_aliases_for_privacy_tier(tier),
            "Remote execution where plaintext may be visible to the selected runner under normal service terms.",
            vec!["basic transport security", "standard operational controls"],
            vec![
                "The remote runner may see plaintext inputs and outputs.",
                "Operational logs may contain sensitive metadata unless another policy forbids it.",
            ],
            vec![
                PrivacyExecutionLocationV1::Browser,
                PrivacyExecutionLocationV1::LocalDevice,
                PrivacyExecutionLocationV1::RemoteRunner,
                PrivacyExecutionLocationV1::AiMiner,
            ],
            PrivacyDataMovementRuleV1::PlaintextMayReachRemoteRunner,
            false,
            false,
            false,
            false,
            false,
            false,
            vec![
                IntegrityTier::ReceiptOnly,
                IntegrityTier::ValidatorSpotCheck,
            ],
            "receipts may include plaintext-safe summaries; private payloads should still prefer hashes",
        ),
        PrivacyTier::NoLog | PrivacyTier::NoLogRemote => profile(
            tier.clone(),
            tier_wire_name(tier),
            legacy_aliases_for_privacy_tier(tier),
            "Remote execution where the runner promises not to retain prompt or output logs.",
            vec!["lower log retention", "hash-oriented audit records"],
            vec![
                "No-log is an operational promise, not cryptographic privacy.",
                "The runner still sees plaintext while processing unless paired with TEE, FHE, or local execution.",
            ],
            vec![
                PrivacyExecutionLocationV1::RemoteRunner,
                PrivacyExecutionLocationV1::AiMiner,
                PrivacyExecutionLocationV1::ConfidentialRunner,
            ],
            PrivacyDataMovementRuleV1::PlaintextMayReachRemoteRunner,
            true,
            false,
            false,
            false,
            false,
            false,
            vec![
                IntegrityTier::ReceiptOnly,
                IntegrityTier::ValidatorSpotCheck,
                IntegrityTier::DeterministicReplay,
            ],
            "receipts should avoid plaintext prompts and outputs; use hashes or redacted summaries",
        ),
        PrivacyTier::RedactedInput => profile(
            PrivacyTier::RedactedInput,
            "redacted-input",
            vec![],
            "Local preprocessing removes or masks sensitive fields before remote execution.",
            vec!["reduced remote payload", "redacted input evidence"],
            vec![
                "Redaction quality depends on the preprocessing policy.",
                "Outputs can still reveal sensitive information if the prompt context is insufficiently redacted.",
            ],
            vec![
                PrivacyExecutionLocationV1::Browser,
                PrivacyExecutionLocationV1::LocalDevice,
                PrivacyExecutionLocationV1::RemoteRunner,
                PrivacyExecutionLocationV1::AiMiner,
            ],
            PrivacyDataMovementRuleV1::PlaintextMayReachRemoteRunner,
            true,
            false,
            false,
            false,
            false,
            false,
            vec![
                IntegrityTier::ReceiptOnly,
                IntegrityTier::ValidatorSpotCheck,
            ],
            "receipts must preserve the redaction policy reference and input hashes",
        ),
        PrivacyTier::LocalOnly => profile(
            PrivacyTier::LocalOnly,
            "local-only",
            vec![],
            "Plaintext inputs and outputs stay on the user's local device or explicitly local node.",
            vec![
                "no remote plaintext transfer",
                "local cache control",
                "hash-only external audit",
            ],
            vec![
                "Local-only does not protect data from malware or compromised local runtimes.",
                "Remote fallback must be disabled unless the user explicitly downgrades privacy.",
            ],
            vec![PrivacyExecutionLocationV1::LocalDevice],
            PrivacyDataMovementRuleV1::NoPlaintextLeavesDevice,
            false,
            false,
            false,
            false,
            false,
            false,
            vec![
                IntegrityTier::ReceiptOnly,
                IntegrityTier::DeterministicReplay,
                IntegrityTier::ValidatorSpotCheck,
            ],
            "receipts must keep private inputs and outputs hash-only outside the local device",
        ),
        PrivacyTier::BrowserOnly => profile(
            PrivacyTier::BrowserOnly,
            "browser-only",
            vec![],
            "Plaintext stays inside the browser origin/session, with browser storage and worker isolation controls.",
            vec![
                "browser-local plaintext control",
                "origin-scoped storage",
                "user-mediated browser permissions",
            ],
            vec![
                "Browser-only depends on origin isolation, service-worker policy, IndexedDB hygiene, and browser security.",
                "Large models or indexes may exceed browser memory or storage quota.",
            ],
            vec![PrivacyExecutionLocationV1::Browser],
            PrivacyDataMovementRuleV1::NoPlaintextLeavesBrowser,
            true,
            false,
            false,
            false,
            false,
            false,
            vec![
                IntegrityTier::ReceiptOnly,
                IntegrityTier::DeterministicReplay,
            ],
            "receipts should use browser storage receipts and hash-only private payload evidence",
        ),
        PrivacyTier::EncryptedStorage => profile(
            PrivacyTier::EncryptedStorage,
            "encrypted-storage",
            vec![],
            "Assets are encrypted before durable Swarm storage; key release decides who can decrypt.",
            vec!["encrypted assets at rest", "access-controlled key release"],
            vec![
                "Encrypted storage does not hide plaintext from a runner after decryption.",
                "Key-release mistakes can expose the underlying data.",
            ],
            vec![
                PrivacyExecutionLocationV1::EncryptedStorage,
                PrivacyExecutionLocationV1::Browser,
                PrivacyExecutionLocationV1::LocalDevice,
                PrivacyExecutionLocationV1::ConfidentialRunner,
            ],
            PrivacyDataMovementRuleV1::EncryptedAtRestOnly,
            true,
            true,
            true,
            true,
            false,
            false,
            vec![
                IntegrityTier::ReceiptOnly,
                IntegrityTier::ValidatorSpotCheck,
            ],
            "receipts must reference encrypted asset descriptors and key-release decisions, not raw keys",
        ),
        PrivacyTier::TeeConfidential => profile(
            PrivacyTier::TeeConfidential,
            "tee-confidential",
            vec![],
            "Plaintext may leave the user device only for an attested confidential runner.",
            vec![
                "attested runtime boundary",
                "controlled key release",
                "reduced runner-operator visibility",
            ],
            vec![
                "TEE confidentiality depends on verified attestation and the TEE threat model.",
                "Side channels and implementation bugs remain possible.",
            ],
            vec![PrivacyExecutionLocationV1::ConfidentialRunner],
            PrivacyDataMovementRuleV1::PlaintextOnlyInsideAttestedTee,
            true,
            true,
            true,
            true,
            true,
            false,
            vec![
                IntegrityTier::TeeAttested,
                IntegrityTier::ValidatorSpotCheck,
                IntegrityTier::ReceiptOnly,
            ],
            "receipts must include attestation refs and key-release policy refs when private inputs are decrypted",
        ),
        PrivacyTier::FheEncrypted | PrivacyTier::FheEncryptedInference => profile(
            tier.clone(),
            tier_wire_name(tier),
            legacy_aliases_for_privacy_tier(tier),
            "Specialized inference over encrypted inputs where supported by the package and runner.",
            vec![
                "ciphertext-only remote execution",
                "limited plaintext exposure",
            ],
            vec![
                "FHE support is task-specific and usually slower than plaintext inference.",
                "Model architecture, output handling, and metadata can still leak information.",
            ],
            vec![
                PrivacyExecutionLocationV1::RemoteRunner,
                PrivacyExecutionLocationV1::AiMiner,
                PrivacyExecutionLocationV1::EncryptedStorage,
            ],
            PrivacyDataMovementRuleV1::CiphertextOnly,
            true,
            true,
            true,
            true,
            false,
            true,
            vec![
                IntegrityTier::ZkProofWhenSupported,
                IntegrityTier::ReceiptOnly,
                IntegrityTier::ValidatorSpotCheck,
            ],
            "receipts must reference encrypted input/output artifacts and any proof or verifier metadata",
        ),
        PrivacyTier::SplitTrustRedundant | PrivacyTier::MpcExperimental => profile(
            tier.clone(),
            tier_wire_name(tier),
            legacy_aliases_for_privacy_tier(tier),
            "Private work is split across independent runners or MPC-style participants so no single normal runner gets the full plaintext.",
            vec![
                "reduced single-runner exposure",
                "redundant or multi-party evidence",
            ],
            vec![
                "Split-trust privacy depends on participant independence and correct protocol implementation.",
                "It is experimental and can add latency, coordination cost, and failure modes.",
            ],
            vec![
                PrivacyExecutionLocationV1::MultiParty,
                PrivacyExecutionLocationV1::RemoteRunner,
                PrivacyExecutionLocationV1::AiMiner,
            ],
            PrivacyDataMovementRuleV1::SplitAcrossIndependentRunners,
            true,
            true,
            true,
            true,
            false,
            false,
            vec![
                IntegrityTier::RedundantExecution,
                IntegrityTier::ValidatorSpotCheck,
                IntegrityTier::ReceiptOnly,
            ],
            "receipts must identify participating runners and preserve per-party hashes or partial receipts",
        ),
        PrivacyTier::ZkVerifiedInference => profile(
            PrivacyTier::ZkVerifiedInference,
            "zk-verified-inference",
            vec![],
            "Execution produces proof evidence for supported inference circuits or verifiers.",
            vec![
                "verifiable computation claims",
                "proof-backed audit evidence",
            ],
            vec![
                "zk verification proves specific circuit claims; it is not general privacy by itself.",
                "Private inputs still need local, encrypted, FHE, TEE, or split-trust handling.",
            ],
            vec![
                PrivacyExecutionLocationV1::RemoteRunner,
                PrivacyExecutionLocationV1::AiMiner,
                PrivacyExecutionLocationV1::Validator,
            ],
            PrivacyDataMovementRuleV1::ProofOnly,
            true,
            false,
            false,
            false,
            false,
            true,
            vec![IntegrityTier::ZkProofWhenSupported],
            "receipts must include proof refs, verifier refs, and public input hashes",
        ),
    }
}

pub fn privacy_tier_preference_order() -> Vec<PrivacyTier> {
    vec![
        PrivacyTier::BrowserOnly,
        PrivacyTier::LocalOnly,
        PrivacyTier::FheEncryptedInference,
        PrivacyTier::FheEncrypted,
        PrivacyTier::ZkVerifiedInference,
        PrivacyTier::TeeConfidential,
        PrivacyTier::SplitTrustRedundant,
        PrivacyTier::MpcExperimental,
        PrivacyTier::EncryptedStorage,
        PrivacyTier::NoLogRemote,
        PrivacyTier::NoLog,
        PrivacyTier::RedactedInput,
        PrivacyTier::StandardRemote,
        PrivacyTier::Standard,
        PrivacyTier::Public,
    ]
}

pub fn privacy_tier_satisfies(available: &PrivacyTier, required: &PrivacyTier) -> bool {
    if available == required {
        return true;
    }

    match available {
        PrivacyTier::BrowserOnly => matches!(
            required,
            PrivacyTier::Public
                | PrivacyTier::Standard
                | PrivacyTier::StandardRemote
                | PrivacyTier::NoLog
                | PrivacyTier::NoLogRemote
                | PrivacyTier::RedactedInput
                | PrivacyTier::LocalOnly
                | PrivacyTier::BrowserOnly
        ),
        PrivacyTier::LocalOnly => matches!(
            required,
            PrivacyTier::Public
                | PrivacyTier::Standard
                | PrivacyTier::StandardRemote
                | PrivacyTier::NoLog
                | PrivacyTier::NoLogRemote
                | PrivacyTier::RedactedInput
                | PrivacyTier::LocalOnly
        ),
        PrivacyTier::TeeConfidential => matches!(
            required,
            PrivacyTier::Public
                | PrivacyTier::Standard
                | PrivacyTier::StandardRemote
                | PrivacyTier::NoLog
                | PrivacyTier::NoLogRemote
                | PrivacyTier::EncryptedStorage
                | PrivacyTier::TeeConfidential
        ),
        PrivacyTier::FheEncrypted | PrivacyTier::FheEncryptedInference => matches!(
            required,
            PrivacyTier::Public
                | PrivacyTier::Standard
                | PrivacyTier::StandardRemote
                | PrivacyTier::NoLog
                | PrivacyTier::NoLogRemote
                | PrivacyTier::EncryptedStorage
                | PrivacyTier::FheEncrypted
                | PrivacyTier::FheEncryptedInference
        ),
        PrivacyTier::SplitTrustRedundant | PrivacyTier::MpcExperimental => matches!(
            required,
            PrivacyTier::Public
                | PrivacyTier::Standard
                | PrivacyTier::StandardRemote
                | PrivacyTier::NoLog
                | PrivacyTier::NoLogRemote
                | PrivacyTier::SplitTrustRedundant
                | PrivacyTier::MpcExperimental
        ),
        PrivacyTier::ZkVerifiedInference => matches!(
            required,
            PrivacyTier::Public
                | PrivacyTier::Standard
                | PrivacyTier::StandardRemote
                | PrivacyTier::ZkVerifiedInference
        ),
        PrivacyTier::EncryptedStorage => matches!(
            required,
            PrivacyTier::Public
                | PrivacyTier::Standard
                | PrivacyTier::StandardRemote
                | PrivacyTier::EncryptedStorage
        ),
        PrivacyTier::NoLog | PrivacyTier::NoLogRemote => matches!(
            required,
            PrivacyTier::Public
                | PrivacyTier::Standard
                | PrivacyTier::StandardRemote
                | PrivacyTier::NoLog
                | PrivacyTier::NoLogRemote
        ),
        PrivacyTier::RedactedInput => matches!(
            required,
            PrivacyTier::Public
                | PrivacyTier::Standard
                | PrivacyTier::StandardRemote
                | PrivacyTier::RedactedInput
        ),
        PrivacyTier::Standard | PrivacyTier::StandardRemote => {
            matches!(
                required,
                PrivacyTier::Public | PrivacyTier::Standard | PrivacyTier::StandardRemote
            )
        }
        PrivacyTier::Public => matches!(required, PrivacyTier::Public),
    }
}

pub fn assess_privacy_requirement(
    request: &PrivacyRequirementAssessmentRequestV1,
) -> PrivacyRequirementAssessmentV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let offered_profile = privacy_tier_profile(&request.offered_tier);
    let requested_profile = privacy_tier_profile(&request.requested_tier);

    if request.schema_version != PRIVACY_REQUIREMENT_ASSESSMENT_REQUEST_SCHEMA_VERSION {
        issues.push(issue(
            "$.schemaVersion",
            format!(
                "Expected schemaVersion to be {PRIVACY_REQUIREMENT_ASSESSMENT_REQUEST_SCHEMA_VERSION}"
            ),
        ));
    }
    if !privacy_tier_satisfies(&request.offered_tier, &request.requested_tier) {
        issues.push(issue(
            "$.offeredTier",
            "Offered privacy tier does not satisfy requested privacy tier",
        ));
    }
    if !offered_profile
        .allowed_execution
        .contains(&request.runner_location)
    {
        issues.push(issue(
            "$.runnerLocation",
            "Runner location is not allowed for the offered privacy tier",
        ));
    }
    if (matches!(
        request.requested_tier,
        PrivacyTier::LocalOnly | PrivacyTier::BrowserOnly
    ) || matches!(
        request.offered_tier,
        PrivacyTier::LocalOnly | PrivacyTier::BrowserOnly
    )) && request.allows_remote_plaintext
    {
        issues.push(issue(
            "$.allowsRemotePlaintext",
            "Local-only or browser-only privacy cannot allow remote plaintext transfer",
        ));
    }
    if offered_profile.requires_user_consent && !request.has_user_consent {
        warnings.push(issue(
            "$.hasUserConsent",
            "Tier should be presented as an explicit user consent decision before data movement",
        ));
    }
    if offered_profile.requires_access_grant && !request.has_access_grant {
        issues.push(issue(
            "$.hasAccessGrant",
            "Tier requires an access grant before private asset use",
        ));
    }
    if offered_profile.requires_encryption && !request.has_encrypted_asset_descriptor {
        issues.push(issue(
            "$.hasEncryptedAssetDescriptor",
            "Tier requires an encrypted asset descriptor",
        ));
    }
    if offered_profile.requires_key_release_policy && !request.has_key_release_policy {
        issues.push(issue(
            "$.hasKeyReleasePolicy",
            "Tier requires a key release policy",
        ));
    }
    if offered_profile.requires_attestation && !request.has_attestation {
        issues.push(issue(
            "$.hasAttestation",
            "Tier requires confidential compute attestation evidence",
        ));
    }
    if offered_profile.requires_proof && request.proof_refs.is_empty() {
        issues.push(issue(
            "$.proofRefs",
            "Tier requires proof or verifier references",
        ));
    }
    if request.offered_tier == PrivacyTier::RedactedInput && !request.has_redaction_plan {
        issues.push(issue(
            "$.hasRedactionPlan",
            "Redacted input privacy requires a redaction plan",
        ));
    }
    if let Some(integrity_tier) = &request.integrity_tier {
        if !offered_profile
            .compatible_integrity_tiers
            .contains(integrity_tier)
        {
            warnings.push(issue(
                "$.integrityTier",
                "Integrity tier is not a normal companion for the offered privacy tier",
            ));
        }
    }
    if matches!(
        request.offered_tier,
        PrivacyTier::NoLog | PrivacyTier::NoLogRemote
    ) {
        warnings.push(issue(
            "$.offeredTier",
            "No-log privacy is weaker than cryptographic privacy because the runner still sees plaintext",
        ));
    }

    let mut required_evidence = Vec::new();
    if offered_profile.requires_encryption {
        required_evidence.push("encrypted-asset-descriptor".to_string());
    }
    if offered_profile.requires_key_release_policy {
        required_evidence.push("key-release-policy".to_string());
    }
    if offered_profile.requires_attestation {
        required_evidence.push("confidential-attestation-ref".to_string());
    }
    if offered_profile.requires_proof {
        required_evidence.push("proof-ref-or-verifier-ref".to_string());
    }
    if request.offered_tier == PrivacyTier::RedactedInput {
        required_evidence.push("redaction-plan".to_string());
    }
    required_evidence.sort();
    required_evidence.dedup();

    PrivacyRequirementAssessmentV1 {
        schema_version: PRIVACY_REQUIREMENT_ASSESSMENT_SCHEMA_VERSION.to_string(),
        object_kind: "privacy_requirement_assessment".to_string(),
        requested_tier: request.requested_tier.clone(),
        offered_tier: request.offered_tier.clone(),
        runner_location: request.runner_location.clone(),
        satisfied: issues.is_empty(),
        issues,
        warnings,
        required_evidence,
        limitations: requested_profile
            .limitations
            .into_iter()
            .chain(offered_profile.limitations)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        assessed_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

#[allow(clippy::too_many_arguments)]
fn profile(
    tier: PrivacyTier,
    tier_name: impl Into<String>,
    aliases: Vec<String>,
    summary: impl Into<String>,
    protects: Vec<&str>,
    limitations: Vec<&str>,
    allowed_execution: Vec<PrivacyExecutionLocationV1>,
    data_movement: PrivacyDataMovementRuleV1,
    requires_user_consent: bool,
    requires_access_grant: bool,
    requires_encryption: bool,
    requires_key_release_policy: bool,
    requires_attestation: bool,
    requires_proof: bool,
    compatible_integrity_tiers: Vec<IntegrityTier>,
    receipt_policy: impl Into<String>,
) -> PrivacyTierProfileV1 {
    PrivacyTierProfileV1 {
        schema_version: PRIVACY_TIER_PROFILE_SCHEMA_VERSION.to_string(),
        object_kind: "privacy_tier_profile".to_string(),
        tier,
        tier_name: tier_name.into(),
        aliases,
        summary: summary.into(),
        protects: protects.into_iter().map(str::to_string).collect(),
        limitations: limitations.into_iter().map(str::to_string).collect(),
        allowed_execution,
        data_movement,
        requires_user_consent,
        requires_access_grant,
        requires_encryption,
        requires_key_release_policy,
        requires_attestation,
        requires_proof,
        compatible_integrity_tiers,
        receipt_policy: receipt_policy.into(),
    }
}

fn legacy_aliases_for_privacy_tier(tier: &PrivacyTier) -> Vec<String> {
    match tier {
        PrivacyTier::Standard => vec!["standard-remote".to_string()],
        PrivacyTier::StandardRemote => vec!["standard".to_string()],
        PrivacyTier::NoLog => vec!["no-log-remote".to_string()],
        PrivacyTier::NoLogRemote => vec!["no-log".to_string()],
        PrivacyTier::FheEncrypted => vec!["fhe-encrypted-inference".to_string()],
        PrivacyTier::FheEncryptedInference => vec!["fhe-encrypted".to_string()],
        PrivacyTier::MpcExperimental => vec!["split-trust-redundant".to_string()],
        PrivacyTier::SplitTrustRedundant => vec!["mpc-experimental".to_string()],
        _ => Vec::new(),
    }
}

fn tier_wire_name(value: &PrivacyTier) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

impl TrustPolicyV1 {
    pub fn local_only(owner: impl Into<String>) -> Self {
        let mut policy = Self {
            schema_version: "swarm-ai.trust-policy.v1".to_string(),
            policy_id: String::new(),
            owner: owner.into(),
            allowed_privacy_tiers: vec![PrivacyTier::LocalOnly],
            allowed_verification_tiers: vec![
                IntegrityTier::ReceiptOnly,
                IntegrityTier::DeterministicReplay,
            ],
            allowed_runners: Vec::new(),
            blocked_runners: Vec::new(),
            allowed_publishers: Vec::new(),
            allow_open_miners: false,
            allow_consumer_gpu: true,
            require_receipt: true,
            require_validation: false,
            max_price: None,
            max_latency_ms: None,
            region_hints: Vec::new(),
            data_retention_rule: DataRetentionRule::NoRetention,
            logging_rule: LoggingRule::HashOnlyAuditLogs,
            tool_permission_rule: ToolPermissionRule::PackageManifestOnly,
            signature: None,
        };
        policy.policy_id =
            canonical_trust_policy_id(&policy).expect("trust policy should serialize for id");
        policy
    }

    pub fn open_marketplace(owner: impl Into<String>) -> Self {
        let mut policy = Self {
            schema_version: "swarm-ai.trust-policy.v1".to_string(),
            policy_id: String::new(),
            owner: owner.into(),
            allowed_privacy_tiers: vec![
                PrivacyTier::Standard,
                PrivacyTier::NoLog,
                PrivacyTier::RedactedInput,
            ],
            allowed_verification_tiers: vec![
                IntegrityTier::ReceiptOnly,
                IntegrityTier::ValidatorSpotCheck,
                IntegrityTier::RedundantExecution,
            ],
            allowed_runners: Vec::new(),
            blocked_runners: Vec::new(),
            allowed_publishers: Vec::new(),
            allow_open_miners: true,
            allow_consumer_gpu: true,
            require_receipt: true,
            require_validation: false,
            max_price: None,
            max_latency_ms: None,
            region_hints: Vec::new(),
            data_retention_rule: DataRetentionRule::DeleteAfterJob,
            logging_rule: LoggingRule::NoPromptOrOutputLogs,
            tool_permission_rule: ToolPermissionRule::PackageManifestOnly,
            signature: None,
        };
        policy.policy_id =
            canonical_trust_policy_id(&policy).expect("trust policy should serialize for id");
        policy
    }
}

pub fn trust_policy_allows_runner(policy: &TrustPolicyV1, runner_id: &str) -> bool {
    if policy
        .blocked_runners
        .iter()
        .any(|blocked| blocked == runner_id)
    {
        return false;
    }
    policy.allowed_runners.is_empty()
        || policy
            .allowed_runners
            .iter()
            .any(|allowed| allowed == runner_id)
}

pub fn canonical_trust_policy_id(policy: &TrustPolicyV1) -> serde_json::Result<String> {
    let value = trust_policy_signing_value(policy)?;
    Ok(format!(
        "trust-policy-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    ))
}

pub fn expected_trust_policy_signature(policy: &TrustPolicyV1) -> serde_json::Result<String> {
    let value = trust_policy_signing_value(policy)?;
    Ok(format!(
        "{DEV_TRUST_POLICY_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&value))
    ))
}

pub fn sign_trust_policy(policy: &mut TrustPolicyV1) -> serde_json::Result<String> {
    let signature = expected_trust_policy_signature(policy)?;
    policy.signature = Some(signature.clone());
    policy.policy_id = canonical_trust_policy_id(policy)?;
    Ok(signature)
}

pub fn verify_trust_policy(policy: &TrustPolicyV1) -> TrustPolicyVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let expected_policy_id =
        canonical_trust_policy_id(policy).unwrap_or_else(|_| "trust-policy-invalid".to_string());
    let expected_signature = expected_trust_policy_signature(policy).ok();

    if policy.schema_version != "swarm-ai.trust-policy.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.trust-policy.v1",
        ));
    }
    require_non_empty(&mut issues, "$.policyId", &policy.policy_id);
    if !policy.policy_id.is_empty() && policy.policy_id != expected_policy_id {
        issues.push(issue(
            "$.policyId",
            "Trust policy id does not match canonical policy content",
        ));
    }
    require_non_empty(&mut issues, "$.owner", &policy.owner);
    require_non_empty_list(
        &mut issues,
        "$.allowedPrivacyTiers",
        policy.allowed_privacy_tiers.len(),
        "Trust policy must allow at least one privacy tier",
    );
    require_non_empty_list(
        &mut issues,
        "$.allowedVerificationTiers",
        policy.allowed_verification_tiers.len(),
        "Trust policy must allow at least one verification tier",
    );
    warn_duplicate_strings(&mut warnings, "$.allowedRunners", &policy.allowed_runners);
    warn_duplicate_strings(&mut warnings, "$.blockedRunners", &policy.blocked_runners);
    warn_duplicate_strings(
        &mut warnings,
        "$.allowedPublishers",
        &policy.allowed_publishers,
    );
    require_non_empty_entries(&mut issues, "$.allowedRunners", &policy.allowed_runners);
    require_non_empty_entries(&mut issues, "$.blockedRunners", &policy.blocked_runners);
    require_non_empty_entries(
        &mut issues,
        "$.allowedPublishers",
        &policy.allowed_publishers,
    );
    for runner in &policy.allowed_runners {
        if policy
            .blocked_runners
            .iter()
            .any(|blocked| blocked == runner)
        {
            issues.push(issue(
                "$.blockedRunners",
                format!("Runner {runner} is both allowed and blocked"),
            ));
        }
    }
    if policy.allow_open_miners
        && !policy.allowed_privacy_tiers.is_empty()
        && policy
            .allowed_privacy_tiers
            .iter()
            .all(|tier| matches!(tier, PrivacyTier::LocalOnly | PrivacyTier::BrowserOnly))
    {
        issues.push(issue(
            "$.allowOpenMiners",
            "Open miner routes cannot satisfy a policy that only allows local-only or browser-only privacy",
        ));
    }
    if policy.allow_open_miners
        && policy.allowed_publishers.is_empty()
        && !policy.require_validation
    {
        warnings.push(issue(
            "$.allowedPublishers",
            "Open miner marketplace policy has no publisher allow-list and does not require validation",
        ));
    }
    if !policy.require_receipt {
        warnings.push(issue(
            "$.requireReceipt",
            "Policy does not require execution receipts, reducing downstream auditability",
        ));
    }
    if let Some(max_price) = &policy.max_price {
        if !max_price.amount.is_finite() || max_price.amount < 0.0 {
            issues.push(issue(
                "$.maxPrice.amount",
                "Maximum price must be a finite non-negative number",
            ));
        }
        require_non_empty(&mut issues, "$.maxPrice.currency", &max_price.currency);
    }
    if matches!(policy.max_latency_ms, Some(0)) {
        issues.push(issue(
            "$.maxLatencyMs",
            "Maximum latency must be greater than zero milliseconds",
        ));
    }
    verify_trust_policy_signature(
        &mut issues,
        &mut warnings,
        policy.signature.as_deref(),
        expected_signature.as_deref(),
    );

    TrustPolicyVerificationV1 {
        schema_version: "swarm-ai.trust-policy-verification.v1".to_string(),
        policy_id: policy.policy_id.clone(),
        expected_policy_id,
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

fn trust_policy_signing_value(policy: &TrustPolicyV1) -> serde_json::Result<Value> {
    let mut unsigned = policy.clone();
    unsigned.policy_id.clear();
    unsigned.signature = None;
    serde_json::to_value(unsigned)
}

fn verify_trust_policy_signature(
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
    signature: Option<&str>,
    expected_signature: Option<&str>,
) {
    let signature = signature.map(str::trim).filter(|value| !value.is_empty());
    match (signature, expected_signature) {
        (None, _) => warnings.push(issue(
            "$.signature",
            "Trust policy is unsigned; verify policyId through a trusted source before use",
        )),
        (Some(signature), Some(expected)) if signature == expected => {}
        (Some(signature), Some(_)) if signature.starts_with(DEV_TRUST_POLICY_SIGNATURE_PREFIX) => {
            issues.push(issue(
                "$.signature",
                "Trust policy dev signature does not match canonical policy content",
            ));
        }
        (Some(_), _) => warnings.push(issue(
            "$.signature",
            "Trust policy signature is not a local-dev signature and was not verified here",
        )),
    }
}

fn require_non_empty(issues: &mut Vec<ValidationIssue>, path: impl Into<String>, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value must not be empty"));
    }
}

fn require_non_empty_list(
    issues: &mut Vec<ValidationIssue>,
    path: impl Into<String>,
    len: usize,
    message: impl Into<String>,
) {
    if len == 0 {
        issues.push(issue(path, message));
    }
}

fn require_non_empty_entries(issues: &mut Vec<ValidationIssue>, path: &str, values: &[String]) {
    for (index, value) in values.iter().enumerate() {
        if value.trim().is_empty() {
            issues.push(issue(format!("{path}[{index}]"), "Value must not be empty"));
        }
    }
}

fn warn_duplicate_strings(warnings: &mut Vec<ValidationIssue>, path: &str, values: &[String]) {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            warnings.push(issue(
                path,
                format!("Duplicate value {value} can be removed"),
            ));
        }
    }
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
    use serde_json::json;

    #[test]
    fn privacy_and_integrity_tiers_match_v2_wire_names() {
        assert_eq!(
            serde_json::to_value(PrivacyTier::TeeConfidential).unwrap(),
            json!("tee-confidential")
        );
        assert_eq!(
            serde_json::to_value(PrivacyTier::BrowserOnly).unwrap(),
            json!("browser-only")
        );
        assert_eq!(
            serde_json::to_value(PrivacyTier::ZkVerifiedInference).unwrap(),
            json!("zk-verified-inference")
        );
        assert_eq!(
            serde_json::to_value(IntegrityTier::ZkProofWhenSupported).unwrap(),
            json!("zk-proof-when-supported")
        );
    }

    #[test]
    fn privacy_catalog_defines_review4_tiers_and_limitations() {
        let catalog = privacy_tier_catalog();

        assert_eq!(catalog.schema_version, PRIVACY_TIER_CATALOG_SCHEMA_VERSION);
        assert!(catalog.profiles.iter().any(|profile| {
            profile.tier == PrivacyTier::BrowserOnly
                && profile.data_movement == PrivacyDataMovementRuleV1::NoPlaintextLeavesBrowser
                && profile
                    .limitations
                    .iter()
                    .any(|limitation| limitation.contains("service-worker"))
        }));
        assert!(catalog.profiles.iter().any(|profile| {
            profile.tier == PrivacyTier::EncryptedStorage
                && profile.requires_encryption
                && profile.requires_key_release_policy
        }));
        assert!(catalog.profiles.iter().any(|profile| {
            profile.tier == PrivacyTier::NoLogRemote
                && profile
                    .limitations
                    .iter()
                    .any(|limitation| limitation.contains("not cryptographic privacy"))
        }));
    }

    #[test]
    fn privacy_assessment_rejects_local_only_remote_plaintext() {
        let assessment = assess_privacy_requirement(&PrivacyRequirementAssessmentRequestV1 {
            schema_version: PRIVACY_REQUIREMENT_ASSESSMENT_REQUEST_SCHEMA_VERSION.to_string(),
            requested_tier: PrivacyTier::LocalOnly,
            offered_tier: PrivacyTier::NoLogRemote,
            runner_location: PrivacyExecutionLocationV1::RemoteRunner,
            integrity_tier: Some(IntegrityTier::ReceiptOnly),
            has_user_consent: true,
            has_access_grant: false,
            has_encrypted_asset_descriptor: false,
            has_key_release_policy: false,
            has_redaction_plan: false,
            has_attestation: false,
            allows_remote_plaintext: true,
            proof_refs: vec![],
        });

        assert!(!assessment.satisfied);
        assert!(
            assessment
                .issues
                .iter()
                .any(|issue| issue.path == "$.offeredTier")
        );
        assert!(assessment.issues.iter().any(|issue| {
            issue.path == "$.allowsRemotePlaintext" || issue.path == "$.runnerLocation"
        }));
    }

    #[test]
    fn privacy_assessment_requires_evidence_for_confidential_and_proof_tiers() {
        let tee = assess_privacy_requirement(&PrivacyRequirementAssessmentRequestV1 {
            schema_version: PRIVACY_REQUIREMENT_ASSESSMENT_REQUEST_SCHEMA_VERSION.to_string(),
            requested_tier: PrivacyTier::TeeConfidential,
            offered_tier: PrivacyTier::TeeConfidential,
            runner_location: PrivacyExecutionLocationV1::ConfidentialRunner,
            integrity_tier: Some(IntegrityTier::TeeAttested),
            has_user_consent: true,
            has_access_grant: true,
            has_encrypted_asset_descriptor: true,
            has_key_release_policy: true,
            has_redaction_plan: false,
            has_attestation: false,
            allows_remote_plaintext: false,
            proof_refs: vec![],
        });
        assert!(!tee.satisfied);
        assert!(
            tee.issues
                .iter()
                .any(|issue| issue.path == "$.hasAttestation")
        );
        assert!(
            tee.required_evidence
                .contains(&"confidential-attestation-ref".to_string())
        );

        let zk = assess_privacy_requirement(&PrivacyRequirementAssessmentRequestV1 {
            schema_version: PRIVACY_REQUIREMENT_ASSESSMENT_REQUEST_SCHEMA_VERSION.to_string(),
            requested_tier: PrivacyTier::ZkVerifiedInference,
            offered_tier: PrivacyTier::ZkVerifiedInference,
            runner_location: PrivacyExecutionLocationV1::Validator,
            integrity_tier: Some(IntegrityTier::ZkProofWhenSupported),
            has_user_consent: true,
            has_access_grant: false,
            has_encrypted_asset_descriptor: false,
            has_key_release_policy: false,
            has_redaction_plan: false,
            has_attestation: false,
            allows_remote_plaintext: false,
            proof_refs: vec![],
        });
        assert!(!zk.satisfied);
        assert!(zk.issues.iter().any(|issue| issue.path == "$.proofRefs"));
    }

    #[test]
    fn privacy_tier_satisfaction_accepts_stronger_local_and_cryptographic_modes() {
        assert!(privacy_tier_satisfies(
            &PrivacyTier::BrowserOnly,
            &PrivacyTier::NoLogRemote
        ));
        assert!(privacy_tier_satisfies(
            &PrivacyTier::FheEncryptedInference,
            &PrivacyTier::EncryptedStorage
        ));
        assert!(!privacy_tier_satisfies(
            &PrivacyTier::NoLogRemote,
            &PrivacyTier::TeeConfidential
        ));
        assert!(!privacy_tier_satisfies(
            &PrivacyTier::ZkVerifiedInference,
            &PrivacyTier::NoLogRemote
        ));
    }

    #[test]
    fn trust_policy_ids_ignore_signature_and_policy_id() {
        let mut left = TrustPolicyV1::local_only("0xUser");
        let mut right = left.clone();
        right.policy_id = "different".to_string();
        right.signature = Some("signature".to_string());

        assert_eq!(left.policy_id, canonical_trust_policy_id(&left).unwrap());
        assert_eq!(
            canonical_trust_policy_id(&left).unwrap(),
            canonical_trust_policy_id(&right).unwrap()
        );

        left.blocked_runners.push("runner-1".to_string());
        assert!(!trust_policy_allows_runner(&left, "runner-1"));
        assert!(trust_policy_allows_runner(&left, "runner-2"));
    }

    #[test]
    fn verify_trust_policy_accepts_unsigned_preset_with_warning() {
        let policy = TrustPolicyV1::open_marketplace("0xUser");
        let verification = verify_trust_policy(&policy);

        assert!(verification.valid);
        assert_eq!(verification.policy_id, verification.expected_policy_id);
        assert!(verification.issues.is_empty());
        assert!(verification.expected_signature.is_some());
        assert!(
            verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signature")
        );
    }

    #[test]
    fn signed_trust_policy_verifies_without_signature_warning() {
        let mut policy = TrustPolicyV1::local_only("0xUser");
        let signature = sign_trust_policy(&mut policy).unwrap();
        let verification = verify_trust_policy(&policy);

        assert!(verification.valid);
        assert_eq!(policy.signature.as_deref(), Some(signature.as_str()));
        assert!(
            !verification
                .warnings
                .iter()
                .any(|warning| warning.path == "$.signature")
        );
    }

    #[test]
    fn verify_trust_policy_rejects_mismatched_dev_signature() {
        let mut policy = TrustPolicyV1::local_only("0xUser");
        sign_trust_policy(&mut policy).unwrap();
        policy.signature = Some(format!("{DEV_TRUST_POLICY_SIGNATURE_PREFIX}:tampered"));

        let verification = verify_trust_policy(&policy);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.signature")
        );
    }

    #[test]
    fn verify_trust_policy_rejects_tampered_policy_id() {
        let mut policy = TrustPolicyV1::local_only("0xUser");
        policy.policy_id = "trust-policy-tampered".to_string();

        let verification = verify_trust_policy(&policy);

        assert!(!verification.valid);
        assert_eq!(
            verification.expected_policy_id,
            canonical_trust_policy_id(&policy).unwrap()
        );
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.policyId")
        );
    }

    #[test]
    fn verify_trust_policy_rejects_contradictory_runner_lists() {
        let mut policy = TrustPolicyV1::open_marketplace("0xUser");
        policy.allowed_runners.push("runner-1".to_string());
        policy.blocked_runners.push("runner-1".to_string());
        policy.policy_id = canonical_trust_policy_id(&policy).unwrap();

        let verification = verify_trust_policy(&policy);

        assert!(!verification.valid);
        assert!(
            verification
                .issues
                .iter()
                .any(|issue| issue.path == "$.blockedRunners")
        );
    }
}
