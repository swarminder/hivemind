use anyhow::Context;
use chrono::{DateTime, SecondsFormat, Utc};
use hivemind_core::{
    ApiSurface, IntegrityTier, Modality, PriceV1, PrivacyTier, RunnerCacheClaimV1, ValidationIssue,
    canonicalize_json, hash_canonical_json,
};
use hivemind_identity::{IdentityKeypairV1, SignatureEnvelopeV1};
use hivemind_marketplace::{
    HardwareExecutionModeV1, HardwareResourceOfferV1, HardwareResourceV1, MinerTrustTierV1,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const DEV_MINER_PROFILE_SIGNATURE_PREFIX: &str = "dev-miner-profile-signature-v1";
const DEV_MINER_HEARTBEAT_SIGNATURE_PREFIX: &str = "dev-miner-heartbeat-signature-v1";
const DEV_MINER_BENCHMARK_SIGNATURE_PREFIX: &str = "dev-miner-benchmark-signature-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MinerDaemonStatus {
    Starting,
    Available,
    Busy,
    Draining,
    Offline,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MinerProfileV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "minerId")]
    pub miner_id: String,
    pub operator: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "daemonVersion")]
    pub daemon_version: String,
    pub hardware: HardwareResourceV1,
    #[serde(rename = "supportedExecutionModes")]
    pub supported_execution_modes: Vec<HardwareExecutionModeV1>,
    #[serde(rename = "supportedEngines")]
    pub supported_engines: Vec<String>,
    #[serde(rename = "supportedApis")]
    pub supported_apis: Vec<ApiSurface>,
    #[serde(rename = "supportedModalities")]
    pub supported_modalities: Vec<Modality>,
    #[serde(rename = "privacyTiers")]
    pub privacy_tiers: Vec<PrivacyTier>,
    #[serde(rename = "verificationTiers")]
    pub verification_tiers: Vec<IntegrityTier>,
    #[serde(rename = "trustTier")]
    pub trust_tier: MinerTrustTierV1,
    #[serde(rename = "hardwareOfferId")]
    pub hardware_offer_id: String,
    #[serde(rename = "termsRef")]
    pub terms_ref: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MinerProfileVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "minerId")]
    pub miner_id: String,
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
pub struct MinerHeartbeatV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "heartbeatId")]
    pub heartbeat_id: String,
    #[serde(rename = "minerId")]
    pub miner_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub status: MinerDaemonStatus,
    #[serde(rename = "observedAt")]
    pub observed_at: String,
    #[serde(rename = "queueDepth")]
    pub queue_depth: u32,
    #[serde(rename = "activeJobs")]
    pub active_jobs: u32,
    #[serde(rename = "currentJobIds", default)]
    pub current_job_ids: Vec<String>,
    #[serde(
        rename = "availableVramGb",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub available_vram_gb: Option<f64>,
    #[serde(rename = "availableRamGb")]
    pub available_ram_gb: f64,
    #[serde(rename = "loadAverage")]
    pub load_average: f64,
    #[serde(rename = "cacheClaims", default)]
    pub cache_claims: Vec<RunnerCacheClaimV1>,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MinerHeartbeatVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "heartbeatId")]
    pub heartbeat_id: String,
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
pub struct MinerBenchmarkMetricV1 {
    pub name: String,
    pub value: f64,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MinerBenchmarkResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    #[serde(rename = "minerId")]
    pub miner_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "hardwareOfferId")]
    pub hardware_offer_id: String,
    #[serde(rename = "benchmarkSuite")]
    pub benchmark_suite: String,
    pub workload: String,
    pub metrics: Vec<MinerBenchmarkMetricV1>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(rename = "privacyTier")]
    pub privacy_tier: PrivacyTier,
    #[serde(rename = "integrityTier")]
    pub integrity_tier: IntegrityTier,
    #[serde(rename = "measuredAt")]
    pub measured_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MinerBenchmarkVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
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
pub struct MinerOnboardingStepV1 {
    pub order: u32,
    pub title: String,
    pub status: String,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MinerOnboardingPlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "minerId")]
    pub miner_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "recommendedTrustTier")]
    pub recommended_trust_tier: MinerTrustTierV1,
    #[serde(rename = "eligibleForPublicJobs")]
    pub eligible_for_public_jobs: bool,
    #[serde(rename = "eligibleForSensitiveJobs")]
    pub eligible_for_sensitive_jobs: bool,
    pub steps: Vec<MinerOnboardingStepV1>,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationIssue>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MinerDashboardSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "minerId")]
    pub miner_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub status: MinerDaemonStatus,
    #[serde(rename = "trustTier")]
    pub trust_tier: MinerTrustTierV1,
    #[serde(rename = "hardwareOfferId")]
    pub hardware_offer_id: String,
    #[serde(rename = "queueDepth")]
    pub queue_depth: u32,
    #[serde(rename = "activeJobs")]
    pub active_jobs: u32,
    #[serde(rename = "completedJobs")]
    pub completed_jobs: u64,
    #[serde(rename = "settledJobs")]
    pub settled_jobs: u64,
    #[serde(rename = "disputedJobs")]
    pub disputed_jobs: u64,
    #[serde(rename = "estimatedEarnings")]
    pub estimated_earnings: PriceV1,
    #[serde(rename = "benchmarkCount")]
    pub benchmark_count: u32,
    #[serde(rename = "warningCount")]
    pub warning_count: u32,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MinerDashboardInputV1 {
    pub profile: MinerProfileV1,
    pub heartbeat: MinerHeartbeatV1,
    #[serde(rename = "hardwareOffer")]
    pub hardware_offer: HardwareResourceOfferV1,
    #[serde(default)]
    pub benchmarks: Vec<MinerBenchmarkResultV1>,
    #[serde(rename = "completedJobs", default)]
    pub completed_jobs: u64,
    #[serde(rename = "settledJobs", default)]
    pub settled_jobs: u64,
    #[serde(rename = "disputedJobs", default)]
    pub disputed_jobs: u64,
    #[serde(rename = "estimatedEarnings", default)]
    pub estimated_earnings: Option<PriceV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MinerRecordType {
    Profile,
    Heartbeat,
    Benchmark,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MinerRecordSummaryV1 {
    #[serde(rename = "recordId")]
    pub record_id: String,
    #[serde(rename = "recordType")]
    pub record_type: MinerRecordType,
    #[serde(rename = "minerId")]
    pub miner_id: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub operator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<MinerDaemonStatus>,
    #[serde(rename = "trustTier", default, skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<MinerTrustTierV1>,
    #[serde(
        rename = "hardwareOfferId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hardware_offer_id: Option<String>,
    #[serde(
        rename = "benchmarkSuite",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub benchmark_suite: Option<String>,
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
pub struct MinerRecordStoreSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "profileCount")]
    pub profile_count: usize,
    #[serde(rename = "heartbeatCount")]
    pub heartbeat_count: usize,
    #[serde(rename = "benchmarkCount")]
    pub benchmark_count: usize,
    #[serde(rename = "recordCount")]
    pub record_count: usize,
    #[serde(rename = "validCount")]
    pub valid_count: usize,
    #[serde(rename = "invalidCount")]
    pub invalid_count: usize,
    #[serde(rename = "availableHeartbeatCount")]
    pub available_heartbeat_count: usize,
    #[serde(rename = "busyHeartbeatCount")]
    pub busy_heartbeat_count: usize,
    #[serde(rename = "memoryUsageSampleCount")]
    pub memory_usage_sample_count: usize,
    #[serde(
        rename = "averageMemoryUsageRatio",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub average_memory_usage_ratio: Option<f64>,
    #[serde(
        rename = "maxMemoryUsageRatio",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_memory_usage_ratio: Option<f64>,
    #[serde(rename = "vramUsageSampleCount")]
    pub vram_usage_sample_count: usize,
    #[serde(
        rename = "averageVramUsageRatio",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub average_vram_usage_ratio: Option<f64>,
    #[serde(
        rename = "maxVramUsageRatio",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_vram_usage_ratio: Option<f64>,
    #[serde(rename = "warningCount")]
    pub warning_count: usize,
    pub records: Vec<MinerRecordSummaryV1>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MinerRecordLookupV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "recordId")]
    pub record_id: String,
    #[serde(rename = "recordType")]
    pub record_type: MinerRecordType,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<MinerProfileV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<MinerHeartbeatV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark: Option<MinerBenchmarkResultV1>,
    #[serde(
        rename = "hardwareOffer",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub hardware_offer: Option<HardwareResourceOfferV1>,
    #[serde(
        rename = "profileVerification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub profile_verification: Option<MinerProfileVerificationV1>,
    #[serde(
        rename = "heartbeatVerification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub heartbeat_verification: Option<MinerHeartbeatVerificationV1>,
    #[serde(
        rename = "benchmarkVerification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub benchmark_verification: Option<MinerBenchmarkVerificationV1>,
    #[serde(
        rename = "onboardingPlan",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub onboarding_plan: Option<MinerOnboardingPlanV1>,
    #[serde(
        rename = "dashboardSummary",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dashboard_summary: Option<MinerDashboardSummaryV1>,
}

pub fn miner_profile_from_hardware_offer(
    offer: &HardwareResourceOfferV1,
    daemon_version: impl Into<String>,
) -> MinerProfileV1 {
    let mut profile = MinerProfileV1 {
        schema_version: "swarm-ai.miner-profile.v1".to_string(),
        miner_id: String::new(),
        operator: offer.operator.clone(),
        runner_id: offer.runner_id.clone(),
        daemon_version: daemon_version.into(),
        hardware: offer.hardware.clone(),
        supported_execution_modes: offer.supported_execution_modes.clone(),
        supported_engines: offer.supported_engines.clone(),
        supported_apis: offer.supported_apis.clone(),
        supported_modalities: offer.supported_modalities.clone(),
        privacy_tiers: offer.privacy_tiers.clone(),
        verification_tiers: offer.verification_tiers.clone(),
        trust_tier: offer.trust_tier.clone(),
        hardware_offer_id: offer.offer_id.clone(),
        terms_ref: offer.terms_ref.clone(),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        signature: None,
    };
    sign_miner_profile(&mut profile);
    profile
}

pub fn sign_miner_profile(profile: &mut MinerProfileV1) {
    profile.signature = Some(expected_miner_profile_signature(profile));
    profile.miner_id = canonical_miner_profile_id(profile);
}

pub fn sign_miner_profile_with_identity(
    profile: &mut MinerProfileV1,
    identity: &IdentityKeypairV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != profile.operator {
        anyhow::bail!(
            "identity subject {} does not match miner operator {}",
            identity.subject,
            profile.operator
        );
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "miner-profile",
        &miner_profile_signing_value(profile),
    )?;
    profile.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    profile.miner_id = canonical_miner_profile_id(profile);
    Ok(envelope)
}

pub fn expected_miner_profile_signature(profile: &MinerProfileV1) -> String {
    format!(
        "{DEV_MINER_PROFILE_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&miner_profile_signing_value(profile)))
    )
}

pub fn canonical_miner_profile_id(profile: &MinerProfileV1) -> String {
    stable_id("miner", &miner_profile_signing_value(profile))
}

pub fn verify_miner_profile(
    profile: &MinerProfileV1,
    offer: Option<&HardwareResourceOfferV1>,
) -> MinerProfileVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_miner_profile_signature(profile));

    if profile.schema_version != "swarm-ai.miner-profile.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.miner-profile.v1",
        ));
    }
    require_non_empty(&mut issues, "$.minerId", &profile.miner_id);
    if !profile.miner_id.is_empty() && profile.miner_id != canonical_miner_profile_id(profile) {
        issues.push(issue(
            "$.minerId",
            "Miner id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.operator", &profile.operator);
    require_non_empty(&mut issues, "$.runnerId", &profile.runner_id);
    require_non_empty(&mut issues, "$.daemonVersion", &profile.daemon_version);
    require_non_empty(&mut issues, "$.hardwareOfferId", &profile.hardware_offer_id);
    require_non_empty(&mut issues, "$.termsRef", &profile.terms_ref);
    validate_hardware(&profile.hardware, "$.hardware", &mut issues, &mut warnings);
    if profile.supported_execution_modes.is_empty() {
        issues.push(issue(
            "$.supportedExecutionModes",
            "Miner profile must declare supported execution modes",
        ));
    }
    if profile.supported_apis.is_empty() {
        issues.push(issue(
            "$.supportedApis",
            "Miner profile must declare supported APIs",
        ));
    }
    if profile.privacy_tiers.is_empty() {
        issues.push(issue(
            "$.privacyTiers",
            "Miner profile must declare supported privacy tiers",
        ));
    }
    if profile.verification_tiers.is_empty() {
        issues.push(issue(
            "$.verificationTiers",
            "Miner profile must declare supported verification tiers",
        ));
    }
    if matches!(
        profile.trust_tier,
        MinerTrustTierV1::Confidential | MinerTrustTierV1::Cryptographic
    ) && !profile
        .privacy_tiers
        .contains(&PrivacyTier::TeeConfidential)
        && !profile.privacy_tiers.contains(&PrivacyTier::FheEncrypted)
    {
        warnings.push(issue(
            "$.trustTier",
            "High trust miner should declare matching confidential or encrypted privacy support",
        ));
    }
    validate_timestamp(&mut issues, "$.createdAt", &profile.created_at);
    if let Some(offer) = offer {
        compare_profile_to_offer(profile, offer, &mut issues, &mut warnings);
    } else {
        warnings.push(issue(
            "$.hardwareOfferId",
            "No HardwareResourceOfferV1 was supplied for profile consistency checks",
        ));
    }
    verify_signature(
        "miner-profile",
        &miner_profile_signing_value(profile),
        profile.signature.as_deref(),
        Some(&profile.operator),
        "$.signature",
        &mut issues,
        &mut warnings,
        &mut expected_signature,
        "Miner profile signature does not match canonical dev signature or Ed25519 operator identity envelope",
    );

    MinerProfileVerificationV1 {
        schema_version: "swarm-ai.miner-profile-verification.v1".to_string(),
        miner_id: profile.miner_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: timestamp(),
    }
}

pub fn miner_heartbeat_from_profile(
    profile: &MinerProfileV1,
    status: MinerDaemonStatus,
    queue_depth: u32,
    active_jobs: u32,
    current_job_ids: Vec<String>,
    load_average: f64,
) -> MinerHeartbeatV1 {
    let mut heartbeat = MinerHeartbeatV1 {
        schema_version: "swarm-ai.miner-heartbeat.v1".to_string(),
        heartbeat_id: String::new(),
        miner_id: profile.miner_id.clone(),
        runner_id: profile.runner_id.clone(),
        status,
        observed_at: timestamp(),
        queue_depth,
        active_jobs,
        current_job_ids,
        available_vram_gb: profile.hardware.vram_gb,
        available_ram_gb: profile.hardware.ram_gb,
        load_average,
        cache_claims: Vec::new(),
        errors: Vec::new(),
        signature: None,
    };
    sign_miner_heartbeat(&mut heartbeat);
    heartbeat
}

pub fn sign_miner_heartbeat(heartbeat: &mut MinerHeartbeatV1) {
    heartbeat.signature = Some(expected_miner_heartbeat_signature(heartbeat));
    heartbeat.heartbeat_id = canonical_miner_heartbeat_id(heartbeat);
}

pub fn expected_miner_heartbeat_signature(heartbeat: &MinerHeartbeatV1) -> String {
    format!(
        "{DEV_MINER_HEARTBEAT_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&miner_heartbeat_signing_value(
            heartbeat
        )))
    )
}

pub fn canonical_miner_heartbeat_id(heartbeat: &MinerHeartbeatV1) -> String {
    stable_id("miner-heartbeat", &miner_heartbeat_signing_value(heartbeat))
}

pub fn verify_miner_heartbeat(
    heartbeat: &MinerHeartbeatV1,
    profile: Option<&MinerProfileV1>,
) -> MinerHeartbeatVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_miner_heartbeat_signature(heartbeat));

    if heartbeat.schema_version != "swarm-ai.miner-heartbeat.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.miner-heartbeat.v1",
        ));
    }
    require_non_empty(&mut issues, "$.heartbeatId", &heartbeat.heartbeat_id);
    if !heartbeat.heartbeat_id.is_empty()
        && heartbeat.heartbeat_id != canonical_miner_heartbeat_id(heartbeat)
    {
        issues.push(issue(
            "$.heartbeatId",
            "Heartbeat id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.minerId", &heartbeat.miner_id);
    require_non_empty(&mut issues, "$.runnerId", &heartbeat.runner_id);
    validate_timestamp(&mut issues, "$.observedAt", &heartbeat.observed_at);
    if heartbeat.load_average < 0.0 {
        issues.push(issue(
            "$.loadAverage",
            "Miner load average must not be negative",
        ));
    }
    if heartbeat.available_ram_gb < 0.0 {
        issues.push(issue(
            "$.availableRamGb",
            "Available RAM must not be negative",
        ));
    }
    if heartbeat.active_jobs > 0 && heartbeat.status == MinerDaemonStatus::Available {
        warnings.push(issue(
            "$.status",
            "Heartbeat is marked available while active jobs are running",
        ));
    }
    if heartbeat.status == MinerDaemonStatus::Error && heartbeat.errors.is_empty() {
        warnings.push(issue(
            "$.errors",
            "Error heartbeat should include an operator-visible error summary",
        ));
    }
    if let Some(profile) = profile {
        if heartbeat.miner_id != profile.miner_id {
            issues.push(issue(
                "$.minerId",
                "Heartbeat minerId does not match supplied miner profile",
            ));
        }
        if heartbeat.runner_id != profile.runner_id {
            issues.push(issue(
                "$.runnerId",
                "Heartbeat runnerId does not match supplied miner profile",
            ));
        }
    }
    verify_signature(
        "miner-heartbeat",
        &miner_heartbeat_signing_value(heartbeat),
        heartbeat.signature.as_deref(),
        None,
        "$.signature",
        &mut issues,
        &mut warnings,
        &mut expected_signature,
        "Miner heartbeat signature does not match canonical dev signature",
    );

    MinerHeartbeatVerificationV1 {
        schema_version: "swarm-ai.miner-heartbeat-verification.v1".to_string(),
        heartbeat_id: heartbeat.heartbeat_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: timestamp(),
    }
}

pub fn miner_benchmark_result(
    profile: &MinerProfileV1,
    offer: &HardwareResourceOfferV1,
    benchmark_suite: impl Into<String>,
    workload: impl Into<String>,
    metrics: Vec<MinerBenchmarkMetricV1>,
    evidence_refs: Vec<String>,
) -> MinerBenchmarkResultV1 {
    let mut result = MinerBenchmarkResultV1 {
        schema_version: "swarm-ai.miner-benchmark-result.v1".to_string(),
        benchmark_id: String::new(),
        miner_id: profile.miner_id.clone(),
        runner_id: profile.runner_id.clone(),
        hardware_offer_id: offer.offer_id.clone(),
        benchmark_suite: benchmark_suite.into(),
        workload: workload.into(),
        metrics,
        evidence_refs,
        privacy_tier: profile
            .privacy_tiers
            .first()
            .cloned()
            .unwrap_or(PrivacyTier::Standard),
        integrity_tier: profile
            .verification_tiers
            .first()
            .cloned()
            .unwrap_or(IntegrityTier::ReceiptOnly),
        measured_at: timestamp(),
        signature: None,
    };
    sign_miner_benchmark_result(&mut result);
    result
}

pub fn sign_miner_benchmark_result(result: &mut MinerBenchmarkResultV1) {
    result.signature = Some(expected_miner_benchmark_signature(result));
    result.benchmark_id = canonical_miner_benchmark_id(result);
}

pub fn sign_miner_benchmark_result_with_identity(
    result: &mut MinerBenchmarkResultV1,
    identity: &IdentityKeypairV1,
    profile: &MinerProfileV1,
) -> anyhow::Result<SignatureEnvelopeV1> {
    if identity.subject != profile.operator {
        anyhow::bail!(
            "identity subject {} does not match miner operator {}",
            identity.subject,
            profile.operator
        );
    }
    if result.miner_id != profile.miner_id {
        anyhow::bail!("benchmark result minerId does not match miner profile");
    }
    let envelope = hivemind_identity::sign_value(
        identity,
        "miner-benchmark-result",
        &miner_benchmark_signing_value(result),
    )?;
    result.signature = Some(hivemind_identity::encode_signature_envelope(&envelope)?);
    result.benchmark_id = canonical_miner_benchmark_id(result);
    Ok(envelope)
}

pub fn expected_miner_benchmark_signature(result: &MinerBenchmarkResultV1) -> String {
    format!(
        "{DEV_MINER_BENCHMARK_SIGNATURE_PREFIX}:{}",
        hash_canonical_json(&canonicalize_json(&miner_benchmark_signing_value(result)))
    )
}

pub fn canonical_miner_benchmark_id(result: &MinerBenchmarkResultV1) -> String {
    stable_id("miner-benchmark", &miner_benchmark_signing_value(result))
}

pub fn verify_miner_benchmark_result(
    result: &MinerBenchmarkResultV1,
    profile: Option<&MinerProfileV1>,
    offer: Option<&HardwareResourceOfferV1>,
) -> MinerBenchmarkVerificationV1 {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut expected_signature = Some(expected_miner_benchmark_signature(result));

    if result.schema_version != "swarm-ai.miner-benchmark-result.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.miner-benchmark-result.v1",
        ));
    }
    require_non_empty(&mut issues, "$.benchmarkId", &result.benchmark_id);
    if !result.benchmark_id.is_empty()
        && result.benchmark_id != canonical_miner_benchmark_id(result)
    {
        issues.push(issue(
            "$.benchmarkId",
            "Benchmark id does not match canonical signed content",
        ));
    }
    require_non_empty(&mut issues, "$.minerId", &result.miner_id);
    require_non_empty(&mut issues, "$.runnerId", &result.runner_id);
    require_non_empty(&mut issues, "$.hardwareOfferId", &result.hardware_offer_id);
    require_non_empty(&mut issues, "$.benchmarkSuite", &result.benchmark_suite);
    require_non_empty(&mut issues, "$.workload", &result.workload);
    validate_timestamp(&mut issues, "$.measuredAt", &result.measured_at);
    if result.metrics.is_empty() {
        issues.push(issue(
            "$.metrics",
            "Miner benchmark must include at least one metric",
        ));
    }
    for (index, metric) in result.metrics.iter().enumerate() {
        let base = format!("$.metrics[{index}]");
        require_non_empty(&mut issues, format!("{base}.name"), &metric.name);
        require_non_empty(&mut issues, format!("{base}.unit"), &metric.unit);
        if !metric.value.is_finite() || metric.value < 0.0 {
            issues.push(issue(
                format!("{base}.value"),
                "Benchmark metric value must be finite and non-negative",
            ));
        }
    }
    if result.evidence_refs.is_empty() {
        warnings.push(issue(
            "$.evidenceRefs",
            "Benchmark has no evidence refs; validator replay will be weaker",
        ));
    }
    if let Some(profile) = profile {
        if result.miner_id != profile.miner_id {
            issues.push(issue(
                "$.minerId",
                "Benchmark minerId does not match supplied miner profile",
            ));
        }
        if !profile.privacy_tiers.contains(&result.privacy_tier) {
            issues.push(issue(
                "$.privacyTier",
                "Benchmark privacy tier is not declared by supplied miner profile",
            ));
        }
        if !profile.verification_tiers.contains(&result.integrity_tier) {
            issues.push(issue(
                "$.integrityTier",
                "Benchmark integrity tier is not declared by supplied miner profile",
            ));
        }
    }
    if let Some(offer) = offer {
        if result.hardware_offer_id != offer.offer_id {
            issues.push(issue(
                "$.hardwareOfferId",
                "Benchmark hardwareOfferId does not match supplied hardware offer",
            ));
        }
        if result.runner_id != offer.runner_id {
            issues.push(issue(
                "$.runnerId",
                "Benchmark runnerId does not match supplied hardware offer",
            ));
        }
    }
    verify_signature(
        "miner-benchmark-result",
        &miner_benchmark_signing_value(result),
        result.signature.as_deref(),
        profile.map(|profile| profile.operator.as_str()),
        "$.signature",
        &mut issues,
        &mut warnings,
        &mut expected_signature,
        "Miner benchmark signature does not match canonical dev signature or Ed25519 operator identity envelope",
    );

    MinerBenchmarkVerificationV1 {
        schema_version: "swarm-ai.miner-benchmark-verification.v1".to_string(),
        benchmark_id: result.benchmark_id.clone(),
        valid: issues.is_empty(),
        issues,
        warnings,
        expected_signature,
        verified_at: timestamp(),
    }
}

pub fn miner_onboarding_plan(
    profile: &MinerProfileV1,
    offer: &HardwareResourceOfferV1,
    benchmarks: &[MinerBenchmarkResultV1],
) -> MinerOnboardingPlanV1 {
    let profile_verification = verify_miner_profile(profile, Some(offer));
    let offer_verification = hivemind_marketplace::verify_hardware_resource_offer(offer);
    let benchmark_verifications: Vec<_> = benchmarks
        .iter()
        .map(|benchmark| verify_miner_benchmark_result(benchmark, Some(profile), Some(offer)))
        .collect();
    let benchmark_valid = !benchmarks.is_empty()
        && benchmark_verifications
            .iter()
            .all(|verification| verification.valid);
    let eligible_for_public_jobs = profile_verification.valid
        && offer_verification.valid
        && !profile.supported_execution_modes.is_empty()
        && !profile.supported_apis.is_empty();
    let eligible_for_sensitive_jobs = eligible_for_public_jobs
        && benchmark_valid
        && matches!(
            profile.trust_tier,
            MinerTrustTierV1::Verified
                | MinerTrustTierV1::Confidential
                | MinerTrustTierV1::Cryptographic
        )
        && (profile.privacy_tiers.contains(&PrivacyTier::NoLog)
            || profile
                .privacy_tiers
                .contains(&PrivacyTier::TeeConfidential)
            || profile.privacy_tiers.contains(&PrivacyTier::FheEncrypted));

    let mut issues = profile_verification.issues.clone();
    issues.extend(
        offer_verification
            .issues
            .iter()
            .map(|issue| ValidationIssue {
                path: format!("$.hardwareOffer{}", issue.path.trim_start_matches('$')),
                message: issue.message.clone(),
            }),
    );
    for verification in &benchmark_verifications {
        issues.extend(verification.issues.clone());
    }

    let mut warnings = profile_verification.warnings.clone();
    warnings.extend(
        offer_verification
            .warnings
            .iter()
            .map(|issue| ValidationIssue {
                path: format!("$.hardwareOffer{}", issue.path.trim_start_matches('$')),
                message: issue.message.clone(),
            }),
    );
    for verification in &benchmark_verifications {
        warnings.extend(verification.warnings.clone());
    }
    if benchmarks.is_empty() {
        warnings.push(issue(
            "$.benchmarks",
            "No miner benchmark result supplied; keep miner on public or low-risk jobs only",
        ));
    }

    let recommended_trust_tier = recommended_trust_tier(profile, benchmark_valid);
    MinerOnboardingPlanV1 {
        schema_version: "swarm-ai.miner-onboarding-plan.v1".to_string(),
        miner_id: profile.miner_id.clone(),
        runner_id: profile.runner_id.clone(),
        recommended_trust_tier,
        eligible_for_public_jobs,
        eligible_for_sensitive_jobs,
        steps: vec![
            step(
                1,
                "Create miner profile",
                profile_verification.valid,
                vec![profile.miner_id.clone()],
            ),
            step(
                2,
                "Publish hardware offer",
                offer_verification.valid,
                vec![offer.offer_id.clone()],
            ),
            step(
                3,
                "Run benchmark challenge",
                benchmark_valid,
                benchmarks
                    .iter()
                    .map(|benchmark| benchmark.benchmark_id.clone())
                    .collect(),
            ),
            step(
                4,
                "Restrict sensitive jobs by trust tier",
                eligible_for_sensitive_jobs,
                Vec::new(),
            ),
        ],
        issues,
        warnings,
        generated_at: timestamp(),
    }
}

pub fn miner_dashboard_summary(input: MinerDashboardInputV1) -> MinerDashboardSummaryV1 {
    let plan = miner_onboarding_plan(&input.profile, &input.hardware_offer, &input.benchmarks);
    MinerDashboardSummaryV1 {
        schema_version: "swarm-ai.miner-dashboard-summary.v1".to_string(),
        miner_id: input.profile.miner_id,
        runner_id: input.profile.runner_id,
        status: input.heartbeat.status,
        trust_tier: plan.recommended_trust_tier,
        hardware_offer_id: input.hardware_offer.offer_id,
        queue_depth: input.heartbeat.queue_depth,
        active_jobs: input.heartbeat.active_jobs,
        completed_jobs: input.completed_jobs,
        settled_jobs: input.settled_jobs,
        disputed_jobs: input.disputed_jobs,
        estimated_earnings: input.estimated_earnings.unwrap_or(PriceV1 {
            amount: 0.0,
            currency: "USD".to_string(),
        }),
        benchmark_count: input.benchmarks.len() as u32,
        warning_count: plan.warnings.len() as u32,
        generated_at: timestamp(),
    }
}

pub fn list_miner_records(miner_dir: &Path) -> anyhow::Result<MinerRecordStoreSummaryV1> {
    let documents = read_miner_documents(miner_dir)?;
    let support = MinerDocumentSupport::from_documents(&documents);

    let mut records = Vec::new();
    let mut profile_count = 0;
    let mut heartbeat_count = 0;
    let mut benchmark_count = 0;
    let mut valid_count = 0;
    let mut available_heartbeat_count = 0;
    let mut busy_heartbeat_count = 0;
    let mut warning_count = 0;

    for (path, document) in documents {
        let path_string = path.display().to_string();
        match document {
            MinerDocument::Profile(profile) => {
                let offer = support.offers.get(&profile.hardware_offer_id);
                let verification = verify_miner_profile(&profile, offer);
                if verification.valid {
                    valid_count += 1;
                }
                profile_count += 1;
                warning_count += verification.warnings.len();
                records.push(miner_profile_index_entry(
                    &profile,
                    &verification,
                    path_string,
                ));
            }
            MinerDocument::Heartbeat(heartbeat) => {
                let profile = support.profiles.get(&heartbeat.miner_id);
                let verification = verify_miner_heartbeat(&heartbeat, profile);
                if verification.valid {
                    valid_count += 1;
                }
                if heartbeat.status == MinerDaemonStatus::Available {
                    available_heartbeat_count += 1;
                }
                if heartbeat.status == MinerDaemonStatus::Busy {
                    busy_heartbeat_count += 1;
                }
                heartbeat_count += 1;
                warning_count += verification.warnings.len();
                records.push(miner_heartbeat_index_entry(
                    &heartbeat,
                    profile,
                    &verification,
                    path_string,
                ));
            }
            MinerDocument::Benchmark(benchmark) => {
                let profile = support.profiles.get(&benchmark.miner_id);
                let offer = support.offers.get(&benchmark.hardware_offer_id);
                let verification = verify_miner_benchmark_result(&benchmark, profile, offer);
                if verification.valid {
                    valid_count += 1;
                }
                benchmark_count += 1;
                warning_count += verification.warnings.len();
                records.push(miner_benchmark_index_entry(
                    &benchmark,
                    profile,
                    &verification,
                    path_string,
                ));
            }
            MinerDocument::HardwareOffer(_) => {}
        }
    }

    records.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then(left.record_id.cmp(&right.record_id))
            .then(left.path.cmp(&right.path))
    });
    let resource_usage = miner_resource_usage_aggregates(&support);

    Ok(MinerRecordStoreSummaryV1 {
        schema_version: "swarm-ai.miner-record-store-summary.v1".to_string(),
        root: miner_dir.display().to_string(),
        profile_count,
        heartbeat_count,
        benchmark_count,
        record_count: records.len(),
        valid_count,
        invalid_count: records.len().saturating_sub(valid_count),
        available_heartbeat_count,
        busy_heartbeat_count,
        memory_usage_sample_count: resource_usage.memory_usage_values.len(),
        average_memory_usage_ratio: average_f64(&resource_usage.memory_usage_values),
        max_memory_usage_ratio: max_f64(&resource_usage.memory_usage_values),
        vram_usage_sample_count: resource_usage.vram_usage_values.len(),
        average_vram_usage_ratio: average_f64(&resource_usage.vram_usage_values),
        max_vram_usage_ratio: max_f64(&resource_usage.vram_usage_values),
        warning_count,
        records,
        generated_at: timestamp(),
    })
}

pub fn get_miner_record(
    miner_dir: &Path,
    record_id: &str,
) -> anyhow::Result<Option<MinerRecordLookupV1>> {
    let record_id = record_id.trim();
    if record_id.is_empty() {
        anyhow::bail!("recordId is required");
    }

    let documents = read_miner_documents(miner_dir)?;
    let support = MinerDocumentSupport::from_documents(&documents);

    for (path, document) in documents {
        match document {
            MinerDocument::Profile(profile) if profile.miner_id == record_id => {
                return Ok(Some(profile_lookup(path, profile, &support)));
            }
            MinerDocument::Heartbeat(heartbeat) if heartbeat.heartbeat_id == record_id => {
                return Ok(Some(heartbeat_lookup(path, heartbeat, &support)));
            }
            MinerDocument::Benchmark(benchmark) if benchmark.benchmark_id == record_id => {
                return Ok(Some(benchmark_lookup(path, benchmark, &support)));
            }
            _ => {}
        }
    }

    Ok(None)
}

#[derive(Debug, Clone)]
enum MinerDocument {
    Profile(MinerProfileV1),
    Heartbeat(MinerHeartbeatV1),
    Benchmark(MinerBenchmarkResultV1),
    HardwareOffer(HardwareResourceOfferV1),
}

#[derive(Debug, Default)]
struct MinerDocumentSupport {
    profiles: BTreeMap<String, MinerProfileV1>,
    offers: BTreeMap<String, HardwareResourceOfferV1>,
    benchmarks_by_miner: BTreeMap<String, Vec<MinerBenchmarkResultV1>>,
    latest_heartbeat_by_miner: BTreeMap<String, MinerHeartbeatV1>,
}

impl MinerDocumentSupport {
    fn from_documents(documents: &[(PathBuf, MinerDocument)]) -> Self {
        let mut support = Self::default();
        for (_, document) in documents {
            match document {
                MinerDocument::Profile(profile) => {
                    support
                        .profiles
                        .insert(profile.miner_id.clone(), profile.clone());
                }
                MinerDocument::HardwareOffer(offer) => {
                    support.offers.insert(offer.offer_id.clone(), offer.clone());
                }
                MinerDocument::Benchmark(benchmark) => {
                    support
                        .benchmarks_by_miner
                        .entry(benchmark.miner_id.clone())
                        .or_default()
                        .push(benchmark.clone());
                }
                MinerDocument::Heartbeat(heartbeat) => {
                    let update = support
                        .latest_heartbeat_by_miner
                        .get(&heartbeat.miner_id)
                        .map(|existing| heartbeat.observed_at > existing.observed_at)
                        .unwrap_or(true);
                    if update {
                        support
                            .latest_heartbeat_by_miner
                            .insert(heartbeat.miner_id.clone(), heartbeat.clone());
                    }
                }
            }
        }
        support
    }

    fn offer_for_profile(&self, profile: &MinerProfileV1) -> Option<HardwareResourceOfferV1> {
        self.offers.get(&profile.hardware_offer_id).cloned()
    }

    fn benchmarks_for_miner(&self, miner_id: &str) -> Vec<MinerBenchmarkResultV1> {
        self.benchmarks_by_miner
            .get(miner_id)
            .cloned()
            .unwrap_or_default()
    }

    fn latest_heartbeat_for_miner(&self, miner_id: &str) -> Option<MinerHeartbeatV1> {
        self.latest_heartbeat_by_miner.get(miner_id).cloned()
    }
}

#[derive(Debug, Default)]
struct MinerResourceUsageAggregates {
    memory_usage_values: Vec<f64>,
    vram_usage_values: Vec<f64>,
}

fn miner_resource_usage_aggregates(support: &MinerDocumentSupport) -> MinerResourceUsageAggregates {
    let mut aggregates = MinerResourceUsageAggregates::default();
    for heartbeat in support.latest_heartbeat_by_miner.values() {
        let Some(profile) = support.profiles.get(&heartbeat.miner_id) else {
            continue;
        };
        let offer = support.offers.get(&profile.hardware_offer_id);
        if !verify_miner_profile(profile, offer).valid
            || !verify_miner_heartbeat(heartbeat, Some(profile)).valid
        {
            continue;
        }
        if let Some(ratio) = usage_ratio(profile.hardware.ram_gb, heartbeat.available_ram_gb) {
            aggregates.memory_usage_values.push(ratio);
        }
        if let (Some(total), Some(available)) =
            (profile.hardware.vram_gb, heartbeat.available_vram_gb)
            && let Some(ratio) = usage_ratio(total, available)
        {
            aggregates.vram_usage_values.push(ratio);
        }
    }
    aggregates
}

fn usage_ratio(total: f64, available: f64) -> Option<f64> {
    if !total.is_finite() || !available.is_finite() || total <= 0.0 {
        return None;
    }
    let used = (total - available).clamp(0.0, total);
    Some(used / total)
}

fn average_f64(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<f64>() / values.len() as f64)
    }
}

fn max_f64(values: &[f64]) -> Option<f64> {
    values.iter().copied().reduce(f64::max)
}

fn read_miner_documents(miner_dir: &Path) -> anyhow::Result<Vec<(PathBuf, MinerDocument)>> {
    let mut files = Vec::new();
    collect_miner_files(miner_dir, &mut files)?;
    files.sort();

    let mut documents = Vec::new();
    for path in files {
        let Some(document) = read_miner_document(&path)? else {
            continue;
        };
        documents.push((path, document));
    }
    Ok(documents)
}

fn collect_miner_files(miner_dir: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    if !miner_dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(miner_dir)
        .with_context(|| format!("failed to read {}", miner_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_miner_files(&path, files)?;
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

fn read_miner_document(path: &Path) -> anyhow::Result<Option<MinerDocument>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let Some(schema_version) = value.get("schemaVersion").and_then(Value::as_str) else {
        return Ok(None);
    };
    match schema_version {
        "swarm-ai.miner-profile.v1" => serde_json::from_value(value)
            .map(MinerDocument::Profile)
            .map(Some)
            .with_context(|| format!("failed to parse miner profile {}", path.display())),
        "swarm-ai.miner-heartbeat.v1" => serde_json::from_value(value)
            .map(MinerDocument::Heartbeat)
            .map(Some)
            .with_context(|| format!("failed to parse miner heartbeat {}", path.display())),
        "swarm-ai.miner-benchmark-result.v1" => serde_json::from_value(value)
            .map(MinerDocument::Benchmark)
            .map(Some)
            .with_context(|| format!("failed to parse miner benchmark {}", path.display())),
        hivemind_marketplace::HARDWARE_RESOURCE_OFFER_SCHEMA_VERSION
        | hivemind_marketplace::LEGACY_HARDWARE_RESOURCE_OFFER_SCHEMA_VERSION => {
            serde_json::from_value(value)
                .map(MinerDocument::HardwareOffer)
                .map(Some)
                .with_context(|| {
                    format!("failed to parse hardware resource offer {}", path.display())
                })
        }
        _ => Ok(None),
    }
}

fn miner_profile_index_entry(
    profile: &MinerProfileV1,
    verification: &MinerProfileVerificationV1,
    path: String,
) -> MinerRecordSummaryV1 {
    MinerRecordSummaryV1 {
        record_id: profile.miner_id.clone(),
        record_type: MinerRecordType::Profile,
        miner_id: profile.miner_id.clone(),
        runner_id: profile.runner_id.clone(),
        operator: profile.operator.clone(),
        status: None,
        trust_tier: Some(profile.trust_tier.clone()),
        hardware_offer_id: Some(profile.hardware_offer_id.clone()),
        benchmark_suite: None,
        warning_count: verification.warnings.len(),
        valid: verification.valid,
        signature_present: profile.signature.is_some(),
        created_at: profile.created_at.clone(),
        path,
    }
}

fn miner_heartbeat_index_entry(
    heartbeat: &MinerHeartbeatV1,
    profile: Option<&MinerProfileV1>,
    verification: &MinerHeartbeatVerificationV1,
    path: String,
) -> MinerRecordSummaryV1 {
    MinerRecordSummaryV1 {
        record_id: heartbeat.heartbeat_id.clone(),
        record_type: MinerRecordType::Heartbeat,
        miner_id: heartbeat.miner_id.clone(),
        runner_id: heartbeat.runner_id.clone(),
        operator: profile
            .map(|profile| profile.operator.clone())
            .unwrap_or_default(),
        status: Some(heartbeat.status.clone()),
        trust_tier: profile.map(|profile| profile.trust_tier.clone()),
        hardware_offer_id: profile.map(|profile| profile.hardware_offer_id.clone()),
        benchmark_suite: None,
        warning_count: verification.warnings.len(),
        valid: verification.valid,
        signature_present: heartbeat.signature.is_some(),
        created_at: heartbeat.observed_at.clone(),
        path,
    }
}

fn miner_benchmark_index_entry(
    benchmark: &MinerBenchmarkResultV1,
    profile: Option<&MinerProfileV1>,
    verification: &MinerBenchmarkVerificationV1,
    path: String,
) -> MinerRecordSummaryV1 {
    MinerRecordSummaryV1 {
        record_id: benchmark.benchmark_id.clone(),
        record_type: MinerRecordType::Benchmark,
        miner_id: benchmark.miner_id.clone(),
        runner_id: benchmark.runner_id.clone(),
        operator: profile
            .map(|profile| profile.operator.clone())
            .unwrap_or_default(),
        status: None,
        trust_tier: profile.map(|profile| profile.trust_tier.clone()),
        hardware_offer_id: Some(benchmark.hardware_offer_id.clone()),
        benchmark_suite: Some(benchmark.benchmark_suite.clone()),
        warning_count: verification.warnings.len(),
        valid: verification.valid,
        signature_present: benchmark.signature.is_some(),
        created_at: benchmark.measured_at.clone(),
        path,
    }
}

fn profile_lookup(
    path: PathBuf,
    profile: MinerProfileV1,
    support: &MinerDocumentSupport,
) -> MinerRecordLookupV1 {
    let offer = support.offer_for_profile(&profile);
    let benchmarks = support.benchmarks_for_miner(&profile.miner_id);
    let heartbeat = support.latest_heartbeat_for_miner(&profile.miner_id);
    let profile_verification = verify_miner_profile(&profile, offer.as_ref());
    let onboarding_plan = offer
        .as_ref()
        .map(|offer| miner_onboarding_plan(&profile, offer, &benchmarks));
    let dashboard_summary = match (heartbeat.clone(), offer.clone()) {
        (Some(heartbeat), Some(offer)) => Some(miner_dashboard_summary(MinerDashboardInputV1 {
            profile: profile.clone(),
            heartbeat,
            hardware_offer: offer,
            benchmarks,
            completed_jobs: 0,
            settled_jobs: 0,
            disputed_jobs: 0,
            estimated_earnings: None,
        })),
        _ => None,
    };
    MinerRecordLookupV1 {
        schema_version: "swarm-ai.miner-record-lookup.v1".to_string(),
        record_id: profile.miner_id.clone(),
        record_type: MinerRecordType::Profile,
        path: path.display().to_string(),
        profile: Some(profile),
        heartbeat: None,
        benchmark: None,
        hardware_offer: offer,
        profile_verification: Some(profile_verification),
        heartbeat_verification: None,
        benchmark_verification: None,
        onboarding_plan,
        dashboard_summary,
    }
}

fn heartbeat_lookup(
    path: PathBuf,
    heartbeat: MinerHeartbeatV1,
    support: &MinerDocumentSupport,
) -> MinerRecordLookupV1 {
    let profile = support.profiles.get(&heartbeat.miner_id).cloned();
    let offer = profile
        .as_ref()
        .and_then(|profile| support.offer_for_profile(profile));
    let benchmarks = support.benchmarks_for_miner(&heartbeat.miner_id);
    let heartbeat_verification = verify_miner_heartbeat(&heartbeat, profile.as_ref());
    let dashboard_summary = match (profile.clone(), offer.clone()) {
        (Some(profile), Some(offer)) => Some(miner_dashboard_summary(MinerDashboardInputV1 {
            profile,
            heartbeat: heartbeat.clone(),
            hardware_offer: offer,
            benchmarks,
            completed_jobs: 0,
            settled_jobs: 0,
            disputed_jobs: 0,
            estimated_earnings: None,
        })),
        _ => None,
    };
    MinerRecordLookupV1 {
        schema_version: "swarm-ai.miner-record-lookup.v1".to_string(),
        record_id: heartbeat.heartbeat_id.clone(),
        record_type: MinerRecordType::Heartbeat,
        path: path.display().to_string(),
        profile,
        heartbeat: Some(heartbeat),
        benchmark: None,
        hardware_offer: offer,
        profile_verification: None,
        heartbeat_verification: Some(heartbeat_verification),
        benchmark_verification: None,
        onboarding_plan: None,
        dashboard_summary,
    }
}

fn benchmark_lookup(
    path: PathBuf,
    benchmark: MinerBenchmarkResultV1,
    support: &MinerDocumentSupport,
) -> MinerRecordLookupV1 {
    let profile = support.profiles.get(&benchmark.miner_id).cloned();
    let offer = support.offers.get(&benchmark.hardware_offer_id).cloned();
    let benchmarks = support.benchmarks_for_miner(&benchmark.miner_id);
    let benchmark_verification =
        verify_miner_benchmark_result(&benchmark, profile.as_ref(), offer.as_ref());
    let onboarding_plan = match (profile.as_ref(), offer.as_ref()) {
        (Some(profile), Some(offer)) => Some(miner_onboarding_plan(profile, offer, &benchmarks)),
        _ => None,
    };
    MinerRecordLookupV1 {
        schema_version: "swarm-ai.miner-record-lookup.v1".to_string(),
        record_id: benchmark.benchmark_id.clone(),
        record_type: MinerRecordType::Benchmark,
        path: path.display().to_string(),
        profile,
        heartbeat: None,
        benchmark: Some(benchmark),
        hardware_offer: offer,
        profile_verification: None,
        heartbeat_verification: None,
        benchmark_verification: Some(benchmark_verification),
        onboarding_plan,
        dashboard_summary: None,
    }
}

fn recommended_trust_tier(profile: &MinerProfileV1, benchmark_valid: bool) -> MinerTrustTierV1 {
    if !benchmark_valid {
        return MinerTrustTierV1::Open;
    }
    if profile
        .verification_tiers
        .contains(&IntegrityTier::ZkProofWhenSupported)
    {
        MinerTrustTierV1::Cryptographic
    } else if profile
        .verification_tiers
        .contains(&IntegrityTier::TeeAttested)
        || profile
            .privacy_tiers
            .contains(&PrivacyTier::TeeConfidential)
    {
        MinerTrustTierV1::Confidential
    } else if matches!(
        profile.trust_tier,
        MinerTrustTierV1::Verified
            | MinerTrustTierV1::Confidential
            | MinerTrustTierV1::Cryptographic
    ) {
        MinerTrustTierV1::Verified
    } else {
        profile.trust_tier.clone()
    }
}

fn compare_profile_to_offer(
    profile: &MinerProfileV1,
    offer: &HardwareResourceOfferV1,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if profile.hardware_offer_id != offer.offer_id {
        issues.push(issue(
            "$.hardwareOfferId",
            "Miner profile does not reference the supplied hardware offer",
        ));
    }
    if profile.runner_id != offer.runner_id {
        issues.push(issue(
            "$.runnerId",
            "Miner profile runnerId does not match supplied hardware offer",
        ));
    }
    if profile.operator != offer.operator {
        issues.push(issue(
            "$.operator",
            "Miner profile operator does not match supplied hardware offer",
        ));
    }
    if profile.hardware != offer.hardware {
        warnings.push(issue(
            "$.hardware",
            "Miner profile hardware differs from supplied hardware offer",
        ));
    }
    if profile.trust_tier != offer.trust_tier {
        warnings.push(issue(
            "$.trustTier",
            "Miner profile trust tier differs from supplied hardware offer",
        ));
    }
}

fn validate_hardware(
    hardware: &HardwareResourceV1,
    base: &str,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
) {
    if hardware.gpu_count == 0 && hardware.cpu_cores.unwrap_or(0) == 0 && hardware.ram_gb <= 0.0 {
        issues.push(issue(
            base,
            "Miner hardware must declare GPU, CPU, or RAM capacity",
        ));
    }
    if hardware.gpu_count > 0 && hardware.vram_gb.unwrap_or(0.0) <= 0.0 {
        warnings.push(issue(
            format!("{base}.vramGb"),
            "GPU miner should declare VRAM for routing and safety checks",
        ));
    }
    if hardware.ram_gb <= 0.0 {
        issues.push(issue(
            format!("{base}.ramGb"),
            "Miner RAM capacity must be greater than zero",
        ));
    }
}

fn validate_timestamp(issues: &mut Vec<ValidationIssue>, path: impl Into<String>, value: &str) {
    if DateTime::parse_from_rfc3339(value).is_err() {
        issues.push(issue(path, "Timestamp must be RFC3339"));
    }
}

fn step(
    order: u32,
    title: impl Into<String>,
    done: bool,
    evidence_refs: Vec<String>,
) -> MinerOnboardingStepV1 {
    MinerOnboardingStepV1 {
        order,
        title: title.into(),
        status: if done { "complete" } else { "pending" }.to_string(),
        evidence_refs,
    }
}

fn verify_signature(
    domain: &str,
    signing_value: &Value,
    signature: Option<&str>,
    expected_subject: Option<&str>,
    path: &str,
    issues: &mut Vec<ValidationIssue>,
    warnings: &mut Vec<ValidationIssue>,
    expected_signature: &mut Option<String>,
    mismatch_message: &str,
) {
    let signature = signature.map(str::trim).filter(|value| !value.is_empty());
    if let Some(signature) = signature {
        if signature.starts_with(hivemind_identity::COMPACT_SIGNATURE_PREFIX) {
            let verification = hivemind_identity::verify_value_signature_string(
                signature,
                domain,
                signing_value,
                expected_subject,
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
            issues.push(issue(path, mismatch_message));
        }
    } else {
        warnings.push(issue(
            path,
            "Object is unsigned; verify through a trusted source",
        ));
    }
}

fn miner_profile_signing_value(profile: &MinerProfileV1) -> Value {
    let mut value = json!(profile);
    value["minerId"] = json!("");
    value["signature"] = Value::Null;
    value
}

fn miner_heartbeat_signing_value(heartbeat: &MinerHeartbeatV1) -> Value {
    let mut value = json!(heartbeat);
    value["heartbeatId"] = json!("");
    value["signature"] = Value::Null;
    value
}

fn miner_benchmark_signing_value(result: &MinerBenchmarkResultV1) -> Value {
    let mut value = json!(result);
    value["benchmarkId"] = json!("");
    value["signature"] = Value::Null;
    value
}

fn stable_id(prefix: &str, value: &Value) -> String {
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(value))[..24]
    )
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn require_non_empty(issues: &mut Vec<ValidationIssue>, path: impl Into<String>, value: &str) {
    if value.trim().is_empty() {
        issues.push(issue(path, "Value is required"));
    }
}

fn signature_issue_path(path: &str) -> String {
    if path == "$" {
        "$.signature".to_string()
    } else {
        format!("$.signature{}", path.trim_start_matches('$'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_offer() -> HardwareResourceOfferV1 {
        hivemind_marketplace::default_hardware_resource_offer(
            &hivemind_remote_runner::default_descriptor(),
            "0xMiner",
        )
    }

    #[test]
    fn profile_round_trips_from_hardware_offer() {
        let offer = default_offer();
        let profile = miner_profile_from_hardware_offer(&offer, "0.1.0");
        let verification = verify_miner_profile(&profile, Some(&offer));
        assert!(verification.valid, "{verification:#?}");
        assert_eq!(profile.runner_id, offer.runner_id);
        assert_eq!(profile.hardware_offer_id, offer.offer_id);
        assert_eq!(
            Some(expected_miner_profile_signature(&profile).as_str()),
            profile.signature.as_deref()
        );
    }

    #[test]
    fn onboarding_requires_benchmark_for_sensitive_work() {
        let offer = default_offer();
        let mut profile = miner_profile_from_hardware_offer(&offer, "0.1.0");
        profile.trust_tier = MinerTrustTierV1::Verified;
        profile.privacy_tiers.push(PrivacyTier::NoLog);
        sign_miner_profile(&mut profile);
        let public_plan = miner_onboarding_plan(&profile, &offer, &[]);
        assert!(public_plan.eligible_for_public_jobs);
        assert!(!public_plan.eligible_for_sensitive_jobs);

        let benchmark = miner_benchmark_result(
            &profile,
            &offer,
            "local-miner-smoke",
            "chat-throughput",
            vec![MinerBenchmarkMetricV1 {
                name: "tokens_per_second".to_string(),
                value: 42.0,
                unit: "tokens/s".to_string(),
            }],
            vec!["bzz://benchmark-evidence".to_string()],
        );
        let sensitive_plan = miner_onboarding_plan(&profile, &offer, &[benchmark]);
        assert!(sensitive_plan.eligible_for_sensitive_jobs);
        assert_eq!(
            sensitive_plan.recommended_trust_tier,
            MinerTrustTierV1::Verified
        );
    }

    #[test]
    fn identity_signed_benchmark_detects_tampering() {
        let offer = default_offer();
        let mut profile = miner_profile_from_hardware_offer(&offer, "0.1.0");
        let identity = hivemind_identity::identity_from_seed("0xMiner", b"miner-seed").unwrap();
        sign_miner_profile_with_identity(&mut profile, &identity).unwrap();
        assert!(verify_miner_profile(&profile, Some(&offer)).valid);

        let mut benchmark = miner_benchmark_result(
            &profile,
            &offer,
            "validator-hidden-suite",
            "embedding-batch",
            vec![MinerBenchmarkMetricV1 {
                name: "items_per_second".to_string(),
                value: 12.5,
                unit: "items/s".to_string(),
            }],
            vec!["sha256://evidence".to_string()],
        );
        sign_miner_benchmark_result_with_identity(&mut benchmark, &identity, &profile).unwrap();
        assert!(verify_miner_benchmark_result(&benchmark, Some(&profile), Some(&offer)).valid);
        benchmark.metrics[0].value = 99_999.0;
        let tampered = verify_miner_benchmark_result(&benchmark, Some(&profile), Some(&offer));
        assert!(!tampered.valid);
        assert!(
            tampered
                .issues
                .iter()
                .any(|issue| issue.path.starts_with("$.signature"))
        );
    }

    #[test]
    fn miner_record_store_lists_and_gets_lifecycle_records() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "hivemind-miner-records-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(dir.join("nested")).unwrap();

        let offer = default_offer();
        let profile = miner_profile_from_hardware_offer(&offer, "0.1.0");
        let mut heartbeat = miner_heartbeat_from_profile(
            &profile,
            MinerDaemonStatus::Busy,
            2,
            1,
            vec!["job-1".to_string()],
            0.42,
        );
        heartbeat.available_ram_gb = profile.hardware.ram_gb / 2.0;
        heartbeat.available_vram_gb = profile.hardware.vram_gb.map(|vram_gb| vram_gb / 4.0);
        sign_miner_heartbeat(&mut heartbeat);
        let benchmark = miner_benchmark_result(
            &profile,
            &offer,
            "local-miner-smoke",
            "chat-throughput",
            vec![MinerBenchmarkMetricV1 {
                name: "tokens_per_second".to_string(),
                value: 42.0,
                unit: "tokens/s".to_string(),
            }],
            vec!["bzz://benchmark-evidence".to_string()],
        );

        fs::write(
            dir.join("hardware-offer.json"),
            serde_json::to_vec_pretty(&offer).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("profile.json"),
            serde_json::to_vec_pretty(&profile).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("nested").join("heartbeat.json"),
            serde_json::to_vec_pretty(&heartbeat).unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join("nested").join("benchmark.json"),
            serde_json::to_vec_pretty(&benchmark).unwrap(),
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

        let summary = list_miner_records(&dir).unwrap();

        assert_eq!(summary.profile_count, 1);
        assert_eq!(summary.heartbeat_count, 1);
        assert_eq!(summary.benchmark_count, 1);
        assert_eq!(summary.record_count, 3);
        assert_eq!(summary.valid_count, 3);
        assert_eq!(summary.busy_heartbeat_count, 1);
        assert_eq!(summary.memory_usage_sample_count, 1);
        assert_eq!(summary.average_memory_usage_ratio, Some(0.5));
        assert_eq!(summary.max_memory_usage_ratio, Some(0.5));
        assert_eq!(summary.vram_usage_sample_count, 1);
        assert_eq!(summary.average_vram_usage_ratio, Some(0.75));
        assert_eq!(summary.max_vram_usage_ratio, Some(0.75));

        let profile_lookup = get_miner_record(&dir, &profile.miner_id).unwrap().unwrap();
        assert_eq!(profile_lookup.record_type, MinerRecordType::Profile);
        assert!(profile_lookup.profile_verification.unwrap().valid);
        assert!(profile_lookup.hardware_offer.is_some());
        assert!(
            profile_lookup
                .onboarding_plan
                .unwrap()
                .eligible_for_public_jobs
        );
        assert_eq!(
            profile_lookup.dashboard_summary.unwrap().active_jobs,
            heartbeat.active_jobs
        );

        let heartbeat_lookup = get_miner_record(&dir, &heartbeat.heartbeat_id)
            .unwrap()
            .unwrap();
        assert_eq!(heartbeat_lookup.record_type, MinerRecordType::Heartbeat);
        assert!(heartbeat_lookup.heartbeat_verification.unwrap().valid);
        assert_eq!(
            heartbeat_lookup.dashboard_summary.unwrap().status,
            MinerDaemonStatus::Busy
        );

        let benchmark_lookup = get_miner_record(&dir, &benchmark.benchmark_id)
            .unwrap()
            .unwrap();
        assert_eq!(benchmark_lookup.record_type, MinerRecordType::Benchmark);
        assert!(benchmark_lookup.benchmark_verification.unwrap().valid);
        assert!(
            benchmark_lookup
                .onboarding_plan
                .unwrap()
                .eligible_for_sensitive_jobs
        );

        assert!(get_miner_record(&dir, "missing").unwrap().is_none());

        fs::remove_dir_all(dir).unwrap();
    }
}
