use crate::job::{ApiSurface, Modality, PriceV1};
use crate::manifest::{
    ArtifactGroup, LicenseInfo, PackageKind, PackageManifestV1, Publisher,
    artifact_group_v2_from_v1, modalities_from_capabilities, supported_apis_from_capabilities,
};
use crate::policy::{PolicyDecision, RiskLevel, evaluate_package_policy};
use crate::trust::{IntegrityTier, PrivacyTier};
use crate::{AccessGrantV1, AccessRevocationListV1};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryPackageRef {
    pub version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "manifestHash")]
    pub manifest_hash: String,
    #[serde(rename = "publishedAt")]
    pub published_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryPublisher {
    pub address: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "publisherProfileRef", default)]
    pub publisher_profile_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryTrust {
    #[serde(rename = "signatureVerified")]
    pub signature_verified: bool,
    #[serde(rename = "validatorScore", default)]
    pub validator_score: Option<f64>,
    #[serde(rename = "downloadCountApprox", default)]
    pub download_count_approx: u64,
    #[serde(default)]
    pub curated: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryBenchmarkScoreV1 {
    #[serde(rename = "benchmarkId")]
    pub benchmark_id: String,
    #[serde(rename = "benchmarkVersion")]
    pub benchmark_version: String,
    #[serde(rename = "evaluationId")]
    pub evaluation_id: String,
    pub quality: f64,
    pub latency: f64,
    pub overall: f64,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryMarketplaceListingSummaryV1 {
    #[serde(rename = "listingId")]
    pub listing_id: String,
    #[serde(rename = "listingType")]
    pub listing_type: String,
    pub owner: String,
    #[serde(
        rename = "packageRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub package_ref: Option<String>,
    #[serde(rename = "pricingMode")]
    pub pricing_mode: String,
    #[serde(rename = "priceHint", default, skip_serializing_if = "Option::is_none")]
    pub price_hint: Option<PriceV1>,
    pub status: String,
    #[serde(rename = "requiresLicense")]
    pub requires_license: bool,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
    #[serde(rename = "validationReportRefs", default)]
    pub validation_report_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryPermissionSummaryV1 {
    pub name: String,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryPolicySummaryV1 {
    #[serde(rename = "riskLevel")]
    pub risk_level: RiskLevel,
    pub decision: PolicyDecision,
    #[serde(rename = "permissionCount")]
    pub permission_count: usize,
    #[serde(rename = "codeExecution")]
    pub code_execution: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryEntryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub name: String,
    pub kind: PackageKind,
    #[serde(rename = "latestVersion")]
    pub latest_version: String,
    #[serde(rename = "stableVersion")]
    pub stable_version: String,
    #[serde(rename = "packageRefs")]
    pub package_refs: Vec<RegistryPackageRef>,
    pub publisher: RegistryPublisher,
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub modalities: Vec<Modality>,
    #[serde(rename = "supportedApis", default)]
    pub supported_apis: Vec<ApiSurface>,
    pub targets: Vec<String>,
    pub engines: Vec<String>,
    pub license: LicenseInfo,
    pub trust: RegistryTrust,
    #[serde(rename = "privacyTiers", default)]
    pub privacy_tiers: Vec<PrivacyTier>,
    #[serde(rename = "verificationTiers", default)]
    pub verification_tiers: Vec<IntegrityTier>,
    #[serde(rename = "browserRunnable", default)]
    pub browser_runnable: bool,
    #[serde(rename = "gpuRequired", default)]
    pub gpu_required: bool,
    #[serde(
        rename = "minMemoryMb",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub min_memory_mb: Option<u64>,
    #[serde(rename = "minVramMb", default, skip_serializing_if = "Option::is_none")]
    pub min_vram_mb: Option<u64>,
    #[serde(rename = "priceHint", default, skip_serializing_if = "Option::is_none")]
    pub price_hint: Option<PriceV1>,
    #[serde(
        rename = "marketplaceListings",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub marketplace_listings: Vec<RegistryMarketplaceListingSummaryV1>,
    #[serde(
        rename = "runnerOfferRefs",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub runner_offer_refs: Vec<String>,
    #[serde(
        rename = "hardwareResourceOfferRefs",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub hardware_resource_offer_refs: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<RegistryPermissionSummaryV1>,
    #[serde(rename = "policySummary", default = "default_policy_summary")]
    pub policy_summary: RegistryPolicySummaryV1,
    #[serde(rename = "benchmarkScores", default)]
    pub benchmark_scores: Vec<RegistryBenchmarkScoreV1>,
    #[serde(rename = "approxArtifactBytes")]
    pub approx_artifact_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistryQueryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(default)]
    pub kind: Option<PackageKind>,
    #[serde(default)]
    pub capability: Option<String>,
    #[serde(default)]
    pub modality: Option<Modality>,
    #[serde(rename = "apiSurface", default)]
    pub api_surface: Option<ApiSurface>,
    #[serde(default)]
    pub publisher: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub engine: Option<String>,
    #[serde(rename = "licenseType", default)]
    pub license_type: Option<String>,
    #[serde(rename = "privacyTier", default)]
    pub privacy_tier: Option<PrivacyTier>,
    #[serde(rename = "verificationTier", default)]
    pub verification_tier: Option<IntegrityTier>,
    #[serde(rename = "maxArtifactBytes", default)]
    pub max_artifact_bytes: Option<u64>,
    #[serde(rename = "minArtifactBytes", default)]
    pub min_artifact_bytes: Option<u64>,
    #[serde(rename = "browserRunnable", default)]
    pub browser_runnable: Option<bool>,
    #[serde(rename = "gpuRequired", default)]
    pub gpu_required: Option<bool>,
    #[serde(rename = "minValidatorScore", default)]
    pub min_validator_score: Option<f64>,
    #[serde(rename = "minBenchmarkScore", default)]
    pub min_benchmark_score: Option<f64>,
    #[serde(rename = "maxPrice", default)]
    pub max_price: Option<PriceV1>,
    #[serde(rename = "pageSize", default = "default_page_size")]
    pub page_size: usize,
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub requester: Option<String>,
    #[serde(rename = "requestedUse", default)]
    pub requested_use: Option<String>,
    #[serde(rename = "runnerId", default)]
    pub runner_id: Option<String>,
    #[serde(rename = "accessGrant", default)]
    pub access_grant: Option<AccessGrantV1>,
    #[serde(rename = "accessRevocationList", default)]
    pub access_revocation_list: Option<AccessRevocationListV1>,
}

fn default_page_size() -> usize {
    20
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RegistrySearchResponse {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub entries: Vec<RegistryEntryV1>,
    #[serde(rename = "nextCursor", default)]
    pub next_cursor: Option<String>,
    #[serde(rename = "totalApprox")]
    pub total_approx: usize,
}

impl RegistryEntryV1 {
    pub fn from_manifest(
        manifest: &PackageManifestV1,
        package_ref: impl Into<String>,
        manifest_hash: impl Into<String>,
        published_at: impl Into<String>,
    ) -> Self {
        let targets = unique(
            manifest
                .artifact_groups
                .iter()
                .map(|group| group.target.clone())
                .collect(),
        );
        let engines = unique(
            manifest
                .artifact_groups
                .iter()
                .map(|group| group.engine.clone())
                .collect(),
        );
        let approx_artifact_bytes = manifest
            .artifact_groups
            .iter()
            .map(|group| group.total_bytes)
            .sum();
        let package_ref = package_ref.into();
        let policy = evaluate_package_policy(manifest, package_ref.clone(), None);
        let artifact_v2: Vec<_> = manifest
            .artifact_groups
            .iter()
            .map(|group| artifact_group_v2_from_v1(&manifest.package_id, group))
            .collect();
        let min_memory_mb = artifact_v2
            .iter()
            .filter_map(|artifact| artifact.required_memory_mb)
            .min();
        let min_vram_mb = artifact_v2
            .iter()
            .filter_map(|artifact| artifact.required_vram_mb)
            .min();
        let browser_runnable = manifest
            .artifact_groups
            .iter()
            .any(artifact_group_is_browser_runnable);
        let gpu_required = min_vram_mb.is_some();

        Self {
            schema_version: "swarm-ai.registry.entry.v1".to_string(),
            package_id: manifest.package_id.clone(),
            name: manifest.name.clone(),
            kind: manifest.kind.clone(),
            latest_version: manifest.version.clone(),
            stable_version: manifest.version.clone(),
            package_refs: vec![RegistryPackageRef {
                version: manifest.version.clone(),
                package_ref,
                manifest_hash: manifest_hash.into(),
                published_at: published_at.into(),
            }],
            publisher: RegistryPublisher::from(&manifest.publisher),
            capabilities: manifest.capabilities.clone(),
            modalities: modalities_from_capabilities(&manifest.capabilities),
            supported_apis: supported_apis_from_capabilities(&manifest.capabilities),
            targets,
            engines,
            license: manifest.license.clone(),
            trust: RegistryTrust {
                signature_verified: false,
                validator_score: Some(0.80),
                download_count_approx: 0,
                curated: false,
            },
            privacy_tiers: registry_privacy_tiers(manifest, browser_runnable),
            verification_tiers: vec![IntegrityTier::ReceiptOnly],
            browser_runnable,
            gpu_required,
            min_memory_mb,
            min_vram_mb,
            price_hint: None,
            marketplace_listings: Vec::new(),
            runner_offer_refs: Vec::new(),
            hardware_resource_offer_refs: Vec::new(),
            permissions: manifest
                .permissions
                .iter()
                .map(|permission| RegistryPermissionSummaryV1 {
                    name: permission.name.clone(),
                    required: permission.required,
                })
                .collect(),
            policy_summary: RegistryPolicySummaryV1 {
                risk_level: policy.risk_level,
                decision: policy.decision,
                permission_count: manifest.permissions.len(),
                code_execution: registry_code_execution(manifest),
                reasons: policy.reasons,
            },
            benchmark_scores: Vec::new(),
            approx_artifact_bytes,
        }
    }
}

impl From<&Publisher> for RegistryPublisher {
    fn from(value: &Publisher) -> Self {
        Self {
            address: value.address.clone(),
            display_name: value.display_name.clone(),
            publisher_profile_ref: value.publisher_profile_ref.clone(),
        }
    }
}

fn artifact_group_is_browser_runnable(group: &ArtifactGroup) -> bool {
    let target = group.target.to_ascii_lowercase();
    let engine = group.engine.to_ascii_lowercase();
    target.contains("browser")
        || target.contains("wasm")
        || engine.contains("wasm")
        || engine.contains("webgpu")
}

fn registry_privacy_tiers(
    manifest: &PackageManifestV1,
    browser_runnable: bool,
) -> Vec<PrivacyTier> {
    let mut tiers = vec![PrivacyTier::Standard];
    if browser_runnable
        || manifest.artifact_groups.iter().any(|group| {
            let target = group.target.to_ascii_lowercase();
            target.contains("local") || target.contains("desktop")
        })
    {
        push_unique(&mut tiers, PrivacyTier::LocalOnly);
    }
    if manifest.permissions.is_empty() {
        push_unique(&mut tiers, PrivacyTier::NoLog);
        push_unique(&mut tiers, PrivacyTier::RedactedInput);
    }
    if manifest.artifact_groups.iter().any(|group| {
        let target = group.target.to_ascii_lowercase();
        let engine = group.engine.to_ascii_lowercase();
        target.contains("tee") || engine.contains("tee") || engine.contains("sgx")
    }) {
        push_unique(&mut tiers, PrivacyTier::TeeConfidential);
    }
    tiers
}

fn unique(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items.dedup();
    items
}

fn push_unique<T: PartialEq>(items: &mut Vec<T>, value: T) {
    if !items.contains(&value) {
        items.push(value);
    }
}

fn registry_code_execution(manifest: &PackageManifestV1) -> String {
    if manifest
        .permissions
        .iter()
        .any(|permission| matches!(permission.name.as_str(), "local.shell" | "local.docker"))
    {
        return "unsandboxed-required".to_string();
    }
    if manifest.artifact_groups.iter().any(|group| {
        matches!(
            group.format.as_str(),
            "wasm" | "binary" | "container" | "python"
        )
    }) {
        return "sandboxed".to_string();
    }
    "none".to_string()
}

fn default_policy_summary() -> RegistryPolicySummaryV1 {
    RegistryPolicySummaryV1 {
        risk_level: RiskLevel::Low,
        decision: PolicyDecision::Allow,
        permission_count: 0,
        code_execution: "none".to_string(),
        reasons: vec!["Package requests no elevated permissions".to_string()],
    }
}
