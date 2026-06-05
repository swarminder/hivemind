use crate::canonical::{canonicalize_json, hash_canonical_json};
use crate::job::{ApiSurface, Modality};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PackageKind {
    Model,
    Agent,
    Tool,
    #[serde(rename = "tool_pack")]
    ToolPack,
    Dataset,
    Benchmark,
    Workflow,
    Service,
    #[serde(rename = "service_descriptor")]
    ServiceDescriptor,
    #[serde(rename = "vector_index")]
    VectorIndex,
    #[serde(rename = "rag_pipeline")]
    RagPipeline,
    #[serde(rename = "embedding_service")]
    EmbeddingService,
    #[serde(rename = "reranker_service")]
    RerankerService,
    #[serde(rename = "image_generation_service")]
    ImageGenerationService,
    #[serde(rename = "image_understanding_service")]
    ImageUnderstandingService,
    #[serde(rename = "speech_to_text_service")]
    SpeechToTextService,
    #[serde(rename = "text_to_speech_service")]
    TextToSpeechService,
    #[serde(rename = "realtime_session_service")]
    RealtimeSessionService,
    #[serde(rename = "service_adapter")]
    ServiceAdapter,
    #[serde(rename = "research_experiment")]
    ResearchExperiment,
    #[serde(rename = "eval_suite")]
    EvalSuite,
    #[serde(rename = "prompt_pack")]
    PromptPack,
    #[serde(rename = "adapter_or_lora")]
    AdapterOrLora,
    #[serde(rename = "fine_tune_recipe")]
    FineTuneRecipe,
    #[serde(rename = "scoring_method")]
    ScoringMethod,
    #[serde(rename = "safety_policy")]
    SafetyPolicy,
    #[serde(rename = "moderation_policy")]
    ModerationPolicy,
    #[serde(rename = "synthetic_data_recipe")]
    SyntheticDataRecipe,
    #[serde(rename = "privacy_method")]
    PrivacyMethod,
    #[serde(rename = "proof_method")]
    ProofMethod,
    #[serde(rename = "hardware_benchmark")]
    HardwareBenchmark,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum LicenseType {
    Open,
    Commercial,
    Private,
    TokenGated,
    Subscription,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LicenseInfo {
    #[serde(rename = "type")]
    pub license_type: LicenseType,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Publisher {
    pub address: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "publisherProfileRef", default)]
    pub publisher_profile_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactMinimum {
    #[serde(rename = "memoryMB", default)]
    pub memory_mb: Option<u64>,
    #[serde(default)]
    pub webgpu: Option<bool>,
    #[serde(rename = "diskMB", default)]
    pub disk_mb: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactGroup {
    pub id: String,
    pub target: String,
    pub engine: String,
    pub format: String,
    pub paths: Vec<String>,
    #[serde(rename = "totalBytes")]
    pub total_bytes: u64,
    pub sha256: String,
    pub minimum: ArtifactMinimum,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PermissionRequest {
    pub name: String,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default = "empty_limits")]
    pub limits: Value,
}

fn empty_limits() -> Value {
    json!({})
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PackageManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub kind: PackageKind,
    pub name: String,
    pub version: String,
    pub publisher: Publisher,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(rename = "artifactGroups")]
    pub artifact_groups: Vec<ArtifactGroup>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(rename = "outputSchema")]
    pub output_schema: Value,
    #[serde(default)]
    pub permissions: Vec<PermissionRequest>,
    pub license: LicenseInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactGroupV2 {
    #[serde(rename = "artifactGroupId")]
    pub artifact_group_id: String,
    pub target: String,
    pub engine: String,
    #[serde(rename = "modelFormat")]
    pub model_format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantization: Option<String>,
    pub files: Vec<String>,
    #[serde(rename = "totalBytes")]
    pub total_bytes: u64,
    pub hashes: BTreeMap<String, String>,
    #[serde(
        rename = "requiredMemoryMb",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub required_memory_mb: Option<u64>,
    #[serde(
        rename = "requiredVramMb",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub required_vram_mb: Option<u64>,
    #[serde(rename = "preferredRunners")]
    pub preferred_runners: Vec<String>,
    #[serde(rename = "fallbackGroups")]
    pub fallback_groups: Vec<String>,
    #[serde(rename = "cacheKey")]
    pub cache_key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct PackageManifestV2Context {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub modalities: Vec<Modality>,
    #[serde(rename = "supportedApis", default)]
    pub supported_apis: Vec<ApiSurface>,
    #[serde(default)]
    pub runtimes: Vec<String>,
    #[serde(rename = "accessPolicy", default)]
    pub access_policy: Value,
    #[serde(default)]
    pub safety: Value,
    #[serde(rename = "validationSuites", default)]
    pub validation_suites: Vec<String>,
    #[serde(default)]
    pub reproducibility: Value,
    #[serde(default)]
    pub lineage: Value,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PackageManifestV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub namespace: String,
    pub name: String,
    pub kind: PackageKind,
    pub publisher: Publisher,
    pub version: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub description: String,
    pub tags: Vec<String>,
    pub modalities: Vec<Modality>,
    pub capabilities: Vec<String>,
    #[serde(rename = "supportedApis")]
    pub supported_apis: Vec<ApiSurface>,
    pub artifacts: Vec<ArtifactGroupV2>,
    pub runtimes: Vec<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(rename = "outputSchema")]
    pub output_schema: Value,
    pub permissions: Vec<PermissionRequest>,
    #[serde(rename = "accessPolicy")]
    pub access_policy: Value,
    pub license: LicenseInfo,
    pub safety: Value,
    #[serde(rename = "validationSuites")]
    pub validation_suites: Vec<String>,
    pub reproducibility: Value,
    pub lineage: Value,
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UniversalCapabilityV1 {
    #[serde(rename = "capabilityId")]
    pub capability_id: String,
    #[serde(default)]
    pub modalities: Vec<String>,
    pub operation: String,
    #[serde(
        rename = "inputContractRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub input_contract_ref: Option<String>,
    #[serde(
        rename = "outputContractRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_contract_ref: Option<String>,
    #[serde(rename = "supportedApiSurfaces", default)]
    pub supported_api_surfaces: Vec<String>,
    #[serde(rename = "supportedStreamingEvents", default)]
    pub supported_streaming_events: Vec<String>,
    #[serde(rename = "runtimeClasses", default)]
    pub runtime_classes: Vec<String>,
    #[serde(rename = "privacyClasses", default)]
    pub privacy_classes: Vec<String>,
    #[serde(rename = "validationClasses", default)]
    pub validation_classes: Vec<String>,
    #[serde(rename = "costHints", default)]
    pub cost_hints: Value,
    #[serde(rename = "latencyHints", default)]
    pub latency_hints: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AssetRoleV1 {
    ModelWeights,
    Tokenizer,
    Config,
    Prompt,
    Tool,
    Dataset,
    Document,
    VectorIndex,
    Benchmark,
    Receipt,
    Report,
    Media,
    Custom,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AssetDescriptorV1 {
    #[serde(rename = "assetId")]
    pub asset_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<AssetRoleV1>,
    #[serde(rename = "assetClass")]
    pub asset_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(rename = "storageRefs", default)]
    pub storage_refs: Vec<String>,
    #[serde(rename = "byteSize", default, skip_serializing_if = "Option::is_none")]
    pub byte_size: Option<u64>,
    #[serde(
        rename = "contentType",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(
        rename = "contentHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub content_hash: Option<String>,
    #[serde(rename = "mimeType", default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modality: Option<String>,
    #[serde(rename = "mediaMetadata", default)]
    pub media_metadata: Value,
    #[serde(default)]
    pub encryption: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<LicenseInfo>,
    #[serde(rename = "accessPolicy", default)]
    pub access_policy: Value,
    #[serde(
        rename = "accessPolicyRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub access_policy_ref: Option<String>,
    #[serde(rename = "cachePolicy", default)]
    pub cache_policy: Value,
    #[serde(rename = "retentionPolicy", default)]
    pub retention_policy: Value,
    #[serde(
        rename = "sensitivityLabel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sensitivity_label: Option<String>,
    #[serde(rename = "createdBy", default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserPublishProfileV1 {
    #[serde(rename = "allowedBrowserPublish")]
    pub allowed_browser_publish: bool,
    #[serde(
        rename = "maxBrowserUploadBytes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_browser_upload_bytes: Option<u64>,
    #[serde(rename = "requiresWalletStoragePurchase")]
    pub requires_wallet_storage_purchase: bool,
    #[serde(
        rename = "recommendedChunking",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub recommended_chunking: Option<String>,
    #[serde(rename = "resumableUploadRequired")]
    pub resumable_upload_required: bool,
    #[serde(rename = "feedUpdateAllowed")]
    pub feed_update_allowed: bool,
    #[serde(rename = "allowedOrigins", default)]
    pub allowed_origins: Vec<String>,
    #[serde(rename = "supportedProviderKinds", default)]
    pub supported_provider_kinds: Vec<String>,
    #[serde(rename = "browserSecurityWarnings", default)]
    pub browser_security_warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct PackageManifestV3Context {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(rename = "browserPublishProfile", default)]
    pub browser_publish_profile: Option<BrowserPublishProfileV1>,
    #[serde(default)]
    pub assets: Vec<AssetDescriptorV1>,
    #[serde(default)]
    pub capabilities: Vec<UniversalCapabilityV1>,
    #[serde(rename = "accessPolicy", default)]
    pub access_policy: Value,
    #[serde(default)]
    pub safety: Value,
    #[serde(rename = "validationSuites", default)]
    pub validation_suites: Vec<String>,
    #[serde(default)]
    pub reproducibility: Value,
    #[serde(default)]
    pub lineage: Value,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PackageManifestV3 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub namespace: String,
    pub name: String,
    pub kind: PackageKind,
    pub publisher: Publisher,
    pub version: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub description: String,
    pub tags: Vec<String>,
    pub capabilities: Vec<UniversalCapabilityV1>,
    pub assets: Vec<AssetDescriptorV1>,
    #[serde(rename = "artifactGroups")]
    pub artifact_groups: Vec<ArtifactGroupV2>,
    pub runtimes: Vec<String>,
    #[serde(rename = "inputContracts")]
    pub input_contracts: Vec<Value>,
    #[serde(rename = "outputContracts")]
    pub output_contracts: Vec<Value>,
    pub permissions: Vec<PermissionRequest>,
    #[serde(rename = "accessPolicy")]
    pub access_policy: Value,
    pub license: LicenseInfo,
    pub safety: Value,
    #[serde(rename = "validationSuites")]
    pub validation_suites: Vec<String>,
    pub reproducibility: Value,
    pub lineage: Value,
    #[serde(
        rename = "browserPublishProfile",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub browser_publish_profile: Option<BrowserPublishProfileV1>,
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeDescriptorV2 {
    #[serde(rename = "runtimeId")]
    pub runtime_id: String,
    #[serde(rename = "runtimeClass")]
    pub runtime_class: String,
    pub target: String,
    pub engine: String,
    #[serde(rename = "modelFormat")]
    pub model_format: String,
    #[serde(rename = "assetRefs", default)]
    pub asset_refs: Vec<String>,
    #[serde(
        rename = "requiredMemoryMb",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub required_memory_mb: Option<u64>,
    #[serde(
        rename = "requiredVramMb",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub required_vram_mb: Option<u64>,
    #[serde(rename = "requiresWebGpu", default)]
    pub requires_web_gpu: bool,
    #[serde(rename = "supportedApiSurfaces", default)]
    pub supported_api_surfaces: Vec<String>,
    #[serde(rename = "supportedModalities", default)]
    pub supported_modalities: Vec<String>,
    #[serde(rename = "privacyTiers", default)]
    pub privacy_tiers: Vec<String>,
    #[serde(rename = "verificationTiers", default)]
    pub verification_tiers: Vec<String>,
    #[serde(rename = "executionHints", default)]
    pub execution_hints: Value,
    #[serde(rename = "cachePolicy", default)]
    pub cache_policy: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilitySetV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub capabilities: Vec<UniversalCapabilityV1>,
    #[serde(rename = "supportedApiSurfaces", default)]
    pub supported_api_surfaces: Vec<String>,
    #[serde(default)]
    pub modalities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyRefV1 {
    #[serde(rename = "policyId")]
    pub policy_id: String,
    #[serde(rename = "policyKind")]
    pub policy_kind: String,
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inline: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceRecordV1 {
    #[serde(rename = "recordId")]
    pub record_id: String,
    pub source: String,
    pub publisher: Publisher,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "sourceSchemaVersion", default)]
    pub source_schema_version: Option<String>,
    #[serde(rename = "sourceManifestHash", default)]
    pub source_manifest_hash: Option<String>,
    #[serde(rename = "evidenceRefs", default)]
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct PackageManifestV4Context {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default)]
    pub assets: Vec<AssetDescriptorV1>,
    #[serde(default)]
    pub capabilities: Vec<UniversalCapabilityV1>,
    #[serde(default)]
    pub runtimes: Vec<RuntimeDescriptorV2>,
    #[serde(rename = "accessPolicy", default)]
    pub access_policy: Value,
    #[serde(rename = "storagePolicy", default)]
    pub storage_policy: Value,
    #[serde(rename = "safetyPolicy", default)]
    pub safety_policy: Value,
    #[serde(default)]
    pub provenance: Vec<ProvenanceRecordV1>,
    #[serde(rename = "browserPublishProfile", default)]
    pub browser_publish_profile: Option<BrowserPublishProfileV1>,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PackageManifestV4 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    pub namespace: String,
    pub name: String,
    #[serde(rename = "packageKind")]
    pub package_kind: PackageKind,
    pub version: String,
    pub publisher: Publisher,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub summary: String,
    pub assets: Vec<AssetDescriptorV1>,
    pub capabilities: Vec<UniversalCapabilityV1>,
    pub runtimes: Vec<RuntimeDescriptorV2>,
    #[serde(rename = "inputSchemas")]
    pub input_schemas: BTreeMap<String, Value>,
    #[serde(rename = "outputSchemas")]
    pub output_schemas: BTreeMap<String, Value>,
    pub license: LicenseInfo,
    #[serde(rename = "accessPolicy")]
    pub access_policy: Value,
    #[serde(rename = "storagePolicy")]
    pub storage_policy: Value,
    #[serde(rename = "safetyPolicy")]
    pub safety_policy: Value,
    pub provenance: Vec<ProvenanceRecordV1>,
    #[serde(
        rename = "browserPublishProfile",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub browser_publish_profile: Option<BrowserPublishProfileV1>,
    #[serde(default)]
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PackageIndexSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageKind")]
    pub package_kind: PackageKind,
    pub version: String,
    pub publisher: Publisher,
    pub summary: String,
    #[serde(rename = "capabilityIds")]
    pub capability_ids: Vec<String>,
    #[serde(rename = "runtimeClasses")]
    pub runtime_classes: Vec<String>,
    #[serde(rename = "assetCount")]
    pub asset_count: usize,
    #[serde(rename = "totalAssetBytes")]
    pub total_asset_bytes: u64,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

pub fn manifest_supports_capability(manifest: &PackageManifestV1, capability: &str) -> bool {
    manifest
        .capabilities
        .iter()
        .any(|declared| declared == capability)
}

pub fn package_manifest_v2_from_v1(manifest: &PackageManifestV1) -> PackageManifestV2 {
    package_manifest_v2_from_v1_with_context(manifest, PackageManifestV2Context::default())
}

pub fn package_manifest_v2_from_v1_with_context(
    manifest: &PackageManifestV1,
    context: PackageManifestV2Context,
) -> PackageManifestV2 {
    let namespace = context
        .namespace
        .unwrap_or_else(|| namespace_from_package_id(&manifest.package_id));
    let mut tags = context.tags;
    tags.extend(manifest.capabilities.iter().cloned());
    tags.push(package_kind_tag(&manifest.kind));
    tags.sort();
    tags.dedup();

    let mut modalities = context.modalities;
    modalities.extend(modalities_from_capabilities(&manifest.capabilities));
    modalities = dedup_modalities(modalities);

    let mut supported_apis = context.supported_apis;
    supported_apis.extend(supported_apis_from_capabilities(&manifest.capabilities));
    supported_apis = dedup_apis(supported_apis);

    let mut runtimes = context.runtimes;
    runtimes.extend(
        manifest
            .artifact_groups
            .iter()
            .map(|group| format!("{}:{}", group.target, group.engine)),
    );
    runtimes.sort();
    runtimes.dedup();

    PackageManifestV2 {
        schema_version: "hivemind.package.v2".to_string(),
        package_id: manifest.package_id.clone(),
        namespace,
        name: manifest.name.clone(),
        kind: manifest.kind.clone(),
        publisher: manifest.publisher.clone(),
        version: manifest.version.clone(),
        created_at: context
            .created_at
            .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string()),
        description: context.description.unwrap_or_else(|| manifest.name.clone()),
        tags,
        modalities,
        capabilities: manifest.capabilities.clone(),
        supported_apis,
        artifacts: manifest
            .artifact_groups
            .iter()
            .map(|group| artifact_group_v2_from_v1(&manifest.package_id, group))
            .collect(),
        runtimes,
        input_schema: manifest.input_schema.clone(),
        output_schema: manifest.output_schema.clone(),
        permissions: manifest.permissions.clone(),
        access_policy: default_if_null(context.access_policy, json!({ "type": "license" })),
        license: manifest.license.clone(),
        safety: default_if_null(context.safety, json!({ "status": "unspecified" })),
        validation_suites: context.validation_suites,
        reproducibility: default_if_null(
            context.reproducibility,
            json!({
                "artifactHashesRequired": true,
                "largeDataReferenced": true
            }),
        ),
        lineage: default_if_null(context.lineage, json!({})),
        signatures: context.signatures,
    }
}

pub fn package_manifest_v3_from_v1(manifest: &PackageManifestV1) -> PackageManifestV3 {
    package_manifest_v3_from_v1_with_context(manifest, PackageManifestV3Context::default())
}

pub fn package_manifest_v3_from_v1_with_context(
    manifest: &PackageManifestV1,
    context: PackageManifestV3Context,
) -> PackageManifestV3 {
    let manifest_v2 = package_manifest_v2_from_v1_with_context(
        manifest,
        PackageManifestV2Context {
            namespace: context.namespace.clone(),
            created_at: context.created_at.clone(),
            description: context.description.clone(),
            tags: context.tags.clone(),
            access_policy: context.access_policy.clone(),
            safety: context.safety.clone(),
            validation_suites: context.validation_suites.clone(),
            reproducibility: context.reproducibility.clone(),
            lineage: context.lineage.clone(),
            signatures: context.signatures.clone(),
            ..Default::default()
        },
    );
    let mut capabilities = context.capabilities;
    capabilities.extend(universal_capabilities_from_manifest_v1(manifest));
    capabilities = dedup_universal_capabilities(capabilities);

    let mut assets = context.assets;
    assets.extend(asset_descriptors_from_manifest_v1(manifest));
    assets = dedup_asset_descriptors(assets);

    PackageManifestV3 {
        schema_version: "hivemind.package.v3".to_string(),
        package_id: manifest_v2.package_id,
        namespace: manifest_v2.namespace,
        name: manifest_v2.name,
        kind: manifest_v2.kind,
        publisher: manifest_v2.publisher,
        version: manifest_v2.version,
        created_at: manifest_v2.created_at,
        description: manifest_v2.description,
        tags: manifest_v2.tags,
        capabilities,
        assets,
        artifact_groups: manifest_v2.artifacts,
        runtimes: manifest_v2.runtimes,
        input_contracts: vec![json!({
            "contractId": "default-input",
            "contractRef": format!("local://package/{}/input-schema", manifest.package_id),
            "schema": manifest.input_schema.clone()
        })],
        output_contracts: vec![json!({
            "contractId": "default-output",
            "contractRef": format!("local://package/{}/output-schema", manifest.package_id),
            "schema": manifest.output_schema.clone()
        })],
        permissions: manifest_v2.permissions,
        access_policy: manifest_v2.access_policy,
        license: manifest_v2.license,
        safety: manifest_v2.safety,
        validation_suites: manifest_v2.validation_suites,
        reproducibility: manifest_v2.reproducibility,
        lineage: manifest_v2.lineage,
        browser_publish_profile: context
            .browser_publish_profile
            .or_else(|| default_browser_publish_profile(manifest)),
        signatures: manifest_v2.signatures,
    }
}

pub fn package_manifest_v4_from_v1(manifest: &PackageManifestV1) -> PackageManifestV4 {
    package_manifest_v4_from_v1_with_context(manifest, PackageManifestV4Context::default())
}

pub fn package_manifest_v4_from_v1_with_context(
    manifest: &PackageManifestV1,
    context: PackageManifestV4Context,
) -> PackageManifestV4 {
    let created_at = context
        .created_at
        .clone()
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());
    let namespace = context
        .namespace
        .clone()
        .unwrap_or_else(|| namespace_from_package_id(&manifest.package_id));
    let mut capabilities = context.capabilities;
    capabilities.extend(universal_capabilities_from_manifest_v1(manifest));
    capabilities = dedup_universal_capabilities(capabilities);

    let mut assets = context.assets;
    assets.extend(asset_descriptors_from_manifest_v1(manifest));
    assets = dedup_asset_descriptors(assets);

    let mut runtimes = context.runtimes;
    runtimes.extend(runtime_descriptors_from_manifest_v1(
        manifest,
        &capabilities,
        &assets,
    ));
    runtimes = dedup_runtime_descriptors(runtimes);

    let mut input_schemas = BTreeMap::new();
    input_schemas.insert("default".to_string(), manifest.input_schema.clone());
    let mut output_schemas = BTreeMap::new();
    output_schemas.insert("default".to_string(), manifest.output_schema.clone());

    let browser_publish_profile = context
        .browser_publish_profile
        .or_else(|| default_browser_publish_profile(manifest));
    let storage_policy = default_if_null(
        context.storage_policy,
        storage_policy_for_manifest(manifest, browser_publish_profile.as_ref()),
    );
    let mut provenance = context.provenance;
    if provenance.is_empty() {
        provenance.push(default_provenance_record(
            manifest,
            &created_at,
            "PackageManifestV1 projection",
        ));
    }

    PackageManifestV4 {
        schema_version: "hivemind.package_manifest.v4".to_string(),
        object_kind: "package_manifest".to_string(),
        package_id: manifest.package_id.clone(),
        namespace,
        name: manifest.name.clone(),
        package_kind: manifest.kind.clone(),
        version: manifest.version.clone(),
        publisher: manifest.publisher.clone(),
        created_at,
        summary: context.summary.unwrap_or_else(|| manifest.name.clone()),
        assets,
        capabilities,
        runtimes,
        input_schemas,
        output_schemas,
        license: manifest.license.clone(),
        access_policy: default_if_null(context.access_policy, json!({ "type": "license" })),
        storage_policy,
        safety_policy: default_if_null(
            context.safety_policy,
            json!({
                "status": "unspecified",
                "requiresReviewForProductionListing": true,
                "permissionsAreExplicit": !manifest.permissions.is_empty()
            }),
        ),
        provenance,
        browser_publish_profile,
        signatures: context.signatures,
    }
}

pub fn capability_set_from_manifest_v4(manifest: &PackageManifestV4) -> CapabilitySetV1 {
    let mut supported_api_surfaces = BTreeSet::new();
    let mut modalities = BTreeSet::new();
    for capability in &manifest.capabilities {
        supported_api_surfaces.extend(capability.supported_api_surfaces.iter().cloned());
        modalities.extend(capability.modalities.iter().cloned());
    }
    CapabilitySetV1 {
        schema_version: "hivemind.capability_set.v1".to_string(),
        package_id: manifest.package_id.clone(),
        capabilities: manifest.capabilities.clone(),
        supported_api_surfaces: supported_api_surfaces.into_iter().collect(),
        modalities: modalities.into_iter().collect(),
    }
}

pub fn package_index_summary_from_manifest_v4(
    manifest: &PackageManifestV4,
) -> PackageIndexSummaryV1 {
    let mut runtime_classes = BTreeSet::new();
    for runtime in &manifest.runtimes {
        runtime_classes.insert(runtime.runtime_class.clone());
    }
    PackageIndexSummaryV1 {
        schema_version: "hivemind.package_index_summary.v1".to_string(),
        package_id: manifest.package_id.clone(),
        package_kind: manifest.package_kind.clone(),
        version: manifest.version.clone(),
        publisher: manifest.publisher.clone(),
        summary: manifest.summary.clone(),
        capability_ids: manifest
            .capabilities
            .iter()
            .map(|capability| capability.capability_id.clone())
            .collect(),
        runtime_classes: runtime_classes.into_iter().collect(),
        asset_count: manifest.assets.len(),
        total_asset_bytes: manifest
            .assets
            .iter()
            .filter_map(|asset| asset.byte_size)
            .sum(),
        created_at: manifest.created_at.clone(),
    }
}

pub fn universal_capabilities_from_manifest_v1(
    manifest: &PackageManifestV1,
) -> Vec<UniversalCapabilityV1> {
    let mut capabilities = Vec::new();
    for capability in &manifest.capabilities {
        capabilities.push(universal_capability_from_legacy_capability(
            manifest, capability,
        ));
    }
    if capabilities.is_empty() {
        capabilities.push(universal_capability_from_legacy_capability(
            manifest,
            &package_kind_tag(&manifest.kind),
        ));
    }
    dedup_universal_capabilities(capabilities)
}

pub fn asset_descriptors_from_manifest_v1(manifest: &PackageManifestV1) -> Vec<AssetDescriptorV1> {
    manifest
        .artifact_groups
        .iter()
        .map(|artifact| AssetDescriptorV1 {
            asset_id: format!("artifact-{}", slug_component(&artifact.id)),
            role: Some(asset_role_for_package_kind(&manifest.kind)),
            asset_class: asset_class_for_package_kind(&manifest.kind).to_string(),
            path: artifact.paths.first().cloned(),
            reference: artifact
                .paths
                .first()
                .map(|path| format!("package://{}/{}", manifest.package_id, path)),
            storage_refs: artifact
                .paths
                .iter()
                .map(|path| format!("package://{}/{}", manifest.package_id, path))
                .collect(),
            byte_size: Some(artifact.total_bytes),
            content_type: Some(content_type_for_artifact_format(&artifact.format).to_string()),
            hash: Some(format!("sha256:{}", artifact.sha256)),
            content_hash: Some(format!("sha256:{}", artifact.sha256)),
            mime_type: Some(content_type_for_artifact_format(&artifact.format).to_string()),
            modality: primary_modality_for_manifest(manifest),
            media_metadata: json!({
                "artifactGroupId": artifact.id,
                "target": artifact.target,
                "engine": artifact.engine,
                "format": artifact.format,
                "paths": artifact.paths
            }),
            encryption: json!({ "mode": "none" }),
            sensitivity: Some("public".to_string()),
            license: Some(manifest.license.clone()),
            access_policy: json!({ "source": "package-license" }),
            access_policy_ref: Some(format!(
                "local://package/{}/access-policy",
                manifest.package_id
            )),
            cache_policy: json!({
                "cacheKey": format!("{}:{}:{}", manifest.package_id, artifact.id, artifact.sha256),
                "pinRecommended": false
            }),
            retention_policy: json!({ "mode": "package-artifact" }),
            sensitivity_label: Some("public-package-artifact".to_string()),
            created_by: Some(manifest.publisher.address.clone()),
            created_at: Some("1970-01-01T00:00:00Z".to_string()),
            signatures: Vec::new(),
        })
        .collect()
}

pub fn artifact_group_v2_from_v1(
    package_id: &str,
    artifact_group: &ArtifactGroup,
) -> ArtifactGroupV2 {
    let mut hashes = BTreeMap::new();
    hashes.insert("sha256".to_string(), artifact_group.sha256.clone());
    ArtifactGroupV2 {
        artifact_group_id: artifact_group.id.clone(),
        target: artifact_group.target.clone(),
        engine: artifact_group.engine.clone(),
        model_format: artifact_group.format.clone(),
        quantization: None,
        files: artifact_group.paths.clone(),
        total_bytes: artifact_group.total_bytes,
        hashes,
        required_memory_mb: artifact_group.minimum.memory_mb,
        required_vram_mb: required_vram_mb(artifact_group),
        preferred_runners: preferred_runners_for_artifact(artifact_group),
        fallback_groups: Vec::new(),
        cache_key: format!(
            "{}:{}:{}",
            package_id, artifact_group.id, artifact_group.sha256
        ),
    }
}

pub fn runtime_descriptors_from_manifest_v1(
    manifest: &PackageManifestV1,
    capabilities: &[UniversalCapabilityV1],
    assets: &[AssetDescriptorV1],
) -> Vec<RuntimeDescriptorV2> {
    manifest
        .artifact_groups
        .iter()
        .map(|artifact| {
            let runtime_class = runtime_class_for_artifact(artifact).to_string();
            let asset_id = asset_id_for_artifact_group(artifact);
            let asset_refs = assets
                .iter()
                .filter(|asset| asset.asset_id == asset_id)
                .map(|asset| format!("local://package/{}/assets/{}", manifest.package_id, asset.asset_id))
                .collect::<Vec<_>>();
            let supported_api_surfaces = capability_strings(
                capabilities
                    .iter()
                    .flat_map(|capability| capability.supported_api_surfaces.iter().cloned()),
            );
            let supported_modalities = capability_strings(
                capabilities
                    .iter()
                    .flat_map(|capability| capability.modalities.iter().cloned()),
            );
            let privacy_tiers = capability_strings(
                capabilities
                    .iter()
                    .flat_map(|capability| capability.privacy_classes.iter().cloned()),
            );
            let verification_tiers = capability_strings(
                capabilities
                    .iter()
                    .flat_map(|capability| capability.validation_classes.iter().cloned()),
            );
            RuntimeDescriptorV2 {
                runtime_id: format!("runtime-{}", slug_component(&artifact.id)),
                runtime_class,
                target: artifact.target.clone(),
                engine: artifact.engine.clone(),
                model_format: artifact.format.clone(),
                asset_refs,
                required_memory_mb: artifact.minimum.memory_mb,
                required_vram_mb: required_vram_mb(artifact),
                requires_web_gpu: artifact.minimum.webgpu.unwrap_or(false),
                supported_api_surfaces,
                supported_modalities,
                privacy_tiers,
                verification_tiers,
                execution_hints: json!({
                    "preferredRunners": preferred_runners_for_artifact(artifact),
                    "diskMb": artifact.minimum.disk_mb,
                    "largeModelWarning": artifact.total_bytes > 2 * 1024 * 1024 * 1024
                }),
                cache_policy: json!({
                    "cacheKey": format!("{}:{}:{}", manifest.package_id, artifact.id, artifact.sha256),
                    "contentAddressed": true
                }),
            }
        })
        .collect()
}

fn namespace_from_package_id(package_id: &str) -> String {
    package_id
        .split_once('/')
        .map(|(namespace, _)| namespace)
        .filter(|namespace| !namespace.trim().is_empty())
        .unwrap_or("default")
        .to_string()
}

fn universal_capability_from_legacy_capability(
    manifest: &PackageManifestV1,
    capability: &str,
) -> UniversalCapabilityV1 {
    let capability_id = capability_id_for_legacy_capability(capability);
    let mut runtime_classes = runtime_classes_from_artifacts(&manifest.artifact_groups);
    if runtime_classes.is_empty() {
        runtime_classes.push("service".to_string());
    }

    UniversalCapabilityV1 {
        capability_id: capability_id.clone(),
        modalities: modality_names_for_capability(capability),
        operation: operation_for_capability(capability).to_string(),
        input_contract_ref: Some(format!(
            "local://package/{}/input-schema",
            manifest.package_id
        )),
        output_contract_ref: Some(format!(
            "local://package/{}/output-schema",
            manifest.package_id
        )),
        supported_api_surfaces: supported_apis_from_capabilities(&[capability.to_string()])
            .into_iter()
            .map(api_surface_wire_name)
            .collect(),
        supported_streaming_events: streaming_events_for_capability(capability),
        runtime_classes,
        privacy_classes: privacy_classes_for_capability(manifest, capability),
        validation_classes: validation_classes_for_capability(manifest, capability),
        cost_hints: json!({
            "source": "package-manifest",
            "pricingRequiredBeforeProduction": true
        }),
        latency_hints: json!({
            "source": "artifact-metadata",
            "coldCacheExpected": true
        }),
    }
}

fn capability_id_for_legacy_capability(capability: &str) -> String {
    match capability {
        "chat" => "text.chat.general".to_string(),
        "embedding" => "text.embedding.general".to_string(),
        "classification" => "text.classify.general".to_string(),
        "ocr" => "document.ocr.general".to_string(),
        "image-understanding" => "vision.understand.general".to_string(),
        "image-generation" => "image.generate.general".to_string(),
        "speech-to-text" => "audio.transcribe.general".to_string(),
        "text-to-speech" => "audio.synthesize.general".to_string(),
        "rag" => "document.answer.retrieval_augmented".to_string(),
        "vector-search" => "vector.retrieve.general".to_string(),
        "tool-use" | "tool" => "tool.call.general".to_string(),
        "fine-tune" => "model.fine_tune.general".to_string(),
        "evaluation" | "eval" => "model.evaluate.general".to_string(),
        "batch" => "batch.execute.general".to_string(),
        "realtime" => "realtime.session.general".to_string(),
        "moderation" => "safety.moderate.general".to_string(),
        other => format!("custom.{}", slug_component(other)),
    }
}

fn modality_names_for_capability(capability: &str) -> Vec<String> {
    let names: Vec<&str> = match capability {
        "chat" => vec!["text", "chat"],
        "embedding" => vec!["text", "embedding"],
        "classification" => vec!["text", "structured_output"],
        "ocr" => vec!["document", "image", "text"],
        "image-understanding" => vec!["image", "text"],
        "image-generation" => vec!["image", "text"],
        "speech-to-text" => vec!["audio", "text"],
        "text-to-speech" => vec!["text", "audio"],
        "rag" => vec!["document", "vector", "text"],
        "vector-search" => vec!["vector", "document"],
        "tool-use" | "tool" => vec!["tool", "structured_output"],
        "fine-tune" => vec!["model_weights", "training_data"],
        "evaluation" | "eval" => vec!["evaluation_data", "text"],
        "batch" => vec!["mixed_multimodal"],
        "realtime" => vec!["mixed_multimodal", "audio", "text"],
        "moderation" => vec!["text", "image", "audio"],
        _ => vec!["mixed_multimodal"],
    };
    names.into_iter().map(str::to_string).collect()
}

fn operation_for_capability(capability: &str) -> &'static str {
    match capability {
        "chat" | "image-generation" => "generate",
        "embedding" => "embed",
        "classification" | "moderation" => "classify",
        "ocr" => "extract",
        "image-understanding" => "caption",
        "speech-to-text" => "transcribe",
        "text-to-speech" => "synthesize_speech",
        "rag" => "answer",
        "vector-search" => "retrieve",
        "tool-use" | "tool" => "call_tool",
        "fine-tune" => "fine_tune",
        "evaluation" | "eval" => "evaluate",
        "batch" => "execute_workflow",
        "realtime" => "stream",
        _ => "transform",
    }
}

fn streaming_events_for_capability(capability: &str) -> Vec<String> {
    let events: Vec<&str> = match capability {
        "chat" | "realtime" => vec![
            "started",
            "heartbeat",
            "text_delta",
            "tool_call_requested",
            "tool_call_result",
            "partial_receipt",
            "completed",
            "error",
            "cancelled",
        ],
        "embedding" | "vector-search" | "rag" => vec![
            "started",
            "retrieval_event",
            "embedding_progress",
            "partial_receipt",
            "completed",
            "error",
        ],
        "image-generation" => vec![
            "started",
            "image_progress",
            "partial_receipt",
            "completed",
            "error",
        ],
        "speech-to-text" | "text-to-speech" => vec![
            "started",
            "audio_chunk",
            "partial_receipt",
            "completed",
            "error",
        ],
        "batch" | "fine-tune" | "evaluation" | "eval" => vec![
            "started",
            "queue_update",
            "artifact_prepare_progress",
            "validation_event",
            "partial_receipt",
            "completed",
            "error",
            "cancelled",
        ],
        _ => vec!["started", "partial_receipt", "completed", "error"],
    };
    events.into_iter().map(str::to_string).collect()
}

fn runtime_classes_from_artifacts(artifact_groups: &[ArtifactGroup]) -> Vec<String> {
    let mut runtime_classes = BTreeSet::new();
    for artifact in artifact_groups {
        let target = artifact.target.to_ascii_lowercase();
        let engine = artifact.engine.to_ascii_lowercase();
        if target.contains("browser") || engine.contains("wasm") || engine.contains("webgpu") {
            runtime_classes.insert("browser".to_string());
        }
        if target.contains("local")
            || engine.contains("rust")
            || engine.contains("llama.cpp")
            || engine.contains("onnx")
        {
            runtime_classes.insert("local".to_string());
        }
        if target.contains("cuda")
            || target.contains("gpu")
            || engine.contains("vllm")
            || engine.contains("tensorrt")
            || engine.contains("onnxruntime-gpu")
        {
            runtime_classes.insert("remote_gpu".to_string());
            runtime_classes.insert("miner".to_string());
        }
    }
    runtime_classes.into_iter().collect()
}

fn privacy_classes_for_capability(manifest: &PackageManifestV1, _capability: &str) -> Vec<String> {
    let mut privacy_classes = BTreeSet::from(["standard".to_string(), "no_log".to_string()]);
    let runtimes = runtime_classes_from_artifacts(&manifest.artifact_groups);
    if runtimes
        .iter()
        .any(|runtime| runtime == "browser" || runtime == "local")
    {
        privacy_classes.insert("local_only".to_string());
    }
    if manifest
        .capabilities
        .iter()
        .any(|capability| capability.contains("confidential") || capability.contains("tee"))
    {
        privacy_classes.insert("tee_confidential".to_string());
    }
    privacy_classes.into_iter().collect()
}

fn validation_classes_for_capability(
    manifest: &PackageManifestV1,
    capability: &str,
) -> Vec<String> {
    let mut validation_classes = BTreeSet::from(["receipt_only".to_string()]);
    if matches!(
        capability,
        "evaluation" | "eval" | "benchmark" | "classification" | "ocr" | "rag"
    ) || matches!(
        manifest.kind,
        PackageKind::Benchmark | PackageKind::EvalSuite
    ) {
        validation_classes.insert("validator_spot_check".to_string());
        validation_classes.insert("challenge".to_string());
    }
    validation_classes.into_iter().collect()
}

fn asset_id_for_artifact_group(artifact: &ArtifactGroup) -> String {
    format!("artifact-{}", slug_component(&artifact.id))
}

fn asset_role_for_package_kind(kind: &PackageKind) -> AssetRoleV1 {
    match kind {
        PackageKind::Dataset => AssetRoleV1::Dataset,
        PackageKind::Benchmark | PackageKind::EvalSuite | PackageKind::HardwareBenchmark => {
            AssetRoleV1::Benchmark
        }
        PackageKind::Workflow | PackageKind::RagPipeline => AssetRoleV1::Config,
        PackageKind::VectorIndex => AssetRoleV1::VectorIndex,
        PackageKind::PromptPack => AssetRoleV1::Prompt,
        PackageKind::Tool | PackageKind::ToolPack | PackageKind::ServiceAdapter => {
            AssetRoleV1::Tool
        }
        PackageKind::ResearchExperiment => AssetRoleV1::Report,
        PackageKind::FineTuneRecipe
        | PackageKind::SafetyPolicy
        | PackageKind::ModerationPolicy
        | PackageKind::SyntheticDataRecipe
        | PackageKind::PrivacyMethod
        | PackageKind::ProofMethod => AssetRoleV1::Config,
        _ => AssetRoleV1::ModelWeights,
    }
}

fn asset_class_for_package_kind(kind: &PackageKind) -> &'static str {
    match kind {
        PackageKind::Dataset => "dataset",
        PackageKind::Benchmark | PackageKind::EvalSuite => "evaluation_set",
        PackageKind::Workflow | PackageKind::RagPipeline => "workflow",
        PackageKind::VectorIndex => "vector_index",
        PackageKind::PromptPack => "prompt",
        PackageKind::Tool | PackageKind::ToolPack | PackageKind::ServiceAdapter => "tool_schema",
        PackageKind::ServiceDescriptor => "service_descriptor",
        PackageKind::ResearchExperiment => "notebook",
        PackageKind::FineTuneRecipe => "config",
        PackageKind::SafetyPolicy | PackageKind::ModerationPolicy => "policy",
        _ => "model_weight",
    }
}

fn primary_modality_for_manifest(manifest: &PackageManifestV1) -> Option<String> {
    modalities_from_capabilities(&manifest.capabilities)
        .into_iter()
        .next()
        .map(modality_wire_name)
}

fn runtime_class_for_artifact(artifact: &ArtifactGroup) -> &'static str {
    let target = artifact.target.to_ascii_lowercase();
    let engine = artifact.engine.to_ascii_lowercase();
    if target.contains("browser") || engine.contains("wasm") || engine.contains("webgpu") {
        "browser"
    } else if target.contains("cuda")
        || target.contains("gpu")
        || engine.contains("vllm")
        || engine.contains("tensorrt")
        || engine.contains("onnxruntime-gpu")
    {
        "remote_gpu"
    } else if target.contains("local")
        || engine.contains("rust")
        || engine.contains("llama.cpp")
        || engine.contains("onnx")
    {
        "local"
    } else {
        "service"
    }
}

fn content_type_for_artifact_format(format: &str) -> &'static str {
    match format.to_ascii_lowercase().as_str() {
        "json" | "jsonl" => "application/json",
        "txt" | "text" | "md" | "markdown" => "text/plain; charset=utf-8",
        "safetensors" | "gguf" | "onnx" | "bin" | "wasm" => "application/octet-stream",
        _ => "application/octet-stream",
    }
}

fn storage_policy_for_manifest(
    manifest: &PackageManifestV1,
    browser_publish_profile: Option<&BrowserPublishProfileV1>,
) -> Value {
    let total_bytes: u64 = manifest
        .artifact_groups
        .iter()
        .map(|artifact| artifact.total_bytes)
        .sum();
    json!({
        "mode": "content-addressed-assets",
        "largeDataReferenced": true,
        "lazyLoadingRequired": true,
        "totalAssetBytes": total_bytes,
        "immutableVersionRequired": true,
        "mutableChannelsUseFeeds": true,
        "browserNativePublishing": browser_publish_profile.is_some(),
        "supportedBrowserProviderKinds": browser_publish_profile
            .map(|profile| profile.supported_provider_kinds.clone())
            .unwrap_or_default()
    })
}

fn default_provenance_record(
    manifest: &PackageManifestV1,
    created_at: &str,
    source: &str,
) -> ProvenanceRecordV1 {
    let source_value = serde_json::to_value(manifest).unwrap_or_else(|_| json!({}));
    let source_manifest_hash = hash_canonical_json(&canonicalize_json(&source_value));
    ProvenanceRecordV1 {
        record_id: format!("provenance-{}", &source_manifest_hash[..24]),
        source: source.to_string(),
        publisher: manifest.publisher.clone(),
        created_at: created_at.to_string(),
        source_schema_version: Some(manifest.schema_version.clone()),
        source_manifest_hash: Some(format!("sha256:{source_manifest_hash}")),
        evidence_refs: Vec::new(),
    }
}

fn dedup_runtime_descriptors(runtimes: Vec<RuntimeDescriptorV2>) -> Vec<RuntimeDescriptorV2> {
    let mut by_id = BTreeMap::new();
    for runtime in runtimes {
        by_id.entry(runtime.runtime_id.clone()).or_insert(runtime);
    }
    by_id.into_values().collect()
}

fn capability_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values: Vec<String> = values.into_iter().collect();
    values.sort();
    values.dedup();
    values
}

fn default_browser_publish_profile(
    manifest: &PackageManifestV1,
) -> Option<BrowserPublishProfileV1> {
    let total_bytes: u64 = manifest
        .artifact_groups
        .iter()
        .map(|artifact| artifact.total_bytes)
        .sum();
    let browser_publishable_kind = matches!(
        manifest.kind,
        PackageKind::PromptPack
            | PackageKind::Tool
            | PackageKind::ToolPack
            | PackageKind::Dataset
            | PackageKind::Benchmark
            | PackageKind::Workflow
            | PackageKind::VectorIndex
            | PackageKind::RagPipeline
            | PackageKind::ServiceDescriptor
            | PackageKind::ResearchExperiment
            | PackageKind::EvalSuite
            | PackageKind::SafetyPolicy
            | PackageKind::ModerationPolicy
    );
    let small_enough_for_browser = total_bytes <= 64 * 1024 * 1024;
    if !browser_publishable_kind && !small_enough_for_browser {
        return None;
    }

    Some(BrowserPublishProfileV1 {
        allowed_browser_publish: true,
        max_browser_upload_bytes: Some(64 * 1024 * 1024),
        requires_wallet_storage_purchase: true,
        recommended_chunking: Some("provider-default".to_string()),
        resumable_upload_required: total_bytes > 16 * 1024 * 1024,
        feed_update_allowed: true,
        allowed_origins: Vec::new(),
        supported_provider_kinds: vec![
            "weeb3_npm".to_string(),
            "bee_js_gateway".to_string(),
            "local_bee_bridge".to_string(),
            "hosted_upload_relay".to_string(),
        ],
        browser_security_warnings: vec![
            "Require explicit consent before wallet-funded storage purchase".to_string(),
            "Do not expose signing keys or decryption keys to untrusted frames".to_string(),
            "Verify uploaded manifest and content hashes before feed updates".to_string(),
        ],
    })
}

fn dedup_universal_capabilities(
    capabilities: Vec<UniversalCapabilityV1>,
) -> Vec<UniversalCapabilityV1> {
    let mut by_id = BTreeMap::new();
    for capability in capabilities {
        by_id
            .entry(capability.capability_id.clone())
            .or_insert(capability);
    }
    by_id.into_values().collect()
}

fn dedup_asset_descriptors(assets: Vec<AssetDescriptorV1>) -> Vec<AssetDescriptorV1> {
    let mut by_id = BTreeMap::new();
    for asset in assets {
        by_id.entry(asset.asset_id.clone()).or_insert(asset);
    }
    by_id.into_values().collect()
}

fn api_surface_wire_name(api_surface: ApiSurface) -> String {
    serde_json::to_value(api_surface)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "hivemind_native".to_string())
}

fn modality_wire_name(modality: Modality) -> String {
    serde_json::to_value(modality)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "text".to_string())
}

fn package_kind_tag(kind: &PackageKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "package".to_string())
}

fn slug_component(value: &str) -> String {
    let slug: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let collapsed = slug
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if collapsed.is_empty() {
        "custom".to_string()
    } else {
        collapsed
    }
}

pub(crate) fn modalities_from_capabilities(capabilities: &[String]) -> Vec<Modality> {
    let mut modalities = Vec::new();
    for capability in capabilities {
        match capability.as_str() {
            "chat" => {
                modalities.push(Modality::Chat);
                modalities.push(Modality::Text);
            }
            "embedding" => {
                modalities.push(Modality::Embedding);
                modalities.push(Modality::Text);
            }
            "classification" => {
                modalities.push(Modality::StructuredOutput);
                modalities.push(Modality::Text);
            }
            "ocr" | "image-understanding" => {
                modalities.push(Modality::Image);
                modalities.push(Modality::Text);
            }
            "image-generation" => {
                modalities.push(Modality::Image);
                modalities.push(Modality::Text);
            }
            "speech-to-text" | "text-to-speech" => {
                modalities.push(Modality::Audio);
                modalities.push(Modality::Text);
            }
            "rag" | "vector-search" => {
                modalities.push(Modality::VectorSearch);
                modalities.push(Modality::Document);
                modalities.push(Modality::Text);
            }
            "tool-use" | "tool" => {
                modalities.push(Modality::ToolCall);
                modalities.push(Modality::StructuredOutput);
            }
            "fine-tune" => modalities.push(Modality::TrainingData),
            "evaluation" | "eval" => modalities.push(Modality::EvaluationData),
            _ => {}
        }
    }
    dedup_modalities(modalities)
}

pub(crate) fn supported_apis_from_capabilities(capabilities: &[String]) -> Vec<ApiSurface> {
    let mut apis = vec![ApiSurface::HivemindNative];
    for capability in capabilities {
        match capability.as_str() {
            "chat" => {
                apis.push(ApiSurface::OpenAiChatCompletions);
                apis.push(ApiSurface::OpenAiResponses);
                apis.push(ApiSurface::AnthropicMessages);
                apis.push(ApiSurface::GeminiGenerateContent);
            }
            "embedding" => {
                apis.push(ApiSurface::OpenAiEmbeddings);
                apis.push(ApiSurface::HuggingFaceInference);
            }
            "classification" => apis.push(ApiSurface::HuggingFaceInference),
            "image-generation" => {
                apis.push(ApiSurface::OpenAiImages);
                apis.push(ApiSurface::ImageGeneration);
            }
            "image-understanding" | "ocr" => apis.push(ApiSurface::ImageUnderstanding),
            "speech-to-text" => {
                apis.push(ApiSurface::OpenAiAudio);
                apis.push(ApiSurface::SpeechToText);
            }
            "text-to-speech" => {
                apis.push(ApiSurface::OpenAiAudio);
                apis.push(ApiSurface::TextToSpeech);
            }
            "rag" => apis.push(ApiSurface::RagQuery),
            "vector-search" => {
                apis.push(ApiSurface::OpenAiVectorStores);
                apis.push(ApiSurface::VectorSearch);
            }
            "batch" => {
                apis.push(ApiSurface::OpenAiBatches);
                apis.push(ApiSurface::Batch);
            }
            "fine-tune" => {
                apis.push(ApiSurface::OpenAiFineTuning);
                apis.push(ApiSurface::FineTune);
            }
            "evaluation" | "eval" => {
                apis.push(ApiSurface::OpenAiEvals);
                apis.push(ApiSurface::EvalRun);
            }
            "realtime" => {
                apis.push(ApiSurface::OpenAiRealtime);
                apis.push(ApiSurface::GeminiLive);
                apis.push(ApiSurface::RealtimeSession);
            }
            "moderation" => apis.push(ApiSurface::Moderation),
            _ => {}
        }
    }
    dedup_apis(apis)
}

fn dedup_modalities(values: Vec<Modality>) -> Vec<Modality> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.contains(&value) {
            deduped.push(value);
        }
    }
    deduped
}

fn dedup_apis(values: Vec<ApiSurface>) -> Vec<ApiSurface> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.contains(&value) {
            deduped.push(value);
        }
    }
    deduped
}

fn required_vram_mb(artifact_group: &ArtifactGroup) -> Option<u64> {
    let target = artifact_group.target.to_ascii_lowercase();
    let engine = artifact_group.engine.to_ascii_lowercase();
    let gpu_bound = ["cuda", "gpu", "vllm", "tensorrt", "onnxruntime-gpu"]
        .iter()
        .any(|needle| target.contains(needle) || engine.contains(needle));
    gpu_bound
        .then_some(artifact_group.minimum.memory_mb)
        .flatten()
}

fn preferred_runners_for_artifact(artifact_group: &ArtifactGroup) -> Vec<String> {
    let mut runners = BTreeSet::new();
    let target = artifact_group.target.to_ascii_lowercase();
    let engine = artifact_group.engine.to_ascii_lowercase();
    if target.contains("browser") || engine.contains("wasm") || engine.contains("webgpu") {
        runners.insert("browser".to_string());
    }
    if target.contains("local") || engine.contains("rust") || engine.contains("llama.cpp") {
        runners.insert("local".to_string());
    }
    if target.contains("cuda")
        || target.contains("gpu")
        || engine.contains("vllm")
        || engine.contains("tensorrt")
    {
        runners.insert("remote-gpu".to_string());
        runners.insert("marketplace-miner".to_string());
    }
    runners.into_iter().collect()
}

fn default_if_null(value: Value, fallback: Value) -> Value {
    if value.is_null() { fallback } else { value }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rd_package_kinds_match_v2_wire_names() {
        assert_eq!(
            serde_json::to_value(PackageKind::ResearchExperiment).unwrap(),
            json!("research_experiment")
        );
        assert_eq!(
            serde_json::to_value(PackageKind::FineTuneRecipe).unwrap(),
            json!("fine_tune_recipe")
        );
        assert_eq!(
            serde_json::to_value(PackageKind::HardwareBenchmark).unwrap(),
            json!("hardware_benchmark")
        );
        assert_eq!(
            serde_json::to_value(PackageKind::VectorIndex).unwrap(),
            json!("vector_index")
        );
        assert_eq!(
            serde_json::to_value(PackageKind::RagPipeline).unwrap(),
            json!("rag_pipeline")
        );
        assert_eq!(
            serde_json::to_value(PackageKind::EmbeddingService).unwrap(),
            json!("embedding_service")
        );
        assert_eq!(
            serde_json::to_value(PackageKind::RealtimeSessionService).unwrap(),
            json!("realtime_session_service")
        );
        assert_eq!(
            serde_json::to_value(PackageKind::ToolPack).unwrap(),
            json!("tool_pack")
        );
        assert_eq!(
            serde_json::to_value(PackageKind::ServiceDescriptor).unwrap(),
            json!("service_descriptor")
        );
        assert_eq!(
            serde_json::to_value(PackageKind::Custom).unwrap(),
            json!("custom")
        );
    }

    #[test]
    fn package_manifest_v2_projection_preserves_v1_identity_and_artifacts() {
        let manifest = PackageManifestV1 {
            schema_version: "swarm-ai.package.v1".to_string(),
            package_id: "hivemind/hello-chat".to_string(),
            kind: PackageKind::Model,
            name: "Hello Chat".to_string(),
            version: "0.1.0".to_string(),
            publisher: Publisher {
                address: "0x0".to_string(),
                display_name: "Hivemind Labs".to_string(),
                publisher_profile_ref: None,
            },
            capabilities: vec!["chat".to_string(), "image-generation".to_string()],
            artifact_groups: vec![ArtifactGroup {
                id: "remote-vllm-chat".to_string(),
                target: "cuda-vllm".to_string(),
                engine: "vllm".to_string(),
                format: "safetensors".to_string(),
                paths: vec!["model/config.json".to_string()],
                total_bytes: 42,
                sha256: "a".repeat(64),
                minimum: ArtifactMinimum {
                    memory_mb: Some(24 * 1024),
                    webgpu: Some(false),
                    disk_mb: Some(1024),
                },
            }],
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            permissions: vec![PermissionRequest {
                name: "network".to_string(),
                purpose: Some("tool use".to_string()),
                required: false,
                limits: json!({ "domains": ["example.com"] }),
            }],
            license: LicenseInfo {
                license_type: LicenseType::Open,
                name: Some("Apache-2.0".to_string()),
                url: None,
            },
        };

        let manifest_v2 = package_manifest_v2_from_v1_with_context(
            &manifest,
            PackageManifestV2Context {
                created_at: Some("2026-06-03T00:00:00Z".to_string()),
                description: Some("A test chat package".to_string()),
                signatures: vec!["local://signature".to_string()],
                ..Default::default()
            },
        );

        assert_eq!(manifest_v2.schema_version, "hivemind.package.v2");
        assert_eq!(manifest_v2.package_id, manifest.package_id);
        assert_eq!(manifest_v2.namespace, "hivemind");
        assert_eq!(manifest_v2.created_at, "2026-06-03T00:00:00Z");
        assert!(manifest_v2.modalities.contains(&Modality::Chat));
        assert!(
            manifest_v2
                .supported_apis
                .contains(&ApiSurface::OpenAiChatCompletions)
        );
        assert!(
            manifest_v2
                .supported_apis
                .contains(&ApiSurface::OpenAiImages)
        );
        assert_eq!(
            manifest_v2.artifacts[0].artifact_group_id,
            "remote-vllm-chat"
        );
        assert_eq!(manifest_v2.artifacts[0].model_format, "safetensors");
        assert_eq!(manifest_v2.artifacts[0].required_vram_mb, Some(24 * 1024));
        assert!(
            manifest_v2.artifacts[0]
                .preferred_runners
                .contains(&"marketplace-miner".to_string())
        );
        assert_eq!(manifest_v2.signatures, vec!["local://signature"]);
    }

    #[test]
    fn package_manifest_v3_adds_universal_capabilities_assets_and_browser_publish_profile() {
        let manifest = PackageManifestV1 {
            schema_version: "swarm-ai.package.v1".to_string(),
            package_id: "hivemind/browser-prompt-pack".to_string(),
            kind: PackageKind::PromptPack,
            name: "Browser Prompt Pack".to_string(),
            version: "0.1.0".to_string(),
            publisher: Publisher {
                address: "0xBrowserPublisher".to_string(),
                display_name: "Browser Publisher".to_string(),
                publisher_profile_ref: None,
            },
            capabilities: vec!["chat".to_string(), "rag".to_string()],
            artifact_groups: vec![ArtifactGroup {
                id: "browser-wasm".to_string(),
                target: "browser-webgpu".to_string(),
                engine: "wasm".to_string(),
                format: "json".to_string(),
                paths: vec!["prompts/system.json".to_string()],
                total_bytes: 1024,
                sha256: "b".repeat(64),
                minimum: ArtifactMinimum {
                    memory_mb: Some(256),
                    webgpu: Some(true),
                    disk_mb: Some(1),
                },
            }],
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            permissions: Vec::new(),
            license: LicenseInfo {
                license_type: LicenseType::Open,
                name: Some("MIT".to_string()),
                url: None,
            },
        };

        let manifest_v3 = package_manifest_v3_from_v1(&manifest);

        assert_eq!(manifest_v3.schema_version, "hivemind.package.v3");
        assert!(manifest_v3.capabilities.iter().any(|capability| {
            capability.capability_id == "text.chat.general"
                && capability.runtime_classes.contains(&"browser".to_string())
                && capability
                    .privacy_classes
                    .contains(&"local_only".to_string())
        }));
        assert!(
            manifest_v3
                .capabilities
                .iter()
                .any(|capability| capability.capability_id
                    == "document.answer.retrieval_augmented")
        );
        assert_eq!(manifest_v3.assets.len(), 1);
        assert_eq!(manifest_v3.assets[0].asset_class, "prompt");
        assert_eq!(
            manifest_v3.assets[0].storage_refs,
            vec!["package://hivemind/browser-prompt-pack/prompts/system.json"]
        );
        assert!(manifest_v3.browser_publish_profile.is_some());
        assert!(
            manifest_v3
                .browser_publish_profile
                .as_ref()
                .unwrap()
                .supported_provider_kinds
                .contains(&"weeb3_npm".to_string())
        );
    }

    #[test]
    fn package_manifest_v4_projects_review4_contract_fields() {
        let manifest = PackageManifestV1 {
            schema_version: "swarm-ai.package.v1".to_string(),
            package_id: "hivemind/gpu-chat".to_string(),
            kind: PackageKind::Model,
            name: "GPU Chat".to_string(),
            version: "0.2.0".to_string(),
            publisher: Publisher {
                address: "0xPublisher".to_string(),
                display_name: "Hivemind Publisher".to_string(),
                publisher_profile_ref: Some("bzz://publisher-profile".to_string()),
            },
            capabilities: vec!["chat".to_string()],
            artifact_groups: vec![ArtifactGroup {
                id: "cuda-vllm".to_string(),
                target: "cuda-vllm".to_string(),
                engine: "vllm".to_string(),
                format: "safetensors".to_string(),
                paths: vec![
                    "model/config.json".to_string(),
                    "model/weights.safetensors".to_string(),
                ],
                total_bytes: 8 * 1024 * 1024 * 1024,
                sha256: "c".repeat(64),
                minimum: ArtifactMinimum {
                    memory_mb: Some(64 * 1024),
                    webgpu: Some(false),
                    disk_mb: Some(8192),
                },
            }],
            input_schema: json!({ "type": "object", "required": ["messages"] }),
            output_schema: json!({ "type": "object", "required": ["message"] }),
            permissions: Vec::new(),
            license: LicenseInfo {
                license_type: LicenseType::Commercial,
                name: Some("Commercial Eval".to_string()),
                url: None,
            },
        };

        let manifest_v4 = package_manifest_v4_from_v1_with_context(
            &manifest,
            PackageManifestV4Context {
                created_at: Some("2026-06-05T00:00:00Z".to_string()),
                summary: Some("A GPU-backed chat package".to_string()),
                ..Default::default()
            },
        );

        assert_eq!(manifest_v4.schema_version, "hivemind.package_manifest.v4");
        assert_eq!(manifest_v4.object_kind, "package_manifest");
        assert_eq!(manifest_v4.package_kind, PackageKind::Model);
        assert_eq!(manifest_v4.summary, "A GPU-backed chat package");
        assert_eq!(manifest_v4.input_schemas["default"], manifest.input_schema);
        assert_eq!(
            manifest_v4.output_schemas["default"],
            manifest.output_schema
        );
        assert_eq!(manifest_v4.assets.len(), 1);
        assert_eq!(manifest_v4.assets[0].role, Some(AssetRoleV1::ModelWeights));
        assert_eq!(
            manifest_v4.assets[0].hash,
            Some(format!("sha256:{}", "c".repeat(64)))
        );
        assert_eq!(
            manifest_v4.assets[0].content_type.as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(manifest_v4.runtimes.len(), 1);
        assert_eq!(manifest_v4.runtimes[0].runtime_class, "remote_gpu");
        assert_eq!(manifest_v4.runtimes[0].required_vram_mb, Some(64 * 1024));
        assert!(
            manifest_v4.runtimes[0]
                .execution_hints
                .get("preferredRunners")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .any(|value| value == "marketplace-miner")
        );
        assert_eq!(
            manifest_v4.storage_policy["largeDataReferenced"],
            json!(true)
        );
        assert_eq!(manifest_v4.provenance.len(), 1);
        assert_eq!(
            manifest_v4.provenance[0].source_schema_version.as_deref(),
            Some("swarm-ai.package.v1")
        );

        let capability_set = capability_set_from_manifest_v4(&manifest_v4);
        assert!(
            capability_set
                .supported_api_surfaces
                .contains(&"openai_chat_completions".to_string())
        );

        let summary = package_index_summary_from_manifest_v4(&manifest_v4);
        assert_eq!(summary.schema_version, "hivemind.package_index_summary.v1");
        assert_eq!(summary.asset_count, 1);
        assert_eq!(summary.total_asset_bytes, 8 * 1024 * 1024 * 1024);
        assert_eq!(summary.runtime_classes, vec!["remote_gpu".to_string()]);
    }
}
