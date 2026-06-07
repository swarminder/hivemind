use hivemind_core::{ErrorCode, SwarmAiErrorV1};
use hivemind_storage::{
    BrowserStorageCapabilityProbeV1, BrowserStorageEncryptionModeV1, BrowserStoragePermissionV1,
    BrowserStoragePurchaseAuthorizationV1, BrowserStoragePurchaseQuoteV1, BrowserStorageSessionV2,
    BrowserStorageStateEntryV1, BrowserStorageStateReportV1, BrowserSwarmProviderProfileV1,
    BrowserSwarmStorageMethodV4, BrowserSwarmStorageProviderV4, DirectoryManifestV1,
    DownloadResponseV1, StorageCapabilities, StorageCostV1, StorageEventActionV2,
    StorageEventReceiptV2, StorageEventStatusV1, StorageFeedUpdateResultV1, StorageProvider,
    StorageProviderKindV4, StorageStatusV1, UploadResponseV1, browser_storage_capability_probe,
    browser_storage_purchase_authorization, browser_storage_purchase_quote,
    browser_storage_session_v2, browser_storage_state_report,
    default_browser_swarm_storage_providers_v4, sign_browser_storage_capability_probe,
    sign_browser_storage_purchase_authorization, sign_browser_storage_purchase_quote,
    sign_browser_storage_session_v2, sign_browser_storage_state_report,
    sign_storage_event_receipt_v2, storage_event_receipt_v2,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

pub const BROWSER_SWARM_STORAGE_PROVIDER_V6_SCHEMA_VERSION: &str =
    "hivemind.browser-swarm-storage-provider.v6";
pub const BROWSER_PUBLISH_ONE_RESULT_SCHEMA_VERSION: &str =
    "hivemind.browser-publish-one-result.v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Weeb3AdapterDescriptorV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "npmPackage")]
    pub npm_package: String,
    #[serde(rename = "wasmInit")]
    pub wasm_init: String,
    #[serde(rename = "clientClass")]
    pub client_class: String,
    #[serde(rename = "supportsGatewayFallback")]
    pub supports_gateway_fallback: bool,
    #[serde(rename = "supportsBrowserNode")]
    pub supports_browser_node: bool,
    #[serde(rename = "providerContract")]
    pub provider_contract: BrowserSwarmProviderV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmProviderV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmBootstrapNodeV1 {
    pub multiaddr: String,
    pub trusted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmCacheConfigV1 {
    #[serde(rename = "useIndexedDb")]
    pub use_indexed_db: bool,
    #[serde(rename = "maxBytes")]
    pub max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmFallbackV1 {
    pub provider: String,
    #[serde(rename = "baseUrl")]
    pub base_url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmConfigV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "networkId")]
    pub network_id: String,
    #[serde(rename = "bootstrapNodes")]
    pub bootstrap_nodes: Vec<BrowserSwarmBootstrapNodeV1>,
    pub cache: BrowserSwarmCacheConfigV1,
    #[serde(default)]
    pub fallback: Option<BrowserSwarmFallbackV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmCapabilitiesV1 {
    pub retrieval: bool,
    pub upload: bool,
    pub feeds: bool,
    #[serde(rename = "serviceWorkerWebsiteLoading")]
    pub service_worker_website_loading: bool,
    #[serde(rename = "gatewayFallback")]
    pub gateway_fallback: bool,
    #[serde(rename = "packageManifestDownload")]
    pub package_manifest_download: bool,
    #[serde(rename = "modelCache")]
    pub model_cache: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserSwarmProviderState {
    Stopped,
    Running,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserSwarmRetrievalSource {
    Cache,
    Weeb3,
    GatewayFallback,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmCacheStatusV1 {
    #[serde(rename = "useIndexedDb")]
    pub use_indexed_db: bool,
    #[serde(rename = "maxBytes")]
    pub max_bytes: u64,
    #[serde(rename = "usedBytes")]
    pub used_bytes: u64,
    #[serde(rename = "entryCount")]
    pub entry_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmStatusV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub state: BrowserSwarmProviderState,
    #[serde(rename = "networkId")]
    pub network_id: String,
    #[serde(rename = "activeProvider")]
    pub active_provider: String,
    pub capabilities: BrowserSwarmCapabilitiesV1,
    pub cache: BrowserSwarmCacheStatusV1,
    #[serde(rename = "fallbackAvailable")]
    pub fallback_available: bool,
    pub warnings: Vec<String>,
    #[serde(default)]
    pub error: Option<SwarmAiErrorV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmRetrievalV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default)]
    pub path: Option<String>,
    pub source: BrowserSwarmRetrievalSource,
    #[serde(rename = "fromCache")]
    pub from_cache: bool,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(rename = "cacheKey")]
    pub cache_key: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmCompatibilityReportV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub compatible: bool,
    pub capabilities: BrowserSwarmCapabilitiesV1,
    pub warnings: Vec<String>,
    #[serde(rename = "securityReview")]
    pub security_review: BrowserSwarmSecurityReviewV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmSecurityReviewV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "serviceWorkerScope")]
    pub service_worker_scope: String,
    #[serde(rename = "iframeSandbox")]
    pub iframe_sandbox: String,
    #[serde(rename = "indexedDbBoundary")]
    pub indexed_db_boundary: String,
    #[serde(rename = "uploadApprovalRequired")]
    pub upload_approval_required: bool,
    #[serde(rename = "privateKeyExposure")]
    pub private_key_exposure: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmRetrieveRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmManifestResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub manifest: DirectoryManifestV1,
    pub retrieval: BrowserSwarmRetrievalV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmFileResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "contentBase64")]
    pub content_base64: String,
    pub retrieval: BrowserSwarmRetrievalV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserSwarmReadinessLabelV1 {
    Mock,
    BrowserTest,
    Testnet,
    Production,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserSwarmStorageProviderV6 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "objectKind")]
    pub object_kind: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "providerName")]
    pub provider_name: String,
    #[serde(rename = "providerVersion")]
    pub provider_version: String,
    #[serde(rename = "providerKind")]
    pub provider_kind: StorageProviderKindV4,
    pub profile: BrowserSwarmProviderProfileV1,
    pub readiness: BrowserSwarmReadinessLabelV1,
    #[serde(rename = "executionLayer")]
    pub execution_layer: String,
    #[serde(rename = "publicationLayer")]
    pub publication_layer: String,
    #[serde(rename = "auditLayer")]
    pub audit_layer: String,
    #[serde(rename = "testScope")]
    pub test_scope: String,
    #[serde(rename = "supportedMethods")]
    pub supported_methods: Vec<BrowserSwarmStorageMethodV4>,
    #[serde(rename = "privacyTiers")]
    pub privacy_tiers: Vec<String>,
    #[serde(rename = "integrityTiers")]
    pub integrity_tiers: Vec<String>,
    #[serde(rename = "walletRequired")]
    pub wallet_required: bool,
    #[serde(rename = "explicitConsentRequired")]
    pub explicit_consent_required: bool,
    #[serde(rename = "liveWalletSpendAllowed")]
    pub live_wallet_spend_allowed: bool,
    #[serde(rename = "contractV4")]
    pub contract_v4: BrowserSwarmStorageProviderV4,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserPublishOneResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub provider: BrowserSwarmStorageProviderV6,
    pub probe: BrowserStorageCapabilityProbeV1,
    pub quote: BrowserStoragePurchaseQuoteV1,
    pub authorization: BrowserStoragePurchaseAuthorizationV1,
    pub session: BrowserStorageSessionV2,
    pub upload: UploadResponseV1,
    pub retrieval: BrowserSwarmRetrievalV1,
    #[serde(rename = "contentHash")]
    pub content_hash: String,
    #[serde(rename = "retrievedSizeBytes")]
    pub retrieved_size_bytes: usize,
    #[serde(rename = "verifiedRoundTrip")]
    pub verified_round_trip: bool,
    pub receipts: Vec<StorageEventReceiptV2>,
    #[serde(rename = "stateReport")]
    pub state_report: BrowserStorageStateReportV1,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BrowserSwarmProvider<F> {
    config: BrowserSwarmConfigV1,
    state: BrowserSwarmProviderState,
    cache: BTreeMap<String, DownloadResponseV1>,
    fallback: Option<F>,
    last_error: Option<SwarmAiErrorV1>,
}

pub struct BrowserPublishOnePilot<F> {
    provider_contract: BrowserSwarmStorageProviderV6,
    provider: BrowserSwarmProvider<F>,
    browser_name: String,
    browser_version: String,
    origin: String,
    network_id: Option<String>,
    chain_id: Option<String>,
    wallet_address: String,
    probe: Option<BrowserStorageCapabilityProbeV1>,
    quote: Option<BrowserStoragePurchaseQuoteV1>,
    authorization: Option<BrowserStoragePurchaseAuthorizationV1>,
    session: Option<BrowserStorageSessionV2>,
    receipts: Vec<StorageEventReceiptV2>,
    feed_updates: Vec<StorageFeedUpdateResultV1>,
    sensitive_state_cleared: bool,
}

pub fn descriptor() -> Weeb3AdapterDescriptorV1 {
    Weeb3AdapterDescriptorV1 {
        schema_version: "swarm-ai.weeb3-adapter.v1".to_string(),
        npm_package: "@lat-murmeldjur/weeb_3".to_string(),
        wasm_init: "init()".to_string(),
        client_class: "Weeb3No103".to_string(),
        supports_gateway_fallback: true,
        supports_browser_node: true,
        provider_contract: browser_swarm_provider_contract(),
    }
}

pub fn browser_swarm_provider_contract() -> BrowserSwarmProviderV1 {
    BrowserSwarmProviderV1 {
        schema_version: "swarm-ai.browser-swarm-provider.v1".to_string(),
        methods: vec![
            "start(config)".to_string(),
            "stop()".to_string(),
            "getStatus()".to_string(),
            "retrieve(refOrAddress)".to_string(),
            "downloadManifest(ref)".to_string(),
            "downloadFile(ref, path)".to_string(),
            "upload(file, options)".to_string(),
            "resetStamp()".to_string(),
        ],
    }
}

pub fn mock_browser_swarm_storage_provider_v6() -> BrowserSwarmStorageProviderV6 {
    let contract_v4 = default_browser_swarm_storage_providers_v4()
        .into_iter()
        .find(|provider| provider.provider_id == "weeb3-browser")
        .expect("default browser Swarm provider catalog should include weeb3-browser");
    browser_swarm_storage_provider_v6_from_v4(
        contract_v4,
        BrowserSwarmReadinessLabelV1::BrowserTest,
    )
}

pub fn browser_swarm_storage_provider_v6_from_v4(
    contract_v4: BrowserSwarmStorageProviderV4,
    readiness: BrowserSwarmReadinessLabelV1,
) -> BrowserSwarmStorageProviderV6 {
    let mut warnings = contract_v4.capability_report.security_warnings.clone();
    warnings.extend(contract_v4.capability_report.limitations.clone());
    warnings.push(
        "Mock/browser-test readiness records the production object flow but must not spend live wallet funds"
            .to_string(),
    );

    BrowserSwarmStorageProviderV6 {
        schema_version: BROWSER_SWARM_STORAGE_PROVIDER_V6_SCHEMA_VERSION.to_string(),
        object_kind: "browser_swarm_storage_provider".to_string(),
        provider_id: contract_v4.provider_id.clone(),
        provider_name: contract_v4.provider_name.clone(),
        provider_version: "v6-pilot".to_string(),
        provider_kind: contract_v4.provider_kind.clone(),
        profile: contract_v4.profile.clone(),
        readiness,
        execution_layer: "browser-local-remote-or-miner".to_string(),
        publication_layer: "swarm-bee-weeb3-application-data".to_string(),
        audit_layer: "storage-event-receipt-v2".to_string(),
        test_scope: "mock-first local provider; live wallet and Bee usage must be opt-in"
            .to_string(),
        supported_methods: contract_v4.capability_report.methods.clone(),
        privacy_tiers: vec![
            "public".to_string(),
            "client-side-encrypted".to_string(),
            "provider-managed".to_string(),
        ],
        integrity_tiers: vec![
            "hash-verified".to_string(),
            "receipt-backed".to_string(),
            "replication-or-validation-future".to_string(),
        ],
        wallet_required: contract_v4.wallet_required,
        explicit_consent_required: true,
        live_wallet_spend_allowed: matches!(readiness, BrowserSwarmReadinessLabelV1::Production),
        contract_v4,
        warnings,
    }
}

pub fn zero_dev_storage_cost() -> StorageCostV1 {
    StorageCostV1 {
        amount: 0.0,
        currency: "DEV".to_string(),
        asset: None,
    }
}

pub fn default_browser_swarm_config() -> BrowserSwarmConfigV1 {
    BrowserSwarmConfigV1 {
        schema_version: "swarm-ai.browser-swarm-config.v1".to_string(),
        network_id: "10".to_string(),
        bootstrap_nodes: Vec::new(),
        cache: BrowserSwarmCacheConfigV1 {
            use_indexed_db: true,
            max_bytes: 5_000_000_000,
        },
        fallback: Some(BrowserSwarmFallbackV1 {
            provider: "gateway".to_string(),
            base_url: "http://127.0.0.1:1633".to_string(),
        }),
    }
}

pub fn detect_capabilities(
    config: &BrowserSwarmConfigV1,
    fallback_attached: bool,
) -> BrowserSwarmCapabilitiesV1 {
    let direct_weeb3_possible = !config.bootstrap_nodes.is_empty();
    let retrieval = direct_weeb3_possible || fallback_attached || config.fallback.is_some();
    BrowserSwarmCapabilitiesV1 {
        retrieval,
        upload: false,
        feeds: false,
        service_worker_website_loading: false,
        gateway_fallback: fallback_attached || config.fallback.is_some(),
        package_manifest_download: retrieval,
        model_cache: config.cache.use_indexed_db && config.cache.max_bytes > 0,
    }
}

pub fn security_review(config: &BrowserSwarmConfigV1) -> BrowserSwarmSecurityReviewV1 {
    BrowserSwarmSecurityReviewV1 {
        schema_version: "swarm-ai.browser-swarm-security-review.v1".to_string(),
        service_worker_scope: "must be scoped to the Hivemind app origin and not package content"
            .to_string(),
        iframe_sandbox: "AI package websites must run with an explicit sandbox policy".to_string(),
        indexed_db_boundary: if config.cache.use_indexed_db {
            "public package cache and private package cache must use separate object stores"
                .to_string()
        } else {
            "IndexedDB cache disabled by configuration".to_string()
        },
        upload_approval_required: true,
        private_key_exposure: "publisher keys are never exposed to package code".to_string(),
        notes: vec![
            "Large downloads should be moved to workers when the host browser runtime is attached"
                .to_string(),
            "Gateway fallback must return identical bytes or fail closed".to_string(),
        ],
    }
}

pub fn compatibility_report(
    config: &BrowserSwarmConfigV1,
    fallback_attached: bool,
) -> BrowserSwarmCompatibilityReportV1 {
    let capabilities = detect_capabilities(config, fallback_attached);
    let mut warnings = Vec::new();
    if config.bootstrap_nodes.is_empty() {
        warnings.push("No browser Swarm bootstrap nodes configured".to_string());
    }
    if !fallback_attached && config.fallback.is_some() {
        warnings.push("Fallback is configured but no Rust StorageProvider is attached".to_string());
    }
    if !config.cache.use_indexed_db {
        warnings.push("Browser model cache is disabled".to_string());
    }
    let compatible = capabilities.retrieval && capabilities.package_manifest_download;
    BrowserSwarmCompatibilityReportV1 {
        schema_version: "swarm-ai.browser-swarm-compatibility.v1".to_string(),
        compatible,
        capabilities,
        warnings,
        security_review: security_review(config),
    }
}

impl BrowserSwarmProvider<()> {
    pub fn without_fallback(config: BrowserSwarmConfigV1) -> Self {
        BrowserSwarmProvider {
            config,
            state: BrowserSwarmProviderState::Stopped,
            cache: BTreeMap::new(),
            fallback: None,
            last_error: None,
        }
    }
}

impl<F> BrowserSwarmProvider<F> {
    pub fn config(&self) -> &BrowserSwarmConfigV1 {
        &self.config
    }

    pub fn start(&mut self) -> BrowserSwarmStatusV1 {
        self.state = BrowserSwarmProviderState::Running;
        self.last_error = None;
        self.status()
    }

    pub fn stop(&mut self) -> BrowserSwarmStatusV1 {
        self.state = BrowserSwarmProviderState::Stopped;
        self.status()
    }

    pub fn status(&self) -> BrowserSwarmStatusV1 {
        let fallback_available = self.fallback.is_some();
        let capabilities = detect_capabilities(&self.config, fallback_available);
        let mut warnings = Vec::new();
        if self.config.bootstrap_nodes.is_empty() {
            warnings.push("browser-weeb3-runtime-unattached".to_string());
        }
        if !fallback_available && self.config.fallback.is_some() {
            warnings.push("gateway-fallback-configured-but-unattached".to_string());
        }
        if self.config.cache.max_bytes == 0 {
            warnings.push("browser-cache-disabled-by-size-limit".to_string());
        }

        BrowserSwarmStatusV1 {
            schema_version: "swarm-ai.browser-swarm-status.v1".to_string(),
            state: self.state,
            network_id: self.config.network_id.clone(),
            active_provider: active_provider(&self.config, fallback_available),
            capabilities,
            cache: self.cache_status(),
            fallback_available,
            warnings,
            error: self.last_error.clone(),
        }
    }

    pub fn cache_status(&self) -> BrowserSwarmCacheStatusV1 {
        BrowserSwarmCacheStatusV1 {
            use_indexed_db: self.config.cache.use_indexed_db,
            max_bytes: self.config.cache.max_bytes,
            used_bytes: self
                .cache
                .values()
                .map(|entry| entry.size_bytes as u64)
                .sum(),
            entry_count: self.cache.len(),
        }
    }

    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    pub fn compatibility_report(&self) -> BrowserSwarmCompatibilityReportV1 {
        compatibility_report(&self.config, self.fallback.is_some())
    }

    fn cache_get(&self, reference: &str, path: Option<&str>) -> Option<&DownloadResponseV1> {
        self.cache.get(&cache_key(reference, path))
    }

    fn cache_insert(&mut self, response: DownloadResponseV1) -> Vec<String> {
        let mut warnings = Vec::new();
        if !self.config.cache.use_indexed_db || self.config.cache.max_bytes == 0 {
            warnings.push("cache-disabled".to_string());
            return warnings;
        }
        let used = self.cache_status().used_bytes;
        let next = used.saturating_add(response.size_bytes as u64);
        if next > self.config.cache.max_bytes {
            warnings.push("cache-size-limit-exceeded".to_string());
            return warnings;
        }
        self.cache.insert(
            cache_key(&response.reference, response.path.as_deref()),
            response,
        );
        warnings
    }
}

impl<F: StorageProvider> BrowserSwarmProvider<F> {
    pub fn with_fallback(config: BrowserSwarmConfigV1, fallback: F) -> Self {
        BrowserSwarmProvider {
            config,
            state: BrowserSwarmProviderState::Stopped,
            cache: BTreeMap::new(),
            fallback: Some(fallback),
            last_error: None,
        }
    }

    pub fn retrieve_with_report(
        &mut self,
        reference: &str,
    ) -> Result<(DownloadResponseV1, BrowserSwarmRetrievalV1), SwarmAiErrorV1> {
        if let Some(cached) = self.cache_get(reference, None) {
            let response = cached.clone();
            let report = retrieval_report(
                &response,
                BrowserSwarmRetrievalSource::Cache,
                true,
                Vec::new(),
            );
            return Ok((response, report));
        }

        let Some(fallback) = self.fallback.as_ref() else {
            return Err(unattached_fallback_error(reference, None));
        };
        let response = fallback.download_bytes(reference)?;
        let mut warnings = vec!["retrieved-through-gateway-fallback".to_string()];
        warnings.extend(self.cache_insert(response.clone()));
        let report = retrieval_report(
            &response,
            BrowserSwarmRetrievalSource::GatewayFallback,
            false,
            warnings,
        );
        Ok((response, report))
    }

    pub fn download_manifest_with_report(
        &mut self,
        reference: &str,
    ) -> Result<(DirectoryManifestV1, BrowserSwarmRetrievalV1), SwarmAiErrorV1> {
        let Some(fallback) = self.fallback.as_ref() else {
            return Err(unattached_fallback_error(reference, Some("swarm-ai.json")));
        };
        let manifest = fallback.download_manifest(reference)?;
        let retrieval = BrowserSwarmRetrievalV1 {
            schema_version: "swarm-ai.browser-swarm-retrieval.v1".to_string(),
            reference: reference.to_string(),
            path: None,
            source: BrowserSwarmRetrievalSource::GatewayFallback,
            from_cache: false,
            content_type: "application/vnd.swarm.directory-manifest+json".to_string(),
            size_bytes: manifest.total_bytes,
            sha256: None,
            cache_key: cache_key(reference, None),
            warnings: vec!["manifest-loaded-through-gateway-fallback".to_string()],
        };
        Ok((manifest, retrieval))
    }

    pub fn download_file_with_report(
        &mut self,
        reference: &str,
        path: &str,
    ) -> Result<(DownloadResponseV1, BrowserSwarmRetrievalV1), SwarmAiErrorV1> {
        if let Some(cached) = self.cache_get(reference, Some(path)) {
            let response = cached.clone();
            let report = retrieval_report(
                &response,
                BrowserSwarmRetrievalSource::Cache,
                true,
                Vec::new(),
            );
            return Ok((response, report));
        }

        let Some(fallback) = self.fallback.as_ref() else {
            return Err(unattached_fallback_error(reference, Some(path)));
        };
        let response = fallback.download_file(reference, path)?;
        let mut warnings = vec!["file-loaded-through-gateway-fallback".to_string()];
        warnings.extend(self.cache_insert(response.clone()));
        let report = retrieval_report(
            &response,
            BrowserSwarmRetrievalSource::GatewayFallback,
            false,
            warnings,
        );
        Ok((response, report))
    }

    pub fn upload_bytes_with_approval(
        &mut self,
        bytes: Vec<u8>,
        approved: bool,
    ) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        if !approved {
            return Err(upload_requires_approval());
        }
        let Some(fallback) = self.fallback.as_mut() else {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::UnsupportedOperation,
                "browser Swarm upload requires an attached provider runtime",
            ));
        };
        fallback.upload_bytes(bytes)
    }
}

impl<F: StorageProvider> BrowserPublishOnePilot<F> {
    pub fn mock_with_fallback(
        config: BrowserSwarmConfigV1,
        fallback: F,
        origin: impl Into<String>,
        wallet_address: impl Into<String>,
    ) -> Self {
        Self::with_provider(
            BrowserSwarmProvider::with_fallback(config, fallback),
            mock_browser_swarm_storage_provider_v6(),
            origin,
            wallet_address,
        )
    }

    pub fn with_provider(
        provider: BrowserSwarmProvider<F>,
        provider_contract: BrowserSwarmStorageProviderV6,
        origin: impl Into<String>,
        wallet_address: impl Into<String>,
    ) -> Self {
        let network_id = Some(provider.config.network_id.clone());
        BrowserPublishOnePilot {
            provider_contract,
            provider,
            browser_name: "mock-browser".to_string(),
            browser_version: "browser-test".to_string(),
            origin: origin.into(),
            network_id,
            chain_id: Some("eip155:100".to_string()),
            wallet_address: wallet_address.into(),
            probe: None,
            quote: None,
            authorization: None,
            session: None,
            receipts: Vec::new(),
            feed_updates: Vec::new(),
            sensitive_state_cleared: false,
        }
    }

    pub fn provider_contract(&self) -> &BrowserSwarmStorageProviderV6 {
        &self.provider_contract
    }

    pub fn provider(&self) -> &BrowserSwarmProvider<F> {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut BrowserSwarmProvider<F> {
        &mut self.provider
    }

    pub fn receipts(&self) -> &[StorageEventReceiptV2] {
        &self.receipts
    }

    pub fn probe_capabilities(
        &mut self,
        wallet_providers_detected: Vec<String>,
        estimated_quota_bytes: Option<u64>,
    ) -> Result<BrowserStorageCapabilityProbeV1, SwarmAiErrorV1> {
        let mut probe = browser_storage_capability_probe(
            &self.provider_contract.contract_v4,
            &self.browser_name,
            &self.browser_version,
            &self.origin,
            self.network_id.clone(),
            wallet_providers_detected,
            estimated_quota_bytes,
        );
        sign_browser_storage_capability_probe(&mut probe).map_err(signature_error)?;
        self.probe = Some(probe.clone());
        Ok(probe)
    }

    pub fn quote_purchase(
        &mut self,
        requested_bytes: u64,
        duration_seconds: u64,
        estimated_cost: StorageCostV1,
    ) -> Result<BrowserStoragePurchaseQuoteV1, SwarmAiErrorV1> {
        let probe = self.require_probe()?.clone();
        let mut quote = browser_storage_purchase_quote(
            &self.provider_contract.contract_v4,
            &probe,
            requested_bytes,
            duration_seconds,
            estimated_cost,
            self.chain_id.clone(),
        );
        sign_browser_storage_purchase_quote(&mut quote).map_err(signature_error)?;
        self.quote = Some(quote.clone());
        Ok(quote)
    }

    pub fn authorize_purchase(
        &mut self,
        approved: bool,
        prompt_text: impl AsRef<[u8]>,
    ) -> Result<BrowserStoragePurchaseAuthorizationV1, SwarmAiErrorV1> {
        let quote = self.require_quote()?.clone();
        let mut authorization = browser_storage_purchase_authorization(
            &quote,
            self.wallet_address.clone(),
            approved,
            prompt_text,
        );
        sign_browser_storage_purchase_authorization(&mut authorization).map_err(signature_error)?;
        self.authorization = Some(authorization.clone());
        Ok(authorization)
    }

    pub fn start_session(
        &mut self,
        approved: bool,
    ) -> Result<BrowserStorageSessionV2, SwarmAiErrorV1> {
        require_explicit_consent("start_session", approved)?;
        if let Some(session) = self.session.clone() {
            return Ok(session);
        }

        let probe = self.require_probe()?.clone();
        let authorization = self.authorization.clone();
        let (quota_bytes, duration_seconds) = self
            .quote
            .as_ref()
            .map(|quote| (quote.requested_bytes, quote.duration_seconds))
            .unwrap_or((64 * 1024 * 1024, 60 * 60));
        let mut session = browser_storage_session_v2(
            &self.provider_contract.contract_v4,
            &probe,
            authorization.as_ref(),
            quota_bytes,
            duration_seconds,
        );
        sign_browser_storage_session_v2(&mut session).map_err(signature_error)?;
        self.session = Some(session.clone());
        self.record_receipt(
            StorageEventActionV2::Start,
            None,
            None,
            None,
            0,
            StorageEventStatusV1::Succeeded,
        )?;
        Ok(session)
    }

    pub fn buy_or_reuse_storage(
        &mut self,
        approved: bool,
        reuse_existing: bool,
    ) -> Result<StorageEventReceiptV2, SwarmAiErrorV1> {
        require_explicit_consent("buy_or_reuse_storage", approved)?;
        if !reuse_existing {
            let authorization = self.require_authorization()?;
            if !authorization.approved {
                return Err(SwarmAiErrorV1::new(
                    ErrorCode::AccessDenied,
                    "storage purchase cannot proceed without approved wallet authorization",
                ));
            }
        }
        let session = self.start_session(true)?;
        let action = if reuse_existing {
            StorageEventActionV2::Reuse
        } else {
            StorageEventActionV2::Buy
        };
        self.record_receipt(
            action,
            None,
            None,
            None,
            session.quota_bytes,
            StorageEventStatusV1::Succeeded,
        )
    }

    pub fn reset_storage(
        &mut self,
        approved: bool,
    ) -> Result<StorageEventReceiptV2, SwarmAiErrorV1> {
        require_explicit_consent("reset_storage", approved)?;
        self.require_permission(BrowserStoragePermissionV1::ResetStorage)?;
        self.provider.clear_cache();
        self.sensitive_state_cleared = true;
        self.record_receipt(
            StorageEventActionV2::Reset,
            None,
            None,
            None,
            0,
            StorageEventStatusV1::Succeeded,
        )
    }

    pub fn upload_blob(
        &mut self,
        bytes: Vec<u8>,
        approved: bool,
    ) -> Result<(UploadResponseV1, StorageEventReceiptV2), SwarmAiErrorV1> {
        require_explicit_consent("upload_blob", approved)?;
        self.require_permission(BrowserStoragePermissionV1::Upload)?;
        let content_hash = sha256_content_hash(&bytes);
        let upload = self.provider.upload_bytes_with_approval(bytes, true)?;
        let receipt = self.record_receipt(
            StorageEventActionV2::Upload,
            None,
            Some(upload.reference.clone()),
            Some(content_hash),
            upload.size_bytes as u64,
            StorageEventStatusV1::Succeeded,
        )?;
        Ok((upload, receipt))
    }

    pub fn upload_file(
        &mut self,
        bytes: Vec<u8>,
        _file_name: impl AsRef<str>,
        approved: bool,
    ) -> Result<(UploadResponseV1, StorageEventReceiptV2), SwarmAiErrorV1> {
        self.upload_blob(bytes, approved)
    }

    pub fn upload_manifest(
        &mut self,
        manifest_json: Vec<u8>,
        approved: bool,
    ) -> Result<(UploadResponseV1, StorageEventReceiptV2), SwarmAiErrorV1> {
        self.upload_blob(manifest_json, approved)
    }

    pub fn upload_directory(
        &mut self,
        root: &Path,
        approved: bool,
    ) -> Result<(UploadResponseV1, StorageEventReceiptV2), SwarmAiErrorV1> {
        require_explicit_consent("upload_directory", approved)?;
        self.require_permission(BrowserStoragePermissionV1::Upload)?;
        let Some(fallback) = self.provider.fallback.as_mut() else {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::UnsupportedOperation,
                "browser Swarm directory upload requires an attached provider runtime",
            ));
        };
        let upload = fallback.upload_directory(root)?;
        let receipt = self.record_receipt(
            StorageEventActionV2::Upload,
            None,
            Some(upload.reference.clone()),
            Some(format!("directory-ref:{}", upload.reference)),
            upload.size_bytes as u64,
            StorageEventStatusV1::Succeeded,
        )?;
        Ok((upload, receipt))
    }

    pub fn retrieve(
        &mut self,
        reference: &str,
        expected_content_hash: Option<&str>,
    ) -> Result<
        (
            DownloadResponseV1,
            BrowserSwarmRetrievalV1,
            StorageEventReceiptV2,
        ),
        SwarmAiErrorV1,
    > {
        self.require_permission(BrowserStoragePermissionV1::Retrieve)?;
        let (download, retrieval) = self.provider.retrieve_with_report(reference)?;
        let content_hash = sha256_content_hash(&download.bytes);
        if let Some(expected) = expected_content_hash
            && !content_hash_matches(expected, &content_hash)
        {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::ValidationFailed,
                "retrieved bytes did not match expected content hash",
            )
            .with_details(json!({
                "ref": reference,
                "expected": expected,
                "actual": content_hash,
            })));
        }
        let receipt = self.record_receipt(
            StorageEventActionV2::Retrieve,
            None,
            Some(download.reference.clone()),
            Some(content_hash),
            download.size_bytes as u64,
            StorageEventStatusV1::Succeeded,
        )?;
        Ok((download, retrieval, receipt))
    }

    pub fn update_feed(
        &mut self,
        topic: &str,
        owner: &str,
        reference: &str,
        approved: bool,
    ) -> Result<(StorageFeedUpdateResultV1, StorageEventReceiptV2), SwarmAiErrorV1> {
        require_explicit_consent("update_feed", approved)?;
        self.require_permission(BrowserStoragePermissionV1::FeedUpdate)?;
        let Some(fallback) = self.provider.fallback.as_mut() else {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::UnsupportedOperation,
                "browser Swarm feed update requires an attached provider runtime",
            ));
        };
        let update = fallback.update_feed(topic, owner, reference)?;
        let receipt = self.record_receipt(
            StorageEventActionV2::FeedUpdate,
            Some(topic.to_string()),
            Some(reference.to_string()),
            None,
            0,
            StorageEventStatusV1::Succeeded,
        )?;
        self.feed_updates.push(update.clone());
        Ok((update, receipt))
    }

    pub fn clear_sensitive_state(
        &mut self,
        approved: bool,
    ) -> Result<(StorageEventReceiptV2, BrowserStorageStateReportV1), SwarmAiErrorV1> {
        require_explicit_consent("clear_sensitive_state", approved)?;
        self.require_session()?;
        self.provider.clear_cache();
        self.sensitive_state_cleared = true;
        let receipt = self.record_receipt(
            StorageEventActionV2::ClearState,
            None,
            None,
            None,
            0,
            StorageEventStatusV1::Succeeded,
        )?;
        let report = self.state_report()?;
        Ok((receipt, report))
    }

    pub fn state_report(&mut self) -> Result<BrowserStorageStateReportV1, SwarmAiErrorV1> {
        let session = self.require_session()?.clone();
        let mut entries = Vec::new();
        let cache_status = self.provider.cache_status();
        if cache_status.entry_count > 0 && !self.sensitive_state_cleared {
            entries.push(BrowserStorageStateEntryV1 {
                state_kind: "indexed-db-cache".to_string(),
                key_ref: "local://browser-storage/indexed-db/cache".to_string(),
                sensitive: false,
                clearable: true,
                size_bytes: Some(cache_status.used_bytes),
            });
        }
        if !self.receipts.is_empty() && !self.sensitive_state_cleared {
            entries.push(BrowserStorageStateEntryV1 {
                state_kind: "receipt-index".to_string(),
                key_ref: "local://browser-storage/receipts".to_string(),
                sensitive: true,
                clearable: true,
                size_bytes: None,
            });
        }
        let mut report =
            browser_storage_state_report(&session, entries, vec![format!("{}/", self.origin)]);
        sign_browser_storage_state_report(&mut report).map_err(signature_error)?;
        Ok(report)
    }

    pub fn publish_one_blob(
        &mut self,
        bytes: Vec<u8>,
    ) -> Result<BrowserPublishOneResultV1, SwarmAiErrorV1> {
        let expected_bytes = bytes.clone();
        let requested_bytes = (bytes.len() as u64).max(1024 * 1024);
        let probe = self.probe_capabilities(
            vec!["mock-wallet".to_string()],
            Some(requested_bytes.max(self.provider.config.cache.max_bytes)),
        )?;
        let quote = self.quote_purchase(requested_bytes, 60 * 60, zero_dev_storage_cost())?;
        let authorization = self.authorize_purchase(
            true,
            "Approve mock browser storage purchase for Hivemind publish-one pilot",
        )?;
        self.buy_or_reuse_storage(true, false)?;
        let content_hash = sha256_content_hash(&bytes);
        let (upload, _upload_receipt) = self.upload_blob(bytes, true)?;
        let (download, retrieval, _retrieve_receipt) =
            self.retrieve(&upload.reference, Some(&content_hash))?;
        let state_report = self.state_report()?;
        Ok(BrowserPublishOneResultV1 {
            schema_version: BROWSER_PUBLISH_ONE_RESULT_SCHEMA_VERSION.to_string(),
            provider: self.provider_contract.clone(),
            probe,
            quote,
            authorization,
            session: self.require_session()?.clone(),
            upload,
            retrieval,
            content_hash,
            retrieved_size_bytes: download.size_bytes,
            verified_round_trip: download.bytes == expected_bytes,
            receipts: self.receipts.clone(),
            state_report,
            warnings: self.provider_contract.warnings.clone(),
        })
    }

    fn require_probe(&self) -> Result<&BrowserStorageCapabilityProbeV1, SwarmAiErrorV1> {
        self.probe
            .as_ref()
            .ok_or_else(|| missing_pilot_state("probe", "probe_capabilities"))
    }

    fn require_quote(&self) -> Result<&BrowserStoragePurchaseQuoteV1, SwarmAiErrorV1> {
        self.quote
            .as_ref()
            .ok_or_else(|| missing_pilot_state("quote", "quote_purchase"))
    }

    fn require_authorization(
        &self,
    ) -> Result<&BrowserStoragePurchaseAuthorizationV1, SwarmAiErrorV1> {
        self.authorization
            .as_ref()
            .ok_or_else(|| missing_pilot_state("authorization", "authorize_purchase"))
    }

    fn require_session(&self) -> Result<&BrowserStorageSessionV2, SwarmAiErrorV1> {
        self.session
            .as_ref()
            .ok_or_else(|| missing_pilot_state("session", "start_session"))
    }

    fn require_permission(
        &self,
        permission: BrowserStoragePermissionV1,
    ) -> Result<(), SwarmAiErrorV1> {
        let session = self.require_session()?;
        if session.permissions.contains(&permission) {
            Ok(())
        } else {
            Err(SwarmAiErrorV1::new(
                ErrorCode::AccessDenied,
                "browser storage session does not include the requested permission",
            )
            .with_details(json!({ "permission": permission })))
        }
    }

    fn record_receipt(
        &mut self,
        action: StorageEventActionV2,
        feed_topic: Option<String>,
        reference: Option<String>,
        content_hash: Option<String>,
        byte_size: u64,
        status: StorageEventStatusV1,
    ) -> Result<StorageEventReceiptV2, SwarmAiErrorV1> {
        let session = self.require_session()?.clone();
        let mut receipt = storage_event_receipt_v2(
            &session,
            action,
            reference,
            content_hash,
            byte_size,
            BrowserStorageEncryptionModeV1::None,
            status,
            None,
        );
        receipt.feed_topic = feed_topic;
        sign_storage_event_receipt_v2(&mut receipt).map_err(signature_error)?;
        self.receipts.push(receipt.clone());
        Ok(receipt)
    }
}

impl<F: StorageProvider> StorageProvider for BrowserSwarmProvider<F> {
    fn get_status(&self) -> StorageStatusV1 {
        let status = self.status();
        StorageStatusV1 {
            schema_version: "swarm-ai.storage.status.v1".to_string(),
            provider: "browser-swarm-weeb3".to_string(),
            capabilities: StorageCapabilities {
                upload: false,
                download: status.capabilities.retrieval,
                feeds: false,
                pinning: false,
                act: false,
                pss: false,
            },
            retry_policy: None,
        }
    }

    fn download_bytes(&self, reference: &str) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        if let Some(cached) = self.cache_get(reference, None) {
            return Ok(cached.clone());
        }
        let Some(fallback) = self.fallback.as_ref() else {
            return Err(unattached_fallback_error(reference, None));
        };
        fallback.download_bytes(reference)
    }

    fn upload_bytes(&mut self, _bytes: Vec<u8>) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        Err(upload_requires_approval())
    }

    fn upload_directory(
        &mut self,
        _root: &std::path::Path,
    ) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        Err(upload_requires_approval())
    }

    fn download_manifest(&self, reference: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1> {
        let Some(fallback) = self.fallback.as_ref() else {
            return Err(unattached_fallback_error(reference, None));
        };
        fallback.download_manifest(reference)
    }

    fn download_file(
        &self,
        reference: &str,
        path: &str,
    ) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        if let Some(cached) = self.cache_get(reference, Some(path)) {
            return Ok(cached.clone());
        }
        let Some(fallback) = self.fallback.as_ref() else {
            return Err(unattached_fallback_error(reference, Some(path)));
        };
        fallback.download_file(reference, path)
    }
}

pub fn cache_key(reference: &str, path: Option<&str>) -> String {
    match path {
        Some(path) => format!("{}#{}", reference.trim(), path.trim()),
        None => reference.trim().to_string(),
    }
}

pub fn retrieval_report(
    response: &DownloadResponseV1,
    source: BrowserSwarmRetrievalSource,
    from_cache: bool,
    warnings: Vec<String>,
) -> BrowserSwarmRetrievalV1 {
    BrowserSwarmRetrievalV1 {
        schema_version: "swarm-ai.browser-swarm-retrieval.v1".to_string(),
        reference: response.reference.clone(),
        path: response.path.clone(),
        source,
        from_cache,
        content_type: response.content_type.clone(),
        size_bytes: response.size_bytes,
        sha256: response.sha256.clone(),
        cache_key: cache_key(&response.reference, response.path.as_deref()),
        warnings,
    }
}

pub fn encode_file_result(
    response: DownloadResponseV1,
    retrieval: BrowserSwarmRetrievalV1,
) -> BrowserSwarmFileResultV1 {
    BrowserSwarmFileResultV1 {
        schema_version: "swarm-ai.browser-swarm-file-result.v1".to_string(),
        content_base64: base64_encode(&response.bytes),
        retrieval,
    }
}

fn active_provider(config: &BrowserSwarmConfigV1, fallback_available: bool) -> String {
    if !config.bootstrap_nodes.is_empty() {
        "weeb3".to_string()
    } else if fallback_available {
        "gateway-fallback".to_string()
    } else {
        "unattached".to_string()
    }
}

fn unattached_fallback_error(reference: &str, path: Option<&str>) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(
        ErrorCode::UnsupportedOperation,
        "browser Swarm retrieval needs the weeb3 runtime or an attached fallback provider",
    )
    .with_details(json!({ "ref": reference, "path": path }))
}

fn upload_requires_approval() -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(
        ErrorCode::AccessDenied,
        "browser Swarm uploads require explicit user approval",
    )
}

fn require_explicit_consent(action: &str, approved: bool) -> Result<(), SwarmAiErrorV1> {
    if approved {
        Ok(())
    } else {
        Err(SwarmAiErrorV1::new(
            ErrorCode::AccessDenied,
            "browser storage action requires explicit user approval",
        )
        .with_details(json!({ "action": action })))
    }
}

fn missing_pilot_state(state: &str, required_method: &str) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(
        ErrorCode::InvalidRequest,
        "browser publish-one pilot lifecycle state is missing",
    )
    .with_details(json!({
        "missing": state,
        "requiredMethod": required_method,
    }))
}

fn signature_error(error: serde_json::Error) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(
        ErrorCode::ExecutionFailed,
        "failed to sign browser storage lifecycle object",
    )
    .with_details(json!({ "error": error.to_string() }))
}

fn sha256_content_hash(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn content_hash_matches(expected: &str, actual: &str) -> bool {
    let expected = expected.strip_prefix("sha256:").unwrap_or(expected);
    let actual = actual.strip_prefix("sha256:").unwrap_or(actual);
    expected == actual
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0b0000_0011) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b1 & 0b0000_1111) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(b2 & 0b0011_1111) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_storage::{
        LocalDirectoryStorageProvider, MemoryStorageProvider, StorageProvider,
        verify_browser_storage_state_report, verify_storage_event_receipt_v2,
    };
    use std::fs;

    #[test]
    fn reports_gateway_fallback_status() {
        let config = default_browser_swarm_config();
        let fallback = LocalDirectoryStorageProvider::new(std::env::temp_dir());
        let mut provider = BrowserSwarmProvider::with_fallback(config, fallback);

        let status = provider.start();

        assert_eq!(status.state, BrowserSwarmProviderState::Running);
        assert_eq!(status.active_provider, "gateway-fallback");
        assert!(status.capabilities.retrieval);
        assert!(status.capabilities.model_cache);
    }

    #[test]
    fn downloads_file_through_fallback_and_cache() {
        let root = std::env::temp_dir().join(format!(
            "hivemind-weeb3-adapter-test-{}",
            std::process::id()
        ));
        let package = root.join("package");
        let storage_root = root.join("storage");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(package.join("model")).unwrap();
        fs::write(package.join("swarm-ai.json"), "{}").unwrap();
        fs::write(package.join("model/config.json"), "{\"ok\":true}").unwrap();

        let mut storage = LocalDirectoryStorageProvider::new(&storage_root);
        let upload = storage.upload_directory(&package).unwrap();
        let mut provider =
            BrowserSwarmProvider::with_fallback(default_browser_swarm_config(), storage);

        let (first, first_report) = provider
            .download_file_with_report(&upload.reference, "model/config.json")
            .unwrap();
        let (second, second_report) = provider
            .download_file_with_report(&upload.reference, "model/config.json")
            .unwrap();

        assert_eq!(first.bytes, b"{\"ok\":true}");
        assert_eq!(first.bytes, second.bytes);
        assert!(!first_report.from_cache);
        assert!(second_report.from_cache);
        assert_eq!(provider.cache_status().entry_count, 1);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn upload_requires_explicit_approval() {
        let fallback = LocalDirectoryStorageProvider::new(std::env::temp_dir());
        let mut provider =
            BrowserSwarmProvider::with_fallback(default_browser_swarm_config(), fallback);

        let error = provider.upload_bytes(vec![1, 2, 3]).unwrap_err();

        assert_eq!(error.code, ErrorCode::AccessDenied);
    }

    #[test]
    fn publish_one_pilot_round_trips_and_signs_receipts() {
        let storage = MemoryStorageProvider::default();
        let mut pilot = BrowserPublishOnePilot::mock_with_fallback(
            default_browser_swarm_config(),
            storage,
            "https://hivemind.local",
            "0x0000000000000000000000000000000000000001",
        );

        let result = pilot
            .publish_one_blob(b"browser publish-one pilot".to_vec())
            .unwrap();

        assert_eq!(
            result.provider.schema_version,
            BROWSER_SWARM_STORAGE_PROVIDER_V6_SCHEMA_VERSION
        );
        assert_eq!(
            result.provider.readiness,
            BrowserSwarmReadinessLabelV1::BrowserTest
        );
        assert!(result.verified_round_trip);
        assert!(result.content_hash.starts_with("sha256:"));
        assert!(result.receipts.iter().any(|receipt| {
            receipt.action == StorageEventActionV2::Upload
                && receipt.reference.as_deref() == Some(result.upload.reference.as_str())
        }));
        assert!(
            result
                .receipts
                .iter()
                .all(|receipt| verify_storage_event_receipt_v2(receipt).valid)
        );
        assert!(verify_browser_storage_state_report(&result.state_report).valid);
    }

    #[test]
    fn publish_one_pilot_refuses_upload_without_consent() {
        let storage = MemoryStorageProvider::default();
        let mut pilot = BrowserPublishOnePilot::mock_with_fallback(
            default_browser_swarm_config(),
            storage,
            "https://hivemind.local",
            "0x0000000000000000000000000000000000000001",
        );

        pilot
            .probe_capabilities(vec!["mock-wallet".to_string()], Some(1024 * 1024))
            .unwrap();
        pilot
            .quote_purchase(1024 * 1024, 60 * 60, zero_dev_storage_cost())
            .unwrap();
        pilot
            .authorize_purchase(true, "Approve mock storage")
            .unwrap();
        pilot.buy_or_reuse_storage(true, false).unwrap();

        let error = pilot
            .upload_blob(b"no consent".to_vec(), false)
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::AccessDenied);
        assert!(
            !pilot
                .receipts()
                .iter()
                .any(|receipt| receipt.action == StorageEventActionV2::Upload)
        );
    }

    #[test]
    fn publish_one_pilot_records_feed_reset_and_clear_state() {
        let storage = MemoryStorageProvider::default();
        let mut pilot = BrowserPublishOnePilot::mock_with_fallback(
            default_browser_swarm_config(),
            storage,
            "https://hivemind.local",
            "0x0000000000000000000000000000000000000001",
        );

        pilot
            .probe_capabilities(vec!["mock-wallet".to_string()], Some(1024 * 1024))
            .unwrap();
        pilot
            .quote_purchase(1024 * 1024, 60 * 60, zero_dev_storage_cost())
            .unwrap();
        pilot
            .authorize_purchase(true, "Approve mock storage")
            .unwrap();
        pilot.buy_or_reuse_storage(true, false).unwrap();
        let (upload, _) = pilot.upload_blob(b"feed target".to_vec(), true).unwrap();

        let (feed_update, feed_receipt) = pilot
            .update_feed(
                "hivemind-test-feed",
                "0x0000000000000000000000000000000000000001",
                &upload.reference,
                true,
            )
            .unwrap();
        let reset_receipt = pilot.reset_storage(true).unwrap();
        let (clear_receipt, clear_report) = pilot.clear_sensitive_state(true).unwrap();

        assert_eq!(
            feed_update.pointer.target_ref.as_deref(),
            Some(upload.reference.as_str())
        );
        assert_eq!(feed_receipt.action, StorageEventActionV2::FeedUpdate);
        assert_eq!(reset_receipt.action, StorageEventActionV2::Reset);
        assert_eq!(clear_receipt.action, StorageEventActionV2::ClearState);
        assert!(clear_report.indexed_db_entries.is_empty());
        assert!(verify_storage_event_receipt_v2(&feed_receipt).valid);
        assert!(verify_storage_event_receipt_v2(&reset_receipt).valid);
        assert!(verify_storage_event_receipt_v2(&clear_receipt).valid);
        assert!(verify_browser_storage_state_report(&clear_report).valid);
    }
}
