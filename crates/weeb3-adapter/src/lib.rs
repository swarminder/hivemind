use hivemind_core::{ErrorCode, SwarmAiErrorV1};
use hivemind_storage::{
    DirectoryManifestV1, DownloadResponseV1, StorageCapabilities, StorageProvider, StorageStatusV1,
    UploadResponseV1,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

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

#[derive(Debug, Clone)]
pub struct BrowserSwarmProvider<F> {
    config: BrowserSwarmConfigV1,
    state: BrowserSwarmProviderState,
    cache: BTreeMap<String, DownloadResponseV1>,
    fallback: Option<F>,
    last_error: Option<SwarmAiErrorV1>,
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
    use hivemind_storage::{LocalDirectoryStorageProvider, StorageProvider};
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
}
