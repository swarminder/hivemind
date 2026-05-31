use chrono::{SecondsFormat, Utc};
use hivemind_core::{ErrorCode, SwarmAiErrorV1, canonicalize_json, hash_canonical_json};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const BEE_DEFAULT_MAX_RETRIES: u32 = 2;
const BEE_RETRY_BACKOFF_MS: u64 = 150;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageCapabilities {
    pub upload: bool,
    pub download: bool,
    pub feeds: bool,
    pub pinning: bool,
    pub act: bool,
    pub pss: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageStatusV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub provider: String,
    pub capabilities: StorageCapabilities,
    #[serde(
        rename = "retryPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub retry_policy: Option<StorageRetryPolicyV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageRetryPolicyV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "maxRetries")]
    pub max_retries: u32,
    #[serde(rename = "backoffMs")]
    pub backoff_ms: u64,
    #[serde(rename = "retryableStatusCodes")]
    pub retryable_status_codes: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageFeedPointerV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "feedRef")]
    pub feed_ref: String,
    pub topic: String,
    pub owner: String,
    #[serde(rename = "targetRef", default)]
    pub target_ref: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageFeedUpdateResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "feedRef")]
    pub feed_ref: String,
    pub pointer: StorageFeedPointerV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageFeedResolutionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "feedRef")]
    pub feed_ref: String,
    pub pointer: StorageFeedPointerV1,
    #[serde(rename = "targetRef", default)]
    pub target_ref: Option<String>,
    #[serde(rename = "resolvedAt")]
    pub resolved_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StoragePinResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub pinned: bool,
    pub provider: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StorageTransferMetricsV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "resolveMs")]
    pub resolve_ms: u64,
    #[serde(rename = "firstByteMs")]
    pub first_byte_ms: u64,
    #[serde(rename = "totalMs")]
    pub total_ms: u64,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    #[serde(rename = "retryCount")]
    pub retry_count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DownloadResponseV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub path: Option<String>,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    pub sha256: Option<String>,
    pub metrics: StorageTransferMetricsV1,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UploadResponseV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    pub pinned: bool,
    #[serde(rename = "redundancyLevel")]
    pub redundancy_level: u8,
    #[serde(rename = "postageBatchId")]
    pub postage_batch_id: Option<String>,
    pub metrics: StorageTransferMetricsV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StoredFileV1 {
    pub path: String,
    #[serde(rename = "contentRef")]
    pub content_ref: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DirectoryManifestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub files: Vec<StoredFileV1>,
    #[serde(rename = "totalBytes")]
    pub total_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LocalStorageInspectionV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub kind: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    #[serde(rename = "fileCount")]
    pub file_count: usize,
    #[serde(default)]
    pub manifest: Option<DirectoryManifestV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LocalStorageCacheSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "objectCount")]
    pub object_count: usize,
    #[serde(rename = "manifestCount")]
    pub manifest_count: usize,
    #[serde(rename = "totalObjectBytes")]
    pub total_object_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BeeStorageConfig {
    #[serde(rename = "apiUrl")]
    pub api_url: String,
    #[serde(rename = "postageBatchId")]
    pub postage_batch_id: Option<String>,
    pub pin: bool,
    #[serde(rename = "deferredUpload")]
    pub deferred_upload: bool,
    #[serde(rename = "redundancyLevel")]
    pub redundancy_level: u8,
}

impl BeeStorageConfig {
    pub fn local(postage_batch_id: Option<String>) -> Self {
        Self {
            api_url: "http://127.0.0.1:1633".to_string(),
            postage_batch_id,
            pin: false,
            deferred_upload: true,
            redundancy_level: 0,
        }
    }

    pub fn status(&self) -> StorageStatusV1 {
        StorageStatusV1 {
            schema_version: "swarm-ai.storage.status.v1".to_string(),
            provider: "bee-http".to_string(),
            capabilities: StorageCapabilities {
                upload: self.postage_batch_id.is_some(),
                download: true,
                feeds: false,
                pinning: true,
                act: false,
                pss: false,
            },
            retry_policy: Some(bee_retry_policy()),
        }
    }
}

pub trait StorageProvider {
    fn get_status(&self) -> StorageStatusV1;
    fn download_bytes(&self, reference: &str) -> Result<DownloadResponseV1, SwarmAiErrorV1>;
    fn upload_bytes(&mut self, bytes: Vec<u8>) -> Result<UploadResponseV1, SwarmAiErrorV1>;
    fn upload_directory(&mut self, root: &Path) -> Result<UploadResponseV1, SwarmAiErrorV1>;
    fn download_manifest(&self, reference: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1>;
    fn download_file(
        &self,
        reference: &str,
        path: &str,
    ) -> Result<DownloadResponseV1, SwarmAiErrorV1>;
    fn create_feed(
        &mut self,
        topic: &str,
        owner: &str,
    ) -> Result<StorageFeedPointerV1, SwarmAiErrorV1> {
        let _ = (topic, owner);
        Err(unsupported(
            "storage provider does not support feed creation",
        ))
    }
    fn update_feed(
        &mut self,
        topic: &str,
        owner: &str,
        reference: &str,
    ) -> Result<StorageFeedUpdateResultV1, SwarmAiErrorV1> {
        let _ = (topic, owner, reference);
        Err(unsupported(
            "storage provider does not support feed updates",
        ))
    }
    fn resolve_feed(&self, feed_ref: &str) -> Result<StorageFeedResolutionV1, SwarmAiErrorV1> {
        let _ = feed_ref;
        Err(unsupported(
            "storage provider does not support feed resolution",
        ))
    }
    fn pin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        let _ = reference;
        Err(unsupported("storage provider does not support pinning"))
    }
    fn unpin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        let _ = reference;
        Err(unsupported("storage provider does not support unpinning"))
    }
}

#[derive(Debug, Clone)]
pub struct BeeHttpStorageProvider {
    config: BeeStorageConfig,
}

#[derive(Debug, Deserialize)]
struct BeeReferenceResponse {
    reference: String,
}

#[derive(Debug, Clone)]
enum BeeHttpMethod {
    Get,
    Post,
    Delete,
}

#[derive(Debug, Clone)]
struct BeeHttpRequest {
    method: BeeHttpMethod,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct BeeHttpResponse {
    status: reqwest::StatusCode,
    content_type: String,
    bytes: Vec<u8>,
}

impl BeeHttpRequest {
    fn get(url: String) -> Self {
        Self {
            method: BeeHttpMethod::Get,
            url,
            headers: Vec::new(),
            body: None,
        }
    }

    fn post(url: String) -> Self {
        Self {
            method: BeeHttpMethod::Post,
            url,
            headers: Vec::new(),
            body: None,
        }
    }

    fn delete(url: String) -> Self {
        Self {
            method: BeeHttpMethod::Delete,
            url,
            headers: Vec::new(),
            body: None,
        }
    }

    fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }
}

impl BeeHttpResponse {
    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).to_string()
    }
}

impl BeeHttpStorageProvider {
    pub fn new(config: BeeStorageConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &BeeStorageConfig {
        &self.config
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.config.api_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    fn upload_request(&self, path: &str) -> Result<BeeHttpRequest, SwarmAiErrorV1> {
        let Some(batch_id) = self.config.postage_batch_id.as_deref() else {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "Bee uploads require a postage batch id",
            ));
        };

        Ok(BeeHttpRequest::post(self.endpoint(path))
            .header("swarm-postage-batch-id", batch_id)
            .header("swarm-pin", self.config.pin.to_string())
            .header(
                "swarm-deferred-upload",
                self.config.deferred_upload.to_string(),
            )
            .header(
                "swarm-redundancy-level",
                self.config.redundancy_level.to_string(),
            ))
    }

    fn response_error(
        &self,
        status: reqwest::StatusCode,
        body: String,
        operation: &str,
        retry_count: u32,
    ) -> SwarmAiErrorV1 {
        let code = match status.as_u16() {
            400 => ErrorCode::InvalidRequest,
            402 | 403 => ErrorCode::AccessDenied,
            404 => ErrorCode::PackageNotFound,
            _ => ErrorCode::ExecutionFailed,
        };
        SwarmAiErrorV1::new(code, format!("Bee {operation} failed with HTTP {status}"))
            .with_details(json!({ "body": body, "retryCount": retry_count }))
    }

    fn send_with_retry(
        &self,
        operation: &str,
        mut request: impl FnMut() -> Result<BeeHttpRequest, SwarmAiErrorV1>,
    ) -> Result<(BeeHttpResponse, u32), SwarmAiErrorV1> {
        let mut retry_count = 0;
        loop {
            let request = request()?;
            match send_bee_http_request(request, operation) {
                Ok(response) => {
                    if is_transient_status(response.status) && retry_count < BEE_DEFAULT_MAX_RETRIES
                    {
                        retry_count += 1;
                        sleep_before_retry(retry_count);
                        continue;
                    }
                    return Ok((response, retry_count));
                }
                Err(error) => {
                    if retry_count < BEE_DEFAULT_MAX_RETRIES {
                        retry_count += 1;
                        sleep_before_retry(retry_count);
                        continue;
                    }
                    return Err(bee_error_with_retry(error, operation, retry_count));
                }
            }
        }
    }
}

impl StorageProvider for BeeHttpStorageProvider {
    fn get_status(&self) -> StorageStatusV1 {
        self.config.status()
    }

    fn download_bytes(&self, reference: &str) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let reference = normalize_ref(reference);
        let endpoint = self.endpoint(&format!("bytes/{reference}"));
        let (response, retry_count) = self.send_with_retry("download bytes", || {
            Ok(BeeHttpRequest::get(endpoint.clone()))
        })?;
        let first_byte_ms = elapsed_ms(start);
        let status = response.status;
        if !status.is_success() {
            let body = response.body_text();
            return Err(self.response_error(status, body, "download bytes", retry_count));
        }
        let bytes = response.bytes;
        let metrics = transfer_metrics(start, first_byte_ms, bytes.len(), retry_count);
        Ok(DownloadResponseV1 {
            schema_version: "swarm-ai.storage.download.v1".to_string(),
            reference: normalized_ref(&reference),
            path: None,
            content_type: response.content_type,
            size_bytes: bytes.len(),
            sha256: Some(sha256_hex(&bytes)),
            metrics,
            bytes,
        })
    }

    fn upload_bytes(&mut self, bytes: Vec<u8>) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let size_bytes = bytes.len();
        let (response, retry_count) = self.send_with_retry("upload bytes", || {
            Ok(self
                .upload_request("bytes")?
                .header("content-type", "application/octet-stream")
                .body(bytes.clone()))
        })?;
        let first_byte_ms = elapsed_ms(start);
        let status = response.status;
        if !status.is_success() {
            let body = response.body_text();
            return Err(self.response_error(status, body, "upload bytes", retry_count));
        }
        let body = parse_bee_reference_response(&response.bytes, "upload bytes")?;
        Ok(upload_response(
            normalized_ref(&body.reference),
            size_bytes,
            self.config.pin,
            self.config.redundancy_level,
            transfer_metrics(start, first_byte_ms, size_bytes, retry_count),
        ))
    }

    fn upload_directory(&mut self, root: &Path) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let tarball = tar_directory(root)?;
        let size_bytes = tarball.len();
        let (response, retry_count) = self.send_with_retry("upload directory", || {
            Ok(self
                .upload_request("bzz")?
                .header("content-type", "application/x-tar")
                .header("swarm-collection", "true")
                .body(tarball.clone()))
        })?;
        let first_byte_ms = elapsed_ms(start);
        let status = response.status;
        if !status.is_success() {
            let body = response.body_text();
            return Err(self.response_error(status, body, "upload directory", retry_count));
        }
        let body = parse_bee_reference_response(&response.bytes, "upload directory")?;
        Ok(upload_response(
            normalized_ref(&body.reference),
            size_bytes,
            self.config.pin,
            self.config.redundancy_level,
            transfer_metrics(start, first_byte_ms, size_bytes, retry_count),
        ))
    }

    fn download_manifest(&self, _reference: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1> {
        Err(unsupported(
            "Bee manifests are virtual filesystem tries; use download_file for paths",
        ))
    }

    fn download_file(
        &self,
        reference: &str,
        path: &str,
    ) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        if !is_relative_package_path(path) {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "requested file path is not a safe relative path",
            )
            .with_details(json!({ "path": path })));
        }
        let reference_without_scheme = normalize_ref(reference);
        let endpoint = self.endpoint(&format!("bzz/{reference_without_scheme}/{path}"));
        let (response, retry_count) = self.send_with_retry("download file", || {
            Ok(BeeHttpRequest::get(endpoint.clone()))
        })?;
        let first_byte_ms = elapsed_ms(start);
        let status = response.status;
        if !status.is_success() {
            let body = response.body_text();
            return Err(self.response_error(status, body, "download file", retry_count));
        }
        let bytes = response.bytes;
        let metrics = transfer_metrics(start, first_byte_ms, bytes.len(), retry_count);
        Ok(DownloadResponseV1 {
            schema_version: "swarm-ai.storage.download.v1".to_string(),
            reference: normalized_ref(&reference_without_scheme),
            path: Some(path.to_string()),
            content_type: response.content_type,
            size_bytes: bytes.len(),
            sha256: Some(sha256_hex(&bytes)),
            metrics,
            bytes,
        })
    }

    fn pin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        let reference_without_scheme = normalize_ref(reference);
        let endpoint = self.endpoint(&format!("pins/{reference_without_scheme}"));
        let (response, retry_count) = self.send_with_retry("pin reference", || {
            Ok(BeeHttpRequest::post(endpoint.clone()))
        })?;
        let status = response.status;
        if !status.is_success() {
            let body = response.body_text();
            return Err(self.response_error(status, body, "pin reference", retry_count));
        }
        Ok(pin_result(
            normalized_ref(&reference_without_scheme),
            true,
            "bee-http",
        ))
    }

    fn unpin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        let reference_without_scheme = normalize_ref(reference);
        let endpoint = self.endpoint(&format!("pins/{reference_without_scheme}"));
        let (response, retry_count) = self.send_with_retry("unpin reference", || {
            Ok(BeeHttpRequest::delete(endpoint.clone()))
        })?;
        let status = response.status;
        if !status.is_success() {
            let body = response.body_text();
            return Err(self.response_error(status, body, "unpin reference", retry_count));
        }
        Ok(pin_result(
            normalized_ref(&reference_without_scheme),
            false,
            "bee-http",
        ))
    }
}

#[derive(Debug, Default)]
pub struct MemoryStorageProvider {
    objects: BTreeMap<String, Vec<u8>>,
    feeds: BTreeMap<String, StorageFeedPointerV1>,
    pins: BTreeSet<String>,
}

impl StorageProvider for MemoryStorageProvider {
    fn get_status(&self) -> StorageStatusV1 {
        StorageStatusV1 {
            schema_version: "swarm-ai.storage.status.v1".to_string(),
            provider: "memory".to_string(),
            capabilities: StorageCapabilities {
                upload: true,
                download: true,
                feeds: true,
                pinning: true,
                act: false,
                pss: false,
            },
            retry_policy: None,
        }
    }

    fn download_bytes(&self, reference: &str) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let Some(bytes) = self.objects.get(reference) else {
            return Err(not_found(reference));
        };
        let metrics = transfer_metrics(start, elapsed_ms(start), bytes.len(), 0);

        Ok(DownloadResponseV1 {
            schema_version: "swarm-ai.storage.download.v1".to_string(),
            reference: reference.to_string(),
            path: None,
            content_type: "application/octet-stream".to_string(),
            size_bytes: bytes.len(),
            sha256: Some(sha256_hex(bytes)),
            metrics,
            bytes: bytes.clone(),
        })
    }

    fn upload_bytes(&mut self, bytes: Vec<u8>) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let digest = sha256_hex(&bytes);
        let reference = format!("bzz://memory-bytes-{digest}");
        let size_bytes = bytes.len();
        self.objects.insert(reference.clone(), bytes);
        Ok(upload_response(
            reference,
            size_bytes,
            false,
            0,
            transfer_metrics(start, elapsed_ms(start), size_bytes, 0),
        ))
    }

    fn upload_directory(&mut self, _root: &Path) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        Err(unsupported(
            "memory provider does not support directory upload",
        ))
    }

    fn download_manifest(&self, reference: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1> {
        let response = self.download_bytes(reference)?;
        serde_json::from_slice(&response.bytes).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::InvalidManifest,
                "object is not a directory manifest",
            )
            .with_details(json!({ "ref": reference, "error": error.to_string() }))
        })
    }

    fn download_file(
        &self,
        reference: &str,
        path: &str,
    ) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let manifest = self.download_manifest(reference)?;
        let Some(file) = manifest.files.iter().find(|file| file.path == path) else {
            return Err(not_found(path));
        };
        let mut response = self.download_bytes(&file.content_ref)?;
        response.reference = reference.to_string();
        response.path = Some(path.to_string());
        response.content_type = file.content_type.clone();
        response.size_bytes = file.size_bytes;
        response.sha256 = Some(file.sha256.clone());
        response.metrics = transfer_metrics(start, elapsed_ms(start), file.size_bytes, 0);
        Ok(response)
    }

    fn create_feed(
        &mut self,
        topic: &str,
        owner: &str,
    ) -> Result<StorageFeedPointerV1, SwarmAiErrorV1> {
        validate_feed_identity(topic, owner)?;
        let feed_ref = memory_feed_ref(topic, owner);
        let pointer = StorageFeedPointerV1 {
            schema_version: "swarm-ai.storage.feed-pointer.v1".to_string(),
            feed_ref: feed_ref.clone(),
            topic: topic.to_string(),
            owner: owner.to_string(),
            target_ref: None,
            updated_at: timestamp(),
        };
        self.feeds.insert(feed_ref, pointer.clone());
        Ok(pointer)
    }

    fn update_feed(
        &mut self,
        topic: &str,
        owner: &str,
        reference: &str,
    ) -> Result<StorageFeedUpdateResultV1, SwarmAiErrorV1> {
        validate_feed_identity(topic, owner)?;
        let target_ref = normalize_target_ref(reference)?;
        let feed_ref = memory_feed_ref(topic, owner);
        let pointer = StorageFeedPointerV1 {
            schema_version: "swarm-ai.storage.feed-pointer.v1".to_string(),
            feed_ref: feed_ref.clone(),
            topic: topic.to_string(),
            owner: owner.to_string(),
            target_ref: Some(target_ref),
            updated_at: timestamp(),
        };
        self.feeds.insert(feed_ref.clone(), pointer.clone());
        Ok(StorageFeedUpdateResultV1 {
            schema_version: "swarm-ai.storage.feed-update-result.v1".to_string(),
            feed_ref,
            pointer,
        })
    }

    fn resolve_feed(&self, feed_ref: &str) -> Result<StorageFeedResolutionV1, SwarmAiErrorV1> {
        let feed_ref = normalize_memory_feed_ref(feed_ref)?;
        let Some(pointer) = self.feeds.get(&feed_ref) else {
            return Err(not_found(&feed_ref));
        };
        Ok(StorageFeedResolutionV1 {
            schema_version: "swarm-ai.storage.feed-resolution.v1".to_string(),
            feed_ref,
            pointer: pointer.clone(),
            target_ref: pointer.target_ref.clone(),
            resolved_at: timestamp(),
        })
    }

    fn pin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        let reference = normalize_target_ref(reference)?;
        self.pins.insert(reference.clone());
        Ok(pin_result(reference, true, "memory"))
    }

    fn unpin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        let reference = normalize_target_ref(reference)?;
        self.pins.remove(&reference);
        Ok(pin_result(reference, false, "memory"))
    }
}

#[derive(Debug, Clone)]
pub struct LocalDirectoryStorageProvider {
    root: PathBuf,
}

impl LocalDirectoryStorageProvider {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn inspect(&self, reference: &str) -> Result<LocalStorageInspectionV1, SwarmAiErrorV1> {
        let normalized = normalize_ref(reference);
        if let Some(hash) = normalized.strip_prefix("local-dir-") {
            let manifest = self.read_manifest_by_hash(hash)?;
            return Ok(LocalStorageInspectionV1 {
                schema_version: "swarm-ai.storage.inspect.v1".to_string(),
                reference: normalized_ref(&normalized),
                kind: "directory".to_string(),
                size_bytes: manifest.total_bytes,
                file_count: manifest.files.len(),
                manifest: Some(manifest),
            });
        }

        if let Some(hash) = normalized.strip_prefix("local-bytes-") {
            let bytes = self.read_object_by_hash(hash)?;
            return Ok(LocalStorageInspectionV1 {
                schema_version: "swarm-ai.storage.inspect.v1".to_string(),
                reference: normalized_ref(&normalized),
                kind: "bytes".to_string(),
                size_bytes: bytes.len(),
                file_count: 1,
                manifest: None,
            });
        }

        Err(not_found(reference))
    }

    pub fn cache_summary(&self) -> Result<LocalStorageCacheSummaryV1, SwarmAiErrorV1> {
        self.ensure_dirs()?;
        let object_dir = self.objects_dir();
        let manifest_dir = self.manifests_dir();
        let object_files = list_files(&object_dir)?;
        let manifest_files = list_files(&manifest_dir)?;
        let total_object_bytes = object_files
            .iter()
            .filter_map(|path| fs::metadata(path).ok())
            .map(|metadata| metadata.len())
            .sum();

        Ok(LocalStorageCacheSummaryV1 {
            schema_version: "swarm-ai.storage.cache-summary.v1".to_string(),
            root: self.root.display().to_string(),
            object_count: object_files.len(),
            manifest_count: manifest_files.len(),
            total_object_bytes,
        })
    }

    fn ensure_dirs(&self) -> Result<(), SwarmAiErrorV1> {
        fs::create_dir_all(self.objects_dir()).map_err(io_error)?;
        fs::create_dir_all(self.manifests_dir()).map_err(io_error)?;
        fs::create_dir_all(self.feeds_dir()).map_err(io_error)?;
        fs::create_dir_all(self.pins_dir()).map_err(io_error)?;
        Ok(())
    }

    fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    fn manifests_dir(&self) -> PathBuf {
        self.root.join("manifests")
    }

    fn feeds_dir(&self) -> PathBuf {
        self.root.join("feeds")
    }

    fn pins_dir(&self) -> PathBuf {
        self.root.join("pins")
    }

    fn feed_path(&self, feed_ref: &str) -> Result<PathBuf, SwarmAiErrorV1> {
        let feed_ref = normalize_local_feed_ref(feed_ref)?;
        let Some(hash) = normalize_ref(&feed_ref)
            .strip_prefix("local-feed-")
            .map(str::to_string)
        else {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "feedRef must be a local storage feed reference",
            )
            .with_details(json!({ "feedRef": feed_ref })));
        };
        Ok(self.feeds_dir().join(format!("{hash}.json")))
    }

    fn pin_path(&self, reference: &str) -> PathBuf {
        self.pins_dir()
            .join(format!("{}.json", safe_file_component(reference)))
    }

    fn write_feed_pointer(&self, pointer: &StorageFeedPointerV1) -> Result<(), SwarmAiErrorV1> {
        let path = self.feed_path(&pointer.feed_ref)?;
        fs::write(
            &path,
            serde_json::to_vec_pretty(pointer).map_err(serialization_error)?,
        )
        .map_err(io_error)
    }

    fn read_feed_pointer(&self, feed_ref: &str) -> Result<StorageFeedPointerV1, SwarmAiErrorV1> {
        let path = self.feed_path(feed_ref)?;
        let bytes = fs::read(&path).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::PackageNotFound,
                "feed pointer is not present in local storage",
            )
            .with_details(json!({ "path": path.display().to_string(), "error": error.to_string() }))
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            SwarmAiErrorV1::new(ErrorCode::InvalidManifest, "stored feed pointer is invalid")
                .with_details(
                    json!({ "path": path.display().to_string(), "error": error.to_string() }),
                )
        })
    }

    fn read_object_by_hash(&self, hash: &str) -> Result<Vec<u8>, SwarmAiErrorV1> {
        let path = self.objects_dir().join(hash);
        fs::read(&path).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::PackageNotFound,
                "object is not present in local storage",
            )
            .with_details(json!({ "path": path.display().to_string(), "error": error.to_string() }))
        })
    }

    fn read_manifest_by_hash(&self, hash: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1> {
        let path = self.manifests_dir().join(format!("{hash}.json"));
        let bytes = fs::read(&path).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::PackageNotFound,
                "manifest is not present in local storage",
            )
            .with_details(json!({ "path": path.display().to_string(), "error": error.to_string() }))
        })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            SwarmAiErrorV1::new(ErrorCode::InvalidManifest, "stored manifest is invalid")
                .with_details(
                    json!({ "path": path.display().to_string(), "error": error.to_string() }),
                )
        })
    }
}

impl StorageProvider for LocalDirectoryStorageProvider {
    fn get_status(&self) -> StorageStatusV1 {
        StorageStatusV1 {
            schema_version: "swarm-ai.storage.status.v1".to_string(),
            provider: "local-directory".to_string(),
            capabilities: StorageCapabilities {
                upload: true,
                download: true,
                feeds: true,
                pinning: true,
                act: false,
                pss: false,
            },
            retry_policy: None,
        }
    }

    fn download_bytes(&self, reference: &str) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        let normalized = normalize_ref(reference);
        let Some(hash) = normalized.strip_prefix("local-bytes-") else {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::UnsupportedOperation,
                "reference is not a byte object",
            )
            .with_details(json!({ "ref": reference })));
        };
        let bytes = self.read_object_by_hash(hash)?;
        let metrics = transfer_metrics(start, elapsed_ms(start), bytes.len(), 0);
        Ok(DownloadResponseV1 {
            schema_version: "swarm-ai.storage.download.v1".to_string(),
            reference: normalized_ref(&normalized),
            path: None,
            content_type: "application/octet-stream".to_string(),
            size_bytes: bytes.len(),
            sha256: Some(sha256_hex(&bytes)),
            metrics,
            bytes,
        })
    }

    fn upload_bytes(&mut self, bytes: Vec<u8>) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        self.ensure_dirs()?;
        let hash = sha256_hex(&bytes);
        let path = self.objects_dir().join(&hash);
        if !path.exists() {
            fs::write(&path, &bytes).map_err(io_error)?;
        }
        Ok(upload_response(
            format!("bzz://local-bytes-{hash}"),
            bytes.len(),
            false,
            0,
            transfer_metrics(start, elapsed_ms(start), bytes.len(), 0),
        ))
    }

    fn upload_directory(&mut self, root: &Path) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        self.ensure_dirs()?;
        let mut files = Vec::new();
        for source in list_files(root)? {
            let relative = source
                .strip_prefix(root)
                .map_err(|error| {
                    SwarmAiErrorV1::new(
                        ErrorCode::ExecutionFailed,
                        "failed to resolve relative path",
                    )
                    .with_details(json!({ "error": error.to_string() }))
                })?
                .to_string_lossy()
                .replace('\\', "/");

            if !is_relative_package_path(&relative) {
                return Err(SwarmAiErrorV1::new(
                    ErrorCode::InvalidManifest,
                    "directory contains an unsafe path",
                )
                .with_details(json!({ "path": relative })));
            }

            let bytes = fs::read(&source).map_err(io_error)?;
            let upload = self.upload_bytes(bytes.clone())?;
            files.push(StoredFileV1 {
                path: relative.clone(),
                content_ref: upload.reference,
                content_type: content_type_for_path(&relative).to_string(),
                size_bytes: bytes.len(),
                sha256: sha256_hex(&bytes),
            });
        }

        files.sort_by(|left, right| left.path.cmp(&right.path));
        let total_bytes = files.iter().map(|file| file.size_bytes).sum();
        let manifest = DirectoryManifestV1 {
            schema_version: "swarm-ai.storage.directory-manifest.v1".to_string(),
            files,
            total_bytes,
        };
        let value = serde_json::to_value(&manifest).map_err(serialization_error)?;
        let manifest_hash = hash_canonical_json(&canonicalize_json(&value));
        let manifest_path = self.manifests_dir().join(format!("{manifest_hash}.json"));
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(serialization_error)?;
        if !manifest_path.exists() {
            fs::write(&manifest_path, manifest_bytes).map_err(io_error)?;
        }

        Ok(upload_response(
            format!("bzz://local-dir-{manifest_hash}"),
            total_bytes,
            false,
            0,
            transfer_metrics(start, elapsed_ms(start), total_bytes, 0),
        ))
    }

    fn download_manifest(&self, reference: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1> {
        let normalized = normalize_ref(reference);
        let Some(hash) = normalized.strip_prefix("local-dir-") else {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::UnsupportedOperation,
                "reference is not a directory manifest",
            )
            .with_details(json!({ "ref": reference })));
        };
        self.read_manifest_by_hash(hash)
    }

    fn download_file(
        &self,
        reference: &str,
        path: &str,
    ) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let start = Instant::now();
        if !is_relative_package_path(path) {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "requested file path is not a safe relative path",
            )
            .with_details(json!({ "path": path })));
        }
        let manifest = self.download_manifest(reference)?;
        let Some(file) = manifest.files.iter().find(|file| file.path == path) else {
            return Err(not_found(path));
        };
        let mut response = self.download_bytes(&file.content_ref)?;
        response.reference = reference.to_string();
        response.path = Some(path.to_string());
        response.content_type = file.content_type.clone();
        response.size_bytes = file.size_bytes;
        response.sha256 = Some(file.sha256.clone());
        response.metrics = transfer_metrics(start, elapsed_ms(start), file.size_bytes, 0);
        Ok(response)
    }

    fn create_feed(
        &mut self,
        topic: &str,
        owner: &str,
    ) -> Result<StorageFeedPointerV1, SwarmAiErrorV1> {
        validate_feed_identity(topic, owner)?;
        self.ensure_dirs()?;
        let feed_ref = local_feed_ref(topic, owner);
        let pointer = StorageFeedPointerV1 {
            schema_version: "swarm-ai.storage.feed-pointer.v1".to_string(),
            feed_ref: feed_ref.clone(),
            topic: topic.to_string(),
            owner: owner.to_string(),
            target_ref: None,
            updated_at: timestamp(),
        };
        self.write_feed_pointer(&pointer)?;
        Ok(pointer)
    }

    fn update_feed(
        &mut self,
        topic: &str,
        owner: &str,
        reference: &str,
    ) -> Result<StorageFeedUpdateResultV1, SwarmAiErrorV1> {
        validate_feed_identity(topic, owner)?;
        self.ensure_dirs()?;
        let target_ref = normalize_target_ref(reference)?;
        let feed_ref = local_feed_ref(topic, owner);
        let pointer = StorageFeedPointerV1 {
            schema_version: "swarm-ai.storage.feed-pointer.v1".to_string(),
            feed_ref: feed_ref.clone(),
            topic: topic.to_string(),
            owner: owner.to_string(),
            target_ref: Some(target_ref),
            updated_at: timestamp(),
        };
        self.write_feed_pointer(&pointer)?;
        Ok(StorageFeedUpdateResultV1 {
            schema_version: "swarm-ai.storage.feed-update-result.v1".to_string(),
            feed_ref,
            pointer,
        })
    }

    fn resolve_feed(&self, feed_ref: &str) -> Result<StorageFeedResolutionV1, SwarmAiErrorV1> {
        let feed_ref = normalize_local_feed_ref(feed_ref)?;
        let pointer = self.read_feed_pointer(&feed_ref)?;
        Ok(StorageFeedResolutionV1 {
            schema_version: "swarm-ai.storage.feed-resolution.v1".to_string(),
            feed_ref,
            target_ref: pointer.target_ref.clone(),
            pointer,
            resolved_at: timestamp(),
        })
    }

    fn pin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        self.ensure_dirs()?;
        let reference = normalize_target_ref(reference)?;
        let result = pin_result(reference.clone(), true, "local-directory");
        let path = self.pin_path(&reference);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&result).map_err(serialization_error)?,
        )
        .map_err(io_error)?;
        Ok(result)
    }

    fn unpin(&mut self, reference: &str) -> Result<StoragePinResultV1, SwarmAiErrorV1> {
        self.ensure_dirs()?;
        let reference = normalize_target_ref(reference)?;
        let path = self.pin_path(&reference);
        if path.exists() {
            fs::remove_file(&path).map_err(io_error)?;
        }
        Ok(pin_result(reference, false, "local-directory"))
    }
}

pub fn normalize_ref(reference: &str) -> String {
    reference
        .trim()
        .strip_prefix("bzz://")
        .unwrap_or(reference.trim())
        .to_string()
}

fn normalized_ref(reference_without_scheme: &str) -> String {
    format!("bzz://{reference_without_scheme}")
}

fn upload_response(
    reference: String,
    size_bytes: usize,
    pinned: bool,
    redundancy_level: u8,
    metrics: StorageTransferMetricsV1,
) -> UploadResponseV1 {
    UploadResponseV1 {
        schema_version: "swarm-ai.storage.upload.v1".to_string(),
        reference,
        size_bytes,
        pinned,
        redundancy_level,
        postage_batch_id: None,
        metrics,
    }
}

fn transfer_metrics(
    start: Instant,
    first_byte_ms: u64,
    size_bytes: usize,
    retry_count: u32,
) -> StorageTransferMetricsV1 {
    let total_ms = elapsed_ms(start);
    StorageTransferMetricsV1 {
        schema_version: "swarm-ai.storage.transfer-metrics.v1".to_string(),
        resolve_ms: first_byte_ms,
        first_byte_ms,
        total_ms,
        size_bytes,
        retry_count,
    }
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn pin_result(reference: String, pinned: bool, provider: &str) -> StoragePinResultV1 {
    StoragePinResultV1 {
        schema_version: "swarm-ai.storage.pin-result.v1".to_string(),
        reference,
        pinned,
        provider: provider.to_string(),
        updated_at: timestamp(),
    }
}

fn local_feed_ref(topic: &str, owner: &str) -> String {
    format!("bzz://local-feed-{}", feed_hash(topic, owner))
}

fn memory_feed_ref(topic: &str, owner: &str) -> String {
    format!("bzz://memory-feed-{}", feed_hash(topic, owner))
}

fn feed_hash(topic: &str, owner: &str) -> String {
    hash_canonical_json(&canonicalize_json(&json!({
        "topic": topic,
        "owner": owner,
    })))
}

fn normalize_local_feed_ref(feed_ref: &str) -> Result<String, SwarmAiErrorV1> {
    let normalized = normalize_ref(feed_ref);
    if normalized.starts_with("local-feed-") {
        Ok(normalized_ref(&normalized))
    } else {
        Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "feedRef must be a local feed reference",
        )
        .with_details(json!({ "feedRef": feed_ref })))
    }
}

fn normalize_memory_feed_ref(feed_ref: &str) -> Result<String, SwarmAiErrorV1> {
    let normalized = normalize_ref(feed_ref);
    if normalized.starts_with("memory-feed-") {
        Ok(normalized_ref(&normalized))
    } else {
        Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "feedRef must be a memory feed reference",
        )
        .with_details(json!({ "feedRef": feed_ref })))
    }
}

fn normalize_target_ref(reference: &str) -> Result<String, SwarmAiErrorV1> {
    let normalized = normalize_ref(reference);
    if normalized.trim().is_empty() || normalized.contains('/') || normalized.contains('\\') {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "storage reference must be a non-empty bzz:// reference",
        )
        .with_details(json!({ "ref": reference })));
    }
    Ok(normalized_ref(&normalized))
}

fn validate_feed_identity(topic: &str, owner: &str) -> Result<(), SwarmAiErrorV1> {
    if topic.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "feed topic is required",
        ));
    }
    if owner.trim().is_empty() {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::InvalidRequest,
            "feed owner is required",
        ));
    }
    Ok(())
}

fn timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn safe_file_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect()
}

fn list_files(root: &Path) -> Result<Vec<PathBuf>, SwarmAiErrorV1> {
    let mut files = Vec::new();
    if !root.exists() {
        return Ok(files);
    }
    collect_files(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<(), SwarmAiErrorV1> {
    for entry in fs::read_dir(path).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(io_error)?;
        if file_type.is_dir() {
            collect_files(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn tar_directory(root: &Path) -> Result<Vec<u8>, SwarmAiErrorV1> {
    let mut buffer = Vec::new();
    {
        let cursor = Cursor::new(&mut buffer);
        let mut builder = tar::Builder::new(cursor);
        for source in list_files(root)? {
            let relative = source
                .strip_prefix(root)
                .map_err(|error| {
                    SwarmAiErrorV1::new(
                        ErrorCode::ExecutionFailed,
                        "failed to resolve relative path",
                    )
                    .with_details(json!({ "error": error.to_string() }))
                })?
                .to_string_lossy()
                .replace('\\', "/");
            if !is_relative_package_path(&relative) {
                return Err(SwarmAiErrorV1::new(
                    ErrorCode::InvalidManifest,
                    "directory contains an unsafe path",
                )
                .with_details(json!({ "path": relative })));
            }
            builder
                .append_path_with_name(&source, &relative)
                .map_err(io_error)?;
        }
        builder.finish().map_err(io_error)?;
    }
    Ok(buffer)
}

fn is_relative_package_path(path: &str) -> bool {
    if path.trim().is_empty()
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains(':')
        || path.contains('\\')
    {
        return false;
    }
    !path.split('/').any(|part| part == ".." || part.is_empty())
}

fn content_type_for_path(path: &str) -> &'static str {
    if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".txt") || path.ends_with(".md") {
        "text/plain; charset=utf-8"
    } else if path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".wasm") {
        "application/wasm"
    } else {
        "application/octet-stream"
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn io_error(error: std::io::Error) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(ErrorCode::ExecutionFailed, "local storage I/O failed")
        .with_details(json!({ "error": error.to_string() }))
}

fn serialization_error(error: serde_json::Error) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(
        ErrorCode::ExecutionFailed,
        "local storage serialization failed",
    )
    .with_details(json!({ "error": error.to_string() }))
}

fn http_error(error: reqwest::Error) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(ErrorCode::ExecutionFailed, "Bee HTTP request failed")
        .with_details(json!({ "error": error.to_string() }))
}

fn send_bee_http_request(
    request: BeeHttpRequest,
    operation: &str,
) -> Result<BeeHttpResponse, SwarmAiErrorV1> {
    let operation = operation.to_string();
    let handle = thread::Builder::new()
        .name(format!("bee-http-{operation}"))
        .spawn(move || {
            let client = reqwest::blocking::Client::new();
            let mut builder = match request.method {
                BeeHttpMethod::Get => client.get(&request.url),
                BeeHttpMethod::Post => client.post(&request.url),
                BeeHttpMethod::Delete => client.delete(&request.url),
            };
            for (name, value) in &request.headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            if let Some(body) = request.body {
                builder = builder.body(body);
            }
            let response = builder.send().map_err(http_error)?;
            let status = response.status();
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let bytes = response.bytes().map_err(http_error)?.to_vec();
            Ok(BeeHttpResponse {
                status,
                content_type,
                bytes,
            })
        })
        .map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::ExecutionFailed,
                "failed to spawn Bee HTTP worker",
            )
            .with_details(json!({ "operation": operation, "error": error.to_string() }))
        })?;

    handle.join().map_err(|_| {
        SwarmAiErrorV1::new(ErrorCode::ExecutionFailed, "Bee HTTP worker panicked")
            .with_details(json!({ "operation": operation }))
    })?
}

fn parse_bee_reference_response(
    bytes: &[u8],
    operation: &str,
) -> Result<BeeReferenceResponse, SwarmAiErrorV1> {
    serde_json::from_slice(bytes).map_err(|error| {
        SwarmAiErrorV1::new(
            ErrorCode::ExecutionFailed,
            format!("Bee {operation} response was not valid JSON"),
        )
        .with_details(json!({ "error": error.to_string() }))
    })
}

fn bee_error_with_retry(
    mut error: SwarmAiErrorV1,
    operation: &str,
    retry_count: u32,
) -> SwarmAiErrorV1 {
    let details = match error.details {
        Value::Object(mut map) => {
            map.insert("operation".to_string(), json!(operation));
            map.insert("retryCount".to_string(), json!(retry_count));
            Value::Object(map)
        }
        other => json!({
            "operation": operation,
            "retryCount": retry_count,
            "details": other
        }),
    };
    error.details = details;
    error
}

fn is_transient_status(status: reqwest::StatusCode) -> bool {
    bee_retryable_status_codes()
        .iter()
        .any(|code| status.as_u16() == *code)
}

fn sleep_before_retry(retry_count: u32) {
    let multiplier = u64::from(retry_count).min(8);
    thread::sleep(Duration::from_millis(
        BEE_RETRY_BACKOFF_MS.saturating_mul(multiplier),
    ));
}

fn bee_retry_policy() -> StorageRetryPolicyV1 {
    StorageRetryPolicyV1 {
        schema_version: "swarm-ai.storage.retry-policy.v1".to_string(),
        max_retries: BEE_DEFAULT_MAX_RETRIES,
        backoff_ms: BEE_RETRY_BACKOFF_MS,
        retryable_status_codes: bee_retryable_status_codes(),
    }
}

fn bee_retryable_status_codes() -> Vec<u16> {
    vec![408, 429, 502, 503, 504]
}

fn not_found(reference: &str) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(
        ErrorCode::PackageNotFound,
        "object is not present in storage",
    )
    .with_details(json!({ "ref": reference }))
}

fn unsupported(message: &str) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(ErrorCode::UnsupportedOperation, message)
}

#[cfg(test)]
mod tests {
    use super::{
        BeeHttpStorageProvider, BeeStorageConfig, LocalDirectoryStorageProvider, StorageProvider,
    };
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::thread;

    #[test]
    fn uploads_and_downloads_directory_file() {
        let root =
            std::env::temp_dir().join(format!("hivemind-storage-test-{}", std::process::id()));
        let package = root.join("package");
        let storage = root.join("storage");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(package.join("model")).unwrap();
        fs::write(package.join("swarm-ai.json"), "{}").unwrap();
        fs::write(package.join("model/config.json"), "{\"ok\":true}").unwrap();

        let mut provider = LocalDirectoryStorageProvider::new(&storage);
        let upload = provider.upload_directory(&package).unwrap();
        assert_eq!(
            upload.metrics.schema_version,
            "swarm-ai.storage.transfer-metrics.v1"
        );
        assert_eq!(upload.metrics.size_bytes, upload.size_bytes);
        let manifest = provider.download_manifest(&upload.reference).unwrap();
        assert_eq!(manifest.files.len(), 2);
        let file = provider
            .download_file(&upload.reference, "model/config.json")
            .unwrap();
        assert_eq!(file.bytes, b"{\"ok\":true}");
        assert_eq!(file.metrics.size_bytes, file.size_bytes);
        assert_eq!(file.metrics.retry_count, 0);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_feeds_and_pins_round_trip() {
        let root =
            std::env::temp_dir().join(format!("hivemind-storage-feed-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let mut provider = LocalDirectoryStorageProvider::new(&root);
        let created = provider.create_feed("latest", "0xPublisher").unwrap();
        assert!(created.target_ref.is_none());

        let update = provider
            .update_feed("latest", "0xPublisher", "bzz://local-dir-example")
            .unwrap();
        assert_eq!(
            update.pointer.target_ref.as_deref(),
            Some("bzz://local-dir-example")
        );

        let resolved = provider.resolve_feed(&update.feed_ref).unwrap();
        assert_eq!(resolved.target_ref, update.pointer.target_ref);

        let pin = provider.pin("bzz://local-dir-example").unwrap();
        assert!(pin.pinned);
        let unpin = provider.unpin("bzz://local-dir-example").unwrap();
        assert!(!unpin.pinned);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn bee_retry_policy_marks_transient_gateway_failures() {
        assert!(super::is_transient_status(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(super::is_transient_status(
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(super::is_transient_status(
            reqwest::StatusCode::GATEWAY_TIMEOUT
        ));
        assert!(!super::is_transient_status(
            reqwest::StatusCode::BAD_REQUEST
        ));
        assert!(!super::is_transient_status(reqwest::StatusCode::NOT_FOUND));
    }

    #[test]
    fn bee_download_retries_transient_statuses() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_server = attempts.clone();
        let server = thread::spawn(move || {
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; 1024];
                let _ = stream.read(&mut request);
                let attempt = attempts_for_server.fetch_add(1, Ordering::SeqCst) + 1;
                if attempt < 3 {
                    stream
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nbusy",
                        )
                        .unwrap();
                } else {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
                        )
                        .unwrap();
                }
            }
        });

        let provider = BeeHttpStorageProvider::new(BeeStorageConfig {
            api_url: format!("http://{address}"),
            postage_batch_id: None,
            pin: false,
            deferred_upload: true,
            redundancy_level: 0,
        });
        let response = provider.download_bytes("bzz://retry-test").unwrap();

        assert_eq!(response.bytes, b"ok");
        assert_eq!(response.metrics.retry_count, 2);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        server.join().unwrap();
    }
}
