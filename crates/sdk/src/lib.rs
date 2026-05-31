pub use hivemind_access as access;
pub use hivemind_benchmarks as benchmarks;
pub use hivemind_browser_runner as browser_runner;
pub use hivemind_core as core;
pub use hivemind_local_runner as local_runner;
pub use hivemind_marketplace as marketplace;
pub use hivemind_package as package;
pub use hivemind_policy as policy;
pub use hivemind_publisher as publisher;
pub use hivemind_receipts as receipts;
pub use hivemind_registry as registry;
pub use hivemind_remote_runner as remote_runner;
pub use hivemind_router as router;
pub use hivemind_storage as storage;
pub use hivemind_validator as validator;
pub use hivemind_weeb3_adapter as weeb3_adapter;

use chrono::{SecondsFormat, Utc};
use hivemind_core::{
    ArtifactGroup, ErrorCode, ExecutionMetrics, ExecutionOptions, ExecutionPrivacy,
    ExecutionReceiptV1, ExecutionRequestV1, ExecutionResponseV1, ExecutionStatus,
    PackageManifestV1, ReceiptDraft, RunnerDescriptorV1, SwarmAiErrorV1, ValidationIssue,
    ValidationReport, canonicalize_json as core_canonicalize_json, create_signed_receipt,
    hash_canonical_json as core_hash_canonical_json, select_artifact_group,
    validate_package_manifest_value,
};
use hivemind_publisher::PublicationRecordV1;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Instant;
use storage::{
    DirectoryManifestV1, DownloadResponseV1, StorageCapabilities, StorageProvider, StorageStatusV1,
    StorageTransferMetricsV1, StoredFileV1, UploadResponseV1,
};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityResult {
    Passed,
    Failed,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompatibilityTestResultV1 {
    pub name: String,
    pub status: CompatibilityStatus,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct CompatibilityPerformanceV1 {
    #[serde(rename = "manifestParseMs")]
    pub manifest_parse_ms: u64,
    #[serde(rename = "storageDownloadMs")]
    pub storage_download_ms: u64,
    #[serde(rename = "coldStartMs")]
    pub cold_start_ms: u64,
    #[serde(rename = "warmStartMs")]
    pub warm_start_ms: u64,
    #[serde(rename = "executionMs")]
    pub execution_ms: u64,
    #[serde(rename = "receiptCreationMs")]
    pub receipt_creation_ms: u64,
    #[serde(rename = "downloadBytes")]
    pub download_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CompatibilityReportV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "componentName")]
    pub component_name: String,
    #[serde(rename = "componentVersion")]
    pub component_version: String,
    #[serde(rename = "interfaceVersion")]
    pub interface_version: String,
    #[serde(rename = "testedAt")]
    pub tested_at: String,
    pub tests: Vec<CompatibilityTestResultV1>,
    pub performance: CompatibilityPerformanceV1,
    pub result: CompatibilityResult,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SdkVerificationV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub valid: bool,
    pub issues: Vec<ValidationIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MockFileV1 {
    pub path: String,
    #[serde(rename = "contentType")]
    pub content_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct MockStorageProvider {
    objects: BTreeMap<String, Vec<u8>>,
    manifests: BTreeMap<String, DirectoryManifestV1>,
}

pub fn parse_package_manifest(value: &Value) -> Result<PackageManifestV1, SwarmAiErrorV1> {
    serde_json::from_value(value.clone()).map_err(|error| {
        SwarmAiErrorV1::new(ErrorCode::InvalidManifest, "JSON is not PackageManifestV1")
            .with_details(json!({ "error": error.to_string() }))
    })
}

pub fn validate_package_manifest(value: &Value) -> ValidationReport {
    validate_package_manifest_value(value)
}

pub fn canonicalize_json(value: &Value) -> Value {
    core_canonicalize_json(value)
}

pub fn hash_canonical(value: &Value) -> String {
    core_hash_canonical_json(value)
}

pub fn verify_publication_record(record: &PublicationRecordV1) -> SdkVerificationV1 {
    let publisher_verification = hivemind_publisher::verify_publication_record(record);
    verification(publisher_verification.issues)
}

pub fn create_execution_request(
    package_ref: impl Into<String>,
    package_id: impl Into<String>,
    package_version: impl Into<String>,
    task: impl Into<String>,
    input: Value,
) -> ExecutionRequestV1 {
    ExecutionRequestV1 {
        schema_version: "swarm-ai.execution.request.v1".to_string(),
        request_id: Uuid::new_v4().to_string(),
        package_ref: package_ref.into(),
        package_id: package_id.into(),
        package_version: package_version.into(),
        preferred_artifact_group: None,
        task: task.into(),
        input,
        options: ExecutionOptions::default(),
        privacy: ExecutionPrivacy::default(),
        access_grant: None,
        access_revocation_list: None,
    }
}

pub fn validate_execution_response(
    response: &ExecutionResponseV1,
    request: Option<&ExecutionRequestV1>,
) -> SdkVerificationV1 {
    let mut issues = Vec::new();
    if response.schema_version != "swarm-ai.execution.response.v1" {
        issues.push(issue(
            "$.schemaVersion",
            "Expected schemaVersion to be swarm-ai.execution.response.v1",
        ));
    }
    if let Some(request) = request {
        if response.request_id != request.request_id {
            issues.push(issue(
                "$.requestId",
                "Execution response requestId must match the request",
            ));
        }
    }
    match response.status {
        ExecutionStatus::Succeeded => {
            if response.error.is_some() {
                issues.push(issue(
                    "$.error",
                    "Succeeded execution responses must not include an error",
                ));
            }
        }
        ExecutionStatus::Failed => {
            if response.error.is_none() {
                issues.push(issue(
                    "$.error",
                    "Failed execution responses must include ErrorV1",
                ));
            }
        }
        ExecutionStatus::Cancelled | ExecutionStatus::Partial => {}
    }
    verification(issues)
}

pub fn create_receipt(
    request: &ExecutionRequestV1,
    response: &ExecutionResponseV1,
    manifest: &PackageManifestV1,
    artifact_group: impl AsRef<str>,
    manifest_hash: impl AsRef<str>,
    runner_id: impl AsRef<str>,
) -> ExecutionReceiptV1 {
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    create_signed_receipt(ReceiptDraft {
        request,
        response,
        manifest,
        artifact_group: artifact_group.as_ref(),
        manifest_hash: manifest_hash.as_ref(),
        runner_id: runner_id.as_ref(),
        route_id: None,
        policy: None,
        started_at: &now,
        finished_at: &now,
    })
}

pub fn verify_receipt(receipt: &ExecutionReceiptV1) -> SdkVerificationV1 {
    let receipt_verification = hivemind_receipts::verify_receipt(receipt);
    verification(
        receipt_verification
            .issues
            .into_iter()
            .map(|issue| ValidationIssue {
                path: issue.path,
                message: issue.message,
            })
            .collect(),
    )
}

pub fn load_package(
    storage_provider: &impl StorageProvider,
    package_ref: &str,
) -> anyhow::Result<package::LocalPackage> {
    package::load_package_from_storage(package_ref, storage_provider)
}

pub fn select_artifact_group_for_runner(
    manifest: &PackageManifestV1,
    runner: &RunnerDescriptorV1,
    preferred_artifact_group: Option<&str>,
) -> Option<ArtifactGroup> {
    select_artifact_group(
        manifest,
        preferred_artifact_group,
        &runner.targets,
        &runner.engines,
    )
    .cloned()
}

pub fn create_error(
    code: ErrorCode,
    message: impl Into<String>,
    details: Option<Value>,
) -> SwarmAiErrorV1 {
    let error = SwarmAiErrorV1::new(code, message);
    if let Some(details) = details {
        error.with_details(details)
    } else {
        error
    }
}

pub fn mock_runner_descriptor() -> RunnerDescriptorV1 {
    local_runner::descriptor()
}

pub fn execute_mock_request(request: &ExecutionRequestV1) -> ExecutionResponseV1 {
    let started = Instant::now();
    let output = match request.task.as_str() {
        "embedding" => json!({
            "embedding": deterministic_embedding(&request.input),
            "model": request.package_id,
        }),
        "classification" => json!({ "label": "general", "score": 0.75 }),
        "chat" => json!({
            "message": {
                "role": "assistant",
                "content": "Mock runner response"
            }
        }),
        _ => json!({ "echo": request.input, "task": request.task }),
    };
    let elapsed = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    ExecutionResponseV1::succeeded(
        request.request_id.clone(),
        output,
        ExecutionMetrics {
            queue_ms: 0,
            load_ms: 0,
            compute_ms: elapsed,
            total_ms: elapsed,
            input_tokens: None,
            output_tokens: None,
        },
    )
}

pub fn certify_package_dir(path: &Path) -> anyhow::Result<CompatibilityReportV1> {
    let mut tests = Vec::new();
    let mut performance = CompatibilityPerformanceV1::default();

    let parse_timer = Instant::now();
    let manifest_value = package::read_manifest_value(path)?;
    performance.manifest_parse_ms = elapsed_ms(parse_timer);

    let package_validation = timed_test("validates-package-manifest-v1", || {
        package::validate_package_dir(path)
            .map(|report| {
                if report.valid {
                    Ok(())
                } else {
                    Err(format!(
                        "{} issue(s): {}",
                        report.issues.len(),
                        report
                            .issues
                            .first()
                            .map(|issue| issue.message.clone())
                            .unwrap_or_else(|| "unknown validation error".to_string())
                    ))
                }
            })
            .map_err(|error| error.to_string())?
    });
    tests.push(package_validation);

    tests.push(timed_test("ignores-unknown-optional-fields", || {
        let mut value = manifest_value.clone();
        let Some(object) = value.as_object_mut() else {
            return Err("manifest root is not an object".to_string());
        };
        object.insert(
            "xSdkForwardCompatibilityProbe".to_string(),
            json!({ "ignored": true }),
        );
        let report = validate_package_manifest_value(&value);
        if report.valid {
            Ok(())
        } else {
            Err("manifest with unknown optional field did not validate".to_string())
        }
    }));

    let package = package::load_package_from_dir(path)?;
    let request = create_execution_request(
        package.package_ref.clone(),
        package.manifest.package_id.clone(),
        package.manifest.version.clone(),
        package
            .manifest
            .capabilities
            .first()
            .cloned()
            .unwrap_or_else(|| "embedding".to_string()),
        json!({ "text": "compatibility smoke" }),
    );

    tests.push(timed_test("accepts-execution-request-v1", || {
        let value = serde_json::to_value(&request).map_err(|error| error.to_string())?;
        serde_json::from_value::<ExecutionRequestV1>(value)
            .map(|_| ())
            .map_err(|error| error.to_string())
    }));

    let execution_timer = Instant::now();
    let response = execute_mock_request(&request);
    performance.execution_ms = elapsed_ms(execution_timer);

    tests.push(timed_test("validates-execution-response-v1", || {
        let verification = validate_execution_response(&response, Some(&request));
        if verification.valid {
            Ok(())
        } else {
            Err(verification
                .issues
                .first()
                .map(|issue| issue.message.clone())
                .unwrap_or_else(|| "response validation failed".to_string()))
        }
    }));

    let receipt_timer = Instant::now();
    let artifact_group = package
        .manifest
        .artifact_groups
        .first()
        .map(|group| group.id.as_str())
        .unwrap_or("unknown");
    let receipt = create_receipt(
        &request,
        &response,
        &package.manifest,
        artifact_group,
        &package.manifest_hash,
        "sdk-mock-runner",
    );
    performance.receipt_creation_ms = elapsed_ms(receipt_timer);
    tests.push(timed_test("verifies-receipt-v1", || {
        let verification = verify_receipt(&receipt);
        if verification.valid {
            Ok(())
        } else {
            Err("receipt canonical hash did not verify".to_string())
        }
    }));

    let mut storage = MockStorageProvider::default();
    let storage_timer = Instant::now();
    let upload = storage.upload_directory(path).map_err(|error| {
        anyhow::anyhow!("failed to upload package into SDK mock storage: {error}")
    })?;
    performance.download_bytes = upload.size_bytes as u64;
    let storage_validation = package::validate_package_ref(&upload.reference, &storage)?;
    performance.storage_download_ms = elapsed_ms(storage_timer);
    tests.push(test_result(
        "loads-package-from-mock-storage",
        if storage_validation.valid {
            CompatibilityStatus::Passed
        } else {
            CompatibilityStatus::Failed
        },
        performance.storage_download_ms,
        storage_validation
            .issues
            .first()
            .map(|issue| issue.message.clone()),
    ));

    tests.push(timed_test("selects-artifact-group-for-runner", || {
        select_artifact_group_for_runner(&package.manifest, &mock_runner_descriptor(), None)
            .map(|_| ())
            .ok_or_else(|| "mock runner cannot select a compatible artifact group".to_string())
    }));

    let result = compatibility_result(&tests);
    Ok(CompatibilityReportV1 {
        schema_version: "swarm-ai.compatibility-report.v1".to_string(),
        component_name: "package-and-sdk".to_string(),
        component_version: env!("CARGO_PKG_VERSION").to_string(),
        interface_version: hivemind_core::INTERFACE_VERSION.to_string(),
        tested_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        tests,
        performance,
        result,
    })
}

impl MockStorageProvider {
    pub fn put_directory_files<I>(&mut self, files: I) -> Result<UploadResponseV1, SwarmAiErrorV1>
    where
        I: IntoIterator<Item = MockFileV1>,
    {
        let mut stored_files = Vec::new();
        let mut total_bytes = 0usize;
        for file in files {
            if file.path.trim().is_empty()
                || file.path.starts_with('/')
                || file.path.contains('\\')
                || file
                    .path
                    .split('/')
                    .any(|part| part.is_empty() || part == "..")
            {
                return Err(SwarmAiErrorV1::new(
                    ErrorCode::InvalidRequest,
                    "Mock storage file paths must be relative package paths",
                )
                .with_details(json!({ "path": file.path })));
            }
            total_bytes += file.bytes.len();
            let digest = sha256_hex(&file.bytes);
            let content_ref = format!("bzz://sdk-mock-bytes-{digest}");
            self.objects.insert(content_ref.clone(), file.bytes.clone());
            stored_files.push(StoredFileV1 {
                path: file.path,
                content_ref,
                content_type: file.content_type,
                size_bytes: file.bytes.len(),
                sha256: digest,
            });
        }
        stored_files.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = DirectoryManifestV1 {
            schema_version: "swarm-ai.storage.directory-manifest.v1".to_string(),
            files: stored_files,
            total_bytes,
        };
        let manifest_bytes = serde_json::to_vec(&manifest).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "Failed to serialize mock manifest",
            )
            .with_details(json!({ "error": error.to_string() }))
        })?;
        let reference = format!("bzz://sdk-mock-dir-{}", sha256_hex(&manifest_bytes));
        self.objects.insert(reference.clone(), manifest_bytes);
        self.manifests.insert(reference.clone(), manifest);
        Ok(upload_response(reference, total_bytes))
    }
}

impl StorageProvider for MockStorageProvider {
    fn get_status(&self) -> StorageStatusV1 {
        StorageStatusV1 {
            schema_version: "swarm-ai.storage.status.v1".to_string(),
            provider: "sdk-mock".to_string(),
            capabilities: StorageCapabilities {
                upload: true,
                download: true,
                feeds: false,
                pinning: false,
                act: false,
                pss: false,
            },
            retry_policy: None,
        }
    }

    fn download_bytes(&self, reference: &str) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let timer = Instant::now();
        let Some(bytes) = self.objects.get(reference) else {
            return Err(not_found(reference));
        };
        Ok(DownloadResponseV1 {
            schema_version: "swarm-ai.storage.download.v1".to_string(),
            reference: reference.to_string(),
            path: None,
            content_type: "application/octet-stream".to_string(),
            size_bytes: bytes.len(),
            sha256: Some(sha256_hex(bytes)),
            metrics: storage_metrics(timer, elapsed_ms(timer), bytes.len()),
            bytes: bytes.clone(),
        })
    }

    fn upload_bytes(&mut self, bytes: Vec<u8>) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let reference = format!("bzz://sdk-mock-bytes-{}", sha256_hex(&bytes));
        let size_bytes = bytes.len();
        self.objects.insert(reference.clone(), bytes);
        Ok(upload_response(reference, size_bytes))
    }

    fn upload_directory(&mut self, root: &Path) -> Result<UploadResponseV1, SwarmAiErrorV1> {
        let files = collect_mock_files(root).map_err(|error| {
            SwarmAiErrorV1::new(ErrorCode::InvalidRequest, "Failed to read directory").with_details(
                json!({ "root": root.display().to_string(), "error": error.to_string() }),
            )
        })?;
        self.put_directory_files(files)
    }

    fn download_manifest(&self, reference: &str) -> Result<DirectoryManifestV1, SwarmAiErrorV1> {
        self.manifests
            .get(reference)
            .cloned()
            .ok_or_else(|| not_found(reference))
    }

    fn download_file(
        &self,
        reference: &str,
        path: &str,
    ) -> Result<DownloadResponseV1, SwarmAiErrorV1> {
        let timer = Instant::now();
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
        response.metrics = storage_metrics(timer, elapsed_ms(timer), file.size_bytes);
        Ok(response)
    }
}

fn collect_mock_files(root: &Path) -> anyhow::Result<Vec<MockFileV1>> {
    let mut files = Vec::new();
    collect_mock_files_inner(root, root, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn collect_mock_files_inner(
    root: &Path,
    current: &Path,
    files: &mut Vec<MockFileV1>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_mock_files_inner(root, &path, files)?;
        } else {
            let relative = path
                .strip_prefix(root)?
                .to_string_lossy()
                .replace('\\', "/");
            files.push(MockFileV1 {
                path: relative.clone(),
                content_type: content_type_for_path(&relative).to_string(),
                bytes: fs::read(path)?,
            });
        }
    }
    Ok(())
}

fn timed_test(
    name: &'static str,
    test: impl FnOnce() -> Result<(), String>,
) -> CompatibilityTestResultV1 {
    let timer = Instant::now();
    match test() {
        Ok(()) => test_result(name, CompatibilityStatus::Passed, elapsed_ms(timer), None),
        Err(message) => test_result(
            name,
            CompatibilityStatus::Failed,
            elapsed_ms(timer),
            Some(message),
        ),
    }
}

fn test_result(
    name: impl Into<String>,
    status: CompatibilityStatus,
    duration_ms: u64,
    message: Option<String>,
) -> CompatibilityTestResultV1 {
    CompatibilityTestResultV1 {
        name: name.into(),
        status,
        duration_ms,
        message,
    }
}

fn compatibility_result(tests: &[CompatibilityTestResultV1]) -> CompatibilityResult {
    let failed = tests
        .iter()
        .filter(|test| test.status == CompatibilityStatus::Failed)
        .count();
    let skipped = tests
        .iter()
        .filter(|test| test.status == CompatibilityStatus::Skipped)
        .count();
    if failed == 0 && skipped == 0 {
        CompatibilityResult::Passed
    } else if failed == tests.len() {
        CompatibilityResult::Failed
    } else {
        CompatibilityResult::Partial
    }
}

fn deterministic_embedding(input: &Value) -> Vec<f32> {
    let bytes = serde_json::to_vec(input).unwrap_or_default();
    let digest = Sha256::digest(bytes);
    digest
        .chunks(4)
        .take(8)
        .map(|chunk| {
            let mut value = 0u32;
            for byte in chunk {
                value = (value << 8) | u32::from(*byte);
            }
            (value as f32 / u32::MAX as f32) * 2.0 - 1.0
        })
        .collect()
}

fn verification(issues: Vec<ValidationIssue>) -> SdkVerificationV1 {
    SdkVerificationV1 {
        schema_version: "swarm-ai.sdk-verification.v1".to_string(),
        valid: issues.is_empty(),
        issues,
    }
}

fn issue(path: impl Into<String>, message: impl Into<String>) -> ValidationIssue {
    ValidationIssue {
        path: path.into(),
        message: message.into(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn upload_response(reference: String, size_bytes: usize) -> UploadResponseV1 {
    let timer = Instant::now();
    UploadResponseV1 {
        schema_version: "swarm-ai.storage.upload.v1".to_string(),
        reference,
        size_bytes,
        pinned: false,
        redundancy_level: 0,
        postage_batch_id: None,
        metrics: storage_metrics(timer, elapsed_ms(timer), size_bytes),
    }
}

fn storage_metrics(
    timer: Instant,
    first_byte_ms: u64,
    size_bytes: usize,
) -> StorageTransferMetricsV1 {
    StorageTransferMetricsV1 {
        schema_version: "swarm-ai.storage.transfer-metrics.v1".to_string(),
        resolve_ms: first_byte_ms,
        first_byte_ms,
        total_ms: elapsed_ms(timer),
        size_bytes,
        retry_count: 0,
    }
}

fn not_found(reference: &str) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(
        ErrorCode::PackageNotFound,
        "Mock storage reference not found",
    )
    .with_details(json!({ "ref": reference }))
}

fn content_type_for_path(path: &str) -> &'static str {
    if path.ends_with(".json") {
        "application/json"
    } else if path.ends_with(".txt") {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn elapsed_ms(timer: Instant) -> u64 {
    timer.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_hashes_match_core_canonicalization() {
        let left = json!({ "b": 1, "a": true });
        let right = json!({ "a": true, "b": 1 });

        assert_eq!(hash_canonical(&left), hash_canonical(&right));
    }

    #[test]
    fn mock_storage_loads_package_ref() {
        let mut storage = MockStorageProvider::default();
        let upload = storage
            .put_directory_files(vec![
                MockFileV1 {
                    path: "swarm-ai.json".to_string(),
                    content_type: "application/json".to_string(),
                    bytes: serde_json::to_vec(&manifest()).unwrap(),
                },
                MockFileV1 {
                    path: "model/config.json".to_string(),
                    content_type: "application/json".to_string(),
                    bytes: br#"{"ok":true}"#.to_vec(),
                },
            ])
            .unwrap();

        let package = load_package(&storage, &upload.reference).unwrap();

        assert_eq!(package.manifest.package_id, "sdk/test");
    }

    #[test]
    fn verifies_receipts_created_by_sdk() {
        let manifest = parse_package_manifest(&manifest()).unwrap();
        let request = create_execution_request(
            "bzz://pkg",
            "sdk/test",
            "0.1.0",
            "embedding",
            json!({ "text": "hello" }),
        );
        let response = execute_mock_request(&request);
        let receipt = create_receipt(
            &request,
            &response,
            &manifest,
            "local",
            "0".repeat(64),
            "runner-1",
        );

        assert!(verify_receipt(&receipt).valid);
    }

    fn manifest() -> Value {
        json!({
            "schemaVersion": "swarm-ai.package.v1",
            "packageId": "sdk/test",
            "kind": "model",
            "name": "SDK Test",
            "version": "0.1.0",
            "publisher": {"address": "0x0", "displayName": "SDK"},
            "capabilities": ["embedding"],
            "artifactGroups": [{
                "id": "local",
                "target": "local-mock",
                "engine": "rust-mock",
                "format": "json",
                "paths": ["model/config.json"],
                "totalBytes": 1,
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "minimum": {"memoryMB": 1, "webgpu": false}
            }],
            "inputSchema": {"type": "object"},
            "outputSchema": {"type": "object"},
            "permissions": [],
            "license": {"type": "open", "name": "Apache-2.0"}
        })
    }
}
