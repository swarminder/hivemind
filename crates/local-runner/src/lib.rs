use chrono::{SecondsFormat, Utc};
use hivemind_access::evaluate_execution_access_with_revocations;
use hivemind_core::{
    AccessDecision, AccessEvaluationV1, AccessGrantV1, ErrorCode, ExecutionMetrics,
    ExecutionRequestV1, ExecutionResponseV1, ExecutionStatus, LicenseType, PackageManifestV1,
    RunnerDescriptorV1, RunnerLimits, RunnerType, SwarmAiErrorV1, license_requires_access_grant,
    manifest_supports_capability, runner_supports_capability, select_artifact_group,
};
use hivemind_package::{LocalPackage, load_package_from_storage};
use hivemind_policy::{
    PolicyDecision, PolicyDecisionV1, evaluate_package_policy, policy_execution_block_reason,
};
use hivemind_receipts::{ReceiptDraft, create_signed_receipt, receipt_policy_evidence};
use hivemind_storage::StorageProvider;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const RUNNER_ID: &str = "local-dev-runner";
const SENSITIVE_CACHE_MARKER_FILE: &str = ".swarm-ai-sensitive-cache.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "kebab-case")]
pub enum CacheSensitivity {
    #[default]
    Public,
    Protected,
    Private,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SensitiveCacheMarkerV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "artifactGroup")]
    pub artifact_group: String,
    #[serde(rename = "cacheSensitivity")]
    pub cache_sensitivity: CacheSensitivity,
    #[serde(rename = "accessGrantId", default)]
    pub access_grant_id: Option<String>,
    pub reason: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InstalledPackageV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageVersion")]
    pub package_version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "manifestHash")]
    pub manifest_hash: String,
    #[serde(rename = "artifactGroup")]
    pub artifact_group: String,
    #[serde(rename = "cachePath")]
    pub cache_path: String,
    pub files: Vec<CachedArtifactFileV1>,
    #[serde(rename = "policyDecision", default)]
    pub policy_decision: Option<PolicyDecisionV1>,
    #[serde(rename = "accessEvaluation", default)]
    pub access_evaluation: Option<AccessEvaluationV1>,
    #[serde(rename = "cacheSensitivity", default)]
    pub cache_sensitivity: CacheSensitivity,
    #[serde(rename = "sensitiveCacheMarker", default)]
    pub sensitive_cache_marker: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CachedArtifactFileV1 {
    pub path: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: usize,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LocalRunnerCacheSummaryV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    pub installs: Vec<InstalledPackageV1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LocalRunnerCacheClearResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "removedInstalls")]
    pub removed_installs: usize,
    #[serde(rename = "removedBytes")]
    pub removed_bytes: usize,
    #[serde(rename = "removedCachePaths")]
    pub removed_cache_paths: Vec<String>,
}

pub fn descriptor() -> RunnerDescriptorV1 {
    RunnerDescriptorV1 {
        schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
        runner_id: RUNNER_ID.to_string(),
        runner_type: RunnerType::Local,
        targets: vec![
            "local-mock".to_string(),
            "browser-wasm".to_string(),
            "node-cpu".to_string(),
        ],
        engines: vec!["rust-mock".to_string(), "wasm-mock".to_string()],
        capabilities: vec![
            "embedding".to_string(),
            "classification".to_string(),
            "chat".to_string(),
        ],
        limits: RunnerLimits {
            max_memory_mb: 4096,
            max_input_bytes: 128 * 1024,
            max_concurrent_jobs: 4,
        },
        queue_depth: 0,
        warm_package_refs: Vec::new(),
    }
}

pub fn install_from_storage(
    package_ref: &str,
    storage: &impl StorageProvider,
    cache_dir: &Path,
    preferred_artifact_group: Option<&str>,
    access_grant: Option<&AccessGrantV1>,
) -> anyhow::Result<InstalledPackageV1> {
    install_from_storage_with_revocations(
        package_ref,
        storage,
        cache_dir,
        preferred_artifact_group,
        access_grant,
        None,
    )
}

pub fn install_from_storage_with_revocations(
    package_ref: &str,
    storage: &impl StorageProvider,
    cache_dir: &Path,
    preferred_artifact_group: Option<&str>,
    access_grant: Option<&AccessGrantV1>,
    access_revocation_list: Option<&hivemind_core::AccessRevocationListV1>,
) -> anyhow::Result<InstalledPackageV1> {
    install_from_storage_with_revocations_and_policy(
        package_ref,
        storage,
        cache_dir,
        preferred_artifact_group,
        access_grant,
        access_revocation_list,
        false,
    )
}

pub fn install_from_storage_with_revocations_and_policy(
    package_ref: &str,
    storage: &impl StorageProvider,
    cache_dir: &Path,
    preferred_artifact_group: Option<&str>,
    access_grant: Option<&AccessGrantV1>,
    access_revocation_list: Option<&hivemind_core::AccessRevocationListV1>,
    developer_mode: bool,
) -> anyhow::Result<InstalledPackageV1> {
    let package = load_package_from_storage(package_ref, storage)?;
    let policy =
        evaluate_package_policy(&package.manifest, package_ref, Some(RUNNER_ID.to_string()));
    if policy.decision == PolicyDecision::Deny && !developer_mode {
        anyhow::bail!(
            "package policy denied before artifact download: {}",
            policy.reasons.join("; ")
        );
    }
    let access = evaluate_execution_access_with_revocations(
        &package.manifest,
        package_ref,
        "install",
        "local-dev",
        "runner-service",
        Some(RUNNER_ID),
        access_grant,
        access_revocation_list,
    );
    if access.decision != AccessDecision::Granted {
        anyhow::bail!(
            "package access denied before artifact download: {}",
            access.reasons.join("; ")
        );
    }
    let descriptor = descriptor();
    let artifact = select_artifact_group(
        &package.manifest,
        preferred_artifact_group,
        &descriptor.targets,
        &descriptor.engines,
    )
    .ok_or_else(|| anyhow::anyhow!("no compatible artifact group for local runner"))?;
    let install_dir = cache_dir
        .join(safe_file_component(package_ref))
        .join(&artifact.id);
    fs::create_dir_all(&install_dir)?;

    let mut files = Vec::new();
    for path in &artifact.paths {
        let response = storage
            .download_file(package_ref, path)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let destination = install_dir.join(path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&destination, &response.bytes)?;
        files.push(CachedArtifactFileV1 {
            path: path.to_string(),
            size_bytes: response.size_bytes,
            sha256: response.sha256,
        });
    }

    let manifest_destination = install_dir.join("swarm-ai.json");
    fs::write(
        &manifest_destination,
        serde_json::to_vec_pretty(&package.manifest)?,
    )?;

    let cache_sensitivity = cache_sensitivity_for(&package.manifest);
    let sensitive_cache_marker = write_sensitive_cache_marker(
        &install_dir,
        &package.manifest,
        package_ref,
        &artifact.id,
        &cache_sensitivity,
        &access,
    )?;

    let install = InstalledPackageV1 {
        schema_version: "swarm-ai.local-runner.install.v1".to_string(),
        package_id: package.manifest.package_id.clone(),
        package_version: package.manifest.version.clone(),
        package_ref: package_ref.to_string(),
        manifest_hash: package.manifest_hash.clone(),
        artifact_group: artifact.id.clone(),
        cache_path: install_dir.display().to_string(),
        files,
        policy_decision: Some(policy),
        access_evaluation: Some(access),
        cache_sensitivity,
        sensitive_cache_marker,
    };
    fs::write(
        install_dir.join("install.json"),
        serde_json::to_vec_pretty(&install)?,
    )?;
    Ok(install)
}

pub fn list_cache(cache_dir: &Path) -> anyhow::Result<LocalRunnerCacheSummaryV1> {
    let mut installs = Vec::new();
    if cache_dir.exists() {
        collect_install_records(cache_dir, &mut installs)?;
    }
    installs.sort_by(|left, right| {
        left.package_id
            .cmp(&right.package_id)
            .then(left.artifact_group.cmp(&right.artifact_group))
    });
    Ok(LocalRunnerCacheSummaryV1 {
        schema_version: "swarm-ai.local-runner.cache-summary.v1".to_string(),
        root: cache_dir.display().to_string(),
        installs,
    })
}

pub fn clear_cache(
    cache_dir: &Path,
    package_ref: &str,
) -> anyhow::Result<LocalRunnerCacheClearResultV1> {
    let package_ref = package_ref.trim();
    if package_ref.is_empty() {
        anyhow::bail!("packageRef is required to clear local runner cache");
    }

    let mut records = Vec::new();
    if cache_dir.exists() {
        collect_install_records_with_paths(cache_dir, &mut records)?;
    }

    let canonical_root = if cache_dir.exists() {
        Some(fs::canonicalize(cache_dir)?)
    } else {
        None
    };
    let mut removed_bytes = 0usize;
    let mut removed_cache_paths = Vec::new();
    for (install, install_record_path) in records {
        if install.package_ref != package_ref {
            continue;
        }
        let Some(install_dir) = install_record_path.parent() else {
            continue;
        };
        if let Some(root) = &canonical_root {
            let canonical_install_dir = fs::canonicalize(install_dir)?;
            if !canonical_install_dir.starts_with(root) {
                anyhow::bail!(
                    "refusing to clear cache path outside cache root: {}",
                    install_dir.display()
                );
            }
        }
        removed_bytes += install
            .files
            .iter()
            .map(|file| file.size_bytes)
            .sum::<usize>();
        removed_cache_paths.push(install_dir.display().to_string());
        fs::remove_dir_all(install_dir)?;
        if let Some(package_dir) = install_dir.parent() {
            let _ = fs::remove_dir(package_dir);
        }
    }

    Ok(LocalRunnerCacheClearResultV1 {
        schema_version: "swarm-ai.local-runner.cache-clear-result.v1".to_string(),
        package_ref: package_ref.to_string(),
        removed_installs: removed_cache_paths.len(),
        removed_bytes,
        removed_cache_paths,
    })
}

pub async fn execute_from_storage(
    request: ExecutionRequestV1,
    storage: &impl StorageProvider,
) -> anyhow::Result<ExecutionResponseV1> {
    let package = load_package_from_storage(&request.package_ref, storage)?;
    Ok(execute(request, package).await)
}

pub async fn execute(request: ExecutionRequestV1, package: LocalPackage) -> ExecutionResponseV1 {
    execute_with_route(request, package, None).await
}

pub async fn execute_with_route(
    request: ExecutionRequestV1,
    package: LocalPackage,
    route_id: Option<String>,
) -> ExecutionResponseV1 {
    let started = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let timer = Instant::now();
    let descriptor = descriptor();
    let receipt_route_id = route_id.unwrap_or_else(|| format!("local-{RUNNER_ID}"));
    let policy = evaluate_package_policy(
        &package.manifest,
        &package.package_ref,
        Some(descriptor.runner_id.clone()),
    );
    let access = evaluate_execution_access_with_revocations(
        &package.manifest,
        &request.package_ref,
        &request.request_id,
        "local-dev",
        "runner-service",
        Some(RUNNER_ID),
        request.access_grant.as_ref(),
        request.access_revocation_list.as_ref(),
    );

    if let Some(policy_reason) = policy_execution_block_reason(&policy) {
        return ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(ErrorCode::AccessDenied, policy_reason)
                .with_details(json!({ "policy": policy })),
            ExecutionMetrics::default(),
        );
    }

    if access.decision != AccessDecision::Granted {
        return ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::AccessDenied,
                "Package license requires an access grant",
            )
            .with_details(json!({ "access": access })),
            ExecutionMetrics::default(),
        );
    }

    if !manifest_supports_capability(&package.manifest, &request.task) {
        let task = request.task.clone();
        return ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::UnsupportedOperation,
                format!("Package does not declare support for task {task}"),
            ),
            ExecutionMetrics::default(),
        );
    }

    if !runner_supports_capability(&descriptor, &request.task) {
        let task = request.task.clone();
        return ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::UnsupportedOperation,
                format!("Local runner does not declare support for task {task}"),
            ),
            ExecutionMetrics::default(),
        );
    }

    let Some(artifact) = select_artifact_group(
        &package.manifest,
        request.preferred_artifact_group.as_deref(),
        &descriptor.targets,
        &descriptor.engines,
    ) else {
        return ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::UnsupportedTarget,
                "No artifact group matches this runner",
            ),
            ExecutionMetrics::default(),
        );
    };

    let output = match request.task.as_str() {
        "embedding" => json!({
            "embedding": deterministic_embedding(&request.input),
            "model": package.manifest.package_id,
        }),
        "classification" => classify(&request.input),
        "chat" => chat(&request.input),
        _ => json!({
            "echo": request.input,
            "task": request.task,
            "runner": RUNNER_ID,
        }),
    };

    let elapsed = timer.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    let metrics = ExecutionMetrics {
        queue_ms: 0,
        load_ms: 1,
        compute_ms: elapsed,
        total_ms: elapsed + 1,
        input_tokens: estimate_tokens(&request.input),
        output_tokens: None,
    };
    let mut response = ExecutionResponseV1 {
        schema_version: "swarm-ai.execution.response.v1".to_string(),
        request_id: request.request_id.clone(),
        status: ExecutionStatus::Succeeded,
        output,
        metrics,
        receipt_ref: None,
        error: None,
        metadata: json!({
            "runnerId": RUNNER_ID,
            "routeId": receipt_route_id,
            "artifactGroup": artifact.id,
            "policy": policy,
            "access": access,
        }),
    };

    let finished = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let policy_evidence = receipt_policy_evidence(&policy, finished.clone());
    let receipt = create_signed_receipt(ReceiptDraft {
        request: &request,
        response: &response,
        manifest: &package.manifest,
        artifact_group: &artifact.id,
        manifest_hash: &package.manifest_hash,
        runner_id: RUNNER_ID,
        route_id: Some(receipt_route_id),
        policy: Some(policy_evidence),
        started_at: &started,
        finished_at: &finished,
    });
    response.receipt_ref = Some(format!("local://receipt/{}", receipt.receipt_id));
    response.metadata["receipt"] = serde_json::to_value(receipt).unwrap_or_else(|_| json!(null));
    response
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

fn classify(input: &Value) -> Value {
    let text = input_text(input).to_lowercase();
    let label = if text.contains("hello") || text.contains("hi") {
        "greeting"
    } else if text.contains("error") || text.contains("fail") {
        "problem"
    } else {
        "general"
    };
    json!({ "label": label, "score": 0.77 })
}

fn chat(input: &Value) -> Value {
    let text = input_text(input);
    json!({
        "message": {
            "role": "assistant",
            "content": format!("Local dev runner received: {text}")
        }
    })
}

fn input_text(input: &Value) -> String {
    input
        .get("text")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| input.to_string())
}

fn estimate_tokens(input: &Value) -> Option<u64> {
    Some(input_text(input).split_whitespace().count() as u64)
}

fn collect_install_records(
    root: &Path,
    installs: &mut Vec<InstalledPackageV1>,
) -> anyhow::Result<()> {
    let mut records = Vec::new();
    collect_install_records_with_paths(root, &mut records)?;
    installs.extend(records.into_iter().map(|(install, _)| install));
    Ok(())
}

fn collect_install_records_with_paths(
    root: &Path,
    installs: &mut Vec<(InstalledPackageV1, PathBuf)>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_install_records_with_paths(&path, installs)?;
        } else if path.file_name().and_then(|name| name.to_str()) == Some("install.json") {
            let bytes = fs::read(&path)?;
            installs.push((serde_json::from_slice(&bytes)?, path));
        }
    }
    Ok(())
}

fn cache_sensitivity_for(manifest: &PackageManifestV1) -> CacheSensitivity {
    if manifest.license.license_type == LicenseType::Private {
        CacheSensitivity::Private
    } else if license_requires_access_grant(&manifest.license.license_type) {
        CacheSensitivity::Protected
    } else {
        CacheSensitivity::Public
    }
}

fn write_sensitive_cache_marker(
    install_dir: &Path,
    manifest: &PackageManifestV1,
    package_ref: &str,
    artifact_group: &str,
    cache_sensitivity: &CacheSensitivity,
    access: &AccessEvaluationV1,
) -> anyhow::Result<Option<String>> {
    if cache_sensitivity == &CacheSensitivity::Public {
        return Ok(None);
    }

    let marker = SensitiveCacheMarkerV1 {
        schema_version: "swarm-ai.local-runner.sensitive-cache-marker.v1".to_string(),
        package_id: manifest.package_id.clone(),
        package_version: manifest.version.clone(),
        package_ref: package_ref.to_string(),
        artifact_group: artifact_group.to_string(),
        cache_sensitivity: cache_sensitivity.clone(),
        access_grant_id: access.grant_id.clone(),
        reason: cache_sensitivity_reason(manifest, cache_sensitivity),
        created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    };
    let marker_path = install_dir.join(SENSITIVE_CACHE_MARKER_FILE);
    fs::write(&marker_path, serde_json::to_vec_pretty(&marker)?)?;
    Ok(Some(marker_path.display().to_string()))
}

fn cache_sensitivity_reason(
    manifest: &PackageManifestV1,
    cache_sensitivity: &CacheSensitivity,
) -> String {
    match cache_sensitivity {
        CacheSensitivity::Public => {
            "Open package cache does not require special marking".to_string()
        }
        CacheSensitivity::Protected => format!(
            "Package license {:?} requires an access grant; cached artifacts are protected package data",
            manifest.license.license_type
        ),
        CacheSensitivity::Private => {
            "Private package cache contains access-controlled package data".to_string()
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ArtifactGroup, ArtifactMinimum, ExecutionOptions, ExecutionPrivacy, LicenseInfo,
        LicenseType, PackageKind, PermissionRequest, Publisher, license_policy_from_manifest,
    };
    use hivemind_storage::{LocalDirectoryStorageProvider, StorageProvider};
    use serde_json::{Value, json};

    #[test]
    fn clears_only_matching_package_ref() {
        let root = unique_temp_dir("hivemind-local-runner-cache-test");
        let first_dir = root.join("first").join("local-rust-mock");
        let second_dir = root.join("second").join("local-rust-mock");
        write_install(&first_dir, "bzz://first", 7);
        write_install(&second_dir, "bzz://second", 11);

        let result = clear_cache(&root, "bzz://first").unwrap();
        let summary = list_cache(&root).unwrap();

        assert_eq!(result.removed_installs, 1);
        assert_eq!(result.removed_bytes, 7);
        assert!(!first_dir.exists());
        assert!(second_dir.exists());
        assert_eq!(summary.installs.len(), 1);
        assert_eq!(summary.installs[0].package_ref, "bzz://second");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn protected_install_writes_sensitive_cache_marker() {
        let root = unique_temp_dir("hivemind-sensitive-cache-test");
        let package_dir = root.join("package");
        let storage_dir = root.join("storage");
        let cache_dir = root.join("runner");
        fs::create_dir_all(package_dir.join("model")).unwrap();
        fs::write(package_dir.join("model").join("config.json"), "{}").unwrap();
        fs::write(
            package_dir.join("model").join("tokenizer.json"),
            "{\"tokens\":[]}",
        )
        .unwrap();
        let manifest = manifest(LicenseType::Commercial);
        fs::write(
            package_dir.join("swarm-ai.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let mut storage = LocalDirectoryStorageProvider::new(storage_dir);
        let upload = storage.upload_directory(&package_dir).unwrap();
        let policy = license_policy_from_manifest(&manifest, &upload.reference);
        let grant = hivemind_access::dev_access_grant(
            &policy,
            "local-dev",
            "runner-service",
            Some(RUNNER_ID.to_string()),
            None,
        );
        let install =
            install_from_storage(&upload.reference, &storage, &cache_dir, None, Some(&grant))
                .unwrap();

        assert_eq!(install.cache_sensitivity, CacheSensitivity::Protected);
        let marker_path = install
            .sensitive_cache_marker
            .as_ref()
            .map(PathBuf::from)
            .expect("protected install should write marker");
        assert!(marker_path.exists());
        let marker: SensitiveCacheMarkerV1 =
            serde_json::from_slice(&fs::read(marker_path).unwrap()).unwrap();
        assert_eq!(marker.package_id, "hivemind/cache-sensitive");
        assert_eq!(marker.cache_sensitivity, CacheSensitivity::Protected);
        assert_eq!(marker.access_grant_id, Some(grant.grant_id));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn denied_policy_blocks_install_before_artifact_cache() {
        let root = unique_temp_dir("hivemind-policy-cache-test");
        let package_dir = root.join("package");
        let storage_dir = root.join("storage");
        let cache_dir = root.join("runner");
        fs::create_dir_all(package_dir.join("model")).unwrap();
        fs::write(package_dir.join("model").join("config.json"), "{}").unwrap();
        fs::write(
            package_dir.join("model").join("tokenizer.json"),
            "{\"tokens\":[]}",
        )
        .unwrap();
        let mut manifest = manifest(LicenseType::Open);
        manifest.permissions.push(PermissionRequest {
            name: "local.shell".to_string(),
            purpose: Some("run setup script".to_string()),
            required: true,
            limits: json!({}),
        });
        fs::write(
            package_dir.join("swarm-ai.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let mut storage = LocalDirectoryStorageProvider::new(storage_dir);
        let upload = storage.upload_directory(&package_dir).unwrap();
        let error =
            install_from_storage(&upload.reference, &storage, &cache_dir, None, None).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("package policy denied before artifact download")
        );
        assert!(!cache_dir.exists());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn developer_mode_can_cache_policy_denied_package_for_inspection() {
        let root = unique_temp_dir("hivemind-policy-developer-cache-test");
        let package_dir = root.join("package");
        let storage_dir = root.join("storage");
        let cache_dir = root.join("runner");
        fs::create_dir_all(package_dir.join("model")).unwrap();
        fs::write(package_dir.join("model").join("config.json"), "{}").unwrap();
        fs::write(
            package_dir.join("model").join("tokenizer.json"),
            "{\"tokens\":[]}",
        )
        .unwrap();
        let mut manifest = manifest(LicenseType::Open);
        manifest.permissions.push(PermissionRequest {
            name: "local.shell".to_string(),
            purpose: Some("run setup script".to_string()),
            required: true,
            limits: json!({}),
        });
        fs::write(
            package_dir.join("swarm-ai.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let mut storage = LocalDirectoryStorageProvider::new(storage_dir);
        let upload = storage.upload_directory(&package_dir).unwrap();
        let install = install_from_storage_with_revocations_and_policy(
            &upload.reference,
            &storage,
            &cache_dir,
            None,
            None,
            None,
            true,
        )
        .unwrap();

        let policy = install
            .policy_decision
            .expect("install should preserve policy decision");
        assert_eq!(policy.decision, PolicyDecision::Deny);
        assert!(PathBuf::from(&install.cache_path).exists());

        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn consent_required_policy_blocks_local_execution() {
        let mut manifest = manifest(LicenseType::Open);
        manifest.permissions.push(PermissionRequest {
            name: "network.http".to_string(),
            purpose: Some("call an external API".to_string()),
            required: false,
            limits: json!({ "allowedHosts": ["api.example.com"] }),
        });
        let package = LocalPackage {
            root: PathBuf::new(),
            manifest,
            manifest_hash: "0".repeat(64),
            package_ref: "bzz://pkg".to_string(),
        };
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: package.package_ref.clone(),
            package_id: package.manifest.package_id.clone(),
            package_version: package.manifest.version.clone(),
            preferred_artifact_group: None,
            task: "embedding".to_string(),
            input: json!({ "text": "hello local" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let response = execute(request, package).await;

        assert_eq!(response.status, ExecutionStatus::Failed);
        assert_eq!(
            response.error.as_ref().unwrap().code,
            ErrorCode::AccessDenied
        );
        assert_eq!(
            response
                .error
                .as_ref()
                .unwrap()
                .details
                .get("policy")
                .and_then(|policy| policy.get("decision"))
                .and_then(Value::as_str),
            Some("ask-user")
        );
    }

    fn write_install(dir: &Path, package_ref: &str, size_bytes: usize) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("model.bin"), vec![0u8; size_bytes]).unwrap();
        let install = InstalledPackageV1 {
            schema_version: "swarm-ai.local-runner.install.v1".to_string(),
            package_id: "hivemind/cache-test".to_string(),
            package_version: "0.1.0".to_string(),
            package_ref: package_ref.to_string(),
            manifest_hash: "hash".to_string(),
            artifact_group: "local-rust-mock".to_string(),
            cache_path: dir.display().to_string(),
            files: vec![CachedArtifactFileV1 {
                path: "model.bin".to_string(),
                size_bytes,
                sha256: None,
            }],
            policy_decision: None,
            access_evaluation: None,
            cache_sensitivity: CacheSensitivity::Public,
            sensitive_cache_marker: None,
        };
        fs::write(
            dir.join("install.json"),
            serde_json::to_vec_pretty(&install).unwrap(),
        )
        .unwrap();
    }

    fn manifest(license_type: LicenseType) -> PackageManifestV1 {
        PackageManifestV1 {
            schema_version: "swarm-ai.package.v1".to_string(),
            package_id: "hivemind/cache-sensitive".to_string(),
            kind: PackageKind::Model,
            name: "Cache Sensitive".to_string(),
            version: "0.1.0".to_string(),
            publisher: Publisher {
                address: "0x0000000000000000000000000000000000000000".to_string(),
                display_name: "Hivemind".to_string(),
                publisher_profile_ref: None,
            },
            capabilities: vec!["embedding".to_string()],
            artifact_groups: vec![ArtifactGroup {
                id: "local-rust-mock".to_string(),
                target: "local-mock".to_string(),
                engine: "rust-mock".to_string(),
                format: "json".to_string(),
                paths: vec![
                    "model/config.json".to_string(),
                    "model/tokenizer.json".to_string(),
                ],
                total_bytes: 2,
                sha256: "0".repeat(64),
                minimum: ArtifactMinimum {
                    memory_mb: Some(1),
                    webgpu: Some(false),
                    disk_mb: None,
                },
            }],
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            permissions: Vec::new(),
            license: LicenseInfo {
                license_type,
                name: Some("Example".to_string()),
                url: None,
            },
        }
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        path
    }
}
