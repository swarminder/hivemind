use chrono::{SecondsFormat, Utc};
use hivemind_access::evaluate_execution_access_with_revocations;
use hivemind_core::{
    AccessDecision, ErrorCode, ExecutionMetrics, ExecutionReceiptV1, ExecutionRequestV1,
    ExecutionResponseV1, ExecutionStatus, PackageManifestV1, ReceiptDraft, RunnerDescriptorV1,
    RunnerLimits, RunnerType, SwarmAiErrorV1, canonicalize_json, create_signed_receipt,
    evaluate_package_policy, hash_canonical_json, manifest_supports_capability,
    policy_execution_block_reason, receipt_policy_evidence, runner_supports_capability,
    select_artifact_group,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Instant;

const BROWSER_RUNNER_ID: &str = "browser-dev-runner";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserRunnerV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserCapabilitiesV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub webgpu: bool,
    pub wasm: bool,
    #[serde(rename = "serviceWorker")]
    pub service_worker: bool,
    #[serde(rename = "indexedDb")]
    pub indexed_db: bool,
    #[serde(rename = "estimatedMemoryMB")]
    pub estimated_memory_mb: u64,
    #[serde(rename = "supportedEngines")]
    pub supported_engines: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserArtifactFileV1 {
    pub path: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserRunAssessmentV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "canRun")]
    pub can_run: bool,
    #[serde(rename = "artifactGroup", default)]
    pub artifact_group: Option<String>,
    #[serde(rename = "estimatedDownloadBytes")]
    pub estimated_download_bytes: u64,
    pub reasons: Vec<String>,
    pub warnings: Vec<String>,
    #[serde(rename = "handoffReason", default)]
    pub handoff_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserPreparePlanV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageId")]
    pub package_id: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "artifactGroup")]
    pub artifact_group: String,
    #[serde(rename = "target")]
    pub target: String,
    pub engine: String,
    #[serde(rename = "totalBytes")]
    pub total_bytes: u64,
    pub files: Vec<BrowserArtifactFileV1>,
    #[serde(rename = "cacheKey")]
    pub cache_key: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserPreparedPackageV1 {
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
    #[serde(rename = "cacheKey")]
    pub cache_key: String,
    #[serde(rename = "cachedBytes")]
    pub cached_bytes: u64,
    #[serde(rename = "preparedAt")]
    pub prepared_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct BrowserRunnerMetricsV1 {
    #[serde(rename = "preparedPackages")]
    pub prepared_packages: usize,
    #[serde(rename = "cachedBytes")]
    pub cached_bytes: u64,
    #[serde(rename = "lastLoadMs")]
    pub last_load_ms: u64,
    #[serde(rename = "lastComputeMs")]
    pub last_compute_ms: u64,
    #[serde(rename = "lastTotalMs")]
    pub last_total_ms: u64,
}

pub fn browser_runner_contract() -> BrowserRunnerV1 {
    BrowserRunnerV1 {
        schema_version: "swarm-ai.browser-runner.v1".to_string(),
        methods: vec![
            "detectCapabilities()".to_string(),
            "canRun(packageManifest, artifactGroup)".to_string(),
            "prepare(packageRef, artifactGroup)".to_string(),
            "execute(executionRequest)".to_string(),
            "cancel(requestId)".to_string(),
            "clearCache(packageRef)".to_string(),
            "getMetrics()".to_string(),
        ],
    }
}

pub fn default_browser_capabilities() -> BrowserCapabilitiesV1 {
    BrowserCapabilitiesV1 {
        schema_version: "swarm-ai.browser-capabilities.v1".to_string(),
        webgpu: false,
        wasm: true,
        service_worker: true,
        indexed_db: true,
        estimated_memory_mb: 2048,
        supported_engines: vec!["wasm-mock".to_string(), "rust-mock".to_string()],
        warnings: Vec::new(),
    }
}

pub fn runner_descriptor(capabilities: &BrowserCapabilitiesV1) -> RunnerDescriptorV1 {
    RunnerDescriptorV1 {
        schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
        runner_id: BROWSER_RUNNER_ID.to_string(),
        runner_type: RunnerType::Browser,
        targets: browser_targets(capabilities),
        engines: capabilities.supported_engines.clone(),
        capabilities: vec![
            "embedding".to_string(),
            "classification".to_string(),
            "chat".to_string(),
        ],
        limits: RunnerLimits {
            max_memory_mb: capabilities.estimated_memory_mb,
            max_input_bytes: 64 * 1024,
            max_concurrent_jobs: 1,
        },
        queue_depth: 0,
        warm_package_refs: Vec::new(),
    }
}

pub fn browser_capabilities_from_hints(
    webgpu: bool,
    wasm: bool,
    service_worker: bool,
    indexed_db: bool,
    estimated_memory_mb: u64,
    supported_engines: Vec<String>,
) -> BrowserCapabilitiesV1 {
    let mut warnings = Vec::new();
    if !wasm {
        warnings.push("wasm-unavailable".to_string());
    }
    if estimated_memory_mb < 1024 {
        warnings.push("low-memory".to_string());
    }
    if !indexed_db {
        warnings.push("model-cache-unavailable".to_string());
    }
    BrowserCapabilitiesV1 {
        schema_version: "swarm-ai.browser-capabilities.v1".to_string(),
        webgpu,
        wasm,
        service_worker,
        indexed_db,
        estimated_memory_mb,
        supported_engines,
        warnings,
    }
}

pub fn browser_targets(capabilities: &BrowserCapabilitiesV1) -> Vec<String> {
    if capabilities.webgpu {
        vec!["browser-webgpu".to_string(), "browser-wasm".to_string()]
    } else {
        vec!["browser-wasm".to_string()]
    }
}

pub fn can_run_in_browser(
    manifest: &PackageManifestV1,
    capabilities: &BrowserCapabilitiesV1,
    preferred_artifact_group: Option<&str>,
) -> bool {
    select_browser_artifact(manifest, capabilities, preferred_artifact_group).is_some()
}

pub fn select_browser_artifact<'a>(
    manifest: &'a PackageManifestV1,
    capabilities: &BrowserCapabilitiesV1,
    preferred_artifact_group: Option<&str>,
) -> Option<&'a hivemind_core::ArtifactGroup> {
    if !capabilities.wasm {
        return None;
    }
    let targets = browser_targets(capabilities);
    select_artifact_group(
        manifest,
        preferred_artifact_group,
        &targets,
        &capabilities.supported_engines,
    )
}

pub fn assess_package(
    manifest: &PackageManifestV1,
    capabilities: &BrowserCapabilitiesV1,
    preferred_artifact_group: Option<&str>,
) -> BrowserRunAssessmentV1 {
    let mut reasons = Vec::new();
    let mut warnings = capabilities.warnings.clone();

    if !capabilities.wasm {
        return BrowserRunAssessmentV1 {
            schema_version: "swarm-ai.browser-run-assessment.v1".to_string(),
            package_id: manifest.package_id.clone(),
            can_run: false,
            artifact_group: None,
            estimated_download_bytes: 0,
            reasons: vec!["Browser WASM support is required".to_string()],
            warnings,
            handoff_reason: Some("wasm-unavailable".to_string()),
        };
    }

    let Some(artifact) = select_browser_artifact(manifest, capabilities, preferred_artifact_group)
    else {
        return BrowserRunAssessmentV1 {
            schema_version: "swarm-ai.browser-run-assessment.v1".to_string(),
            package_id: manifest.package_id.clone(),
            can_run: false,
            artifact_group: None,
            estimated_download_bytes: 0,
            reasons: vec!["No browser-compatible artifact group matches this device".to_string()],
            warnings,
            handoff_reason: Some("unsupported-browser-target".to_string()),
        };
    };

    if let Some(memory_mb) = artifact.minimum.memory_mb {
        if memory_mb > capabilities.estimated_memory_mb {
            reasons.push(format!(
                "Artifact requires {memory_mb} MB but browser estimate is {} MB",
                capabilities.estimated_memory_mb
            ));
            warnings.push("insufficient-memory".to_string());
        }
    }
    if artifact.minimum.webgpu.unwrap_or(false) && !capabilities.webgpu {
        reasons.push("Artifact requires WebGPU but this browser does not expose it".to_string());
    }
    if artifact.total_bytes > 256 * 1024 * 1024 {
        warnings.push("large-browser-download".to_string());
    }
    if reasons.is_empty() {
        reasons.push("Browser can run the selected artifact group".to_string());
    }
    let can_run = !warnings
        .iter()
        .any(|warning| warning == "insufficient-memory")
        && !(artifact.minimum.webgpu.unwrap_or(false) && !capabilities.webgpu);

    BrowserRunAssessmentV1 {
        schema_version: "swarm-ai.browser-run-assessment.v1".to_string(),
        package_id: manifest.package_id.clone(),
        can_run,
        artifact_group: Some(artifact.id.clone()),
        estimated_download_bytes: artifact.total_bytes,
        reasons,
        warnings,
        handoff_reason: (!can_run).then(|| "device-capability-mismatch".to_string()),
    }
}

pub fn prepare_plan(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
    manifest_hash: impl Into<String>,
    capabilities: &BrowserCapabilitiesV1,
    preferred_artifact_group: Option<&str>,
) -> Result<BrowserPreparePlanV1, SwarmAiErrorV1> {
    let package_ref = package_ref.into();
    let manifest_hash = manifest_hash.into();
    let assessment = assess_package(manifest, capabilities, preferred_artifact_group);
    if !assessment.can_run {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::UnsupportedTarget,
            "Browser cannot run this package",
        )
        .with_details(json!(assessment)));
    }
    let artifact_id = assessment
        .artifact_group
        .as_deref()
        .ok_or_else(|| SwarmAiErrorV1::new(ErrorCode::UnsupportedTarget, "No artifact selected"))?;
    let artifact = manifest
        .artifact_groups
        .iter()
        .find(|group| group.id == artifact_id)
        .ok_or_else(|| {
            SwarmAiErrorV1::new(ErrorCode::UnsupportedTarget, "Selected artifact is missing")
        })?;
    let cache_key = stable_id(
        "browser-cache",
        &json!({
            "packageRef": package_ref,
            "manifestHash": manifest_hash,
            "artifactGroup": artifact.id,
        }),
    );
    let per_file = if artifact.paths.is_empty() {
        0
    } else {
        artifact.total_bytes / artifact.paths.len() as u64
    };
    Ok(BrowserPreparePlanV1 {
        schema_version: "swarm-ai.browser-prepare-plan.v1".to_string(),
        package_id: manifest.package_id.clone(),
        package_ref,
        artifact_group: artifact.id.clone(),
        target: artifact.target.clone(),
        engine: artifact.engine.clone(),
        total_bytes: artifact.total_bytes,
        files: artifact
            .paths
            .iter()
            .map(|path| BrowserArtifactFileV1 {
                path: path.clone(),
                size_bytes: per_file,
            })
            .collect(),
        cache_key,
        warnings: assessment.warnings,
    })
}

pub fn record_prepared_package(
    manifest: &PackageManifestV1,
    manifest_hash: impl Into<String>,
    plan: &BrowserPreparePlanV1,
) -> BrowserPreparedPackageV1 {
    BrowserPreparedPackageV1 {
        schema_version: "swarm-ai.browser-prepared-package.v1".to_string(),
        package_id: manifest.package_id.clone(),
        package_version: manifest.version.clone(),
        package_ref: plan.package_ref.clone(),
        manifest_hash: manifest_hash.into(),
        artifact_group: plan.artifact_group.clone(),
        cache_key: plan.cache_key.clone(),
        cached_bytes: plan.total_bytes,
        prepared_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }
}

pub fn execute_prepared(
    request: ExecutionRequestV1,
    manifest: &PackageManifestV1,
    prepared: &BrowserPreparedPackageV1,
) -> ExecutionResponseV1 {
    execute_prepared_with_route(request, manifest, prepared, None)
}

pub fn execute_prepared_with_route(
    request: ExecutionRequestV1,
    manifest: &PackageManifestV1,
    prepared: &BrowserPreparedPackageV1,
    route_id: Option<String>,
) -> ExecutionResponseV1 {
    if request.package_ref != prepared.package_ref || request.package_id != prepared.package_id {
        return ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "Execution request does not match prepared browser package",
            ),
            ExecutionMetrics::default(),
        );
    }

    let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let receipt_route_id = route_id.unwrap_or_else(|| format!("browser-{BROWSER_RUNNER_ID}"));
    let policy = evaluate_package_policy(
        manifest,
        &prepared.package_ref,
        Some(BROWSER_RUNNER_ID.to_string()),
    );
    if let Some(policy_reason) = policy_execution_block_reason(&policy) {
        return ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(ErrorCode::AccessDenied, policy_reason)
                .with_details(json!({ "policy": policy })),
            ExecutionMetrics::default(),
        );
    }
    let access = evaluate_execution_access_with_revocations(
        manifest,
        &prepared.package_ref,
        &request.request_id,
        "local-dev",
        "runner-service",
        Some(BROWSER_RUNNER_ID),
        request.access_grant.as_ref(),
        request.access_revocation_list.as_ref(),
    );
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
    let timer = Instant::now();
    let output = match request.task.as_str() {
        "embedding" => json!({
            "embedding": deterministic_embedding(&request.input),
            "model": manifest.package_id,
            "runner": BROWSER_RUNNER_ID,
        }),
        "classification" => classify(&request.input),
        "chat" => chat(&request.input),
        _ => json!({
            "echo": request.input,
            "task": request.task,
            "runner": BROWSER_RUNNER_ID,
        }),
    };
    let compute_ms = timer.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    let metrics = ExecutionMetrics {
        queue_ms: 0,
        load_ms: 0,
        compute_ms,
        total_ms: compute_ms,
        input_tokens: Some(input_text(&request.input).split_whitespace().count() as u64),
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
            "runnerId": BROWSER_RUNNER_ID,
            "routeId": receipt_route_id,
            "artifactGroup": prepared.artifact_group,
            "cacheKey": prepared.cache_key,
            "executionLocation": "browser",
            "policy": policy,
            "access": access,
        }),
    };
    let finished_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let policy_evidence = receipt_policy_evidence(&policy, finished_at.clone());
    let receipt = create_signed_receipt(ReceiptDraft {
        request: &request,
        response: &response,
        manifest,
        artifact_group: &prepared.artifact_group,
        manifest_hash: &prepared.manifest_hash,
        runner_id: BROWSER_RUNNER_ID,
        route_id: Some(receipt_route_id),
        policy: Some(policy_evidence),
        started_at: &started_at,
        finished_at: &finished_at,
    });
    response.receipt_ref = Some(format!("local://receipt/{}", receipt.receipt_id));
    response.metadata["receipt"] = serde_json::to_value(receipt).unwrap_or_else(|_| json!(null));
    response
}

pub fn execute_manifest(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
    request: ExecutionRequestV1,
    capabilities: &BrowserCapabilitiesV1,
) -> ExecutionResponseV1 {
    let manifest_hash = manifest_hash(manifest);
    execute_manifest_with_hash(manifest, package_ref, manifest_hash, request, capabilities)
}

pub fn execute_manifest_with_hash(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
    manifest_hash: impl Into<String>,
    request: ExecutionRequestV1,
    capabilities: &BrowserCapabilitiesV1,
) -> ExecutionResponseV1 {
    execute_manifest_with_hash_and_route(
        manifest,
        package_ref,
        manifest_hash,
        request,
        capabilities,
        None,
    )
}

pub fn execute_manifest_with_hash_and_route(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
    manifest_hash: impl Into<String>,
    request: ExecutionRequestV1,
    capabilities: &BrowserCapabilitiesV1,
    route_id: Option<String>,
) -> ExecutionResponseV1 {
    if !manifest_supports_capability(manifest, &request.task) {
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
    let descriptor = runner_descriptor(capabilities);
    let package_ref = package_ref.into();
    let access = evaluate_execution_access_with_revocations(
        manifest,
        &package_ref,
        &request.request_id,
        "local-dev",
        "runner-service",
        Some(&descriptor.runner_id),
        request.access_grant.as_ref(),
        request.access_revocation_list.as_ref(),
    );
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

    if !runner_supports_capability(&descriptor, &request.task) {
        let task = request.task.clone();
        return ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::UnsupportedOperation,
                format!("Browser runner does not declare support for task {task}"),
            ),
            ExecutionMetrics::default(),
        );
    }

    let manifest_hash = manifest_hash.into();
    let plan = match prepare_plan(
        manifest,
        package_ref,
        manifest_hash.clone(),
        capabilities,
        request.preferred_artifact_group.as_deref(),
    ) {
        Ok(plan) => plan,
        Err(error) => {
            return ExecutionResponseV1::failed(
                request.request_id,
                error,
                ExecutionMetrics::default(),
            );
        }
    };
    let prepared = record_prepared_package(manifest, manifest_hash, &plan);
    execute_prepared_with_route(request, manifest, &prepared, route_id)
}

pub fn metrics_from_prepared(
    prepared: &[BrowserPreparedPackageV1],
    last_response: Option<&ExecutionResponseV1>,
) -> BrowserRunnerMetricsV1 {
    BrowserRunnerMetricsV1 {
        prepared_packages: prepared.len(),
        cached_bytes: prepared.iter().map(|package| package.cached_bytes).sum(),
        last_load_ms: last_response
            .map(|response| response.metrics.load_ms)
            .unwrap_or(0),
        last_compute_ms: last_response
            .map(|response| response.metrics.compute_ms)
            .unwrap_or(0),
        last_total_ms: last_response
            .map(|response| response.metrics.total_ms)
            .unwrap_or(0),
    }
}

pub fn manifest_hash(manifest: &PackageManifestV1) -> String {
    let value = serde_json::to_value(manifest).expect("manifest should serialize");
    hash_canonical_json(&canonicalize_json(&value))
}

pub fn receipt_from_browser_response(response: &ExecutionResponseV1) -> Option<ExecutionReceiptV1> {
    serde_json::from_value(response.metadata.get("receipt")?.clone()).ok()
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
    json!({ "label": label, "score": 0.72, "runner": BROWSER_RUNNER_ID })
}

fn chat(input: &Value) -> Value {
    let text = input_text(input);
    json!({
        "message": {
            "role": "assistant",
            "content": format!("Browser dev runner received: {text}")
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

fn stable_id(prefix: &str, value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("browser runner object should serialize");
    format!(
        "{prefix}-{}",
        &hash_canonical_json(&canonicalize_json(&value))[..24]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hivemind_core::{
        ArtifactGroup, ArtifactMinimum, ExecutionOptions, ExecutionPrivacy, LicenseInfo,
        LicenseType, PackageKind, PermissionRequest, PolicyDecision, Publisher,
    };
    use serde_json::Value;

    #[test]
    fn assesses_browser_wasm_artifact() {
        let manifest = package();
        let capabilities = default_browser_capabilities();

        let assessment = assess_package(&manifest, &capabilities, None);

        assert!(assessment.can_run);
        assert_eq!(
            assessment.artifact_group,
            Some("browser-wasm-small".to_string())
        );
    }

    #[test]
    fn executes_embedding_with_receipt() {
        let manifest = package();
        let capabilities = default_browser_capabilities();
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: manifest.package_id.clone(),
            package_version: manifest.version.clone(),
            preferred_artifact_group: None,
            task: "embedding".to_string(),
            input: json!({ "text": "hello browser" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let response = execute_manifest(&manifest, "bzz://pkg", request, &capabilities);

        assert_eq!(response.status, ExecutionStatus::Succeeded);
        assert!(response.output.get("embedding").is_some());
        let receipt = receipt_from_browser_response(&response).expect("receipt should be present");
        assert!(receipt.policy.is_some());
    }

    #[test]
    fn blocks_consent_required_permission_without_approval() {
        let mut manifest = package();
        manifest.permissions.push(PermissionRequest {
            name: "network.http".to_string(),
            purpose: Some("call an external API".to_string()),
            required: false,
            limits: json!({ "allowedHosts": ["api.example.com"] }),
        });
        let capabilities = default_browser_capabilities();
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: manifest.package_id.clone(),
            package_version: manifest.version.clone(),
            preferred_artifact_group: None,
            task: "embedding".to_string(),
            input: json!({ "text": "hello browser" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let response = execute_manifest(&manifest, "bzz://pkg", request, &capabilities);

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

    #[test]
    fn receipt_policy_evidence_matches_browser_runner() {
        let manifest = package();
        let capabilities = default_browser_capabilities();
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: manifest.package_id.clone(),
            package_version: manifest.version.clone(),
            preferred_artifact_group: None,
            task: "embedding".to_string(),
            input: json!({ "text": "hello browser" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let response = execute_manifest(&manifest, "bzz://pkg", request, &capabilities);
        let receipt = receipt_from_browser_response(&response).expect("receipt should be present");
        let policy = receipt.policy.expect("policy evidence should be embedded");

        assert_eq!(
            policy.policy_decision.runner_id.as_deref(),
            Some(BROWSER_RUNNER_ID)
        );
        assert_eq!(policy.policy_decision.decision, PolicyDecision::Allow);
    }

    #[test]
    fn prepared_execution_enforces_access_grants() {
        let mut manifest = package();
        manifest.license.license_type = LicenseType::Commercial;
        manifest.license.name = Some("Commercial".to_string());
        let capabilities = default_browser_capabilities();
        let manifest_hash = manifest_hash(&manifest);
        let plan = prepare_plan(
            &manifest,
            "bzz://pkg",
            manifest_hash.clone(),
            &capabilities,
            None,
        )
        .unwrap();
        let prepared = record_prepared_package(&manifest, manifest_hash, &plan);
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: manifest.package_id.clone(),
            package_version: manifest.version.clone(),
            preferred_artifact_group: None,
            task: "embedding".to_string(),
            input: json!({ "text": "hello browser" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let response = execute_prepared(request, &manifest, &prepared);

        assert_eq!(response.status, ExecutionStatus::Failed);
        assert_eq!(
            response.error.as_ref().unwrap().code,
            ErrorCode::AccessDenied
        );
        assert!(response.error.unwrap().details.get("access").is_some());
    }

    fn package() -> PackageManifestV1 {
        PackageManifestV1 {
            schema_version: "swarm-ai.package.v1".to_string(),
            package_id: "hivemind/browser-test".to_string(),
            kind: PackageKind::Model,
            name: "Browser Test".to_string(),
            version: "0.1.0".to_string(),
            publisher: Publisher {
                address: "0x0".to_string(),
                display_name: "Browser".to_string(),
                publisher_profile_ref: None,
            },
            capabilities: vec!["embedding".to_string()],
            artifact_groups: vec![ArtifactGroup {
                id: "browser-wasm-small".to_string(),
                target: "browser-wasm".to_string(),
                engine: "wasm-mock".to_string(),
                format: "json".to_string(),
                paths: vec!["model/browser/config.json".to_string()],
                total_bytes: 512,
                sha256: "0".repeat(64),
                minimum: ArtifactMinimum {
                    memory_mb: Some(128),
                    webgpu: Some(false),
                    disk_mb: None,
                },
            }],
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            permissions: Vec::new(),
            license: LicenseInfo {
                license_type: LicenseType::Open,
                name: Some("Apache-2.0".to_string()),
                url: None,
            },
        }
    }
}
