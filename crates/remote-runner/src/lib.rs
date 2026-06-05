use chrono::{SecondsFormat, Utc};
use hivemind_access::evaluate_execution_access_with_revocations;
use hivemind_core::{
    AccessDecision, ErrorCode, ExecutionMetrics, ExecutionReceiptV1, ExecutionRequestV1,
    ExecutionResponseV1, ExecutionStatus, PackageManifestV1, ReceiptDraft, RunnerDescriptorV1,
    RunnerLimits, RunnerType, SwarmAiErrorV1, create_signed_receipt, evaluate_package_policy,
    manifest_supports_capability, policy_execution_block_reason, receipt_policy_evidence,
    runner_supports_capability, select_artifact_group,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DEFAULT_REMOTE_RUNNER_ID: &str = "remote-dev-gpu-runner";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RemoteRunnerApiV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RemoteRunnerPerformanceV1 {
    #[serde(rename = "p50FirstTokenMs")]
    pub p50_first_token_ms: u64,
    #[serde(rename = "p50TokensPerSecond")]
    pub p50_tokens_per_second: f64,
    #[serde(rename = "p95QueueMs")]
    pub p95_queue_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RemoteRunnerPricingV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub currency: String,
    #[serde(rename = "baseCost")]
    pub base_cost: f64,
    #[serde(rename = "inputTokenCost")]
    pub input_token_cost: f64,
    #[serde(rename = "outputTokenCost")]
    pub output_token_cost: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RemoteRunnerLoadV1 {
    #[serde(rename = "gpuMemoryTotalMB")]
    pub gpu_memory_total_mb: u64,
    #[serde(rename = "gpuMemoryUsedMB")]
    pub gpu_memory_used_mb: u64,
    #[serde(rename = "activeJobs")]
    pub active_jobs: u32,
    #[serde(rename = "queuedJobs")]
    pub queued_jobs: u32,
    #[serde(rename = "maxConcurrentJobs")]
    pub max_concurrent_jobs: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RemoteRunnerHealthV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub status: String,
    #[serde(rename = "queueDepth")]
    pub queue_depth: u32,
    #[serde(rename = "preparedPackages")]
    pub prepared_packages: usize,
    #[serde(rename = "warmPackageRefs")]
    pub warm_package_refs: Vec<String>,
    pub load: RemoteRunnerLoadV1,
    pub performance: RemoteRunnerPerformanceV1,
    pub pricing: RemoteRunnerPricingV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RemotePrepareRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    #[serde(rename = "preferredArtifactGroup", default)]
    pub preferred_artifact_group: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RemotePreparedPackageV1 {
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
    pub target: String,
    pub engine: String,
    #[serde(rename = "cachedBytes")]
    pub cached_bytes: u64,
    pub warmed: bool,
    #[serde(rename = "preparedAt")]
    pub prepared_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RemoteCancelRequestV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RemoteCancelResultV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub cancelled: bool,
    pub reason: String,
}

pub fn remote_runner_api_contract() -> RemoteRunnerApiV1 {
    RemoteRunnerApiV1 {
        schema_version: "swarm-ai.remote-runner-api.v1".to_string(),
        endpoints: vec![
            "GET /v1/swarm-ai/health".to_string(),
            "GET /v1/swarm-ai/capabilities".to_string(),
            "POST /v1/swarm-ai/jobs/quote".to_string(),
            "POST /v1/swarm-ai/jobs/lease".to_string(),
            "GET /v1/swarm-ai/jobs/{jobId}/stream".to_string(),
            "POST /v1/swarm-ai/prepare".to_string(),
            "POST /v1/swarm-ai/execute".to_string(),
            "POST /v1/swarm-ai/cancel".to_string(),
            "GET /v1/swarm-ai/receipt/{receiptId}".to_string(),
        ],
    }
}

pub fn default_remote_gpu_descriptor(runner_id: impl Into<String>) -> RunnerDescriptorV1 {
    RunnerDescriptorV1 {
        schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
        runner_id: runner_id.into(),
        runner_type: RunnerType::RemoteGpu,
        targets: vec![
            "cuda-vllm".to_string(),
            "remote-openai-compatible".to_string(),
            "local-mock".to_string(),
        ],
        engines: vec![
            "vllm".to_string(),
            "openai-compatible".to_string(),
            "rust-mock".to_string(),
        ],
        capabilities: vec![
            "chat".to_string(),
            "embedding".to_string(),
            "classification".to_string(),
            "ocr".to_string(),
        ],
        limits: RunnerLimits {
            max_memory_mb: 48 * 1024,
            max_input_bytes: 1024 * 1024,
            max_concurrent_jobs: 16,
        },
        queue_depth: 0,
        warm_package_refs: Vec::new(),
    }
}

pub fn default_descriptor() -> RunnerDescriptorV1 {
    default_remote_gpu_descriptor(DEFAULT_REMOTE_RUNNER_ID)
}

pub fn performance_profile() -> RemoteRunnerPerformanceV1 {
    RemoteRunnerPerformanceV1 {
        p50_first_token_ms: 800,
        p50_tokens_per_second: 80.0,
        p95_queue_ms: 2_000,
    }
}

pub fn pricing() -> RemoteRunnerPricingV1 {
    RemoteRunnerPricingV1 {
        schema_version: "swarm-ai.remote-runner-pricing.v1".to_string(),
        currency: "xDAI".to_string(),
        base_cost: 0.01,
        input_token_cost: 0.000_001,
        output_token_cost: 0.000_004,
    }
}

pub fn health(
    descriptor: &RunnerDescriptorV1,
    prepared: &[RemotePreparedPackageV1],
) -> RemoteRunnerHealthV1 {
    let status = if descriptor.queue_depth >= descriptor.limits.max_concurrent_jobs {
        "overloaded"
    } else {
        "ok"
    };
    RemoteRunnerHealthV1 {
        schema_version: "swarm-ai.remote-runner-health.v1".to_string(),
        runner_id: descriptor.runner_id.clone(),
        status: status.to_string(),
        queue_depth: descriptor.queue_depth,
        prepared_packages: prepared.len(),
        warm_package_refs: descriptor.warm_package_refs.clone(),
        load: RemoteRunnerLoadV1 {
            gpu_memory_total_mb: descriptor.limits.max_memory_mb,
            gpu_memory_used_mb: estimated_gpu_memory_used(descriptor, prepared),
            active_jobs: descriptor
                .queue_depth
                .min(descriptor.limits.max_concurrent_jobs),
            queued_jobs: descriptor
                .queue_depth
                .saturating_sub(descriptor.limits.max_concurrent_jobs),
            max_concurrent_jobs: descriptor.limits.max_concurrent_jobs,
        },
        performance: performance_profile(),
        pricing: pricing(),
    }
}

pub fn prepare_manifest(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
    manifest_hash: impl Into<String>,
    descriptor: &RunnerDescriptorV1,
    preferred_artifact_group: Option<&str>,
) -> Result<RemotePreparedPackageV1, SwarmAiErrorV1> {
    let package_ref = package_ref.into();
    let manifest_hash = manifest_hash.into();
    let artifact = select_artifact_group(
        manifest,
        preferred_artifact_group,
        &descriptor.targets,
        &descriptor.engines,
    )
    .ok_or_else(|| {
        SwarmAiErrorV1::new(
            ErrorCode::UnsupportedTarget,
            "No artifact group matches this remote runner",
        )
    })?;

    if artifact.total_bytes > descriptor.limits.max_memory_mb * 1024 * 1024 {
        return Err(SwarmAiErrorV1::new(
            ErrorCode::UnsupportedTarget,
            "Artifact exceeds remote runner memory limit",
        )
        .with_details(json!({
            "artifactBytes": artifact.total_bytes,
            "maxMemoryMB": descriptor.limits.max_memory_mb
        })));
    }

    Ok(RemotePreparedPackageV1 {
        schema_version: "swarm-ai.remote-prepared-package.v1".to_string(),
        package_id: manifest.package_id.clone(),
        package_version: manifest.version.clone(),
        package_ref: package_ref.clone(),
        manifest_hash,
        artifact_group: artifact.id.clone(),
        target: artifact.target.clone(),
        engine: artifact.engine.clone(),
        cached_bytes: artifact.total_bytes,
        warmed: descriptor
            .warm_package_refs
            .iter()
            .any(|reference| reference == &package_ref),
        prepared_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    })
}

pub fn execute_manifest_with_hash(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
    manifest_hash: impl Into<String>,
    request: ExecutionRequestV1,
    descriptor: &RunnerDescriptorV1,
) -> ExecutionResponseV1 {
    execute_manifest_with_hash_and_route(
        manifest,
        package_ref,
        manifest_hash,
        request,
        descriptor,
        None,
    )
}

pub fn execute_manifest_with_hash_and_route(
    manifest: &PackageManifestV1,
    package_ref: impl Into<String>,
    manifest_hash: impl Into<String>,
    request: ExecutionRequestV1,
    descriptor: &RunnerDescriptorV1,
    route_id: Option<String>,
) -> ExecutionResponseV1 {
    let package_ref = package_ref.into();
    let manifest_hash = manifest_hash.into();

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

    if !runner_supports_capability(descriptor, &request.task) {
        let task = request.task.clone();
        return ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::UnsupportedOperation,
                format!("Remote GPU runner does not declare support for task {task}"),
            ),
            ExecutionMetrics::default(),
        );
    }

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

    if descriptor.queue_depth >= descriptor.limits.max_concurrent_jobs {
        return ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::RunnerOverloaded,
                "Remote GPU runner queue is full",
            )
            .with_details(json!({
                "queueDepth": descriptor.queue_depth,
                "maxConcurrentJobs": descriptor.limits.max_concurrent_jobs
            })),
            ExecutionMetrics::default(),
        );
    }

    let input_bytes = serde_json::to_vec(&request.input).unwrap_or_default().len() as u64;
    if input_bytes > descriptor.limits.max_input_bytes {
        return ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "Execution input exceeds remote runner byte limit",
            )
            .with_details(json!({
                "inputBytes": input_bytes,
                "maxInputBytes": descriptor.limits.max_input_bytes
            })),
            ExecutionMetrics::default(),
        );
    }

    let prepared = match prepare_manifest(
        manifest,
        package_ref,
        manifest_hash,
        descriptor,
        request.preferred_artifact_group.as_deref(),
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            return ExecutionResponseV1::failed(
                request.request_id,
                error,
                ExecutionMetrics::default(),
            );
        }
    };

    execute_prepared_with_route(request, manifest, &prepared, descriptor, route_id)
}

pub fn execute_prepared(
    request: ExecutionRequestV1,
    manifest: &PackageManifestV1,
    prepared: &RemotePreparedPackageV1,
    descriptor: &RunnerDescriptorV1,
) -> ExecutionResponseV1 {
    execute_prepared_with_route(request, manifest, prepared, descriptor, None)
}

pub fn execute_prepared_with_route(
    request: ExecutionRequestV1,
    manifest: &PackageManifestV1,
    prepared: &RemotePreparedPackageV1,
    descriptor: &RunnerDescriptorV1,
    route_id: Option<String>,
) -> ExecutionResponseV1 {
    if request.package_ref != prepared.package_ref || request.package_id != prepared.package_id {
        return ExecutionResponseV1::failed(
            request.request_id,
            SwarmAiErrorV1::new(
                ErrorCode::InvalidRequest,
                "Execution request does not match prepared remote package",
            ),
            ExecutionMetrics::default(),
        );
    }

    let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let receipt_route_id = route_id.unwrap_or_else(|| format!("remote-{}", descriptor.runner_id));
    let policy = evaluate_package_policy(
        manifest,
        &prepared.package_ref,
        Some(descriptor.runner_id.clone()),
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
    let queue_ms = u64::from(descriptor.queue_depth) * 25;
    let load_ms = if prepared.warmed { 25 } else { 450 };
    let input_tokens = estimate_tokens(&request.input);
    let output = match request.task.as_str() {
        "embedding" => json!({
            "embedding": deterministic_embedding(&request.input),
            "model": manifest.package_id,
            "runner": descriptor.runner_id,
            "accelerator": "remote-gpu"
        }),
        "classification" => classify(&request.input, &descriptor.runner_id),
        "chat" => chat(
            &request.input,
            request.options.stream,
            &descriptor.runner_id,
        ),
        _ => json!({
            "echo": request.input,
            "task": request.task,
            "runner": descriptor.runner_id,
            "accelerator": "remote-gpu"
        }),
    };
    let output_tokens = estimate_output_tokens(&output);
    let compute_ms = compute_ms_for(&request.task, input_tokens.unwrap_or(0), output_tokens);
    let metrics = ExecutionMetrics {
        queue_ms,
        load_ms,
        compute_ms,
        total_ms: queue_ms + load_ms + compute_ms,
        input_tokens,
        output_tokens: Some(output_tokens),
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
            "runnerId": descriptor.runner_id,
            "routeId": receipt_route_id,
            "artifactGroup": prepared.artifact_group,
            "executionLocation": "remote-gpu",
            "prepared": prepared,
            "pricing": pricing(),
            "streamingRequested": request.options.stream,
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
        runner_id: &descriptor.runner_id,
        route_id: Some(receipt_route_id),
        policy: Some(policy_evidence),
        started_at: &started_at,
        finished_at: &finished_at,
    });
    response.receipt_ref = Some(format!("local://receipt/{}", receipt.receipt_id));
    response.metadata["receipt"] = serde_json::to_value(receipt).unwrap_or_else(|_| json!(null));
    response
}

pub fn cancel(request: RemoteCancelRequestV1) -> RemoteCancelResultV1 {
    RemoteCancelResultV1 {
        schema_version: "swarm-ai.remote-cancel-result.v1".to_string(),
        request_id: request.request_id,
        cancelled: false,
        reason: "No matching queued job in deterministic development runner".to_string(),
    }
}

pub fn receipt_from_remote_response(response: &ExecutionResponseV1) -> Option<ExecutionReceiptV1> {
    serde_json::from_value(response.metadata.get("receipt")?.clone()).ok()
}

fn estimated_gpu_memory_used(
    descriptor: &RunnerDescriptorV1,
    prepared: &[RemotePreparedPackageV1],
) -> u64 {
    let prepared_mb: u64 = prepared
        .iter()
        .map(|package| package.cached_bytes.div_ceil(1024 * 1024))
        .sum();
    let queue_mb = u64::from(descriptor.queue_depth) * 256;
    (prepared_mb + queue_mb).min(descriptor.limits.max_memory_mb)
}

fn deterministic_embedding(input: &Value) -> Vec<f32> {
    let bytes = serde_json::to_vec(input).unwrap_or_default();
    let digest = Sha256::digest(bytes);
    digest
        .chunks(4)
        .take(12)
        .map(|chunk| {
            let mut value = 0u32;
            for byte in chunk {
                value = (value << 8) | u32::from(*byte);
            }
            (value as f32 / u32::MAX as f32) * 2.0 - 1.0
        })
        .collect()
}

fn classify(input: &Value, runner_id: &str) -> Value {
    let text = input_text(input).to_lowercase();
    let label = if text.contains("invoice") || text.contains("receipt") {
        "document"
    } else if text.contains("hello") || text.contains("hi") {
        "greeting"
    } else {
        "general"
    };
    json!({ "label": label, "score": 0.88, "runner": runner_id })
}

fn chat(input: &Value, stream: bool, runner_id: &str) -> Value {
    let text = input_text(input);
    let content = format!("Remote GPU dev runner received: {text}");
    if stream {
        json!({
            "message": { "role": "assistant", "content": content },
            "stream": {
                "mode": "simulated",
                "chunks": [
                    { "index": 0, "delta": "Remote GPU dev runner " },
                    { "index": 1, "delta": "received the request." }
                ]
            },
            "runner": runner_id
        })
    } else {
        json!({
            "message": { "role": "assistant", "content": content },
            "runner": runner_id
        })
    }
}

fn input_text(input: &Value) -> String {
    input
        .get("text")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            input
                .get("messages")
                .and_then(Value::as_array)
                .and_then(|messages| messages.last())
                .and_then(|message| message.get("content"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| input.to_string())
}

fn estimate_tokens(input: &Value) -> Option<u64> {
    Some(input_text(input).split_whitespace().count() as u64)
}

fn estimate_output_tokens(output: &Value) -> u64 {
    output
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .map(|content| content.split_whitespace().count() as u64)
        .unwrap_or_else(|| output.to_string().split_whitespace().count() as u64)
}

fn compute_ms_for(task: &str, input_tokens: u64, output_tokens: u64) -> u64 {
    match task {
        "chat" => 150 + output_tokens.saturating_mul(12),
        "embedding" => 80 + input_tokens.saturating_mul(2),
        "classification" => 60 + input_tokens,
        _ => 90 + input_tokens + output_tokens,
    }
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
    fn prepares_matching_remote_artifact() {
        let descriptor = default_remote_gpu_descriptor("remote-1");
        let prepared =
            prepare_manifest(&package(), "bzz://pkg", "hash", &descriptor, None).unwrap();

        assert_eq!(prepared.artifact_group, "cuda-vllm-fp16");
        assert_eq!(prepared.target, "cuda-vllm");
    }

    #[test]
    fn api_contract_advertises_quote_lease_and_stream_flow() {
        let api = remote_runner_api_contract();

        assert!(
            api.endpoints
                .contains(&"POST /v1/swarm-ai/jobs/quote".to_string())
        );
        assert!(
            api.endpoints
                .contains(&"POST /v1/swarm-ai/jobs/lease".to_string())
        );
        assert!(
            api.endpoints
                .contains(&"GET /v1/swarm-ai/jobs/{jobId}/stream".to_string())
        );
    }

    #[test]
    fn executes_chat_with_receipt() {
        let manifest = package();
        let descriptor = default_remote_gpu_descriptor("remote-1");
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: manifest.package_id.clone(),
            package_version: manifest.version.clone(),
            preferred_artifact_group: None,
            task: "chat".to_string(),
            input: json!({ "text": "hello remote" }),
            options: ExecutionOptions {
                stream: true,
                ..ExecutionOptions::default()
            },
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let response =
            execute_manifest_with_hash(&manifest, "bzz://pkg", "hash", request, &descriptor);

        assert_eq!(response.status, ExecutionStatus::Succeeded);
        assert!(response.output.get("stream").is_some());
        let receipt = receipt_from_remote_response(&response).expect("receipt should be present");
        assert!(receipt.policy.is_some());
    }

    #[test]
    fn overloaded_runner_rejects_execution() {
        let manifest = package();
        let mut descriptor = default_remote_gpu_descriptor("remote-1");
        descriptor.queue_depth = descriptor.limits.max_concurrent_jobs;
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: manifest.package_id.clone(),
            package_version: manifest.version.clone(),
            preferred_artifact_group: None,
            task: "chat".to_string(),
            input: json!({ "text": "hello remote" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let response =
            execute_manifest_with_hash(&manifest, "bzz://pkg", "hash", request, &descriptor);

        assert_eq!(response.status, ExecutionStatus::Failed);
        assert_eq!(response.error.unwrap().code, ErrorCode::RunnerOverloaded);
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
        let descriptor = default_remote_gpu_descriptor("remote-1");
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: manifest.package_id.clone(),
            package_version: manifest.version.clone(),
            preferred_artifact_group: None,
            task: "chat".to_string(),
            input: json!({ "text": "hello remote" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let response =
            execute_manifest_with_hash(&manifest, "bzz://pkg", "hash", request, &descriptor);

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
    fn receipt_policy_evidence_matches_remote_runner() {
        let manifest = package();
        let descriptor = default_remote_gpu_descriptor("remote-1");
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: manifest.package_id.clone(),
            package_version: manifest.version.clone(),
            preferred_artifact_group: None,
            task: "chat".to_string(),
            input: json!({ "text": "hello remote" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let response =
            execute_manifest_with_hash(&manifest, "bzz://pkg", "hash", request, &descriptor);
        let receipt = receipt_from_remote_response(&response).expect("receipt should be present");
        let policy = receipt.policy.expect("policy evidence should be embedded");

        assert_eq!(
            policy.policy_decision.runner_id.as_deref(),
            Some("remote-1")
        );
        assert_eq!(policy.policy_decision.decision, PolicyDecision::Allow);
    }

    #[test]
    fn prepared_execution_enforces_access_grants() {
        let mut manifest = package();
        manifest.license.license_type = LicenseType::Commercial;
        manifest.license.name = Some("Commercial".to_string());
        let descriptor = default_remote_gpu_descriptor("remote-1");
        let prepared = prepare_manifest(&manifest, "bzz://pkg", "hash", &descriptor, None).unwrap();
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-1".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: manifest.package_id.clone(),
            package_version: manifest.version.clone(),
            preferred_artifact_group: None,
            task: "chat".to_string(),
            input: json!({ "text": "hello remote" }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let response = execute_prepared(request, &manifest, &prepared, &descriptor);

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
            package_id: "hivemind/remote-test".to_string(),
            kind: PackageKind::Model,
            name: "Remote Test".to_string(),
            version: "0.1.0".to_string(),
            publisher: Publisher {
                address: "0x0".to_string(),
                display_name: "Remote".to_string(),
                publisher_profile_ref: None,
            },
            capabilities: vec!["chat".to_string(), "embedding".to_string()],
            artifact_groups: vec![ArtifactGroup {
                id: "cuda-vllm-fp16".to_string(),
                target: "cuda-vllm".to_string(),
                engine: "vllm".to_string(),
                format: "safetensors".to_string(),
                paths: vec!["model/remote/model.safetensors".to_string()],
                total_bytes: 2 * 1024 * 1024,
                sha256: "0".repeat(64),
                minimum: ArtifactMinimum {
                    memory_mb: Some(1024),
                    webgpu: Some(false),
                    disk_mb: Some(4096),
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
