use crate::job::{ApiSurface, Modality, PriceModel, PriceV1};
use crate::trust::{IntegrityTier, PrivacyTier};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerType {
    Browser,
    Local,
    RemoteGpu,
    Marketplace,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerLimits {
    #[serde(rename = "maxMemoryMB")]
    pub max_memory_mb: u64,
    #[serde(rename = "maxInputBytes")]
    pub max_input_bytes: u64,
    #[serde(rename = "maxConcurrentJobs")]
    pub max_concurrent_jobs: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerDescriptorV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "runnerType")]
    pub runner_type: RunnerType,
    pub targets: Vec<String>,
    pub engines: Vec<String>,
    pub capabilities: Vec<String>,
    pub limits: RunnerLimits,
    #[serde(rename = "queueDepth")]
    pub queue_depth: u32,
    #[serde(rename = "warmPackageRefs", default)]
    pub warm_package_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerHardwareV1 {
    pub accelerator: String,
    #[serde(rename = "gpuMemoryMB", default)]
    pub gpu_memory_mb: Option<u64>,
    #[serde(rename = "cpuThreads", default)]
    pub cpu_threads: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerMemoryV1 {
    #[serde(rename = "memoryMB")]
    pub memory_mb: u64,
    #[serde(rename = "maxInputBytes")]
    pub max_input_bytes: u64,
    #[serde(rename = "maxConcurrentJobs")]
    pub max_concurrent_jobs: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerCacheClaimV1 {
    #[serde(rename = "packageRef")]
    pub package_ref: String,
    pub warmed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerPriceEntryV1 {
    #[serde(rename = "priceModel")]
    pub price_model: PriceModel,
    pub unit: String,
    pub price: PriceV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerCapabilityV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "runnerType")]
    pub runner_type: RunnerType,
    #[serde(rename = "supportedApis")]
    pub supported_apis: Vec<ApiSurface>,
    #[serde(rename = "supportedModalities")]
    pub supported_modalities: Vec<Modality>,
    #[serde(rename = "supportedPackageKinds")]
    pub supported_package_kinds: Vec<String>,
    #[serde(rename = "supportedModelFormats")]
    pub supported_model_formats: Vec<String>,
    pub engines: Vec<String>,
    pub hardware: RunnerHardwareV1,
    pub memory: RunnerMemoryV1,
    #[serde(rename = "maxContextTokens", default)]
    pub max_context_tokens: Option<u64>,
    #[serde(rename = "maxBatchSize", default)]
    pub max_batch_size: Option<u64>,
    #[serde(rename = "streamingModes")]
    pub streaming_modes: Vec<String>,
    #[serde(rename = "privacyTiers")]
    pub privacy_tiers: Vec<PrivacyTier>,
    #[serde(rename = "verificationTiers")]
    pub verification_tiers: Vec<IntegrityTier>,
    #[serde(rename = "regionHint", default)]
    pub region_hint: Option<String>,
    #[serde(rename = "priceTable")]
    pub price_table: Vec<RunnerPriceEntryV1>,
    #[serde(rename = "cacheClaims")]
    pub cache_claims: Vec<RunnerCacheClaimV1>,
    #[serde(rename = "expiresAt", default)]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct RunnerCapabilityV2Context {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(rename = "publicKey", default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(rename = "toolExecution", default)]
    pub tool_execution: Option<RunnerToolExecutionV2>,
    #[serde(rename = "latencyHints", default)]
    pub latency_hints: Option<RunnerLatencyHintsV2>,
    #[serde(
        rename = "uptimeClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub uptime_claim: Option<f64>,
    #[serde(
        rename = "validatorScoreRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub validator_score_ref: Option<String>,
    #[serde(rename = "termsRef", default, skip_serializing_if = "Option::is_none")]
    pub terms_ref: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerToolExecutionV2 {
    pub supported: bool,
    #[serde(rename = "permissionModel")]
    pub permission_model: String,
    #[serde(rename = "supportedModes")]
    pub supported_modes: Vec<String>,
}

impl Default for RunnerToolExecutionV2 {
    fn default() -> Self {
        Self {
            supported: false,
            permission_model: "manifest-only".to_string(),
            supported_modes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
pub struct RunnerLatencyHintsV2 {
    #[serde(
        rename = "queueDepth",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub queue_depth: Option<u32>,
    #[serde(
        rename = "estimatedQueueMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub estimated_queue_ms: Option<u64>,
    #[serde(
        rename = "estimatedColdStartMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub estimated_cold_start_ms: Option<u64>,
    #[serde(
        rename = "estimatedWarmStartMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub estimated_warm_start_ms: Option<u64>,
    #[serde(
        rename = "timeToFirstOutputMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub time_to_first_output_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunnerCapabilityV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    pub identity: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "runnerType")]
    pub runner_type: RunnerType,
    #[serde(rename = "supportedApis")]
    pub supported_apis: Vec<ApiSurface>,
    #[serde(rename = "supportedModalities")]
    pub supported_modalities: Vec<Modality>,
    #[serde(rename = "supportedPackageKinds")]
    pub supported_package_kinds: Vec<String>,
    #[serde(rename = "supportedModelFormats")]
    pub supported_model_formats: Vec<String>,
    pub engines: Vec<String>,
    pub hardware: RunnerHardwareV1,
    pub memory: RunnerMemoryV1,
    #[serde(rename = "maxContextTokens", default)]
    pub max_context_tokens: Option<u64>,
    #[serde(rename = "maxBatchSize", default)]
    pub max_batch_size: Option<u64>,
    #[serde(rename = "streamingModes")]
    pub streaming_modes: Vec<String>,
    #[serde(rename = "toolExecution")]
    pub tool_execution: RunnerToolExecutionV2,
    #[serde(rename = "privacyTiers")]
    pub privacy_tiers: Vec<PrivacyTier>,
    #[serde(rename = "verificationTiers")]
    pub verification_tiers: Vec<IntegrityTier>,
    #[serde(
        rename = "regionHint",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub region_hint: Option<String>,
    #[serde(rename = "latencyHints")]
    pub latency_hints: RunnerLatencyHintsV2,
    #[serde(rename = "priceTable")]
    pub price_table: Vec<RunnerPriceEntryV1>,
    #[serde(rename = "cacheClaims")]
    pub cache_claims: Vec<RunnerCacheClaimV1>,
    #[serde(
        rename = "uptimeClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub uptime_claim: Option<f64>,
    #[serde(
        rename = "validatorScoreRef",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub validator_score_ref: Option<String>,
    #[serde(rename = "termsRef", default, skip_serializing_if = "Option::is_none")]
    pub terms_ref: Option<String>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

pub fn runner_supports_capability(runner: &RunnerDescriptorV1, capability: &str) -> bool {
    runner
        .capabilities
        .iter()
        .any(|declared| declared == capability)
}

pub fn runner_capability_from_descriptor(runner: &RunnerDescriptorV1) -> RunnerCapabilityV1 {
    RunnerCapabilityV1 {
        schema_version: "swarm-ai.runner-capability.v1".to_string(),
        runner_id: runner.runner_id.clone(),
        runner_type: runner.runner_type.clone(),
        supported_apis: supported_apis_for_runner(runner),
        supported_modalities: supported_modalities_for_runner(runner),
        supported_package_kinds: vec!["model".to_string()],
        supported_model_formats: runner.targets.clone(),
        engines: runner.engines.clone(),
        hardware: hardware_for_runner(runner),
        memory: RunnerMemoryV1 {
            memory_mb: runner.limits.max_memory_mb,
            max_input_bytes: runner.limits.max_input_bytes,
            max_concurrent_jobs: runner.limits.max_concurrent_jobs,
        },
        max_context_tokens: Some((runner.limits.max_input_bytes / 4).max(1)),
        max_batch_size: Some(u64::from(runner.limits.max_concurrent_jobs.max(1))),
        streaming_modes: streaming_modes_for_runner(runner),
        privacy_tiers: privacy_tiers_for_runner(runner),
        verification_tiers: verification_tiers_for_runner(runner),
        region_hint: None,
        price_table: price_table_for_runner(runner),
        cache_claims: runner
            .warm_package_refs
            .iter()
            .map(|package_ref| RunnerCacheClaimV1 {
                package_ref: package_ref.clone(),
                warmed: true,
            })
            .collect(),
        expires_at: None,
        signature: None,
    }
}

pub fn runner_capability_v2_from_v1(capability: &RunnerCapabilityV1) -> RunnerCapabilityV2 {
    runner_capability_v2_from_v1_with_context(capability, RunnerCapabilityV2Context::default())
}

pub fn runner_capability_v2_from_v1_with_context(
    capability: &RunnerCapabilityV1,
    context: RunnerCapabilityV2Context,
) -> RunnerCapabilityV2 {
    RunnerCapabilityV2 {
        schema_version: "hivemind.runner_capability.v2".to_string(),
        runner_id: capability.runner_id.clone(),
        identity: context
            .identity
            .unwrap_or_else(|| format!("local://runner/{}", capability.runner_id)),
        public_key: context
            .public_key
            .unwrap_or_else(|| "local-dev-public-key-unavailable".to_string()),
        runner_type: capability.runner_type.clone(),
        supported_apis: capability.supported_apis.clone(),
        supported_modalities: capability.supported_modalities.clone(),
        supported_package_kinds: capability.supported_package_kinds.clone(),
        supported_model_formats: capability.supported_model_formats.clone(),
        engines: capability.engines.clone(),
        hardware: capability.hardware.clone(),
        memory: capability.memory.clone(),
        max_context_tokens: capability.max_context_tokens,
        max_batch_size: capability.max_batch_size,
        streaming_modes: capability.streaming_modes.clone(),
        tool_execution: context
            .tool_execution
            .unwrap_or_else(|| tool_execution_for_capability(capability)),
        privacy_tiers: capability.privacy_tiers.clone(),
        verification_tiers: capability.verification_tiers.clone(),
        region_hint: capability.region_hint.clone(),
        latency_hints: context
            .latency_hints
            .unwrap_or_else(|| latency_hints_for_capability(capability)),
        price_table: capability.price_table.clone(),
        cache_claims: capability.cache_claims.clone(),
        uptime_claim: context.uptime_claim,
        validator_score_ref: context.validator_score_ref,
        terms_ref: context.terms_ref,
        expires_at: context.expires_at.or_else(|| capability.expires_at.clone()),
        signature: context.signature.or_else(|| capability.signature.clone()),
    }
}

fn supported_apis_for_runner(runner: &RunnerDescriptorV1) -> Vec<ApiSurface> {
    let mut apis = vec![ApiSurface::HivemindNative];
    if runner_supports_capability(runner, "chat") {
        apis.push(ApiSurface::OpenAiChatCompletions);
    }
    if runner_supports_capability(runner, "embedding") {
        apis.push(ApiSurface::OpenAiEmbeddings);
    }
    if runner_supports_capability(runner, "realtime") {
        apis.push(ApiSurface::OpenAiRealtime);
        apis.push(ApiSurface::GeminiLive);
        apis.push(ApiSurface::RealtimeSession);
    }
    dedup_apis(apis)
}

fn supported_modalities_for_runner(runner: &RunnerDescriptorV1) -> Vec<Modality> {
    let mut modalities = Vec::new();
    for capability in &runner.capabilities {
        match capability.as_str() {
            "chat" => {
                modalities.push(Modality::Chat);
                modalities.push(Modality::Text);
            }
            "embedding" => {
                modalities.push(Modality::Embedding);
                modalities.push(Modality::Text);
            }
            "ocr" => {
                modalities.push(Modality::Image);
                modalities.push(Modality::Text);
            }
            "classification" => {
                modalities.push(Modality::Text);
                modalities.push(Modality::StructuredOutput);
            }
            "realtime" => {
                modalities.push(Modality::Audio);
                modalities.push(Modality::Chat);
                modalities.push(Modality::Text);
            }
            _ => {}
        }
    }
    dedup_modalities(modalities)
}

fn hardware_for_runner(runner: &RunnerDescriptorV1) -> RunnerHardwareV1 {
    match runner.runner_type {
        RunnerType::RemoteGpu | RunnerType::Marketplace => RunnerHardwareV1 {
            accelerator: "gpu".to_string(),
            gpu_memory_mb: Some(runner.limits.max_memory_mb),
            cpu_threads: None,
        },
        RunnerType::Browser => RunnerHardwareV1 {
            accelerator: "browser".to_string(),
            gpu_memory_mb: None,
            cpu_threads: None,
        },
        RunnerType::Local => RunnerHardwareV1 {
            accelerator: "cpu-or-local-accelerator".to_string(),
            gpu_memory_mb: None,
            cpu_threads: None,
        },
    }
}

fn streaming_modes_for_runner(runner: &RunnerDescriptorV1) -> Vec<String> {
    let mut modes = vec![
        "heartbeat".to_string(),
        "completed".to_string(),
        "error".to_string(),
    ];
    if runner_supports_capability(runner, "chat") {
        modes.push("text_delta".to_string());
        modes.push("token_delta".to_string());
    }
    if runner_supports_capability(runner, "realtime") {
        modes.push("audio_chunk".to_string());
        modes.push("safety_event".to_string());
    }
    if runner_supports_capability(runner, "embedding") {
        modes.push("embedding_progress".to_string());
    }
    modes.sort();
    modes.dedup();
    modes
}

fn privacy_tiers_for_runner(runner: &RunnerDescriptorV1) -> Vec<PrivacyTier> {
    match runner.runner_type {
        RunnerType::Browser | RunnerType::Local => vec![PrivacyTier::LocalOnly],
        RunnerType::RemoteGpu | RunnerType::Marketplace => {
            vec![PrivacyTier::Standard, PrivacyTier::NoLog]
        }
    }
}

fn verification_tiers_for_runner(runner: &RunnerDescriptorV1) -> Vec<IntegrityTier> {
    match runner.runner_type {
        RunnerType::Browser | RunnerType::Local => {
            vec![
                IntegrityTier::ReceiptOnly,
                IntegrityTier::DeterministicReplay,
            ]
        }
        RunnerType::RemoteGpu => vec![
            IntegrityTier::ReceiptOnly,
            IntegrityTier::ValidatorSpotCheck,
        ],
        RunnerType::Marketplace => vec![IntegrityTier::ReceiptOnly],
    }
}

fn price_table_for_runner(runner: &RunnerDescriptorV1) -> Vec<RunnerPriceEntryV1> {
    match runner.runner_type {
        RunnerType::Browser | RunnerType::Local => vec![RunnerPriceEntryV1 {
            price_model: PriceModel::Fixed,
            unit: "request".to_string(),
            price: PriceV1 {
                amount: 0.0,
                currency: "none".to_string(),
            },
        }],
        RunnerType::RemoteGpu | RunnerType::Marketplace => Vec::new(),
    }
}

fn tool_execution_for_capability(capability: &RunnerCapabilityV1) -> RunnerToolExecutionV2 {
    let tool_apis = [
        ApiSurface::OpenAiResponses,
        ApiSurface::AnthropicMessages,
        ApiSurface::GeminiGenerateContent,
        ApiSurface::GeminiLive,
    ];
    let supports_tool_api = capability
        .supported_apis
        .iter()
        .any(|api| tool_apis.contains(api));
    let supports_tool_modality = capability
        .supported_modalities
        .contains(&Modality::ToolCall);
    if supports_tool_api || supports_tool_modality {
        RunnerToolExecutionV2 {
            supported: true,
            permission_model: "manifest-and-job-approval".to_string(),
            supported_modes: vec![
                "tool_call_requested".to_string(),
                "tool_call_result".to_string(),
            ],
        }
    } else {
        RunnerToolExecutionV2::default()
    }
}

fn latency_hints_for_capability(capability: &RunnerCapabilityV1) -> RunnerLatencyHintsV2 {
    let warm_cache = capability.cache_claims.iter().any(|claim| claim.warmed);
    let accelerator = capability.hardware.accelerator.to_ascii_lowercase();
    let estimated_cold_start_ms = if accelerator.contains("gpu") {
        Some(3_000)
    } else if accelerator.contains("browser") {
        Some(1_500)
    } else {
        Some(500)
    };
    RunnerLatencyHintsV2 {
        queue_depth: None,
        estimated_queue_ms: None,
        estimated_cold_start_ms,
        estimated_warm_start_ms: warm_cache.then_some(150),
        time_to_first_output_ms: capability
            .streaming_modes
            .iter()
            .any(|mode| mode == "text_delta" || mode == "token_delta")
            .then_some(250),
    }
}

fn dedup_apis(mut values: Vec<ApiSurface>) -> Vec<ApiSurface> {
    values.dedup_by(|left, right| left == right);
    values
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_capability_summarizes_descriptor_for_routing_and_quoting() {
        let runner = RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: "remote-1".to_string(),
            runner_type: RunnerType::RemoteGpu,
            targets: vec!["cuda-vllm".to_string()],
            engines: vec!["vllm".to_string()],
            capabilities: vec!["chat".to_string(), "embedding".to_string()],
            limits: RunnerLimits {
                max_memory_mb: 24 * 1024,
                max_input_bytes: 256 * 1024,
                max_concurrent_jobs: 8,
            },
            queue_depth: 2,
            warm_package_refs: vec!["bzz://warm".to_string()],
        };

        let capability = runner_capability_from_descriptor(&runner);

        assert_eq!(capability.runner_id, "remote-1");
        assert!(
            capability
                .supported_apis
                .contains(&ApiSurface::HivemindNative)
        );
        assert!(
            capability
                .supported_apis
                .contains(&ApiSurface::OpenAiChatCompletions)
        );
        assert!(
            capability
                .supported_modalities
                .contains(&Modality::Embedding)
        );
        assert_eq!(capability.hardware.accelerator, "gpu");
        assert_eq!(capability.max_batch_size, Some(8));
        assert_eq!(capability.cache_claims[0].package_ref, "bzz://warm");
        assert!(capability.privacy_tiers.contains(&PrivacyTier::Standard));
        assert!(
            capability
                .verification_tiers
                .contains(&IntegrityTier::ValidatorSpotCheck)
        );
        assert!(
            capability
                .streaming_modes
                .contains(&"token_delta".to_string())
        );
    }

    #[test]
    fn realtime_runner_capability_advertises_standard_live_surfaces() {
        let runner = RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: "realtime-1".to_string(),
            runner_type: RunnerType::RemoteGpu,
            targets: vec!["cuda-realtime".to_string()],
            engines: vec!["realtime-engine".to_string()],
            capabilities: vec!["realtime".to_string()],
            limits: RunnerLimits {
                max_memory_mb: 16 * 1024,
                max_input_bytes: 256 * 1024,
                max_concurrent_jobs: 4,
            },
            queue_depth: 0,
            warm_package_refs: Vec::new(),
        };

        let capability = runner_capability_from_descriptor(&runner);

        assert!(
            capability
                .supported_apis
                .contains(&ApiSurface::OpenAiRealtime)
        );
        assert!(capability.supported_apis.contains(&ApiSurface::GeminiLive));
        assert!(
            capability
                .supported_apis
                .contains(&ApiSurface::RealtimeSession)
        );
        assert!(capability.supported_modalities.contains(&Modality::Audio));
        assert!(
            capability
                .streaming_modes
                .contains(&"audio_chunk".to_string())
        );
    }

    #[test]
    fn runner_capability_v2_projection_adds_identity_latency_and_tool_metadata() {
        let mut capability = runner_capability_from_descriptor(&RunnerDescriptorV1 {
            schema_version: "swarm-ai.runner-descriptor.v1".to_string(),
            runner_id: "tool-runner".to_string(),
            runner_type: RunnerType::RemoteGpu,
            targets: vec!["cuda-vllm".to_string()],
            engines: vec!["vllm".to_string()],
            capabilities: vec!["chat".to_string(), "embedding".to_string()],
            limits: RunnerLimits {
                max_memory_mb: 24 * 1024,
                max_input_bytes: 256 * 1024,
                max_concurrent_jobs: 8,
            },
            queue_depth: 2,
            warm_package_refs: vec!["bzz://warm".to_string()],
        });
        capability.supported_apis.push(ApiSurface::OpenAiResponses);
        capability.supported_modalities.push(Modality::ToolCall);

        let capability_v2 = runner_capability_v2_from_v1_with_context(
            &capability,
            RunnerCapabilityV2Context {
                public_key: Some("ed25519:public-key".to_string()),
                uptime_claim: Some(0.99),
                validator_score_ref: Some("local://reputation/tool-runner".to_string()),
                terms_ref: Some("bzz://runner-terms".to_string()),
                ..Default::default()
            },
        );

        assert_eq!(
            capability_v2.schema_version,
            "hivemind.runner_capability.v2"
        );
        assert_eq!(capability_v2.runner_id, "tool-runner");
        assert_eq!(capability_v2.identity, "local://runner/tool-runner");
        assert_eq!(capability_v2.public_key, "ed25519:public-key");
        assert!(capability_v2.tool_execution.supported);
        assert_eq!(
            capability_v2.tool_execution.permission_model,
            "manifest-and-job-approval"
        );
        assert_eq!(
            capability_v2.latency_hints.estimated_warm_start_ms,
            Some(150)
        );
        assert_eq!(
            capability_v2.latency_hints.time_to_first_output_ms,
            Some(250)
        );
        assert_eq!(capability_v2.uptime_claim, Some(0.99));
        assert_eq!(
            capability_v2.validator_score_ref.as_deref(),
            Some("local://reputation/tool-runner")
        );
        assert_eq!(
            capability_v2.terms_ref.as_deref(),
            Some("bzz://runner-terms")
        );
    }
}
