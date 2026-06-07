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
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const RUNNER_ID: &str = "local-dev-runner";
const SENSITIVE_CACHE_MARKER_FILE: &str = ".swarm-ai-sensitive-cache.json";
pub const LOCAL_MODEL_RUNNER_DESCRIPTOR_SCHEMA_VERSION: &str =
    "hivemind.local-model-runner-descriptor.v1";
pub const LOCAL_MODEL_INFERENCE_OUTPUT_SCHEMA_VERSION: &str =
    "hivemind.local-model-inference-output.v1";
pub const OLLAMA_LOCAL_MODEL_CONFIG_SCHEMA_VERSION: &str = "hivemind.ollama-local-model-config.v1";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum LocalModelEngineKindV1 {
    Mock,
    Ollama,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LocalModelRunnerDescriptorV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runnerId")]
    pub runner_id: String,
    #[serde(rename = "engineKind")]
    pub engine_kind: LocalModelEngineKindV1,
    #[serde(rename = "engineName")]
    pub engine_name: String,
    #[serde(
        rename = "engineVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub engine_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(rename = "chatModel", default, skip_serializing_if = "Option::is_none")]
    pub chat_model: Option<String>,
    #[serde(
        rename = "embeddingModel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub embedding_model: Option<String>,
    #[serde(
        rename = "embeddingDimensions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub embedding_dimensions: Option<u64>,
    #[serde(rename = "contextWindowTokens", default)]
    pub context_window_tokens: Option<u64>,
    #[serde(rename = "supportsChat")]
    pub supports_chat: bool,
    #[serde(rename = "supportsEmbeddings")]
    pub supports_embeddings: bool,
    #[serde(rename = "supportsStreaming")]
    pub supports_streaming: bool,
    pub readiness: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LocalModelInferenceOutputV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub engine: LocalModelRunnerDescriptorV1,
    pub output: Value,
    #[serde(
        rename = "inputTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub input_tokens: Option<u64>,
    #[serde(
        rename = "outputTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_tokens: Option<u64>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OllamaLocalModelConfigV1 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "baseUrl")]
    pub base_url: String,
    #[serde(rename = "chatModel")]
    pub chat_model: String,
    #[serde(rename = "embeddingModel")]
    pub embedding_model: String,
    #[serde(rename = "timeoutMs")]
    pub timeout_ms: u64,
    #[serde(
        rename = "embeddingDimensions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub embedding_dimensions: Option<u64>,
}

pub trait RealLocalModelRunner {
    fn descriptor(&self) -> LocalModelRunnerDescriptorV1;
    fn chat(
        &self,
        request: &ExecutionRequestV1,
    ) -> Result<LocalModelInferenceOutputV1, SwarmAiErrorV1>;
    fn embed(
        &self,
        request: &ExecutionRequestV1,
    ) -> Result<LocalModelInferenceOutputV1, SwarmAiErrorV1>;
}

#[derive(Debug, Clone, Default)]
pub struct MockLocalModelRunner;

#[derive(Debug, Clone)]
pub struct OllamaLocalModelRunner {
    config: OllamaLocalModelConfigV1,
    client: reqwest::blocking::Client,
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
        engines: vec![
            "rust-mock".to_string(),
            "wasm-mock".to_string(),
            "ollama-local".to_string(),
        ],
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

pub fn mock_local_model_runner_descriptor() -> LocalModelRunnerDescriptorV1 {
    LocalModelRunnerDescriptorV1 {
        schema_version: LOCAL_MODEL_RUNNER_DESCRIPTOR_SCHEMA_VERSION.to_string(),
        runner_id: RUNNER_ID.to_string(),
        engine_kind: LocalModelEngineKindV1::Mock,
        engine_name: "rust-mock".to_string(),
        engine_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        endpoint: None,
        chat_model: Some("local/mock-chat".to_string()),
        embedding_model: Some("local/mock-embedding".to_string()),
        embedding_dimensions: Some(8),
        context_window_tokens: Some(4096),
        supports_chat: true,
        supports_embeddings: true,
        supports_streaming: true,
        readiness: "mock".to_string(),
        warnings: vec![
            "Deterministic local mock output is for CI and protocol tests, not real inference"
                .to_string(),
        ],
    }
}

pub fn ollama_config_from_env() -> Option<OllamaLocalModelConfigV1> {
    let engine = env::var("HIVEMIND_LOCAL_MODEL_ENGINE").ok()?;
    if !engine.eq_ignore_ascii_case("ollama") {
        return None;
    }
    Some(OllamaLocalModelConfigV1 {
        schema_version: OLLAMA_LOCAL_MODEL_CONFIG_SCHEMA_VERSION.to_string(),
        base_url: env::var("HIVEMIND_OLLAMA_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:11434".to_string()),
        chat_model: env::var("HIVEMIND_OLLAMA_CHAT_MODEL")
            .or_else(|_| env::var("HIVEMIND_TEST_CHAT_MODEL"))
            .or_else(|_| env::var("HIVEMIND_OLLAMA_MODEL"))
            .unwrap_or_else(|_| "llama3.2".to_string()),
        embedding_model: env::var("HIVEMIND_OLLAMA_EMBED_MODEL")
            .or_else(|_| env::var("HIVEMIND_TEST_EMBED_MODEL"))
            .unwrap_or_else(|_| "nomic-embed-text".to_string()),
        timeout_ms: env::var("HIVEMIND_OLLAMA_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(30_000),
        embedding_dimensions: env::var("HIVEMIND_OLLAMA_EMBED_DIMENSIONS")
            .ok()
            .and_then(|value| value.parse().ok()),
    })
}

pub fn configured_local_model_runner_descriptor() -> LocalModelRunnerDescriptorV1 {
    if let Some(config) = ollama_config_from_env() {
        match OllamaLocalModelRunner::new(config) {
            Ok(runner) => return runner.descriptor(),
            Err(error) => {
                let mut descriptor = mock_local_model_runner_descriptor();
                descriptor.warnings.push(format!(
                    "Configured Ollama runner could not be initialized and mock mode is active: {}",
                    error.message
                ));
                return descriptor;
            }
        }
    }
    mock_local_model_runner_descriptor()
}

impl RealLocalModelRunner for MockLocalModelRunner {
    fn descriptor(&self) -> LocalModelRunnerDescriptorV1 {
        mock_local_model_runner_descriptor()
    }

    fn chat(
        &self,
        request: &ExecutionRequestV1,
    ) -> Result<LocalModelInferenceOutputV1, SwarmAiErrorV1> {
        let output = chat(&request.input);
        Ok(LocalModelInferenceOutputV1 {
            schema_version: LOCAL_MODEL_INFERENCE_OUTPUT_SCHEMA_VERSION.to_string(),
            engine: self.descriptor(),
            output,
            input_tokens: estimate_tokens(&request.input),
            output_tokens: Some(count_tokens(&input_text(&request.input))),
            warnings: vec!["mock-output".to_string()],
        })
    }

    fn embed(
        &self,
        request: &ExecutionRequestV1,
    ) -> Result<LocalModelInferenceOutputV1, SwarmAiErrorV1> {
        Ok(LocalModelInferenceOutputV1 {
            schema_version: LOCAL_MODEL_INFERENCE_OUTPUT_SCHEMA_VERSION.to_string(),
            engine: self.descriptor(),
            output: json!({
                "embedding": deterministic_embedding(&request.input),
                "model": request.package_id,
            }),
            input_tokens: estimate_tokens(&request.input),
            output_tokens: Some(0),
            warnings: vec!["mock-output".to_string()],
        })
    }
}

impl OllamaLocalModelRunner {
    pub fn new(config: OllamaLocalModelConfigV1) -> Result<Self, SwarmAiErrorV1> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|error| {
                SwarmAiErrorV1::new(
                    ErrorCode::ExecutionFailed,
                    "failed to initialize Ollama HTTP client",
                )
                .with_details(json!({ "error": error.to_string() }))
            })?;
        Ok(Self { config, client })
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.config.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    fn post_json(&self, path: &str, payload: Value) -> Result<Value, SwarmAiErrorV1> {
        let endpoint = self.endpoint(path);
        let response = self
            .client
            .post(&endpoint)
            .json(&payload)
            .send()
            .map_err(|error| ollama_http_error("request failed", &endpoint, error))?;
        let status = response.status();
        let body = response
            .text()
            .map_err(|error| ollama_http_error("failed to read response body", &endpoint, error))?;
        if !status.is_success() {
            return Err(SwarmAiErrorV1::new(
                ErrorCode::ExecutionFailed,
                "Ollama request returned an error status",
            )
            .with_details(json!({
                "endpoint": endpoint,
                "status": status.as_u16(),
                "body": body,
            })));
        }
        serde_json::from_str(&body).map_err(|error| {
            SwarmAiErrorV1::new(
                ErrorCode::ExecutionFailed,
                "Ollama response was not valid JSON",
            )
            .with_details(json!({
                "endpoint": endpoint,
                "error": error.to_string(),
            }))
        })
    }

    fn embedding_via_embed(&self, text: &str) -> Result<Value, SwarmAiErrorV1> {
        let response = self.post_json(
            "api/embed",
            json!({
                "model": self.config.embedding_model,
                "input": text,
            }),
        )?;
        let embedding = response
            .get("embeddings")
            .and_then(Value::as_array)
            .and_then(|embeddings| embeddings.first())
            .cloned()
            .or_else(|| response.get("embedding").cloned())
            .ok_or_else(|| {
                SwarmAiErrorV1::new(
                    ErrorCode::ExecutionFailed,
                    "Ollama embed response did not include embeddings",
                )
                .with_details(json!({ "response": response }))
            })?;
        Ok(json!({
            "embedding": embedding,
            "model": self.config.embedding_model,
        }))
    }

    fn embedding_via_legacy_embeddings(&self, text: &str) -> Result<Value, SwarmAiErrorV1> {
        let response = self.post_json(
            "api/embeddings",
            json!({
                "model": self.config.embedding_model,
                "prompt": text,
            }),
        )?;
        let embedding = response.get("embedding").cloned().ok_or_else(|| {
            SwarmAiErrorV1::new(
                ErrorCode::ExecutionFailed,
                "Ollama legacy embeddings response did not include embedding",
            )
            .with_details(json!({ "response": response }))
        })?;
        Ok(json!({
            "embedding": embedding,
            "model": self.config.embedding_model,
        }))
    }
}

impl RealLocalModelRunner for OllamaLocalModelRunner {
    fn descriptor(&self) -> LocalModelRunnerDescriptorV1 {
        LocalModelRunnerDescriptorV1 {
            schema_version: LOCAL_MODEL_RUNNER_DESCRIPTOR_SCHEMA_VERSION.to_string(),
            runner_id: RUNNER_ID.to_string(),
            engine_kind: LocalModelEngineKindV1::Ollama,
            engine_name: "ollama".to_string(),
            engine_version: None,
            endpoint: Some(self.config.base_url.clone()),
            chat_model: Some(self.config.chat_model.clone()),
            embedding_model: Some(self.config.embedding_model.clone()),
            embedding_dimensions: self.config.embedding_dimensions,
            context_window_tokens: None,
            supports_chat: true,
            supports_embeddings: true,
            supports_streaming: false,
            readiness: "local".to_string(),
            warnings: vec![
                "Ollama local inference is opt-in and depends on the operator's local model installation"
                    .to_string(),
            ],
        }
    }

    fn chat(
        &self,
        request: &ExecutionRequestV1,
    ) -> Result<LocalModelInferenceOutputV1, SwarmAiErrorV1> {
        let payload = json!({
            "model": self.config.chat_model,
            "messages": ollama_messages(&request.input),
            "stream": false,
            "options": ollama_options(&request.input),
        });
        let response = self.post_json("api/chat", payload)?;
        let content = response
            .get("message")
            .and_then(|message| message.get("content"))
            .and_then(Value::as_str)
            .or_else(|| response.get("response").and_then(Value::as_str))
            .ok_or_else(|| {
                SwarmAiErrorV1::new(
                    ErrorCode::ExecutionFailed,
                    "Ollama chat response did not include assistant content",
                )
                .with_details(json!({ "response": response }))
            })?
            .to_string();
        Ok(LocalModelInferenceOutputV1 {
            schema_version: LOCAL_MODEL_INFERENCE_OUTPUT_SCHEMA_VERSION.to_string(),
            engine: self.descriptor(),
            output: json!({
                "message": {
                    "role": "assistant",
                    "content": content
                },
                "model": self.config.chat_model,
            }),
            input_tokens: response
                .get("prompt_eval_count")
                .and_then(Value::as_u64)
                .or_else(|| estimate_tokens(&request.input)),
            output_tokens: response
                .get("eval_count")
                .and_then(Value::as_u64)
                .or_else(|| Some(count_tokens(&content))),
            warnings: Vec::new(),
        })
    }

    fn embed(
        &self,
        request: &ExecutionRequestV1,
    ) -> Result<LocalModelInferenceOutputV1, SwarmAiErrorV1> {
        let text = input_text(&request.input);
        let output = self
            .embedding_via_embed(&text)
            .or_else(|_| self.embedding_via_legacy_embeddings(&text))?;
        Ok(LocalModelInferenceOutputV1 {
            schema_version: LOCAL_MODEL_INFERENCE_OUTPUT_SCHEMA_VERSION.to_string(),
            engine: self.descriptor(),
            output,
            input_tokens: estimate_tokens(&request.input),
            output_tokens: Some(0),
            warnings: Vec::new(),
        })
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

    let engine_result = match request.task.as_str() {
        "embedding" | "chat" => match local_model_inference(&request) {
            Ok(result) => Some(result),
            Err(error) => {
                return failed_response_with_receipt(
                    &request,
                    &package,
                    &artifact.id,
                    receipt_route_id,
                    &policy,
                    &started,
                    timer,
                    error,
                );
            }
        },
        _ => None,
    };

    let output = match (request.task.as_str(), engine_result.as_ref()) {
        ("embedding" | "chat", Some(result)) => result.output.clone(),
        ("classification", _) => classify(&request.input),
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
        input_tokens: engine_result
            .as_ref()
            .and_then(|result| result.input_tokens)
            .or_else(|| estimate_tokens(&request.input)),
        output_tokens: engine_result
            .as_ref()
            .and_then(|result| result.output_tokens),
    };
    let local_model_runner = engine_result
        .as_ref()
        .map(|result| result.engine.clone())
        .unwrap_or_else(mock_local_model_runner_descriptor);
    let inference_warnings = engine_result
        .as_ref()
        .map(|result| result.warnings.clone())
        .unwrap_or_default();
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
            "localModelRunner": local_model_runner,
            "inferenceWarnings": inference_warnings,
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

fn local_model_inference(
    request: &ExecutionRequestV1,
) -> Result<LocalModelInferenceOutputV1, SwarmAiErrorV1> {
    if let Some(config) = ollama_config_from_env() {
        let runner = OllamaLocalModelRunner::new(config)?;
        return match request.task.as_str() {
            "chat" => runner.chat(request),
            "embedding" => runner.embed(request),
            _ => Err(SwarmAiErrorV1::new(
                ErrorCode::UnsupportedOperation,
                "configured local model runner does not support this task",
            )),
        };
    }
    let runner = MockLocalModelRunner;
    match request.task.as_str() {
        "chat" => runner.chat(request),
        "embedding" => runner.embed(request),
        _ => Err(SwarmAiErrorV1::new(
            ErrorCode::UnsupportedOperation,
            "mock local model runner does not support this task",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn failed_response_with_receipt(
    request: &ExecutionRequestV1,
    package: &LocalPackage,
    artifact_id: &str,
    receipt_route_id: String,
    policy: &PolicyDecisionV1,
    started: &str,
    timer: Instant,
    error: SwarmAiErrorV1,
) -> ExecutionResponseV1 {
    let elapsed = timer.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    let metrics = ExecutionMetrics {
        queue_ms: 0,
        load_ms: 1,
        compute_ms: elapsed,
        total_ms: elapsed + 1,
        input_tokens: estimate_tokens(&request.input),
        output_tokens: Some(0),
    };
    let mut response =
        ExecutionResponseV1::failed(request.request_id.clone(), error.clone(), metrics);
    response.metadata = json!({
        "runnerId": RUNNER_ID,
        "routeId": receipt_route_id.clone(),
        "artifactGroup": artifact_id,
        "policy": policy,
        "localModelRunner": configured_local_model_runner_descriptor(),
        "inferenceError": error,
    });

    let finished = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let policy_evidence = receipt_policy_evidence(policy, finished.clone());
    let receipt = create_signed_receipt(ReceiptDraft {
        request,
        response: &response,
        manifest: &package.manifest,
        artifact_group: artifact_id,
        manifest_hash: &package.manifest_hash,
        runner_id: RUNNER_ID,
        route_id: Some(receipt_route_id),
        policy: Some(policy_evidence),
        started_at: started,
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

fn count_tokens(text: &str) -> u64 {
    text.split_whitespace().count() as u64
}

fn ollama_messages(input: &Value) -> Vec<Value> {
    let messages = input
        .get("messages")
        .and_then(Value::as_array)
        .map(|messages| {
            messages
                .iter()
                .filter_map(|message| {
                    let role = message
                        .get("role")
                        .and_then(Value::as_str)
                        .unwrap_or("user");
                    let content = message_text(message);
                    (!content.is_empty()).then(|| {
                        json!({
                            "role": role,
                            "content": content,
                        })
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if messages.is_empty() {
        vec![json!({
            "role": "user",
            "content": input_text(input),
        })]
    } else {
        messages
    }
}

fn ollama_options(input: &Value) -> Value {
    let mut options = serde_json::Map::new();
    if let Some(temperature) = input.get("temperature").and_then(Value::as_f64) {
        options.insert("temperature".to_string(), json!(temperature));
    }
    if let Some(max_tokens) = input.get("maxOutputTokens").and_then(Value::as_u64) {
        options.insert("num_predict".to_string(), json!(max_tokens));
    }
    Value::Object(options)
}

fn message_text(message: &Value) -> String {
    match message.get("content") {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|part| {
                part.get("text")
                    .and_then(Value::as_str)
                    .or_else(|| part.get("content").and_then(Value::as_str))
            })
            .collect::<Vec<_>>()
            .join(" "),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

fn ollama_http_error(context: &str, endpoint: &str, error: reqwest::Error) -> SwarmAiErrorV1 {
    SwarmAiErrorV1::new(ErrorCode::ExecutionFailed, format!("Ollama {context}")).with_details(
        json!({
            "endpoint": endpoint,
            "error": error.to_string(),
        }),
    )
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

    #[test]
    fn mock_local_model_runner_reports_descriptor_and_embedding_shape() {
        let runner = MockLocalModelRunner;
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-mock-embedding".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: "hivemind/mock-embedding".to_string(),
            package_version: "0.1.0".to_string(),
            preferred_artifact_group: None,
            task: "embedding".to_string(),
            input: json!("hello embeddings"),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let output = runner.embed(&request).unwrap();

        assert_eq!(output.engine.engine_kind, LocalModelEngineKindV1::Mock);
        assert_eq!(output.engine.embedding_dimensions, Some(8));
        assert_eq!(
            output
                .output
                .get("embedding")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(8)
        );
        assert_eq!(output.warnings, vec!["mock-output"]);
    }

    #[tokio::test]
    async fn execute_chat_attaches_local_model_runner_metadata_and_receipt() {
        let mut manifest = manifest(LicenseType::Open);
        manifest.capabilities = vec!["chat".to_string()];
        let package = LocalPackage {
            root: PathBuf::new(),
            manifest,
            manifest_hash: "0".repeat(64),
            package_ref: "bzz://pkg".to_string(),
        };
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-chat-local-model".to_string(),
            package_ref: package.package_ref.clone(),
            package_id: package.manifest.package_id.clone(),
            package_version: package.manifest.version.clone(),
            preferred_artifact_group: None,
            task: "chat".to_string(),
            input: json!({
                "messages": [{"role": "user", "content": "hello local model"}],
                "text": "hello local model"
            }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let response = execute(request, package).await;

        assert_eq!(response.status, ExecutionStatus::Succeeded);
        assert_eq!(
            response.metadata["localModelRunner"]["engineKind"],
            json!("mock")
        );
        assert_eq!(
            response.metadata["localModelRunner"]["supportsStreaming"],
            json!(true)
        );
        assert!(
            response
                .output
                .get("message")
                .and_then(|message| message.get("content"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .contains("hello local model")
        );
        let receipt: hivemind_core::ExecutionReceiptV1 =
            serde_json::from_value(response.metadata["receipt"].clone()).unwrap();
        assert!(hivemind_receipts::verify_receipt(&receipt).valid);
    }

    #[test]
    fn live_ollama_smoke_is_opt_in() {
        if std::env::var("HIVEMIND_ENABLE_LIVE_OLLAMA_TESTS")
            .ok()
            .as_deref()
            != Some("1")
        {
            return;
        }
        let config = ollama_config_from_env().expect(
            "set HIVEMIND_LOCAL_MODEL_ENGINE=ollama with HIVEMIND_ENABLE_LIVE_OLLAMA_TESTS=1",
        );
        let runner = OllamaLocalModelRunner::new(config).unwrap();
        let request = ExecutionRequestV1 {
            schema_version: "swarm-ai.execution.request.v1".to_string(),
            request_id: "request-live-ollama-chat".to_string(),
            package_ref: "bzz://pkg".to_string(),
            package_id: "hivemind/live-ollama".to_string(),
            package_version: "0.1.0".to_string(),
            preferred_artifact_group: None,
            task: "chat".to_string(),
            input: json!({
                "messages": [{"role": "user", "content": "Say hello in one short sentence."}],
                "text": "Say hello in one short sentence.",
                "maxOutputTokens": 32
            }),
            options: ExecutionOptions::default(),
            privacy: ExecutionPrivacy::default(),
            access_grant: None,
            access_revocation_list: None,
        };

        let output = runner.chat(&request).unwrap();

        assert_eq!(output.engine.engine_kind, LocalModelEngineKindV1::Ollama);
        assert!(
            output
                .output
                .get("message")
                .and_then(|message| message.get("content"))
                .and_then(Value::as_str)
                .is_some_and(|content| !content.trim().is_empty())
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
